//! Secret store abstraction for credential fetching.
//!
//! The proxy uses a `SecretStore` to resolve `credential_ref` entries
//! (e.g. `vault://secret/data/agent-env/openai-key`) at session registration
//! time. Keys are held in memory only — never persisted to SQLite.
//!
//! In production this resolves against HashiCorp Vault. For tests,
//! `MockSecretStore` returns pre-configured keys.

use std::collections::HashMap;
use std::sync::Mutex;

/// Error returned when a credential reference cannot be resolved.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum SecretStoreError {
    #[error("credential ref not found: {0}")]
    NotFound(String),
    #[error("credential ref invalid: {0}")]
    Invalid(String),
    #[error("secret store error: {0}")]
    Internal(String),
}

/// Abstraction over a secret store (Vault in production, mock in tests).
pub trait SecretStore: Send + Sync {
    /// Resolve a credential reference (e.g. `vault://secret/data/path`)
    /// and return the secret value (the API key).
    fn fetch(&self, credential_ref: &str) -> Result<String, SecretStoreError>;
}

/// Mock secret store for tests. Keys are pre-configured in a HashMap.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct MockSecretStore {
    keys: Mutex<HashMap<String, String>>,
}

impl MockSecretStore {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn insert(&self, credential_ref: &str, key: &str) {
        self.keys
            .lock()
            .unwrap()
            .insert(credential_ref.to_string(), key.to_string());
    }
}

impl SecretStore for MockSecretStore {
    fn fetch(&self, credential_ref: &str) -> Result<String, SecretStoreError> {
        self.keys
            .lock()
            .unwrap()
            .get(credential_ref)
            .cloned()
            .ok_or_else(|| SecretStoreError::NotFound(credential_ref.to_string()))
    }
}

/// Parsed components of a `vault://` credential reference.
#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub struct ParsedCredentialRef {
    pub mount: String,
    pub path: String,
}

/// Parse a `vault://<mount>/<path>` credential reference.
///
/// Strips the `vault://` scheme prefix. If the path starts with `data/`,
/// strips that prefix (Vault KV v2 API convention — `vaultrs::kv2::read`
/// adds `data/` internally).
///
/// # Examples
///
/// ```
/// // vault://secret/data/agent-env/openai-key → mount="secret", path="agent-env/openai-key"
/// // vault://secret/my-key                  → mount="secret", path="my-key"
/// ```
fn parse_credential_ref(cref: &str) -> Result<ParsedCredentialRef, SecretStoreError> {
    let rest = cref
        .strip_prefix("vault://")
        .ok_or_else(|| SecretStoreError::Invalid(format!("not a vault:// ref: {cref}")))?;

    let (mount, path) = rest
        .split_once('/')
        .ok_or_else(|| SecretStoreError::Invalid(format!("missing path in ref: {cref}")))?;

    if mount.is_empty() || path.is_empty() {
        return Err(SecretStoreError::Invalid(format!(
            "empty mount or path: {cref}"
        )));
    }

    // Strip "data/" prefix if present (KV v2 convention)
    let path = path.strip_prefix("data/").unwrap_or(path);

    Ok(ParsedCredentialRef {
        mount: mount.to_string(),
        path: path.to_string(),
    })
}

/// HashiCorp Vault secret store using the `vaultrs` crate.
///
/// Connects to Vault at `vault_addr` using `vault_token`. Reads KV v2
/// secrets. The `fetch()` method is synchronous but internally bridges
/// to the async vaultrs API using `tokio::task::block_in_place` +
/// `Handle::block_on`.
///
/// The `tokio::runtime::Handle` is captured at construction time from
/// the currently running tokio runtime.
pub struct VaultSecretStore {
    client: vaultrs::client::VaultClient,
    runtime_handle: tokio::runtime::Handle,
}

impl std::fmt::Debug for VaultSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecretStore")
            .field("client", &"<VaultClient>")
            .field("runtime_handle", &self.runtime_handle)
            .finish()
    }
}

impl VaultSecretStore {
    /// Create a new `VaultSecretStore` connected to Vault at `vault_addr`
    /// using `vault_token`. Must be called from within a tokio runtime
    /// context (the proxy's `#[tokio::main]` runtime).
    ///
    /// # Panics
    ///
    /// Panics if not called from within a tokio runtime context.
    #[allow(dead_code)]
    pub fn new(vault_addr: &str, vault_token: &str) -> Result<Self, SecretStoreError> {
        let settings = vaultrs::client::VaultClientSettingsBuilder::default()
            .address(vault_addr)
            .token(vault_token.to_string())
            .build()
            .map_err(|e| SecretStoreError::Internal(format!("vault client config: {e}")))?;

        let client = vaultrs::client::VaultClient::new(settings)
            .map_err(|e| SecretStoreError::Internal(format!("vault client init: {e}")))?;

        let runtime_handle = tokio::runtime::Handle::try_current()
            .map_err(|e| SecretStoreError::Internal(format!("not in tokio context: {e}")))?;

        Ok(VaultSecretStore {
            client,
            runtime_handle,
        })
    }

    /// Async helper: read a KV v2 secret from Vault and extract the API key.
    async fn fetch_async(&self, mount: &str, path: &str) -> Result<String, SecretStoreError> {
        let response: vaultrs::api::kv2::responses::ReadSecretResponse =
            vaultrs::kv2::read(&self.client, mount, path)
                .await
                .map_err(|e| {
                    let msg = format!("{e}");
                    if msg.contains("not found") || msg.contains("404") {
                        SecretStoreError::NotFound(format!("{mount}/data/{path}: {msg}"))
                    } else {
                        SecretStoreError::Internal(format!("vault read {mount}/data/{path}: {msg}"))
                    }
                })?;

        // The response.data is a serde_json::Value (a JSON object).
        // Try common field names: "key", "api_key", "token".
        // Fall back to the first string value in the object.
        if let serde_json::Value::Object(ref map) = response.data {
            for field in &["key", "api_key", "token"] {
                if let Some(serde_json::Value::String(val)) = map.get(*field) {
                    return Ok(val.clone());
                }
            }
            // Fall back: first string value
            for (_, v) in map {
                if let serde_json::Value::String(val) = v {
                    return Ok(val.clone());
                }
            }
        }

        Err(SecretStoreError::Invalid(format!(
            "secret at {mount}/data/{path} has no string value"
        )))
    }
}

impl SecretStore for VaultSecretStore {
    fn fetch(&self, credential_ref: &str) -> Result<String, SecretStoreError> {
        let parsed = parse_credential_ref(credential_ref)?;

        // Bridge sync → async. Use block_in_place + handle.block_on.
        // block_in_place requires the multi-threaded runtime (which #[tokio::main] provides).
        let mount = parsed.mount.clone();
        let path = parsed.path.clone();

        tokio::task::block_in_place(|| {
            self.runtime_handle
                .block_on(self.fetch_async(&mount, &path))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_fetch_success() {
        let store = MockSecretStore::new();
        store.insert("vault://secret/data/test-key", "sk-test-123");
        assert_eq!(
            store.fetch("vault://secret/data/test-key").unwrap(),
            "sk-test-123"
        );
    }

    #[test]
    fn test_mock_fetch_not_found() {
        let store = MockSecretStore::new();
        let result = store.fetch("vault://secret/data/nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::NotFound(ref_str) => {
                assert_eq!(ref_str, "vault://secret/data/nonexistent");
            }
            e => panic!("expected NotFound, got {e:?}"),
        }
    }

    #[test]
    fn test_parse_credential_ref_with_data_prefix() {
        let parsed = parse_credential_ref("vault://secret/data/agent-env/openai-key").unwrap();
        assert_eq!(parsed.mount, "secret");
        assert_eq!(parsed.path, "agent-env/openai-key");
    }

    #[test]
    fn test_parse_credential_ref_without_data_prefix() {
        let parsed = parse_credential_ref("vault://secret/my-key").unwrap();
        assert_eq!(parsed.mount, "secret");
        assert_eq!(parsed.path, "my-key");
    }

    #[test]
    fn test_parse_credential_ref_nested_path() {
        let parsed = parse_credential_ref("vault://secret/data/agent-env/sub/openai-key").unwrap();
        assert_eq!(parsed.mount, "secret");
        assert_eq!(parsed.path, "agent-env/sub/openai-key");
    }

    #[test]
    fn test_parse_credential_ref_invalid_scheme() {
        let result = parse_credential_ref("http://secret/data/key");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::Invalid(msg) => assert!(msg.contains("not a vault:// ref")),
            e => panic!("expected Invalid, got {e:?}"),
        }
    }

    #[test]
    fn test_parse_credential_ref_missing_path() {
        let result = parse_credential_ref("vault://secret");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::Invalid(msg) => assert!(msg.contains("missing path")),
            e => panic!("expected Invalid, got {e:?}"),
        }
    }

    /// Integration test: requires a Vault dev server running on localhost:8200.
    /// Run with: cargo test --release -- --ignored vault::tests::test_vault_real
    ///
    /// Setup:
    ///   vault server -dev -dev-root-token-id=root &
    ///   VAULT_ADDR=http://127.0.0.1:8200 vault kv put secret/agent-env/openai-key key=sk-test-123
    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // Requires real Vault dev server
    async fn test_vault_real_fetch_success() {
        let store = VaultSecretStore::new("http://127.0.0.1:8200", "root")
            .expect("failed to create VaultSecretStore — is vault dev server running?");

        let key = store
            .fetch("vault://secret/data/agent-env/openai-key")
            .expect("fetch should succeed");
        assert_eq!(key, "sk-test-123");
    }

    /// Integration test: Vault unreachable should return Internal error.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // Slow (timeout-based)
    async fn test_vault_real_unreachable() {
        // Point to a port nothing is listening on
        let store = VaultSecretStore::new("http://127.0.0.1:59999", "root")
            .expect("vault client creation should succeed even if server is down");

        let result = store.fetch("vault://secret/data/agent-env/openai-key");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::Internal(msg) => {
                // Should mention the vault read or connection error
                assert!(
                    msg.contains("vault read")
                        || msg.contains("Connection")
                        || msg.contains("connection")
                );
            }
            e => panic!("expected Internal, got {e:?}"),
        }
    }

    /// Integration test: secret not found should return NotFound error.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // Requires real Vault dev server
    async fn test_vault_real_not_found() {
        let store = VaultSecretStore::new("http://127.0.0.1:8200", "root")
            .expect("failed to create VaultSecretStore");

        let result = store.fetch("vault://secret/data/nonexistent-key-12345");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::NotFound(msg) => {
                assert!(msg.contains("nonexistent-key-12345"));
            }
            SecretStoreError::Internal(msg) => {
                // vaultrs may return 404 as an APIError, which we map to Internal
                // The important thing is that it's an error, not a success
                assert!(msg.contains("vault read") || msg.contains("404"));
            }
            e => panic!("expected NotFound or Internal, got {e:?}"),
        }
    }
}
