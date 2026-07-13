//! Secret store abstraction for credential fetching.
//!
//! The proxy uses a `SecretStore` to resolve `credential_ref` entries
//! (e.g. `vault://secret/data/agent-env/openai-key`) at session registration
//! time. Keys are held in memory only — never persisted to SQLite.
//!
//! In production, `FileSecretStore` reads a pre-decrypted JSON key file
//! (the file is encrypted at rest by an external tool such as `age`, GPG,
//! or LUKS — the proxy does not handle decryption). For tests,
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

/// Abstraction over a secret store (file-based in production, mock in tests).
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

/// File-based secret store for production.
///
/// Reads a pre-decrypted JSON file mapping `credential_ref` URIs to API keys.
/// The file is encrypted at rest by an external tool (`age`, GPG, LUKS) —
/// the proxy reads the already-decrypted plaintext JSON. Keys are held in
/// memory for the proxy's lifetime.
///
/// Format:
/// ```json
/// {
///   "vault://secret/data/agent-env/openai-key": "sk-...",
///   "vault://secret/data/agent-env/anthropic-key": "sk-ant-..."
/// }
/// ```
#[derive(Debug)]
#[allow(dead_code)]
pub struct FileSecretStore {
    keys: HashMap<String, String>,
}

impl FileSecretStore {
    /// Create a `FileSecretStore` from already-decrypted JSON content.
    #[allow(dead_code)]
    pub fn new(plaintext_json: &str) -> Result<Self, SecretStoreError> {
        let keys: HashMap<String, String> = serde_json::from_str(plaintext_json)
            .map_err(|e| SecretStoreError::Invalid(format!("malformed key file JSON: {e}")))?;
        if keys.is_empty() {
            return Err(SecretStoreError::Invalid("key file is empty".into()));
        }
        Ok(Self { keys })
    }

    /// Create a `FileSecretStore` by reading a plaintext JSON file from disk.
    ///
    /// The file should already be decrypted by an external tool before
    /// calling this.
    #[allow(dead_code)]
    pub fn from_file(path: &str) -> Result<Self, SecretStoreError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SecretStoreError::Internal(format!("failed to read key file {path}: {e}"))
        })?;
        Self::new(&content)
    }
}

impl SecretStore for FileSecretStore {
    fn fetch(&self, credential_ref: &str) -> Result<String, SecretStoreError> {
        self.keys
            .get(credential_ref)
            .cloned()
            .ok_or_else(|| SecretStoreError::NotFound(credential_ref.to_string()))
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

    // --- FileSecretStore tests ---

    #[test]
    fn test_file_store_load_and_fetch() {
        let json = r#"{"vault://secret/data/openai-key": "sk-abc123", "vault://secret/data/anthropic-key": "sk-ant-xyz"}"#;
        let store = FileSecretStore::new(json).unwrap();
        assert_eq!(
            store.fetch("vault://secret/data/openai-key").unwrap(),
            "sk-abc123"
        );
        assert_eq!(
            store.fetch("vault://secret/data/anthropic-key").unwrap(),
            "sk-ant-xyz"
        );
    }

    #[test]
    fn test_file_store_missing_key() {
        let json = r#"{"vault://secret/data/openai-key": "sk-abc123"}"#;
        let store = FileSecretStore::new(json).unwrap();
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
    fn test_file_store_malformed_json() {
        let result = FileSecretStore::new("not valid json {{{");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::Invalid(_) => {}
            e => panic!("expected Invalid, got {e:?}"),
        }
    }

    #[test]
    fn test_file_store_empty_file() {
        let result = FileSecretStore::new("{}");
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretStoreError::Invalid(_) => {}
            e => panic!("expected Invalid, got {e:?}"),
        }
    }

    #[test]
    fn test_file_store_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("ae-poc-test-keys.json");
        std::fs::write(&path, r#"{"vault://secret/data/test-key": "sk-from-file"}"#).unwrap();

        let store = FileSecretStore::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(
            store.fetch("vault://secret/data/test-key").unwrap(),
            "sk-from-file"
        );

        std::fs::remove_file(&path).ok();
    }
}
