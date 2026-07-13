//! Secret store abstraction for credential fetching.
//!
//! The proxy uses a `SecretStore` to resolve `credential_ref` entries
//! (e.g., `vault://secret/data/agent-env/openai-key`) at session registration
//! time. Each `credential_ref` maps to a `KeyPair` containing a dummy key
//! (injected into the VM) and a real key (used for upstream API calls).
//! Key pairs are held in memory only — never persisted to SQLite.
//!
//! In production, `FileSecretStore` loads key pairs from stdin (piped from
//! an external decryption tool like `age`). The decrypted JSON goes directly
//! from the tool's stdout into the proxy's process memory — it never exists
//! on disk. For tests, `MockSecretStore` returns pre-configured key pairs.

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

/// A dummy→real key pair. The dummy key is injected into the VM environment;
/// the real key is used for upstream API calls. The proxy swaps the dummy
/// for the real at MITM time.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeyPair {
    pub dummy: String,
    pub real: String,
}

/// Abstraction over a secret store (file-based in production, mock in tests).
pub trait SecretStore: Send + Sync {
    /// Resolve a credential reference and return the `{dummy, real}` key pair.
    fn fetch(&self, credential_ref: &str) -> Result<KeyPair, SecretStoreError>;
}

/// Mock secret store for tests. Key pairs are pre-configured in a HashMap.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct MockSecretStore {
    keys: Mutex<HashMap<String, KeyPair>>,
}

impl MockSecretStore {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn insert(&self, credential_ref: &str, dummy: &str, real: &str) {
        self.keys.lock().unwrap().insert(
            credential_ref.to_string(),
            KeyPair {
                dummy: dummy.to_string(),
                real: real.to_string(),
            },
        );
    }
}

impl SecretStore for MockSecretStore {
    fn fetch(&self, credential_ref: &str) -> Result<KeyPair, SecretStoreError> {
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
/// Loads key pairs from stdin (piped from an external decryption tool).
/// Keys are held in memory for the proxy's lifetime.
///
/// ## Key file format (plaintext JSON, after decryption)
/// ```json
/// {
///   "vault://secret/data/agent-env/openai-key": {
///     "dummy": "sk-dum-a7f3b2c1d4e8...",
///     "real": "sk-proj-AbCdEfGhIjKlMn..."
///   },
///   "vault://secret/data/agent-env/anthropic-key": {
///     "dummy": "sk-ant-dum-x9y8z7w6...",
///     "real": "sk-ant-api03-Realkey..."
///   }
/// }
/// ```
///
/// ## Usage
/// ```bash
/// # Decrypt externally, pipe to the proxy:
/// age -d -i /etc/ae/identity /etc/ae/keys.age | ae-poc
/// ```
#[derive(Debug)]
#[allow(dead_code)]
pub struct FileSecretStore {
    keys: HashMap<String, KeyPair>,
}

impl FileSecretStore {
    /// Create a `FileSecretStore` from already-decrypted JSON content.
    pub fn new(plaintext_json: &str) -> Result<Self, SecretStoreError> {
        let keys: HashMap<String, KeyPair> = serde_json::from_str(plaintext_json)
            .map_err(|e| SecretStoreError::Invalid(format!("malformed key file JSON: {e}")))?;
        if keys.is_empty() {
            return Err(SecretStoreError::Invalid("key file is empty".into()));
        }
        Ok(Self { keys })
    }

    /// Create a `FileSecretStore` by reading plaintext JSON from stdin.
    ///
    /// The operator pipes the decrypted key file from an external decryption
    /// tool (e.g., `age`). The plaintext JSON goes from the tool's stdout
    /// into the proxy's process memory — it never exists on disk.
    ///
    /// Example:
    /// ```bash
    /// age -d -i /etc/ae/identity /etc/ae/keys.age | ae-poc
    /// ```
    pub fn from_stdin() -> Result<Self, SecretStoreError> {
        use std::io::Read;
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| SecretStoreError::Internal(format!("failed to read stdin: {e}")))?;
        Self::new(&input)
    }
}

impl SecretStore for FileSecretStore {
    fn fetch(&self, credential_ref: &str) -> Result<KeyPair, SecretStoreError> {
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
        store.insert(
            "vault://secret/data/test-key",
            "sk-dummy-123",
            "sk-real-456",
        );
        let pair = store.fetch("vault://secret/data/test-key").unwrap();
        assert_eq!(pair.dummy, "sk-dummy-123");
        assert_eq!(pair.real, "sk-real-456");
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
        let json = r#"{"vault://secret/data/openai-key": {"dummy": "sk-dum-abc", "real": "sk-real-abc"}, "vault://secret/data/anthropic-key": {"dummy": "sk-ant-dum-xyz", "real": "sk-ant-real-xyz"}}"#;
        let store = FileSecretStore::new(json).unwrap();
        let pair = store.fetch("vault://secret/data/openai-key").unwrap();
        assert_eq!(pair.dummy, "sk-dum-abc");
        assert_eq!(pair.real, "sk-real-abc");
        let pair = store.fetch("vault://secret/data/anthropic-key").unwrap();
        assert_eq!(pair.dummy, "sk-ant-dum-xyz");
        assert_eq!(pair.real, "sk-ant-real-xyz");
    }

    #[test]
    fn test_file_store_missing_key() {
        let json =
            r#"{"vault://secret/data/openai-key": {"dummy": "sk-dum-abc", "real": "sk-real-abc"}}"#;
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
    fn test_file_store_from_stdin_parsing() {
        // We can't easily pipe in a unit test, so we verify the JSON parsing
        // path is shared with from_stdin via new(). The actual stdin piping
        // is tested via integration (the `|` shell operator).
        let json =
            r#"{"vault://secret/data/test-key": {"dummy": "sk-dum-test", "real": "sk-real-test"}}"#;
        let store = FileSecretStore::new(json).unwrap();
        let pair = store.fetch("vault://secret/data/test-key").unwrap();
        assert_eq!(pair.dummy, "sk-dum-test");
        assert_eq!(pair.real, "sk-real-test");
    }
}
