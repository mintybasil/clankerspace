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
pub struct MockSecretStore {
    keys: Mutex<HashMap<String, String>>,
}

impl MockSecretStore {
    pub fn new() -> Self {
        Self::default()
    }

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
}