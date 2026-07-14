//! Helper functions and path extraction utilities.

// --- Timestamp helpers ---

/// Get the current Unix timestamp in seconds.
pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Format a Unix timestamp (seconds) as an ISO 8601 / RFC 3339 string.
pub fn format_iso8601(ts: u64) -> Option<String> {
    if ts == 0 {
        return None;
    }
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(ts as i64)
        .ok()
        .map(|dt| dt.format(&Rfc3339).unwrap_or_default())
}

// --- Path extraction helpers ---

/// Extract session_id from `/v1/environments/{session_id}`.
/// Returns None if the path doesn't match.
pub fn extract_session_id(path: &str) -> Option<String> {
    let prefix = "/v1/environments/";
    let rest = path.strip_prefix(prefix)?;
    // Session ID should not contain slashes
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest.to_string())
}

/// Extract session_id from `/v1/environments/{session_id}/{suffix}`.
/// Returns None if the path doesn't match the expected suffix.
pub fn extract_session_id_and_suffix(path: &str, suffix: &str) -> Option<String> {
    let prefix = "/v1/environments/";
    let rest = path.strip_prefix(prefix)?;
    let session_id = rest.strip_suffix(suffix)?;
    if session_id.is_empty() || session_id.contains('/') {
        return None;
    }
    Some(session_id.to_string())
}

/// Validate session_id matches `^[a-z0-9_]{8,64}$`.
pub fn is_valid_session_id(s: &str) -> bool {
    if s.len() < 8 || s.len() > 64 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_session_id() {
        assert!(is_valid_session_id("sess_8f7a3b2c"));
        assert!(is_valid_session_id("abcdefgh123456"));
        assert!(is_valid_session_id(&"a".repeat(64)));
        assert!(is_valid_session_id("test_session_001"));

        // Too short
        assert!(!is_valid_session_id("short"));
        assert!(!is_valid_session_id("ab"));
        // Too long
        assert!(!is_valid_session_id(&"a".repeat(65)));
        // Invalid chars
        assert!(!is_valid_session_id("SESSION-UPPER"));
        assert!(!is_valid_session_id("sess-8f7a3b2c"));
        assert!(!is_valid_session_id("sess.8f7a"));
        assert!(!is_valid_session_id("sess 8f7a3b2c"));
    }

    #[test]
    fn test_extract_session_id() {
        assert_eq!(
            extract_session_id("/v1/environments/sess_12345678"),
            Some("sess_12345678".to_string())
        );
        assert_eq!(extract_session_id("/v1/environments/"), None);
        assert_eq!(extract_session_id("/v1/environments"), None);
        assert_eq!(extract_session_id("/v1/environments/abc/def"), None);
    }

    #[test]
    fn test_extract_session_id_and_suffix() {
        assert_eq!(
            extract_session_id_and_suffix("/v1/environments/sess_12345678/serial", "/serial"),
            Some("sess_12345678".to_string())
        );
        assert_eq!(
            extract_session_id_and_suffix("/v1/environments/sess_12345678", "/serial"),
            None
        );
        assert_eq!(
            extract_session_id_and_suffix("/v1/environments/abc/def/serial", "/serial"),
            None
        );
    }
}
