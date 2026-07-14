//! Session management with SQLite persistence.
//!
//! Sessions are keyed by `source_ip` (the VM's TAP interface IP) for fast
//! lookup during proxy CONNECT handling. The `session_id` is the primary key
//! in SQLite and the canonical identifier in the REST API.
//!
//! API keys are deliberately NOT persisted to SQLite — they are held in
//! memory only and must be re-fetched from Vault on proxy restart.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum SessionError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("json: {0}")]
    Json(String),
    #[error("session already exists: {0}")]
    AlreadyExists(String),
    #[error("session not found: {0}")]
    #[allow(dead_code)]
    NotFound(String),
    #[error("invalid session data: {0}")]
    #[allow(dead_code)]
    Invalid(String),
}

impl From<rusqlite::Error> for SessionError {
    fn from(e: rusqlite::Error) -> Self {
        SessionError::Sqlite(e.to_string())
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(e: serde_json::Error) -> Self {
        SessionError::Json(e.to_string())
    }
}

/// A single allowlist entry for a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowlistEntry {
    pub domain: String,
    pub mode: String, // "mitm" or "tunnel"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
}

/// A proxy session. Persisted to SQLite (minus `api_key` which is memory-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub source_ip: String,
    pub allowlist: Vec<AllowlistEntry>,
    pub created_at: u64,         // Unix timestamp (seconds)
    pub expires_at: Option<u64>, // Unix timestamp (seconds), None = no expiry

    /// API key held in memory only — never persisted to SQLite.
    #[serde(skip)]
    pub api_key: Option<String>,
}

/// REST API request body for `POST /sessions`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateSessionRequest {
    pub session_id: String,
    pub source_ip: String,
    pub allowlist: Vec<AllowlistEntry>,
    pub expires_at: Option<String>, // ISO 8601 string from the API
}

/// REST API response for session details.
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SessionResponse {
    pub session_id: String,
    pub source_ip: String,
    pub allowlist: Vec<AllowlistEntry>,
    pub created_at: String,
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<SessionStats>,
    /// Dummy keys for VM environment injection (credential_ref → dummy key).
    /// Only present when the session has mitm-mode entries with credential_refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dummy_keys: Option<HashMap<String, String>>,
}

/// REST API response for `GET /sessions` (list).
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SessionSummary {
    pub session_id: String,
    pub source_ip: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Per-session request statistics (in-memory only, not persisted).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SessionStats {
    pub requests_total: u64,
    pub requests_mitm: u64,
    pub requests_tunnel: u64,
    pub requests_dropped: u64,
    pub bytes_upstream: u64,
    pub bytes_downstream: u64,
}

impl From<&Session> for SessionResponse {
    fn from(s: &Session) -> Self {
        SessionResponse {
            session_id: s.session_id.clone(),
            source_ip: s.source_ip.clone(),
            allowlist: s.allowlist.clone(),
            created_at: format_iso8601(s.created_at).unwrap_or_default(),
            expires_at: s.expires_at.and_then(format_iso8601),
            stats: None,
            dummy_keys: None,
        }
    }
}

impl From<&Session> for SessionSummary {
    fn from(s: &Session) -> Self {
        SessionSummary {
            session_id: s.session_id.clone(),
            source_ip: s.source_ip.clone(),
            created_at: format_iso8601(s.created_at).unwrap_or_default(),
            expires_at: s.expires_at.and_then(format_iso8601),
        }
    }
}

#[allow(dead_code)]
const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    source_ip    TEXT NOT NULL UNIQUE,
    allowlist    TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
";

/// Thread-safe session store backed by SQLite + an in-memory HashMap.
///
/// The in-memory map is keyed by `source_ip` for O(1) lookup during CONNECT
/// handling. SQLite provides durability across proxy restarts.
///
/// The `Mutex<Connection>` is fine for the PoC — the proxy is single-threaded
/// for control-plane operations. A production version would use a connection
/// pool or WAL mode with multiple readers.
pub struct SessionStore {
    /// SQLite connection (guarded by mutex).
    conn: std::sync::Mutex<Connection>,
    /// In-memory map: source_ip → Session (for fast CONNECT lookup).
    sessions: std::sync::Mutex<HashMap<String, Session>>,
    /// In-memory stats per session_id (not persisted to SQLite).
    stats: std::sync::Mutex<HashMap<String, SessionStats>>,
}

impl SessionStore {
    /// Open (or create) the SQLite database at `path` and load sessions
    /// into memory. Expired sessions are purged during load.
    #[allow(dead_code)]
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Arc<Self>, SessionError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA_SQL)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Purge expired sessions on startup
        conn.execute(
            "DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?1",
            rusqlite::params![now as i64],
        )?;

        // Load remaining sessions into memory
        let mut map = HashMap::new();
        let sessions: Vec<Session> = {
            let conn_guard = &conn;
            let mut stmt = conn_guard.prepare(
                "SELECT session_id, source_ip, allowlist, created_at, expires_at FROM sessions",
            )?;
            let rows = stmt.query_map([], |row| {
                let allowlist_json: String = row.get(2)?;
                let allowlist: Vec<AllowlistEntry> =
                    serde_json::from_str(&allowlist_json).unwrap_or_default();
                let expires_at: Option<i64> = row.get(4)?;
                Ok(Session {
                    session_id: row.get(0)?,
                    source_ip: row.get(1)?,
                    allowlist,
                    created_at: row.get::<_, i64>(3)? as u64,
                    expires_at: expires_at.map(|v| v as u64),
                    api_key: None, // Not persisted — re-fetched from Vault on restart
                })
            })?;
            rows.filter_map(|r| r.ok()).collect()
        };
        for session in sessions {
            map.insert(session.source_ip.clone(), session);
        }

        log(&format!(
            "Session store loaded: {} active session(s)",
            map.len()
        ));

        Ok(Arc::new(SessionStore {
            conn: std::sync::Mutex::new(conn),
            sessions: std::sync::Mutex::new(map),
            stats: std::sync::Mutex::new(HashMap::new()),
        }))
    }

    /// Create an in-memory-only store (for testing).
    #[allow(dead_code)]
    pub fn in_memory() -> Result<Arc<Self>, SessionError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Arc::new(SessionStore {
            conn: std::sync::Mutex::new(conn),
            sessions: std::sync::Mutex::new(HashMap::new()),
            stats: std::sync::Mutex::new(HashMap::new()),
        }))
    }

    /// Register a new session. Persists to SQLite and inserts into the
    /// in-memory map.
    pub fn create(&self, mut session: Session) -> Result<(), SessionError> {
        // Check for duplicate session_id in SQLite
        {
            let conn = self.conn.lock().unwrap();
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM sessions WHERE session_id = ?1",
                    rusqlite::params![session.session_id],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if exists {
                return Err(SessionError::AlreadyExists(session.session_id.clone()));
            }

            // Check for duplicate source_ip
            let ip_exists: bool = conn
                .query_row(
                    "SELECT 1 FROM sessions WHERE source_ip = ?1",
                    rusqlite::params![session.source_ip],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if ip_exists {
                return Err(SessionError::AlreadyExists(session.source_ip.clone()));
            }
        }

        // Persist to SQLite (without api_key)
        let allowlist_json = serde_json::to_string(&session.allowlist)?;
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO sessions (session_id, source_ip, allowlist, created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    session.session_id,
                    session.source_ip,
                    allowlist_json,
                    session.created_at as i64,
                    session.expires_at.map(|v| v as i64),
                ],
            )?;
        }

        // Insert into in-memory map
        // Ensure api_key is None (don't persist)
        session.api_key = None;
        let mut map = self.sessions.lock().unwrap();
        map.insert(session.source_ip.clone(), session);

        Ok(())
    }

    /// Get a session by session_id.
    #[allow(dead_code)]
    pub fn get(&self, session_id: &str) -> Option<Session> {
        let map = self.sessions.lock().unwrap();
        map.values().find(|s| s.session_id == session_id).cloned()
    }

    /// Look up a session by source IP (used during CONNECT handling).
    pub fn get_by_ip(&self, source_ip: &str) -> Option<Session> {
        let map = self.sessions.lock().unwrap();
        map.get(source_ip).cloned()
    }

    /// Delete a session by session_id. Removes from both SQLite and memory.
    #[allow(dead_code)]
    pub fn delete(&self, session_id: &str) -> Result<bool, SessionError> {
        // Find the session to get its source_ip (for memory map removal)
        let source_ip = {
            let map = self.sessions.lock().unwrap();
            map.values()
                .find(|s| s.session_id == session_id)
                .map(|s| s.source_ip.clone())
        };

        let source_ip = match source_ip {
            Some(ip) => ip,
            None => return Ok(false), // Not found
        };

        // Remove from SQLite
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?1",
                rusqlite::params![session_id],
            )?;
        }

        // Remove from in-memory map
        {
            let mut map = self.sessions.lock().unwrap();
            map.remove(&source_ip);
        }

        // Remove stats
        {
            self.stats.lock().unwrap().remove(&session_id.to_string());
        }

        Ok(true)
    }

    /// List all active sessions.
    #[allow(dead_code)]
    pub fn list(&self) -> Vec<Session> {
        let map = self.sessions.lock().unwrap();
        map.values().cloned().collect()
    }

    /// Get the count of active sessions.
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Record a request for a session (updates in-memory stats only).
    #[allow(dead_code)]
    pub fn record_stats(&self, session_id: &str, kind: &str, bytes_up: u64, bytes_down: u64) {
        let mut stats = self.stats.lock().unwrap();
        let entry = stats.entry(session_id.to_string()).or_default();
        entry.requests_total += 1;
        match kind {
            "mitm" => entry.requests_mitm += 1,
            "tunnel" => entry.requests_tunnel += 1,
            "dropped" => entry.requests_dropped += 1,
            _ => {}
        }
        entry.bytes_upstream += bytes_up;
        entry.bytes_downstream += bytes_down;
    }

    /// Get stats for a session.
    #[allow(dead_code)]
    pub fn get_stats(&self, session_id: &str) -> Option<SessionStats> {
        self.stats.lock().unwrap().get(session_id).cloned()
    }

    /// Set the API key for a session (memory only, not persisted).
    #[allow(dead_code)]
    pub fn set_api_key(&self, session_id: &str, api_key: String) -> bool {
        let mut map = self.sessions.lock().unwrap();
        if let Some(session) = map.values_mut().find(|s| s.session_id == session_id) {
            session.api_key = Some(api_key);
            true
        } else {
            false
        }
    }
}

#[allow(dead_code)]
fn log(msg: &str) {
    tracing::info!("{}", msg);
}

/// Get the current Unix timestamp in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Parse an ISO 8601 timestamp string into Unix seconds.
/// Returns None if parsing fails or the string is empty.
#[allow(dead_code)]
pub fn parse_iso8601(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    // Try parsing with time crate's OffsetDateTime
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::parse(s, &Rfc3339) {
        Ok(dt) => Some(dt.unix_timestamp() as u64),
        Err(_) => None,
    }
}

/// Format a Unix timestamp (seconds) as an ISO 8601 / RFC 3339 string.
/// Returns None if the timestamp is 0.
#[allow(dead_code)]
pub fn format_iso8601(ts: u64) -> Option<String> {
    if ts == 0 {
        return None;
    }
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(ts as i64)
        .ok()
        .map(|dt| dt.format(&Rfc3339).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(id: &str, ip: &str) -> Session {
        Session {
            session_id: id.to_string(),
            source_ip: ip.to_string(),
            allowlist: vec![AllowlistEntry {
                domain: "api.openai.com".to_string(),
                mode: "mitm".to_string(),
                credential_ref: Some("vault://secret/data/test-key".to_string()),
            }],
            created_at: now_secs(),
            expires_at: Some(now_secs() + 3600),
            api_key: Some("sk-test-key".to_string()),
        }
    }

    #[test]
    fn test_create_and_get() {
        let store = SessionStore::in_memory().unwrap();
        let session = make_session("sess_001", "10.0.1.42");

        store.create(session.clone()).unwrap();

        // Get by session_id
        let retrieved = store.get("sess_001").expect("session should exist");
        assert_eq!(retrieved.session_id, "sess_001");
        assert_eq!(retrieved.source_ip, "10.0.1.42");
        assert_eq!(retrieved.allowlist.len(), 1);
        assert_eq!(retrieved.allowlist[0].domain, "api.openai.com");
        assert_eq!(retrieved.allowlist[0].mode, "mitm");

        // Get by source_ip (used in CONNECT handling)
        let by_ip = store.get_by_ip("10.0.1.42").expect("session should exist");
        assert_eq!(by_ip.session_id, "sess_001");
    }

    #[test]
    fn test_api_key_not_persisted() {
        let store = SessionStore::in_memory().unwrap();
        let mut session = make_session("sess_key", "10.0.1.50");
        session.api_key = Some("sk-secret".to_string());

        store.create(session).unwrap();

        // api_key should be None after create (not persisted)
        let retrieved = store.get("sess_key").unwrap();
        assert_eq!(retrieved.api_key, None);
    }

    #[test]
    fn test_duplicate_session_id_rejected() {
        let store = SessionStore::in_memory().unwrap();
        store.create(make_session("sess_dup", "10.0.1.51")).unwrap();

        let result = store.create(make_session("sess_dup", "10.0.1.52"));
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::AlreadyExists(id) => assert_eq!(id, "sess_dup"),
            e => panic!("expected AlreadyExists, got {e:?}"),
        }
    }

    #[test]
    fn test_duplicate_source_ip_rejected() {
        let store = SessionStore::in_memory().unwrap();
        store.create(make_session("sess_a", "10.0.1.60")).unwrap();

        let result = store.create(make_session("sess_b", "10.0.1.60"));
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::AlreadyExists(ip) => assert_eq!(ip, "10.0.1.60"),
            e => panic!("expected AlreadyExists, got {e:?}"),
        }
    }

    #[test]
    fn test_delete() {
        let store = SessionStore::in_memory().unwrap();
        store.create(make_session("sess_del", "10.0.1.70")).unwrap();

        assert!(store.get("sess_del").is_some());

        let deleted = store.delete("sess_del").unwrap();
        assert!(deleted);

        assert!(store.get("sess_del").is_none());
        assert!(store.get_by_ip("10.0.1.70").is_none());

        // Deleting again returns false
        let deleted_again = store.delete("sess_del").unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_delete_nonexistent() {
        let store = SessionStore::in_memory().unwrap();
        let result = store.delete("nonexistent").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_list() {
        let store = SessionStore::in_memory().unwrap();
        store
            .create(make_session("sess_list1", "10.0.1.80"))
            .unwrap();
        store
            .create(make_session("sess_list2", "10.0.1.81"))
            .unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_count() {
        let store = SessionStore::in_memory().unwrap();
        assert_eq!(store.count(), 0);
        store
            .create(make_session("sess_count", "10.0.1.90"))
            .unwrap();
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_set_api_key() {
        let store = SessionStore::in_memory().unwrap();
        store
            .create(make_session("sess_apikey", "10.0.1.91"))
            .unwrap();

        // api_key is None after create
        assert_eq!(store.get("sess_apikey").unwrap().api_key, None);

        // Set API key (simulates Vault fetch after restart)
        let set = store.set_api_key("sess_apikey", "sk-fetched".to_string());
        assert!(set);

        assert_eq!(
            store.get("sess_apikey").unwrap().api_key,
            Some("sk-fetched".to_string())
        );
    }

    #[test]
    fn test_set_api_key_nonexistent() {
        let store = SessionStore::in_memory().unwrap();
        let set = store.set_api_key("nonexistent", "sk-key".to_string());
        assert!(!set);
    }

    // --- SQLite persistence tests ---

    #[test]
    fn test_persist_and_recover() {
        let db_path = "/tmp/ae-poc-test-session-persist.sqlite";
        let _ = std::fs::remove_file(db_path);

        // Create store, add a session
        {
            let store = SessionStore::open(db_path).unwrap();
            store
                .create(make_session("sess_persist", "10.0.1.100"))
                .unwrap();
            assert_eq!(store.count(), 1);
        }

        // Reopen — session should be recovered from SQLite
        {
            let store = SessionStore::open(db_path).unwrap();
            assert_eq!(store.count(), 1);
            let session = store
                .get("sess_persist")
                .expect("session should survive restart");
            assert_eq!(session.session_id, "sess_persist");
            assert_eq!(session.source_ip, "10.0.1.100");
            assert_eq!(session.allowlist.len(), 1);
            assert_eq!(session.allowlist[0].domain, "api.openai.com");
            assert_eq!(session.allowlist[0].mode, "mitm");
            // api_key not persisted — must be None on recovery
            assert_eq!(session.api_key, None);
        }

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_delete_persists_to_sqlite() {
        let db_path = "/tmp/ae-poc-test-session-delete.sqlite";
        let _ = std::fs::remove_file(db_path);

        // Create store, add a session, delete it
        {
            let store = SessionStore::open(db_path).unwrap();
            store
                .create(make_session("sess_del_persist", "10.0.1.110"))
                .unwrap();
            let deleted = store.delete("sess_del_persist").unwrap();
            assert!(deleted);
        }

        // Reopen — session should be gone
        {
            let store = SessionStore::open(db_path).unwrap();
            assert_eq!(store.count(), 0);
            assert!(store.get("sess_del_persist").is_none());
        }

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_expired_sessions_cleaned_on_startup() {
        let db_path = "/tmp/ae-poc-test-session-expiry.sqlite";
        let _ = std::fs::remove_file(db_path);

        // Create store with one expired and one active session
        {
            let store = SessionStore::open(db_path).unwrap();

            let mut expired = make_session("sess_expired", "10.0.1.120");
            expired.expires_at = Some(now_secs() - 100); // expired 100s ago
            store.create(expired).unwrap();

            let active = make_session("sess_active", "10.0.1.121");
            store.create(active).unwrap();

            assert_eq!(store.count(), 2);
        }

        // Reopen — expired session should be purged
        {
            let store = SessionStore::open(db_path).unwrap();
            assert_eq!(store.count(), 1);
            assert!(store.get("sess_expired").is_none());
            assert!(store.get("sess_active").is_some());
        }

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_no_expiry_session_survives() {
        let db_path = "/tmp/ae-poc-test-session-noexpiry.sqlite";
        let _ = std::fs::remove_file(db_path);

        {
            let store = SessionStore::open(db_path).unwrap();
            let mut session = make_session("sess_noexpiry", "10.0.1.130");
            session.expires_at = None; // no expiry
            store.create(session).unwrap();
        }

        {
            let store = SessionStore::open(db_path).unwrap();
            assert_eq!(store.count(), 1);
            let session = store.get("sess_noexpiry").unwrap();
            assert_eq!(session.expires_at, None);
        }

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_parse_iso8601() {
        assert_eq!(parse_iso8601(""), None);
        assert_eq!(parse_iso8601("not-a-date"), None);
        // Valid RFC3339 timestamp
        let ts = parse_iso8601("2026-07-07T22:37:06Z");
        assert!(ts.is_some());
        assert!(ts.unwrap() > 0);
    }

    #[test]
    fn test_format_iso8601() {
        assert_eq!(format_iso8601(0), None);
        let ts_str = format_iso8601(1751908626).unwrap(); // 2025-07-07T...
        assert!(ts_str.contains("T"));
        assert!(ts_str.contains("Z") || ts_str.contains("+"));
    }

    #[test]
    fn test_format_and_parse_roundtrip() {
        let original = 1751908626u64;
        let formatted = format_iso8601(original).unwrap();
        let parsed = parse_iso8601(&formatted).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_record_and_get_stats() {
        let store = SessionStore::in_memory().unwrap();
        store
            .create(make_session("sess_stats", "10.0.1.200"))
            .unwrap();

        store.record_stats("sess_stats", "mitm", 100, 200);
        store.record_stats("sess_stats", "mitm", 50, 75);
        store.record_stats("sess_stats", "tunnel", 30, 40);
        store.record_stats("sess_stats", "dropped", 0, 0);

        let stats = store.get_stats("sess_stats").expect("stats should exist");
        assert_eq!(stats.requests_total, 4);
        assert_eq!(stats.requests_mitm, 2);
        assert_eq!(stats.requests_tunnel, 1);
        assert_eq!(stats.requests_dropped, 1);
        assert_eq!(stats.bytes_upstream, 180);
        assert_eq!(stats.bytes_downstream, 315);
    }

    #[test]
    fn test_stats_removed_on_delete() {
        let store = SessionStore::in_memory().unwrap();
        store
            .create(make_session("sess_stats_del", "10.0.1.201"))
            .unwrap();
        store.record_stats("sess_stats_del", "mitm", 10, 20);
        assert!(store.get_stats("sess_stats_del").is_some());

        store.delete("sess_stats_del").unwrap();
        assert!(store.get_stats("sess_stats_del").is_none());
    }

    #[test]
    fn test_get_stats_nonexistent() {
        let store = SessionStore::in_memory().unwrap();
        assert!(store.get_stats("nonexistent").is_none());
    }
}
