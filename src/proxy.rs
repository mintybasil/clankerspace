//! MITM TLS proxy core — uses hyper's CONNECT upgrade (from ae-egress-proxy).
//!
//! This is the proven approach from Spike 1: hyper handles the CONNECT
//! request and connection upgrade. The key difference from the raw TCP
//! approach is that hyper's upgrade mechanism properly handles the
//! transition from HTTP to raw bytes, including any buffered data.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::session::{
    CreateSessionRequest, Session, SessionError, SessionListResponse, SessionResponse,
    SessionStore, SessionSummary, now_secs, parse_iso8601,
};
use crate::stream::copy_bidirectional;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(String),
    #[error("http: {0}")]
    Http(String),
}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        ProxyError::Io(e.to_string())
    }
}

/// Shared proxy state.
#[derive(Clone)]
pub struct ProxyState {
    pub server_config: Arc<rustls::ServerConfig>,
    pub upstream_config: Arc<rustls::ClientConfig>,
    /// Global allowlist (PoC mode — used when no session store is configured).
    pub allowlist: Vec<String>,
    /// API key for PoC mode (global, no session store).
    pub api_key: String,
    pub upstream_port: u16,
    pub upstream_host: String,
    pub expected_vm_ip: String,
    /// Session store for production mode (per-session allowlist, source-IP lookup).
    /// When set, takes precedence over the global allowlist.
    pub sessions: Option<Arc<SessionStore>>,
    /// Secret store for credential resolution (Vault in prod, mock in tests).
    pub secret_store: Option<Arc<dyn crate::vault::SecretStore>>,
    /// CA cert SHA-256 fingerprint (hex with colons) for health endpoint.
    pub ca_cert_sha256: String,
    /// Proxy start time (Unix seconds) for uptime calculation.
    pub start_time: u64,
}

/// Handle a raw TCP connection from a client using hyper's HTTP/1.1 server.
pub async fn handle_connection(stream: TcpStream, state: ProxyState) -> Result<(), ProxyError> {
    let peer = stream.peer_addr().ok();
    if let Some(addr) = peer {
        let ip = addr.ip().to_string();
        let is_vm = ip == state.expected_vm_ip;
        log(&format!(
            "CONNECT from {} — {}",
            ip,
            if is_vm {
                "✓ VM source IP (session identified)"
            } else {
                "⚠ unexpected source IP"
            }
        ));
    }

    let io = TokioIo::new(stream);
    let svc = ProxyService { state, peer };
    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades();

    conn.await.map_err(|e| ProxyError::Http(e.to_string()))
}

#[derive(Clone)]
struct ProxyService {
    state: ProxyState,
    peer: Option<std::net::SocketAddr>,
}

impl ProxyService {
    async fn handle_connect(
        self,
        host_port: String,
        mut req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
            None => (host_port.clone(), 443),
        };

        // Session-based allowlist check (production mode)
        let mut session_api_key: Option<String> = None;
        if let Some(store) = &self.state.sessions {
            let peer_ip = self.peer.map(|a| a.ip().to_string());
            let session = peer_ip.and_then(|ip| store.get_by_ip(&ip));

            let session = match session {
                Some(s) => s,
                None => {
                    log(&format!(
                        "DROP: {host} — no session for peer={:?}",
                        self.peer
                    ));
                    let mut resp = Response::new(Full::new(Bytes::new()));
                    *resp.status_mut() = StatusCode::FORBIDDEN;
                    return Ok(resp);
                }
            };

            // Check host against session's allowlist
            let h = host.to_lowercase();
            let allowed = session
                .allowlist
                .iter()
                .any(|a| a.domain.to_lowercase() == h);
            if !allowed {
                log(&format!(
                    "DROP: {host} not in session allowlist (session={})",
                    session.session_id
                ));
                let mut resp = Response::new(Full::new(Bytes::new()));
                *resp.status_mut() = StatusCode::FORBIDDEN;
                return Ok(resp);
            }

            log(&format!(
                "ALLOW: {host}:{port} — session={} mode={}",
                session.session_id,
                session
                    .allowlist
                    .iter()
                    .find(|a| a.domain.to_lowercase() == h)
                    .map(|a| a.mode.as_str())
                    .unwrap_or("unknown")
            ));

            // Capture the session's API key for MITM injection
            session_api_key = session.api_key.clone();
            let _session = session; // keep alive for the upgrade handler
        } else {
            // PoC mode — global allowlist
            if !is_allowlisted(&self.state, &host) {
                log(&format!(
                    "DROP: {host} not in allowlist (peer={:?})",
                    self.peer
                ));
                let mut resp = Response::new(Full::new(Bytes::new()));
                *resp.status_mut() = StatusCode::FORBIDDEN;
                return Ok(resp);
            }

            log(&format!("ALLOW: {host}:{port} — upgrading to MITM TLS"));
        }

        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::OK;

        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let up = match upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    log(&format!("upgrade failed for {host}: {e}"));
                    return;
                }
            };

            let upgraded = TokioIo::new(up);
            log(&format!("MITM: got upgraded connection for {host}"));

            let acceptor = TlsAcceptor::from(self.state.server_config.clone());
            let mut tls_client = match tokio::time::timeout(
                Duration::from_secs(10),
                acceptor.accept(upgraded),
            )
            .await
            {
                Ok(Ok(t)) => {
                    log(&format!("MITM: TLS handshake with client OK for {host}"));
                    t
                }
                Ok(Err(e)) => {
                    log(&format!("TLS accept from client failed for {host}: {e}"));
                    return;
                }
                Err(_) => {
                    log(&format!("TLS accept from client TIMEOUT for {host}"));
                    return;
                }
            };

            let real_port = if self.state.upstream_port != 0 {
                self.state.upstream_port
            } else {
                port
            };
            let real_host = if self.state.upstream_host.is_empty() {
                host.clone()
            } else {
                self.state.upstream_host.clone()
            };
            let upstream_addr = format!("{real_host}:{real_port}");
            log(&format!("MITM: connecting upstream to {upstream_addr}"));

            let tcp_up = match tokio::net::TcpStream::connect(&upstream_addr).await {
                Ok(s) => s,
                Err(e) => {
                    log(&format!(
                        "upstream TCP connect to {upstream_addr} failed: {e}"
                    ));
                    return;
                }
            };

            let server_name = match ServerName::try_from(host.clone()) {
                Ok(n) => n,
                Err(e) => {
                    log(&format!("invalid SNI {host}: {e}"));
                    return;
                }
            };
            let connector = TlsConnector::from(self.state.upstream_config.clone());
            let mut tls_upstream = match connector.connect(server_name, tcp_up).await {
                Ok(t) => {
                    log(&format!("MITM: upstream TLS connected to {host}"));
                    t
                }
                Err(e) => {
                    log(&format!("upstream TLS to {host} failed: {e}"));
                    return;
                }
            };

            let req_bytes = match read_http_request(&mut tls_client).await {
                Ok(b) => b,
                Err(e) => {
                    log(&format!("read inner request from client: {e}"));
                    return;
                }
            };

            // Use session API key if available, otherwise fall back to global key
            let effective_key = session_api_key.as_deref().unwrap_or(&self.state.api_key);
            let forwarded = rewrite_request(&req_bytes, effective_key, &host);
            log(&format!(
                "MITM: forwarding {host} request ({} bytes)",
                forwarded.len()
            ));

            if let Err(e) = tls_upstream.write_all(&forwarded).await {
                log(&format!("write to upstream {host}: {e}"));
                return;
            }
            if let Err(e) = tls_upstream.flush().await {
                log(&format!("flush upstream {host}: {e}"));
                return;
            }

            let _ = copy_bidirectional(&mut tls_client, &mut tls_upstream).await;
            log(&format!("DONE: {host} connection closed"));
        });

        Ok(resp)
    }
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for ProxyService {
    type Response = Response<Full<Bytes>>;
    type Error = ProxyError;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let svc = self.clone();
        Box::pin(async move {
            let method = req.method().clone();
            let uri = req.uri().clone();

            // CONNECT → proxy traffic
            if method == hyper::Method::CONNECT {
                let target = uri.host().unwrap_or("").to_string();
                let port = uri.port_u16().unwrap_or(443);
                let host_port = if target.is_empty() {
                    uri.to_string()
                } else {
                    format!("{target}:{port}")
                };
                return svc.handle_connect(host_port, req).await;
            }

            // Non-CONNECT methods → session management API
            svc.handle_session_api(method, &uri, req).await
        })
    }
}

impl ProxyService {
    /// Route non-CONNECT HTTP requests to the session management API.
    async fn handle_session_api(
        self,
        method: Method,
        uri: &hyper::Uri,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let path = uri.path();

        // Only handle session routes when a session store is configured
        let store = match &self.state.sessions {
            Some(s) => s.clone(),
            None => {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    r#"{"error":{"code":"INVALID_REQUEST","message":"session API not enabled (no session store configured)"}}"#,
                ));
            }
        };

        // Route: POST /sessions
        if path == "/sessions" && method == Method::POST {
            return handle_create_session(store, self.state.secret_store.clone(), req).await;
        }

        // Route: GET /sessions
        if path == "/sessions" && method == Method::GET {
            return Ok(handle_list_sessions(store));
        }

        // Route: GET /sessions/{id} and DELETE /sessions/{id}
        if let Some(session_id) = path.strip_prefix("/sessions/")
            && !session_id.is_empty()
        {
            if method == Method::GET {
                return Ok(handle_get_session(store, session_id));
            }
            if method == Method::DELETE {
                return handle_delete_session(store, session_id).await;
            }
        }

        // Route: GET /health
        if path == "/health" && method == Method::GET {
            return Ok(handle_health(store, &self.state));
        }

        // Fallback
        Ok(json_response(
            StatusCode::NOT_FOUND,
            r#"{"error":{"code":"INVALID_REQUEST","message":"unknown route"}}"#,
        ))
    }
}

// --- Session API handlers ---

async fn handle_create_session(
    store: Arc<SessionStore>,
    secret_store: Option<Arc<dyn crate::vault::SecretStore>>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    // Read body
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            log(&format!("session create: failed to read body: {e}"));
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "failed to read request body",
            ));
        }
    };

    // Parse JSON
    let create_req: CreateSessionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                &format!("malformed JSON: {e}"),
            ));
        }
    };

    // Validate required fields
    if create_req.session_id.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "session_id is required",
        ));
    }
    if create_req.source_ip.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "source_ip is required",
        ));
    }
    if create_req.allowlist.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "allowlist is required",
        ));
    }

    let now = now_secs();
    let expires_at = create_req.expires_at.as_deref().and_then(parse_iso8601);

    // Resolve credential_refs for mitm-mode entries
    let mut resolved_keys: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    if let Some(ref sec_store) = secret_store {
        for entry in &create_req.allowlist {
            if entry.mode == "mitm"
                && let Some(ref cref) = entry.credential_ref
            {
                match sec_store.fetch(cref) {
                    Ok(key) => {
                        resolved_keys.insert(cref.clone(), key);
                    }
                    Err(e) => {
                        return Ok(error_response_with_detail(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "CREDENTIAL_REF_INVALID",
                            "failed to resolve credential reference",
                            &e.to_string(),
                        ));
                    }
                }
            }
        }
    }

    let session = Session {
        session_id: create_req.session_id.clone(),
        source_ip: create_req.source_ip.clone(),
        allowlist: create_req.allowlist.clone(),
        created_at: now,
        expires_at,
        api_key: None, // Keys are fetched from Vault separately, not persisted
    };

    let session_id = session.session_id.clone();

    match store.create(session) {
        Ok(()) => {
            // Store resolved API key for the session (in memory only)
            for entry in &create_req.allowlist {
                if entry.mode == "mitm"
                    && let Some(ref cref) = entry.credential_ref
                    && let Some(key) = resolved_keys.get(cref)
                {
                    store.set_api_key(&session_id, key.clone());
                    break; // one key per session for now
                }
            }

            let session = store.get(&session_id).unwrap();
            let resp = SessionResponse::from(&session);
            let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
            Ok(json_response(StatusCode::CREATED, &json))
        }
        Err(SessionError::AlreadyExists(id)) => Ok(error_response(
            StatusCode::CONFLICT,
            "SESSION_EXISTS",
            &format!("session already exists: {id}"),
        )),
        Err(e) => {
            log(&format!("session create error: {e}"));
            Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            ))
        }
    }
}

fn handle_get_session(store: Arc<SessionStore>, session_id: &str) -> Response<Full<Bytes>> {
    match store.get(session_id) {
        Some(session) => {
            let mut resp = SessionResponse::from(&session);
            // Attach stats if available
            if let Some(stats) = store.get_stats(session_id) {
                resp.stats = Some(stats);
            }
            let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
            json_response(StatusCode::OK, &json)
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            &format!("session not found: {session_id}"),
        ),
    }
}

async fn handle_delete_session(
    store: Arc<SessionStore>,
    session_id: &str,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    match store.delete(session_id) {
        Ok(true) => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .unwrap()),
        Ok(false) => Ok(error_response(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            &format!("session not found: {session_id}"),
        )),
        Err(e) => {
            log(&format!("session delete error: {e}"));
            Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            ))
        }
    }
}

fn handle_list_sessions(store: Arc<SessionStore>) -> Response<Full<Bytes>> {
    let sessions: Vec<SessionSummary> = store.list().iter().map(SessionSummary::from).collect();
    let resp = SessionListResponse { sessions };
    let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
    json_response(StatusCode::OK, &json)
}

fn handle_health(store: Arc<SessionStore>, state: &ProxyState) -> Response<Full<Bytes>> {
    let uptime = crate::session::now_secs().saturating_sub(state.start_time);
    let body = format!(
        r#"{{"status":"ok","ca_cert_sha256":"{}","active_sessions":{},"uptime_secs":{}}}"#,
        state.ca_cert_sha256,
        store.count(),
        uptime
    );
    json_response(StatusCode::OK, &body)
}

// --- JSON response helpers ---

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"error":{{"code":"{}","message":"{}"}}}}"#,
        code,
        message.replace('"', "\\\"")
    );
    json_response(status, &body)
}

fn error_response_with_detail(
    status: StatusCode,
    code: &str,
    message: &str,
    detail: &str,
) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"error":{{"code":"{}","message":"{}","detail":"{}"}}}}"#,
        code,
        message.replace('"', "\\\""),
        detail.replace('"', "\\\"")
    );
    json_response(status, &body)
}

fn is_allowlisted(state: &ProxyState, host: &str) -> bool {
    let h = host.to_lowercase();
    state.allowlist.iter().any(|a| a.to_lowercase() == h)
}

async fn read_http_request<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| ProxyError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        buf.push(tmp[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }

    if buf.is_empty() {
        return Err(ProxyError::Io("empty request from client".into()));
    }

    let header_str = String::from_utf8_lossy(&buf);
    let content_length = extract_content_length(&header_str);
    let is_chunked = header_str
        .to_lowercase()
        .contains("transfer-encoding: chunked");

    if is_chunked {
        read_chunked_body(stream, &mut buf).await?;
    } else if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        let mut read = 0;
        while read < len {
            let n = stream
                .read(&mut body[read..])
                .await
                .map_err(|e| ProxyError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            read += n;
        }
        buf.extend_from_slice(&body[..read]);
    }

    Ok(buf)
}

fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((name, val)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            return val.trim().parse().ok();
        }
    }
    None
}

async fn read_chunked_body<S>(stream: &mut S, buf: &mut Vec<u8>) -> Result<(), ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut tmp = [0u8; 1];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| ProxyError::Io(e.to_string()))?;
        if n == 0 {
            return Ok(());
        }
        buf.push(tmp[0]);
        if buf.len() >= 5 && &buf[buf.len() - 5..] == b"0\r\n\r\n" {
            return Ok(());
        }
    }
}

fn rewrite_request(raw: &[u8], api_key: &str, host: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut lines: Vec<String> = text.split("\r\n").map(String::from).collect();

    lines.retain(|line| {
        if let Some((name, _)) = line.split_once(':') {
            !name.trim().eq_ignore_ascii_case("authorization")
        } else {
            true
        }
    });

    for line in lines.iter_mut() {
        if let Some((name, _)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            *line = format!("Host: {host}");
        }
    }

    let auth_header = format!("Authorization: Bearer {}", api_key);
    if lines.len() > 1 {
        lines.insert(1, auth_header);
    }

    let joined = lines.join("\r\n");
    joined.into_bytes()
}

pub fn log(msg: &str) {
    eprintln!("[proxy] {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::{Ca, CertError};

    fn upstream_client_config() -> Result<Arc<rustls::ClientConfig>, CertError> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    fn test_state() -> ProxyState {
        let ca = Arc::new(Ca::generate().unwrap());
        let server_config = ca.server_config(&["api.openai.com".to_string()]).unwrap();
        ProxyState {
            server_config,
            upstream_config: upstream_client_config().unwrap(),
            allowlist: vec!["api.openai.com".to_string()],
            api_key: "sk-REAL-KEY".into(),
            upstream_port: 0,
            upstream_host: String::new(),
            expected_vm_ip: "10.0.0.2".to_string(),
            sessions: None,
            secret_store: None,
            ca_cert_sha256: "00:11:22:33:44:55".to_string(),
            start_time: 0,
        }
    }

    #[test]
    fn rewrite_strips_client_auth_and_injects_real_key() {
        let state = test_state();
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer PLACEHOLDER\r\n";
        let out = rewrite_request(raw, &state.api_key, "api.openai.com");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Authorization: Bearer sk-REAL-KEY"));
        assert!(!s.contains("PLACEHOLDER"));
    }

    #[test]
    fn allowlist_exact_match() {
        let state = test_state();
        assert!(is_allowlisted(&state, "api.openai.com"));
        assert!(!is_allowlisted(&state, "evil.com"));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::certs::Ca;
    use crate::session::SessionStore;
    use crate::vault::MockSecretStore;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Start a proxy with session store on a random port, return the address.
    async fn start_test_proxy(
        secret_store: Arc<dyn crate::vault::SecretStore>,
    ) -> std::net::SocketAddr {
        let ca = Arc::new(Ca::generate().unwrap());
        let server_config = ca.server_config(&["api.openai.com".to_string()]).unwrap();
        let upstream_config = Ca::upstream_client_config_no_verify().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(ca.ca_der.as_ref());
        let digest = hasher.finalize();
        let ca_fingerprint: String = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        let store = SessionStore::in_memory().unwrap();

        let state = ProxyState {
            server_config,
            upstream_config,
            allowlist: vec![],
            api_key: String::new(),
            upstream_port: 0,
            upstream_host: String::new(),
            expected_vm_ip: String::new(),
            sessions: Some(store),
            secret_store: Some(secret_store),
            ca_cert_sha256: ca_fingerprint,
            start_time: crate::session::now_secs(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let st = state.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, st).await;
                });
            }
        });

        addr
    }

    /// Send a raw HTTP request and return the response bytes.
    async fn http_request(addr: std::net::SocketAddr, req: &str) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(store).await;

        let resp = http_request(
            addr,
            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("200 OK"), "got: {resp_str}");
        assert!(resp_str.contains("\"status\":\"ok\""));
        assert!(resp_str.contains("\"ca_cert_sha256\""));
        assert!(resp_str.contains("\"active_sessions\":0"));
        assert!(resp_str.contains("\"uptime_secs\""));
    }

    #[tokio::test]
    async fn test_create_and_get_session() {
        let secret_store = Arc::new(MockSecretStore::new());
        secret_store.insert("vault://secret/data/test-key", "sk-test-key");
        let addr = start_test_proxy(secret_store).await;

        // POST /sessions
        let body = r#"{"session_id":"sess_test1","source_ip":"10.0.1.42","allowlist":[{"domain":"api.openai.com","mode":"mitm","credential_ref":"vault://secret/data/test-key"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(addr, &req).await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("201 Created"), "got: {resp_str}");
        assert!(resp_str.contains("sess_test1"));
        assert!(resp_str.contains("10.0.1.42"));

        // GET /sessions/sess_test1
        let resp = http_request(
            addr,
            "GET /sessions/sess_test1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("200 OK"), "got: {resp_str}");
        assert!(resp_str.contains("sess_test1"));

        // GET /sessions
        let resp = http_request(
            addr,
            "GET /sessions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("sess_test1"));
    }

    #[tokio::test]
    async fn test_delete_session() {
        let secret_store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(secret_store).await;

        // Create
        let body = r#"{"session_id":"sess_del","source_ip":"10.0.1.50","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = http_request(addr, &req).await;

        // DELETE
        let resp = http_request(
            addr,
            "DELETE /sessions/sess_del HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("204"), "got: {resp_str}");

        // GET should 404
        let resp = http_request(
            addr,
            "GET /sessions/sess_del HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("404"));
        assert!(resp_str.contains("SESSION_NOT_FOUND"));
    }

    #[tokio::test]
    async fn test_create_session_invalid_credential_ref() {
        let secret_store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(secret_store).await;

        let body = r#"{"session_id":"sess_bad","source_ip":"10.0.1.60","allowlist":[{"domain":"api.openai.com","mode":"mitm","credential_ref":"vault://secret/data/nonexistent"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(addr, &req).await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("422"), "got: {resp_str}");
        assert!(resp_str.contains("CREDENTIAL_REF_INVALID"));
    }

    #[tokio::test]
    async fn test_create_session_duplicate() {
        let secret_store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(secret_store).await;

        let body = r#"{"session_id":"sess_dup","source_ip":"10.0.1.70","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = http_request(addr, &req).await;

        // Second create with same ID
        let body2 = r#"{"session_id":"sess_dup","source_ip":"10.0.1.71","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req2 = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body2.len(),
            body2
        );
        let resp = http_request(addr, &req2).await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("409"), "got: {resp_str}");
        assert!(resp_str.contains("SESSION_EXISTS"));
    }

    #[tokio::test]
    async fn test_connect_unregistered_ip_403() {
        let secret_store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(secret_store).await;

        let resp = http_request(
            addr,
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("403"), "got: {resp_str}");
    }

    #[tokio::test]
    async fn test_connect_non_allowlisted_domain_403() {
        let secret_store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(secret_store).await;

        // Register a session for 127.0.0.1 (test connects from localhost)
        let body = r#"{"session_id":"sess_allow","source_ip":"127.0.0.1","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = http_request(addr, &req).await;

        // CONNECT to a non-allowlisted domain
        let resp = http_request(
            addr,
            "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("403"), "got: {resp_str}");
    }

    #[tokio::test]
    async fn test_full_lifecycle() {
        let secret_store = Arc::new(MockSecretStore::new());
        let addr = start_test_proxy(secret_store).await;

        // 1. Register session
        let body = r#"{"session_id":"sess_life","source_ip":"127.0.0.1","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(addr, &req).await;
        assert!(String::from_utf8_lossy(&resp).contains("201"));

        // 2. CONNECT to allowlisted domain should NOT get 403
        let resp = http_request(
            addr,
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            !resp_str.starts_with("HTTP/1.1 403"),
            "CONNECT should not be 403 after registration: {resp_str}"
        );

        // 3. Delete session
        let resp = http_request(
            addr,
            "DELETE /sessions/sess_life HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&resp).contains("204"));

        // 4. CONNECT should now fail with 403
        let resp = http_request(
            addr,
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("403"),
            "CONNECT should be 403 after delete: {resp_str}"
        );
    }
}
