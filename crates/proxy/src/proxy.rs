//! MITM TLS proxy core — uses hyper's CONNECT upgrade (from ae-egress-proxy).
//!
//! This is the proven approach from Spike 1: hyper handles the CONNECT
//! request and connection upgrade. The key difference from the raw TCP
//! approach is that hyper's upgrade mechanism properly handles the
//! transition from HTTP to raw bytes, including any buffered data.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
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
    pub upstream_port: u16,
    pub upstream_host: String,
    pub expected_vm_ip: String,
    /// Session store for per-session allowlist and key-map lookup.
    pub sessions: Arc<SessionStore>,
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
        if is_vm {
            tracing::info!(peer = %ip, "CONNECT from VM source IP (session identified)");
        } else {
            tracing::warn!(peer = %ip, "CONNECT from unexpected source IP");
        }
    }

    let io = TokioIo::new(stream);
    let svc = ProxyService { state, peer };
    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades();

    conn.await.map_err(|e| ProxyError::Http(e.to_string()))
}

/// Handle a unix socket connection for the REST API (session management).
#[allow(dead_code)]
pub async fn handle_session_connection(
    stream: UnixStream,
    state: ProxyState,
) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);
    let svc = SessionApiService { state };
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

        // Session-based allowlist check + key map capture
        let session_key_map: Option<HashMap<String, String>> = {
            let store = &self.state.sessions;
            let peer_ip = self.peer.map(|a| a.ip().to_string());
            let session = peer_ip.and_then(|ip| store.get_by_ip(&ip));

            let session = match session {
                Some(s) => s,
                None => {
                    tracing::warn!(host = %host, peer = ?self.peer, "DROP: no session for peer");
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
                tracing::warn!(host = %host, session_id = %session.session_id, "DROP: not in session allowlist");
                let mut resp = Response::new(Full::new(Bytes::new()));
                *resp.status_mut() = StatusCode::FORBIDDEN;
                return Ok(resp);
            }

            tracing::info!(host = %host, port = port, session_id = %session.session_id, "ALLOW: CONNECT");

            // Capture the session's dummy→real key map for MITM swapping
            Some(session.dummy_to_real.clone())
        };

        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::OK;

        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let up = match upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(host = %host, error = %e, "MITM TLS upgrade failed");
                    return;
                }
            };

            let upgraded = TokioIo::new(up);
            tracing::info!(host = %host, "MITM: got upgraded connection");

            let acceptor = TlsAcceptor::from(self.state.server_config.clone());
            let mut tls_client = match tokio::time::timeout(
                Duration::from_secs(10),
                acceptor.accept(upgraded),
            )
            .await
            {
                Ok(Ok(t)) => {
                    tracing::info!(host = %host, "MITM: TLS handshake with client OK");
                    t
                }
                Ok(Err(e)) => {
                    tracing::error!(host = %host, error = %e, "TLS accept from client failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(host = %host, "TLS accept from client TIMEOUT");
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
            tracing::info!(upstream = %upstream_addr, "MITM: connecting upstream");

            let tcp_up = match tokio::net::TcpStream::connect(&upstream_addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(upstream = %upstream_addr, error = %e, "upstream TCP connect failed");
                    return;
                }
            };

            let server_name = match ServerName::try_from(host.clone()) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(host = %host, error = %e, "invalid SNI");
                    return;
                }
            };
            let connector = TlsConnector::from(self.state.upstream_config.clone());
            let mut tls_upstream = match connector.connect(server_name, tcp_up).await {
                Ok(t) => {
                    tracing::info!(host = %host, "MITM: upstream TLS connected");
                    t
                }
                Err(e) => {
                    tracing::error!(host = %host, error = %e, "upstream TLS failed");
                    return;
                }
            };

            let req_bytes = match read_http_request(&mut tls_client).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "read inner request from client failed");
                    return;
                }
            };

            // Check if this is a WebSocket upgrade request
            let is_websocket = is_websocket_upgrade(&req_bytes);

            let forwarded = if is_websocket {
                // WebSocket: pass headers through without modification.
                // The bidirectional copy handles WebSocket frames (just bytes).
                // Don't strip Authorization or inject keys — WebSocket
                // upgrade must be transparent.
                tracing::info!(host = %host, "MITM: WebSocket upgrade — passing through");
                req_bytes
            } else {
                // Normal HTTP: dummy→real key swap
                let key_map = session_key_map.as_ref().expect("session key map must be set");
                match rewrite_request(&req_bytes, key_map, &host) {
                    Ok(rewritten) => {
                        tracing::info!(host = %host, bytes = rewritten.len(), "MITM: forwarding request (key swapped)");
                        rewritten
                    }
                    Err(RewriteError::UnknownDummyKey(key)) => {
                        tracing::warn!(host = %host, key = %key, "DROP: unknown dummy key in Authorization header");
                        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                        if let Err(e) = tls_client.write_all(resp).await {
                            tracing::error!(host = %host, error = %e, "failed to write 403 to client");
                        }
                        let _ = tls_client.shutdown().await;
                        return;
                    }
                    Err(RewriteError::NoAuthHeader) => {
                        tracing::warn!(host = %host, "DROP: no Authorization header in request");
                        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                        if let Err(e) = tls_client.write_all(resp).await {
                            tracing::error!(host = %host, error = %e, "failed to write 403 to client");
                        }
                        let _ = tls_client.shutdown().await;
                        return;
                    }
                }
            };

            if let Err(e) = tls_upstream.write_all(&forwarded).await {
                tracing::error!(host = %host, error = %e, "write to upstream failed");
                return;
            }
            if let Err(e) = tls_upstream.flush().await {
                tracing::error!(host = %host, error = %e, "flush upstream failed");
                return;
            }

            let _ = copy_bidirectional(&mut tls_client, &mut tls_upstream).await;
            tracing::info!(host = %host, "connection closed");
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

            // TCP port: CONNECT only. Non-CONNECT requests are rejected.
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

            // Non-CONNECT on TCP port — reject (REST API is on unix socket)
            Ok(json_response(
                StatusCode::FORBIDDEN,
                r#"{"error":{"code":"INVALID_REQUEST","message":"TCP port accepts CONNECT only. REST API is on the unix socket."}}"#,
            ))
        })
    }
}

/// Service for the unix socket — handles REST API (session management) only.
#[derive(Clone)]
#[allow(dead_code)]
struct SessionApiService {
    state: ProxyState,
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for SessionApiService {
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
            svc.handle_session_api(method, &uri, req).await
        })
    }
}

impl SessionApiService {
    /// Route HTTP requests to the session management API.
    #[allow(dead_code)]
    async fn handle_session_api(
        self,
        method: Method,
        uri: &hyper::Uri,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let path = uri.path();

        // Session store is always configured
        let store = self.state.sessions.clone();

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

#[allow(dead_code)]
async fn handle_create_session(
    store: Arc<SessionStore>,
    secret_store: Option<Arc<dyn crate::vault::SecretStore>>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    // Read body
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            tracing::error!(error = %e, "session create: failed to read body");
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

    // Resolve credential_refs for mitm-mode entries → {dummy, real} key pairs
    let mut resolved_pairs: std::collections::HashMap<String, crate::vault::KeyPair> =
        std::collections::HashMap::new();
    if let Some(ref sec_store) = secret_store {
        for entry in &create_req.allowlist {
            if entry.mode == "mitm"
                && let Some(ref cref) = entry.credential_ref
            {
                match sec_store.fetch(cref) {
                    Ok(pair) => {
                        resolved_pairs.insert(cref.clone(), pair);
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

    // Build dummy_keys map for the response (credential_ref → dummy key only)
    let dummy_keys: std::collections::HashMap<String, String> = resolved_pairs
        .iter()
        .map(|(cref, pair)| (cref.clone(), pair.dummy.clone()))
        .collect();

    let session = Session {
        session_id: create_req.session_id.clone(),
        source_ip: create_req.source_ip.clone(),
        allowlist: create_req.allowlist.clone(),
        created_at: now,
        expires_at,
        dummy_to_real: HashMap::new(), // Set via set_key_map after create
    };

    let session_id = session.session_id.clone();

    // Build the dummy→real key map from resolved pairs.
    // Multiple mitm entries with different credential_refs are all included.
    let dummy_to_real: HashMap<String, String> = resolved_pairs
        .values()
        .map(|pair| (pair.dummy.clone(), pair.real.clone()))
        .collect();

    match store.create(session) {
        Ok(()) => {
            // Store the dummy→real key map in the session (in memory only)
            if !dummy_to_real.is_empty() {
                store.set_key_map(&session_id, dummy_to_real);
            }

            let session = store.get(&session_id).unwrap();
            let mut resp = SessionResponse::from(&session);
            // Include dummy keys in response for VM environment injection
            if !dummy_keys.is_empty() {
                resp.dummy_keys = Some(dummy_keys);
            }
            let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
            Ok(json_response(StatusCode::CREATED, &json))
        }
        Err(SessionError::AlreadyExists(id)) => Ok(error_response(
            StatusCode::CONFLICT,
            "SESSION_EXISTS",
            &format!("session already exists: {id}"),
        )),
        Err(e) => {
            tracing::error!(error = %e, "session create error");
            Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            ))
        }
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
            tracing::error!(error = %e, "session delete error");
            Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            ))
        }
    }
}

#[allow(dead_code)]
fn handle_list_sessions(store: Arc<SessionStore>) -> Response<Full<Bytes>> {
    let sessions: Vec<SessionSummary> = store.list().iter().map(SessionSummary::from).collect();
    let resp = SessionListResponse { sessions };
    let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
    json_response(StatusCode::OK, &json)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"error":{{"code":"{}","message":"{}"}}}}"#,
        code,
        message.replace('"', "\\\"")
    );
    json_response(status, &body)
}

#[allow(dead_code)]
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

/// Read a complete HTTP/1.1 request from a stream using httparse for header
/// parsing. Returns the raw request bytes (headers + body) because
/// `rewrite_request` operates on the raw bytes.
///
/// Reads headers in 4KB chunks (not byte-by-byte), then reads the body based
/// on Content-Length or chunked transfer encoding (detected from parsed
/// headers).
async fn read_http_request<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    // Read until we find the end of headers (\r\n\r\n)
    let header_end = loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| ProxyError::Io(e.to_string()))?;
        if n == 0 {
            if buf.is_empty() {
                return Err(ProxyError::Io("empty request from client".into()));
            }
            return Err(ProxyError::Io(
                "connection closed before headers complete".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);

        // Search for \r\n\r\n in the buffer
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
    };

    // Parse headers with httparse
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let parse_result = req
        .parse(&buf)
        .map_err(|e| ProxyError::Io(format!("httparse error: {e}")))?;

    match parse_result {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => {
            return Err(ProxyError::Io("incomplete headers after read".into()));
        }
    }

    // Extract Content-Length and Transfer-Encoding from parsed headers
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let val_str = std::str::from_utf8(h.value).unwrap_or("");
            content_length = val_str.trim().parse().ok();
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let val_str = std::str::from_utf8(h.value).unwrap_or("");
            if val_str.to_lowercase().contains("chunked") {
                is_chunked = true;
            }
        }
    }

    // Read body if present
    if is_chunked {
        // Any bytes after header_end in buf are the start of the chunked body
        read_chunked_body(stream, &mut buf, header_end).await?;
    } else if let Some(len) = content_length {
        // We may have already read some body bytes into buf
        let body_bytes_in_buf = buf.len() - header_end;
        if body_bytes_in_buf < len {
            let remaining = len - body_bytes_in_buf;
            let mut body = vec![0u8; remaining];
            let mut read = 0;
            while read < remaining {
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
    }

    Ok(buf)
}

/// Find the position of the \r\n\r\n header terminator in buf.
/// Returns the index of the first byte after \r\n\r\n (start of body).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..=buf.len() - 4 {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Read a chunked transfer-encoded body using buffer-based reads.
/// `body_start` is the offset in `buf` where body data may have already begun.
async fn read_chunked_body<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    body_start: usize,
) -> Result<(), ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut tmp = [0u8; 4096];
    // We need to read chunks until we see the 0-length chunk (0\r\n\r\n).
    // The data after header_end in buf may already contain part of the body.
    // We scan the buffer for the terminating "0\r\n\r\n" and read more if needed.
    loop {
        // Check if we already have the terminator
        let scan_start = body_start.min(buf.len().saturating_sub(1));
        if let Some(pos) = find_terminator(buf, scan_start) {
            // Truncate to just after the terminator
            buf.truncate(pos);
            return Ok(());
        }

        // Read more data
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| ProxyError::Io(e.to_string()))?;
        if n == 0 {
            // Connection closed — return what we have
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Search for the chunked body terminator "0\r\n\r\n" starting from `start`.
/// Returns the position just past the terminator if found.
fn find_terminator(buf: &[u8], start: usize) -> Option<usize> {
    if buf.len() < start + 5 {
        return None;
    }
    // Look for "0\r\n\r\n" which marks the end of chunked encoding
    for i in start..=buf.len() - 5 {
        if &buf[i..i + 5] == b"0\r\n\r\n" {
            return Some(i + 5);
        }
    }
    None
}

/// Check if the raw HTTP request is a WebSocket upgrade request.
///
/// Detects `Connection: Upgrade` and `Upgrade: websocket` headers
/// (case-insensitive). When true, the proxy passes the request through
/// without modification — WebSocket upgrade headers must be preserved
/// and the bidirectional copy handles WebSocket frames as raw bytes.
fn is_websocket_upgrade(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let has_upgrade = text
        .lines()
        .any(|line| line.eq_ignore_ascii_case("connection: upgrade"));
    let has_websocket = text
        .lines()
        .any(|line| line.to_lowercase().contains("upgrade: websocket"));
    has_upgrade && has_websocket
}

/// Error returned when `rewrite_request` cannot proceed.
#[derive(Debug)]
enum RewriteError {
    /// The request had no `Authorization` header.
    NoAuthHeader,
    /// The dummy key in the `Authorization` header was not found in the
    /// session's dummy→real map.
    UnknownDummyKey(String),
}

/// Rewrite an HTTP request for MITM forwarding: extract the dummy key from
/// the `Authorization: Bearer <key>` header, look it up in the session's
/// dummy→real map, and replace it with the real key. Also rewrites the
/// `Host` header to match the upstream host.
///
/// Returns `Err(RewriteError)` if the request has no `Authorization` header
/// or the dummy key is not in the map — the caller should return 403.
fn rewrite_request(
    raw: &[u8],
    dummy_to_real: &HashMap<String, String>,
    host: &str,
) -> Result<Vec<u8>, RewriteError> {
    let text = String::from_utf8_lossy(raw);
    let mut lines: Vec<String> = text.split("\r\n").map(String::from).collect();

    // Extract the dummy key from the Authorization header
    let dummy_key = lines
        .iter()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("authorization") {
                let token = value.trim();
                token.strip_prefix("Bearer ").map(|k| k.trim().to_string())
            } else {
                None
            }
        })
        .ok_or(RewriteError::NoAuthHeader)?;

    // Look up the dummy key in the session's dummy→real map
    let real_key = dummy_to_real
        .get(&dummy_key)
        .ok_or_else(|| RewriteError::UnknownDummyKey(dummy_key.clone()))?;

    // Strip the old Authorization header
    lines.retain(|line| {
        if let Some((name, _)) = line.split_once(':') {
            !name.trim().eq_ignore_ascii_case("authorization")
        } else {
            true
        }
    });

    // Rewrite the Host header
    for line in lines.iter_mut() {
        if let Some((name, _)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            *line = format!("Host: {host}");
        }
    }

    // Inject the real key
    let auth_header = format!("Authorization: Bearer {real_key}");
    if lines.len() > 1 {
        lines.insert(1, auth_header);
    }

    let joined = lines.join("\r\n");
    Ok(joined.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_dummy_to_real_swap() {
        let mut map = HashMap::new();
        map.insert("sk-dummy-abc".to_string(), "sk-real-xyz".to_string());
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dummy-abc\r\n\r\n";
        let out = rewrite_request(raw, &map, "api.openai.com").unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Authorization: Bearer sk-real-xyz"));
        assert!(!s.contains("sk-dummy-abc"));
    }

    #[test]
    fn rewrite_unknown_dummy_key_returns_err() {
        let mut map = HashMap::new();
        map.insert("sk-dummy-known".to_string(), "sk-real-known".to_string());
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dummy-unknown\r\n\r\n";
        let result = rewrite_request(raw, &map, "api.openai.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            RewriteError::UnknownDummyKey(key) => assert_eq!(key, "sk-dummy-unknown"),
            e => panic!("expected UnknownDummyKey, got {e:?}"),
        }
    }

    #[test]
    fn rewrite_no_auth_header_returns_err() {
        let map = HashMap::new();
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let result = rewrite_request(raw, &map, "api.openai.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            RewriteError::NoAuthHeader => {}
            e => panic!("expected NoAuthHeader, got {e:?}"),
        }
    }

    #[test]
    fn rewrite_multiple_keys_in_map() {
        let mut map = HashMap::new();
        map.insert("sk-dummy-1".to_string(), "sk-real-1".to_string());
        map.insert("sk-dummy-2".to_string(), "sk-real-2".to_string());
        // Request with first dummy key
        let raw1 = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dummy-1\r\n\r\n";
        let out1 = rewrite_request(raw1, &map, "api.openai.com").unwrap();
        assert!(String::from_utf8_lossy(&out1).contains("sk-real-1"));
        // Request with second dummy key
        let raw2 = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dummy-2\r\n\r\n";
        let out2 = rewrite_request(raw2, &map, "api.openai.com").unwrap();
        assert!(String::from_utf8_lossy(&out2).contains("sk-real-2"));
    }

    #[test]
    fn rewrite_host_header_updated() {
        let mut map = HashMap::new();
        map.insert("sk-dummy".to_string(), "sk-real".to_string());
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.original.com\r\nAuthorization: Bearer sk-dummy\r\n\r\n";
        let out = rewrite_request(raw, &map, "api.upstream.com").unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Host: api.upstream.com"));
        assert!(!s.contains("api.original.com"));
    }

    // --- WebSocket detection tests ---

    #[test]
    fn test_is_websocket_upgrade_detected() {
        let req = b"GET /ws HTTP/1.1\r\nHost: api.openai.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert!(is_websocket_upgrade(req));
    }

    #[test]
    fn test_is_websocket_upgrade_case_insensitive() {
        let req = b"GET /ws HTTP/1.1\r\nHost: api.openai.com\r\nconnection: upgrade\r\nupgrade: WebSocket\r\n\r\n";
        assert!(is_websocket_upgrade(req));
    }

    #[test]
    fn test_is_websocket_upgrade_missing_connection() {
        let req = b"GET /ws HTTP/1.1\r\nHost: api.openai.com\r\nUpgrade: websocket\r\n\r\n";
        assert!(!is_websocket_upgrade(req));
    }

    #[test]
    fn test_is_websocket_upgrade_missing_upgrade() {
        let req = b"GET /ws HTTP/1.1\r\nHost: api.openai.com\r\nConnection: Upgrade\r\n\r\n";
        assert!(!is_websocket_upgrade(req));
    }

    #[test]
    fn test_is_websocket_upgrade_normal_request() {
        let req = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dum\r\n\r\n";
        assert!(!is_websocket_upgrade(req));
    }

    // --- httparse parser tests ---

    /// A simple struct that implements AsyncRead from a Vec<u8> for testing.
    struct MockStream {
        data: Vec<u8>,
        pos: usize,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl tokio::io::AsyncRead for MockStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.pos >= self.data.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let n = std::cmp::min(buf.remaining(), self.data.len() - self.pos);
            buf.put_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_read_http_request_simple() {
        let request = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let mut stream = MockStream::new(request.to_vec());
        let result = read_http_request(&mut stream).await.unwrap();
        let s = String::from_utf8_lossy(&result);
        assert!(s.contains("GET /v1/models"));
        assert!(s.contains("Host: api.openai.com"));
    }

    #[tokio::test]
    async fn test_read_http_request_with_content_length() {
        let body = r#"{"model":"gpt-4","messages":[]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = MockStream::new(request.into_bytes());
        let result = read_http_request(&mut stream).await.unwrap();
        let s = String::from_utf8_lossy(&result);
        assert!(s.contains("POST /v1/chat/completions"));
        assert!(s.contains(body));
    }

    #[tokio::test]
    async fn test_read_http_request_chunked() {
        // Chunked: "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        let request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut stream = MockStream::new(request.to_vec());
        let result = read_http_request(&mut stream).await.unwrap();
        let s = String::from_utf8_lossy(&result);
        assert!(s.contains("POST /upload"));
        assert!(s.contains("Transfer-Encoding: chunked"));
        assert!(s.contains("Wiki"));
        assert!(s.contains("pedia"));
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

    /// Test proxy handle: TCP address for CONNECT, unix socket path for REST API.
    struct TestProxy {
        tcp_addr: std::net::SocketAddr,
        socket_path: String,
    }

    /// Start a proxy with session store. TCP listener handles CONNECT only,
    /// unix socket listener handles the REST API.
    async fn start_test_proxy(secret_store: Arc<dyn crate::vault::SecretStore>) -> TestProxy {
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
            upstream_port: 0,
            upstream_host: String::new(),
            expected_vm_ip: String::new(),
            sessions: store,
            secret_store: Some(secret_store),
            ca_cert_sha256: ca_fingerprint,
            start_time: crate::session::now_secs(),
        };

        // TCP listener for CONNECT
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp_state = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let st = tcp_state.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, st).await;
                });
            }
        });

        // Unix socket listener for REST API
        let socket_path = format!("/tmp/ae-test-{}-{}.sock", std::process::id(), addr.port());
        std::fs::remove_file(&socket_path).ok();
        let unix_listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let unix_state = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = unix_listener.accept().await {
                let st = unix_state.clone();
                tokio::spawn(async move {
                    let _ = handle_session_connection(stream, st).await;
                });
            }
        });

        TestProxy {
            tcp_addr: addr,
            socket_path,
        }
    }

    /// Send a raw HTTP request over TCP and return the response bytes.
    async fn http_request_tcp(addr: std::net::SocketAddr, req: &str) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    }

    /// Send a raw HTTP request over a unix socket and return the response bytes.
    async fn http_request_unix(socket_path: &str, req: &str) -> Vec<u8> {
        let mut stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let store = Arc::new(MockSecretStore::new());
        let proxy = start_test_proxy(store).await;

        let resp = http_request_unix(
            &proxy.socket_path,
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
        secret_store.insert(
            "vault://secret/data/test-key",
            "sk-dum-test",
            "sk-real-test",
        );
        let proxy = start_test_proxy(secret_store).await;

        // POST /sessions
        let body = r#"{"session_id":"sess_test1","source_ip":"10.0.1.42","allowlist":[{"domain":"api.openai.com","mode":"mitm","credential_ref":"vault://secret/data/test-key"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request_unix(&proxy.socket_path, &req).await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("201 Created"), "got: {resp_str}");
        assert!(resp_str.contains("sess_test1"));
        assert!(resp_str.contains("10.0.1.42"));

        // GET /sessions/sess_test1
        let resp = http_request_unix(
            &proxy.socket_path,
            "GET /sessions/sess_test1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("200 OK"), "got: {resp_str}");
        assert!(resp_str.contains("sess_test1"));

        // GET /sessions
        let resp = http_request_unix(
            &proxy.socket_path,
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
        let proxy = start_test_proxy(secret_store).await;

        // Create
        let body = r#"{"session_id":"sess_del","source_ip":"10.0.1.50","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = http_request_unix(&proxy.socket_path, &req).await;

        // DELETE
        let resp = http_request_unix(
            &proxy.socket_path,
            "DELETE /sessions/sess_del HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("204"), "got: {resp_str}");

        // GET should 404
        let resp = http_request_unix(
            &proxy.socket_path,
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
        let proxy = start_test_proxy(secret_store).await;

        let body = r#"{"session_id":"sess_bad","source_ip":"10.0.1.60","allowlist":[{"domain":"api.openai.com","mode":"mitm","credential_ref":"vault://secret/data/nonexistent"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request_unix(&proxy.socket_path, &req).await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("422"), "got: {resp_str}");
        assert!(resp_str.contains("CREDENTIAL_REF_INVALID"));
    }

    #[tokio::test]
    async fn test_create_session_duplicate() {
        let secret_store = Arc::new(MockSecretStore::new());
        let proxy = start_test_proxy(secret_store).await;

        let body = r#"{"session_id":"sess_dup","source_ip":"10.0.1.70","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = http_request_unix(&proxy.socket_path, &req).await;

        // Second create with same ID
        let body2 = r#"{"session_id":"sess_dup","source_ip":"10.0.1.71","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req2 = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body2.len(),
            body2
        );
        let resp = http_request_unix(&proxy.socket_path, &req2).await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("409"), "got: {resp_str}");
        assert!(resp_str.contains("SESSION_EXISTS"));
    }

    #[tokio::test]
    async fn test_connect_unregistered_ip_403() {
        let secret_store = Arc::new(MockSecretStore::new());
        let proxy = start_test_proxy(secret_store).await;

        let resp = http_request_tcp(
            proxy.tcp_addr,
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("403"), "got: {resp_str}");
    }

    #[tokio::test]
    async fn test_connect_non_allowlisted_domain_403() {
        let secret_store = Arc::new(MockSecretStore::new());
        let proxy = start_test_proxy(secret_store).await;

        // Register a session for 127.0.0.1 (test connects from localhost)
        let body = r#"{"session_id":"sess_allow","source_ip":"127.0.0.1","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = http_request_unix(&proxy.socket_path, &req).await;

        // CONNECT to a non-allowlisted domain
        let resp = http_request_tcp(
            proxy.tcp_addr,
            "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("403"), "got: {resp_str}");
    }

    #[tokio::test]
    async fn test_full_lifecycle() {
        let secret_store = Arc::new(MockSecretStore::new());
        let proxy = start_test_proxy(secret_store).await;

        // 1. Register session via unix socket
        let body = r#"{"session_id":"sess_life","source_ip":"127.0.0.1","allowlist":[{"domain":"api.openai.com","mode":"tunnel"}]}"#;
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request_unix(&proxy.socket_path, &req).await;
        assert!(String::from_utf8_lossy(&resp).contains("201"));

        // 2. CONNECT to allowlisted domain via TCP should NOT get 403
        let resp = http_request_tcp(
            proxy.tcp_addr,
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            !resp_str.starts_with("HTTP/1.1 403"),
            "CONNECT should not be 403 after registration: {resp_str}"
        );

        // 3. Delete session via unix socket
        let resp = http_request_unix(
            &proxy.socket_path,
            "DELETE /sessions/sess_life HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&resp).contains("204"));

        // 4. CONNECT should now fail with 403
        let resp = http_request_tcp(
            proxy.tcp_addr,
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await;
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("403"),
            "CONNECT should be 403 after delete: {resp_str}"
        );
    }

    // --- MITM key-swap integration tests (issue #40) ---

    /// A mock upstream TLS server that captures the forwarded request bytes.
    ///
    /// The proxy connects to this server as its upstream. The server accepts
    /// one TLS connection, reads the HTTP request, stores it, and returns a
    /// minimal HTTP response. The test then inspects `captured_request` to
    /// verify the proxy performed the key swap correctly.
    struct MockUpstream {
        addr: std::net::SocketAddr,
        captured_request: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    impl MockUpstream {
        /// Start a mock upstream TLS server on a random port.
        ///
        /// Returns the server handle. The caller should await `captured_request()`
        /// after sending a request through the proxy.
        async fn start() -> Self {
            use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

            // Generate a self-signed cert for the mock upstream.
            // The proxy uses NoVerifier so any cert is accepted.
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::new(vec!["api.openai.com".to_string()]).unwrap();
            params.distinguished_name = {
                let mut dn = rcgen::DistinguishedName::new();
                dn.push(rcgen::DnType::CommonName, "api.openai.com");
                dn
            };
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
            let cert = params.self_signed(&key).unwrap();

            let cert_der: rustls::pki_types::CertificateDer<'static> = cert.der().clone();
            let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
            );

            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let captured: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
                Arc::new(std::sync::Mutex::new(None));
            let captured_clone = captured.clone();

            tokio::spawn(async move {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let captured = captured_clone.clone();
                    tokio::spawn(async move {
                        let mut tls = match acceptor.accept(stream).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };

                        // Read the forwarded HTTP request
                        let mut buf = vec![0u8; 8192];
                        let n = tls.read(&mut buf).await.unwrap_or(0);
                        if n > 0 {
                            *captured.lock().unwrap() = Some(buf[..n].to_vec());
                        }

                        // Return a minimal HTTP response
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await;
                        let _ = tls.flush().await;
                        let _ = tls.shutdown().await;
                    });
                }
            });

            MockUpstream {
                addr,
                captured_request: captured,
            }
        }

        /// Get the captured request bytes (if the upstream received a request).
        fn captured_request(&self) -> Option<Vec<u8>> {
            self.captured_request.lock().unwrap().clone()
        }
    }

    /// Build a rustls client config that trusts the proxy's generated CA.
    /// This lets the test client complete the MITM TLS handshake.
    fn mitm_client_config(
        ca_der: &rustls::pki_types::CertificateDer<'static>,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der.clone()).unwrap();
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// Start a proxy that points at a mock upstream server.
    /// Returns the test proxy handle and the CA cert (for the client TLS config).
    async fn start_test_proxy_with_upstream(
        secret_store: Arc<dyn crate::vault::SecretStore>,
        upstream_addr: std::net::SocketAddr,
    ) -> (TestProxy, rustls::pki_types::CertificateDer<'static>) {
        let ca = Arc::new(Ca::generate().unwrap());
        let server_config = ca.server_config(&["api.openai.com".to_string()]).unwrap();
        let upstream_config = Ca::upstream_client_config_no_verify().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(ca.ca_der.as_ref());
        let ca_fingerprint: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        let store = SessionStore::in_memory().unwrap();

        let state = ProxyState {
            server_config,
            upstream_config,
            upstream_port: upstream_addr.port(),
            upstream_host: upstream_addr.ip().to_string(),
            expected_vm_ip: String::new(),
            sessions: store,
            secret_store: Some(secret_store),
            ca_cert_sha256: ca_fingerprint,
            start_time: crate::session::now_secs(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp_state = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let st = tcp_state.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, st).await;
                });
            }
        });

        let socket_path = format!("/tmp/ae-test-{}-{}.sock", std::process::id(), addr.port());
        std::fs::remove_file(&socket_path).ok();
        let unix_listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let unix_state = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = unix_listener.accept().await {
                let st = unix_state.clone();
                tokio::spawn(async move {
                    let _ = handle_session_connection(stream, st).await;
                });
            }
        });

        let ca_der = ca.ca_der.clone();
        (
            TestProxy {
                tcp_addr: addr,
                socket_path,
            },
            ca_der,
        )
    }

    /// Register a session with a mitm-mode allowlist entry and credential_ref.
    async fn register_mitm_session(proxy: &TestProxy, session_id: &str, credential_ref: &str) {
        let body = format!(
            r#"{{"session_id":"{}","source_ip":"127.0.0.1","allowlist":[{{"domain":"api.openai.com","mode":"mitm","credential_ref":"{}"}}]}}"#,
            session_id, credential_ref
        );
        let req = format!(
            "POST /sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request_unix(&proxy.socket_path, &req).await;
        assert!(
            String::from_utf8_lossy(&resp).contains("201"),
            "session creation should succeed: {}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Send a CONNECT request, complete the MITM TLS handshake, and send an
    /// HTTP request through the tunnel. Returns the HTTP response from upstream.
    async fn connect_and_send_request(
        proxy: &TestProxy,
        ca_der: &rustls::pki_types::CertificateDer<'static>,
        http_request: &str,
    ) -> Vec<u8> {
        // 1. Connect to the proxy's TCP port
        let mut tcp = tokio::net::TcpStream::connect(proxy.tcp_addr).await.unwrap();

        // 2. Send CONNECT (without Connection: close — the connection must stay open for upgrade)
        tcp.write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
            .await
            .unwrap();
        tcp.flush().await.unwrap();

        // 3. Read the CONNECT response (200 OK)
        let mut buf = vec![0u8; 4096];
        let n = tcp.read(&mut buf).await.unwrap();
        let connect_resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            connect_resp.starts_with("HTTP/1.1 200"),
            "CONNECT should succeed: {connect_resp}"
        );

        // 4. Start TLS handshake on the same connection (MITM side)
        //    The proxy presents a leaf cert signed by its CA, which we trust.
        let client_config = mitm_client_config(ca_der);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name = rustls::pki_types::ServerName::try_from("api.openai.com").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();

        // 5. Send the HTTP request through the TLS tunnel
        tls.write_all(http_request.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();

        // 6. Read the response (from the mock upstream, through the proxy)
        let mut resp = Vec::new();
        let _ = tls.read_to_end(&mut resp).await;
        resp
    }

    #[tokio::test]
    async fn test_mitm_key_swap() {
        let secret_store = Arc::new(MockSecretStore::new());
        secret_store.insert(
            "vault://secret/data/openai-key",
            "sk-dummy-test",
            "sk-real-test",
        );

        let upstream = MockUpstream::start().await;
        let (proxy, ca_der) = start_test_proxy_with_upstream(secret_store, upstream.addr).await;

        // Register a session with a credential_ref
        register_mitm_session(&proxy, "sess_mitm_swap", "vault://secret/data/openai-key").await;

        // Send a request with the dummy key through the MITM tunnel
        let request = "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dummy-test\r\nConnection: close\r\n\r\n";
        let resp = connect_and_send_request(&proxy, &ca_der, request).await;

        // The mock upstream returns "ok" — verify we got a response
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("200 OK") || resp_str.contains("ok"),
            "should get response from upstream: {resp_str}"
        );

        // Verify the upstream received the REAL key (not the dummy)
        let captured = upstream
            .captured_request()
            .expect("upstream should have received a request");
        let captured_str = String::from_utf8_lossy(&captured);
        assert!(
            captured_str.contains("Authorization: Bearer sk-real-test"),
            "upstream should receive the real key: {captured_str}"
        );
        assert!(
            !captured_str.contains("sk-dummy-test"),
            "upstream should NOT see the dummy key: {captured_str}"
        );
    }

    #[tokio::test]
    async fn test_mitm_unknown_dummy_key_403() {
        let secret_store = Arc::new(MockSecretStore::new());
        secret_store.insert(
            "vault://secret/data/openai-key",
            "sk-dummy-known",
            "sk-real-known",
        );

        let upstream = MockUpstream::start().await;
        let (proxy, ca_der) = start_test_proxy_with_upstream(secret_store, upstream.addr).await;

        register_mitm_session(&proxy, "sess_mitm_unknown", "vault://secret/data/openai-key").await;

        // Send a request with an unknown dummy key
        let request = "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-dummy-unknown\r\nConnection: close\r\n\r\n";
        let resp = connect_and_send_request(&proxy, &ca_der, request).await;

        // The proxy should return 403 (not forward to upstream)
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("403"),
            "proxy should return 403 for unknown dummy key: {resp_str}"
        );

        // Upstream should not have received anything
        assert!(
            upstream.captured_request().is_none(),
            "upstream should not receive a request for unknown dummy key"
        );
    }

    #[tokio::test]
    async fn test_mitm_no_auth_header_403() {
        let secret_store = Arc::new(MockSecretStore::new());
        secret_store.insert(
            "vault://secret/data/openai-key",
            "sk-dummy-test",
            "sk-real-test",
        );

        let upstream = MockUpstream::start().await;
        let (proxy, ca_der) = start_test_proxy_with_upstream(secret_store, upstream.addr).await;

        register_mitm_session(&proxy, "sess_mitm_noauth", "vault://secret/data/openai-key").await;

        // Send a request with no Authorization header
        let request = "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\n\r\n";
        let resp = connect_and_send_request(&proxy, &ca_der, request).await;

        // The proxy should return 403
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("403"),
            "proxy should return 403 for missing Authorization header: {resp_str}"
        );

        // Upstream should not have received anything
        assert!(
            upstream.captured_request().is_none(),
            "upstream should not receive a request with no auth header"
        );
    }
}
