//! MITM TLS proxy core — uses hyper's CONNECT upgrade (from ae-egress-proxy).
//!
//! This is the proven approach from Spike 1: hyper handles the CONNECT
//! request and connection upgrade. The key difference from the raw TCP
//! approach is that hyper's upgrade mechanism properly handles the
//! transition from HTTP to raw bytes, including any buffered data.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    pub allowlist: Vec<String>,
    pub api_key: String,
    pub upstream_port: u16,
    pub upstream_host: String,
    pub expected_vm_ip: String,
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

            let forwarded = rewrite_request(&req_bytes, &self.state, &host);
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

            if method != hyper::Method::CONNECT {
                let mut resp = Response::new(Full::new(Bytes::new()));
                *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                *resp.body_mut() =
                    Full::new(Bytes::from_static(b"ae-poc: only CONNECT is supported\n"));
                return Ok(resp);
            }

            let target = uri.host().unwrap_or("").to_string();
            let port = uri.port_u16().unwrap_or(443);
            let host_port = if target.is_empty() {
                uri.to_string()
            } else {
                format!("{target}:{port}")
            };

            svc.handle_connect(host_port, req).await
        })
    }
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

fn rewrite_request(raw: &[u8], state: &ProxyState, host: &str) -> Vec<u8> {
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

    let auth_header = format!("Authorization: Bearer {}", state.api_key);
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
        }
    }

    #[test]
    fn rewrite_strips_client_auth_and_injects_real_key() {
        let state = test_state();
        let raw = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer PLACEHOLDER\r\n\r\n";
        let out = rewrite_request(raw, &state, "api.openai.com");
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
