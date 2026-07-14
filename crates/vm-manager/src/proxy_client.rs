//! Proxy session registration via the egress proxy's unix socket.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::info;

/// Allowlist entry for the proxy session creation request.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyAllowlistEntry {
    pub domain: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
}

/// Proxy session creation request body.
#[derive(Debug, Serialize)]
struct ProxySessionRequest {
    session_id: String,
    source_ip: String,
    allowlist: Vec<ProxyAllowlistEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

/// Proxy session creation response (parsed for dummy_keys).
#[derive(Debug, Deserialize)]
struct ProxySessionResponse {
    #[serde(default)]
    dummy_keys: Option<HashMap<String, String>>,
}

/// Raw HTTP response from the proxy.
pub struct RawHttpResponse {
    pub status: u16,
    pub body: String,
}

/// Send a raw HTTP/1.1 request over a unix socket and parse the response.
async fn http_over_unix(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<RawHttpResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .context(format!("failed to connect to proxy socket: {socket_path}"))?;

    let body_bytes = body.map(|b| b.as_bytes()).unwrap_or(&[]);
    let content_length = body_bytes.len();

    let request = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    };

    stream.write_all(request.as_bytes()).await?;
    if body.is_some() {
        stream.write_all(body_bytes).await?;
    }
    stream.flush().await?;

    // Read full response
    let mut resp_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => resp_buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(anyhow!("failed to read proxy response: {e}")),
        }
    }

    // Parse status line and body
    let resp_str = String::from_utf8_lossy(&resp_buf).to_string();
    let header_end = resp_str
        .find("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed proxy response: no header terminator"))?;
    let header_section = &resp_str[..header_end];
    let body_section = &resp_str[header_end + 4..];

    // Parse status code from first line
    let status_line = header_section.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(RawHttpResponse {
        status,
        body: body_section.to_string(),
    })
}

/// Register a proxy session via the unix socket.
pub async fn register_proxy_session(
    socket_path: &str,
    session_id: &str,
    source_ip: &str,
    allowlist: &[ProxyAllowlistEntry],
    expires_at: Option<&str>,
) -> Result<RawHttpResponse> {
    let req_body = ProxySessionRequest {
        session_id: session_id.to_string(),
        source_ip: source_ip.to_string(),
        allowlist: allowlist.to_vec(),
        expires_at: expires_at.map(|s| s.to_string()),
    };
    let body_json = serde_json::to_string(&req_body)?;
    info!(session_id = %session_id, source_ip = %source_ip, "registering proxy session");
    http_over_unix(socket_path, "POST", "/sessions", Some(&body_json)).await
}

/// Delete a proxy session via the unix socket.
pub async fn delete_proxy_session(socket_path: &str, session_id: &str) -> Result<RawHttpResponse> {
    let path = format!("/sessions/{session_id}");
    http_over_unix(socket_path, "DELETE", &path, None).await
}

/// Parse dummy_keys from a proxy session response body.
pub fn parse_dummy_keys(body: &str) -> HashMap<String, String> {
    serde_json::from_str::<ProxySessionResponse>(body)
        .ok()
        .and_then(|r| r.dummy_keys)
        .unwrap_or_default()
}
