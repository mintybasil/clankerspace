//! ae-proxy — standalone MITM egress proxy binary.
//!
//! Reads API key pairs from stdin (piped from an external decryption tool),
//! starts the egress proxy on 0.0.0.0:9999 with a REST API on the unix
//! socket /run/ae-proxy.sock.

use std::net::SocketAddr;
use std::sync::Arc;

use ae_proxy::{certs, proxy, session, vault};
use anyhow::{Context, Result};

const PROXY_PORT: u16 = 9999;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("starting ae-proxy");

    // Load key pairs from stdin
    let secret_store: Arc<dyn vault::SecretStore> = {
        let store =
            vault::FileSecretStore::from_stdin().context("Failed to read key pairs from stdin")?;
        Arc::new(store)
    };

    let ca = Arc::new(certs::Ca::generate()?);

    let allowlist = vec!["api.openai.com".to_string()];
    let server_config = ca.server_config(&allowlist)?;
    let upstream_config = certs::Ca::upstream_client_config_no_verify()?;

    let ca_cert_sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(ca.ca_der.as_ref());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };

    let proxy_state = proxy::ProxyState {
        server_config,
        upstream_config,
        allowlist,
        api_key: String::new(),
        upstream_port: 443,
        upstream_host: String::new(),
        expected_vm_ip: String::new(),
        sessions: None,
        secret_store: Some(secret_store),
        ca_cert_sha256,
        start_time: session::now_secs(),
    };

    let addr: SocketAddr = format!("0.0.0.0:{PROXY_PORT}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "proxy listening");

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let st = proxy_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy::handle_connection(stream, st).await {
                        tracing::error!(error = %e, "connection error");
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "accept error");
                break;
            }
        }
    }

    Ok(())
}
