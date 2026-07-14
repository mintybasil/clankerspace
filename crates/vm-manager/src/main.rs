//! VM Manager binary — thin entry point.
//!
//! Initializes tracing and starts the VM Manager HTTP server on 127.0.0.1:8080.

mod api;
mod error;
mod helpers;
mod network;
mod proxy_client;
mod state;
mod types;
mod vm;

// Re-export constants from helpers for other modules
mod constants {
    pub const KERNEL_PATH: &str = "vmlinux-5.10-new.bin";
    pub const PROXY_SOCKET_PATH: &str = "/run/ae-proxy.sock";
    pub const PROXY_PORT: u16 = 9999;
    pub const IP_POOL_BASE: [u8; 4] = [10, 0, 1, 0];
}

use std::net::SocketAddr;

use api::run_server;
use network::{
    install_input_filter, install_nftables_base, remove_input_filter, remove_nftables_base,
};
use state::VmManagerState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured JSON logging (same as ae-poc main binary).
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let state = VmManagerState::new();

    tracing::info!(addr = %addr, "starting VM Manager");

    // Install nftables base table (DNAT + forward chains)
    if let Err(e) = install_nftables_base().await {
        tracing::warn!(error = %e, "failed to install nftables base table (may already exist)");
    }

    // Install INPUT filter table (restricts port 9999 to TAP interfaces)
    if let Err(e) = install_input_filter().await {
        tracing::warn!(error = %e, "failed to install nftables INPUT filter");
    }

    // Run until Ctrl+C
    let server = run_server(addr, state);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!(error = %e, "VM Manager server error");
                return Err(e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down VM Manager");
        }
    }

    // Cleanup nftables tables
    let _ = remove_input_filter().await;
    let _ = remove_nftables_base().await;

    Ok(())
}
