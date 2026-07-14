//! VM Manager binary — thin entry point.
//!
//! Initializes tracing and starts the VM Manager HTTP server on 127.0.0.1:8080.

mod vm_manager;

use std::net::SocketAddr;

use vm_manager::{VmManagerState, run_server};

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

    Ok(())
}
