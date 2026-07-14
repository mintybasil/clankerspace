//! Environment state management for the VM Manager.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use serde::Serialize;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::constants;

/// Lifecycle status of an environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentState {
    Running,
    ShuttingDown,
    Exited,
    Failed,
}

impl EnvironmentState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::ShuttingDown => "shutting_down",
            Self::Exited => "exited",
            Self::Failed => "failed",
        }
    }
}

/// In-memory environment record (VM handle stored separately).
pub struct Environment {
    pub session_id: String,
    pub status: EnvironmentState,
    pub vm_ip: String,
    pub tap_interface: String,
    pub started_at: u64,
    pub expires_at: Option<u64>,
    #[allow(dead_code)]
    pub dummy_keys: HashMap<String, String>,
}

/// Shared state for the VM Manager.
#[derive(Clone)]
pub struct VmManagerState {
    /// Environment records keyed by session_id.
    pub environments: Arc<Mutex<HashMap<String, Environment>>>,
    /// Shutdown signal senders keyed by session_id.
    /// Sending on this channel triggers graceful VM shutdown in the background task.
    pub shutdown_txs: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    /// Serial output broadcast handles keyed by session_id.
    /// Each environment gets an mpsc sender that the serial reader task writes to.
    pub serial_txs: Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>,
    /// IP pool state: allocated VM IPs.
    allocated_ips: Arc<Mutex<Vec<String>>>,
    /// Proxy socket path.
    pub proxy_socket: String,
}

impl Default for VmManagerState {
    fn default() -> Self {
        Self::new()
    }
}

impl VmManagerState {
    pub fn new() -> Self {
        Self::with_proxy_socket(constants::PROXY_SOCKET_PATH)
    }

    pub fn with_proxy_socket(proxy_socket: impl Into<String>) -> Self {
        Self {
            environments: Arc::new(Mutex::new(HashMap::new())),
            shutdown_txs: Arc::new(Mutex::new(HashMap::new())),
            serial_txs: Arc::new(Mutex::new(HashMap::new())),
            allocated_ips: Arc::new(Mutex::new(Vec::new())),
            proxy_socket: proxy_socket.into(),
        }
    }

    /// Allocate the next available VM IP from the 10.0.1.0/24 pool.
    /// Uses /30 subnets — each environment gets a unique IP.
    pub async fn allocate_ip(&self) -> Result<String> {
        let mut ips = self.allocated_ips.lock().await;
        // Start at .2 (gateway is .1 for the first /30), increment by 4 for /30 alignment
        // pool: 10.0.1.2, 10.0.1.6, 10.0.1.10, ... up to .254
        for i in 0..64u32 {
            let ip_last = 2 + i * 4; // .2, .6, .10, ... .254
            if ip_last > 254 {
                break;
            }
            let ip = format!(
                "{}.{}.{}.{}",
                constants::IP_POOL_BASE[0],
                constants::IP_POOL_BASE[1],
                constants::IP_POOL_BASE[2],
                ip_last
            );
            if !ips.contains(&ip) {
                ips.push(ip.clone());
                return Ok(ip);
            }
        }
        Err(anyhow!("IP pool exhausted"))
    }

    /// Release a VM IP back to the pool.
    pub async fn release_ip(&self, ip: &str) {
        let mut ips = self.allocated_ips.lock().await;
        ips.retain(|x| x != ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_allocation() {
        let state = VmManagerState::with_proxy_socket("/tmp/test.sock");
        let ip1 = state.allocate_ip().await.unwrap();
        let ip2 = state.allocate_ip().await.unwrap();
        assert_ne!(ip1, ip2);
        assert!(ip1.starts_with("10.0.1."));
        assert!(ip2.starts_with("10.0.1."));

        // Release and re-allocate
        state.release_ip(&ip1).await;
        let ip3 = state.allocate_ip().await.unwrap();
        assert_eq!(ip3, ip1);
    }

    #[tokio::test]
    async fn test_environment_state_management() {
        let state = VmManagerState::with_proxy_socket("/tmp/test.sock");
        let now = crate::helpers::now_secs();

        // Insert environment
        {
            let mut envs = state.environments.lock().await;
            envs.insert(
                "sess_test1234567".to_string(),
                Environment {
                    session_id: "sess_test1234567".to_string(),
                    status: EnvironmentState::Running,
                    vm_ip: "10.0.1.2".to_string(),
                    tap_interface: "tap-sess_test".to_string(),
                    started_at: now,
                    expires_at: Some(now + 3600),
                    dummy_keys: HashMap::new(),
                },
            );
        }

        // Verify it exists
        {
            let envs = state.environments.lock().await;
            assert!(envs.contains_key("sess_test1234567"));
        }
    }
}
