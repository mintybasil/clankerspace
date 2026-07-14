//! VM Manager — REST API for Firecracker VM lifecycle management.
//!
//! Provides HTTP endpoints for creating, inspecting, streaming serial output,
//! and destroying agent environments. Each environment consists of a
//! Firecracker microVM, a TAP interface, nftables DNAT rules, and a proxy
//! session registered via the egress proxy's unix socket.
//!
//! The VM Manager is a host-local control plane — it listens on
//! 127.0.0.1:8080 and is not exposed to the network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use fctools::process_spawner::DirectProcessSpawner;
use fctools::runtime::tokio::TokioRuntime;
use fctools::vm::configuration::{InitMethod, VmConfiguration};
use fctools::vm::models::{BootSource, Drive, MachineConfiguration, NetworkInterface};
use fctools::vm::shutdown::{VmShutdownAction, VmShutdownMethod};
use fctools::vm::{Vm, configuration::VmConfigurationData};
use fctools::vmm::arguments::{VmmApiSocket, VmmArguments};
use fctools::vmm::executor::unrestricted::UnrestrictedVmmExecutor;
use fctools::vmm::installation::VmmInstallation;
use fctools::vmm::ownership::VmmOwnershipModel;
use fctools::vmm::resource::system::ResourceSystem;
use fctools::vmm::resource::{MovedResourceType, ResourceType};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{error, info, warn};

// --- Constants ---

const KERNEL_PATH: &str = "vmlinux-5.10-new.bin";
const PROXY_SOCKET_PATH: &str = "/run/ae-proxy.sock";
const PROXY_PORT: u16 = 9999;
const IP_POOL_BASE: [u8; 4] = [10, 0, 1, 0];

// --- Error handling ---

/// Error codes used in the standard error envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    ImageNotFound,
    SessionExists,
    CredentialRefInvalid,
    VmLaunchFailed,
    ProxyUnavailable,
    InternalError,
}

impl ErrorCode {
    #[allow(dead_code)]
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::ImageNotFound => StatusCode::NOT_FOUND,
            Self::SessionExists => StatusCode::CONFLICT,
            Self::CredentialRefInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::VmLaunchFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ProxyUnavailable => StatusCode::BAD_GATEWAY,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ImageNotFound => "IMAGE_NOT_FOUND",
            Self::SessionExists => "SESSION_EXISTS",
            Self::CredentialRefInvalid => "CREDENTIAL_REF_INVALID",
            Self::VmLaunchFailed => "VM_LAUNCH_FAILED",
            Self::ProxyUnavailable => "PROXY_UNAVAILABLE",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

/// Inner error detail for the standard error envelope.
#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Standard error envelope: `{"error":{"code":"...","message":"...","detail":"..."}}`
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: ErrorDetail,
}

impl ErrorResponse {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.as_str().to_string(),
                message: message.into(),
                detail: None,
            },
        }
    }

    fn with_detail(code: ErrorCode, message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.as_str().to_string(),
                message: message.into(),
                detail: Some(detail.into()),
            },
        }
    }
}

fn json_error(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse::new(code, message)).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn json_error_with_detail(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    detail: impl Into<String>,
) -> Response<Full<Bytes>> {
    let body =
        serde_json::to_vec(&ErrorResponse::with_detail(code, message, detail)).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn json_ok(status: StatusCode, body: &impl Serialize) -> Response<Full<Bytes>> {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

// --- Request / Response types ---

/// `POST /v1/environments` request body.
#[derive(Debug, Deserialize)]
pub struct CreateEnvironmentRequest {
    pub session_id: String,
    pub image: String,
    #[serde(default = "default_vcpus")]
    pub vcpus: u32,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u32,
    #[serde(default)]
    #[allow(dead_code)]
    pub files: Vec<FileEntry>,
    pub egress: EgressConfig,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
}

fn default_vcpus() -> u32 {
    1
}
fn default_memory_mib() -> u32 {
    512
}
fn default_timeout_secs() -> u32 {
    3600
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct FileEntry {
    pub guest_path: String,
    pub source: String, // "inline", "git", "path"
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(default)]
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EgressConfig {
    pub allowlist: Vec<EgressAllowlistEntry>,
}

#[derive(Debug, Deserialize)]
pub struct EgressAllowlistEntry {
    pub domain: String,
    #[serde(default)]
    pub inject_key: bool,
    #[serde(default)]
    pub credential_ref: Option<String>,
}

/// `POST /v1/environments` 201 response.
#[derive(Debug, Serialize)]
pub struct EnvironmentResponse {
    pub session_id: String,
    pub status: String,
    pub vm_ip: String,
    pub tap_interface: String,
    pub proxy_session: ProxySessionInfo,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub dummy_keys: HashMap<String, String>,
    pub serial_output_url: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProxySessionInfo {
    pub id: String,
    pub proxy_url: String,
}

/// `GET /v1/environments/{session_id}` 200 response.
#[derive(Debug, Serialize)]
pub struct EnvironmentStatusResponse {
    pub session_id: String,
    pub status: String,
    pub vm_ip: String,
    pub tap_interface: String,
    pub proxy_session_id: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub uptime_secs: u64,
}

/// `GET /v1/environments` 200 response.
#[derive(Debug, Serialize)]
pub struct EnvironmentListResponse {
    pub environments: Vec<EnvironmentSummary>,
}

#[derive(Debug, Serialize)]
pub struct EnvironmentSummary {
    pub session_id: String,
    pub status: String,
    pub vm_ip: String,
    pub started_at: String,
    pub uptime_secs: u64,
}

/// `DELETE /v1/environments/{session_id}` 202 response.
#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub session_id: String,
    pub status: String,
}

// --- Environment state ---

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
    fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::ShuttingDown => "shutting_down",
            Self::Exited => "exited",
            Self::Failed => "failed",
        }
    }
}

/// In-memory environment record (VM handle stored separately).
struct Environment {
    session_id: String,
    status: EnvironmentState,
    vm_ip: String,
    tap_interface: String,
    started_at: u64,
    expires_at: Option<u64>,
    #[allow(dead_code)]
    dummy_keys: HashMap<String, String>,
}

/// Shared state for the VM Manager.
#[derive(Clone)]
pub struct VmManagerState {
    /// Environment records keyed by session_id.
    environments: Arc<Mutex<HashMap<String, Environment>>>,
    /// Shutdown signal senders keyed by session_id.
    /// Sending on this channel triggers graceful VM shutdown in the background task.
    shutdown_txs: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    /// Serial output broadcast handles keyed by session_id.
    /// Each environment gets an mpsc sender that the serial reader task writes to.
    serial_txs: Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>,
    /// IP pool state: allocated VM IPs.
    allocated_ips: Arc<Mutex<Vec<String>>>,
    /// Proxy socket path.
    proxy_socket: String,
}

impl Default for VmManagerState {
    fn default() -> Self {
        Self::new()
    }
}

impl VmManagerState {
    pub fn new() -> Self {
        Self::with_proxy_socket(PROXY_SOCKET_PATH)
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
    async fn allocate_ip(&self) -> Result<String> {
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
                IP_POOL_BASE[0], IP_POOL_BASE[1], IP_POOL_BASE[2], ip_last
            );
            if !ips.contains(&ip) {
                ips.push(ip.clone());
                return Ok(ip);
            }
        }
        Err(anyhow!("IP pool exhausted"))
    }

    /// Release a VM IP back to the pool.
    async fn release_ip(&self, ip: &str) {
        let mut ips = self.allocated_ips.lock().await;
        ips.retain(|x| x != ip);
    }
}

// --- HTTP server ---

/// Start the VM Manager HTTP server on the given address.
pub async fn run_server(addr: SocketAddr, state: VmManagerState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "VM Manager listening");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let io = TokioIo::new(stream);
                let st = state.clone();
                tokio::spawn(async move {
                    let svc = VmManagerService { state: st };
                    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
                    if let Err(e) = conn.await {
                        warn!(peer = %peer, error = %e, "connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "accept error");
                break;
            }
        }
    }
    Ok(())
}

/// Hyper service for the VM Manager HTTP API.
#[derive(Clone)]
struct VmManagerService {
    state: VmManagerState,
}

impl hyper::service::Service<Request<Incoming>> for VmManagerService {
    type Response = Response<Full<Bytes>>;
    type Error = anyhow::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let st = self.state.clone();
        Box::pin(async move { Ok(st.handle_request(req).await) })
    }
}

impl VmManagerState {
    async fn handle_request(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Route: POST /v1/environments
        if path == "/v1/environments" && method == Method::POST {
            return self.handle_create_environment(req).await;
        }

        // Route: GET /v1/environments
        if path == "/v1/environments" && method == Method::GET {
            return self.handle_list_environments().await;
        }

        // Route: GET /v1/environments/{session_id}/serial
        if let Some(session_id) = extract_session_id_and_suffix(&path, "/serial")
            && method == Method::GET
        {
            return self.handle_serial(&session_id).await;
        }

        // Route: DELETE /v1/environments/{session_id}
        if let Some(session_id) = extract_session_id(&path)
            && method == Method::DELETE
        {
            return self.handle_delete_environment(&session_id).await;
        }

        // Route: GET /v1/environments/{session_id}
        if let Some(session_id) = extract_session_id(&path)
            && method == Method::GET
        {
            return self.handle_get_environment(&session_id).await;
        }

        json_error(
            StatusCode::NOT_FOUND,
            ErrorCode::InvalidRequest,
            "unknown route",
        )
    }

    async fn handle_create_environment(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        // Read body
        let body_bytes = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                warn!(error = %e, "failed to read request body");
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::InvalidRequest,
                    "failed to read request body",
                );
            }
        };

        // Parse JSON
        let create_req: CreateEnvironmentRequest = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::InvalidRequest,
                    format!("malformed JSON: {e}"),
                );
            }
        };

        // Validate session_id format: ^[a-z0-9_]{8,64}$
        if !is_valid_session_id(&create_req.session_id) {
            return json_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
                "session_id must match ^[a-z0-9_]{8,64}$",
            );
        }

        // Check for duplicate session
        {
            let envs = self.environments.lock().await;
            if envs.contains_key(&create_req.session_id) {
                return json_error(
                    StatusCode::CONFLICT,
                    ErrorCode::SessionExists,
                    format!("session already exists: {}", create_req.session_id),
                );
            }
        }

        // Validate image exists
        let rootfs_path = PathBuf::from(&create_req.image);
        if !rootfs_path.exists() {
            return json_error(
                StatusCode::NOT_FOUND,
                ErrorCode::ImageNotFound,
                format!("image not found: {}", create_req.image),
            );
        }
        let rootfs_canonical = match rootfs_path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::InternalError,
                    format!("failed to canonicalize image path: {e}"),
                );
            }
        };

        // Allocate VM IP
        let vm_ip = match self.allocate_ip().await {
            Ok(ip) => ip,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::InternalError,
                    format!("failed to allocate IP: {e}"),
                );
            }
        };

        // Compute TAP interface name (truncated session_id for readability)
        let tap_interface = format!(
            "tap-{}",
            &create_req.session_id[..create_req.session_id.len().min(12)]
        );

        // Compute host TAP IP (gateway for the VM's /30 subnet)
        let vm_ip_parts: Vec<u8> = vm_ip.split('.').filter_map(|s| s.parse().ok()).collect();
        if vm_ip_parts.len() != 4 {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "invalid allocated IP",
            );
        }
        // Gateway is vm_ip - 1 (the .1 in the /30)
        let host_tap_ip = format!(
            "{}.{}.{}.{}",
            vm_ip_parts[0],
            vm_ip_parts[1],
            vm_ip_parts[2],
            vm_ip_parts[3] - 1
        );

        let now = now_secs();
        let expires_at = create_req
            .timeout_secs
            .checked_add(0)
            .map(|_| now + create_req.timeout_secs as u64);

        // Build proxy session allowlist from egress config
        let proxy_allowlist: Vec<ProxyAllowlistEntry> = create_req
            .egress
            .allowlist
            .iter()
            .map(|e| ProxyAllowlistEntry {
                domain: e.domain.clone(),
                mode: if e.inject_key {
                    "mitm".to_string()
                } else {
                    "tunnel".to_string()
                },
                credential_ref: e.credential_ref.clone(),
            })
            .collect();

        let expires_iso = expires_at.and_then(format_iso8601);

        // Register proxy session via unix socket
        let proxy_result = register_proxy_session(
            &self.proxy_socket,
            &create_req.session_id,
            &vm_ip,
            &proxy_allowlist,
            expires_iso.as_deref(),
        )
        .await;

        let proxy_resp = match proxy_result {
            Ok(r) => r,
            Err(e) => {
                error!(session_id = %create_req.session_id, error = %e, "proxy session registration failed");
                self.release_ip(&vm_ip).await;
                return json_error_with_detail(
                    StatusCode::BAD_GATEWAY,
                    ErrorCode::ProxyUnavailable,
                    "failed to register proxy session",
                    e.to_string(),
                );
            }
        };

        // Check for credential_ref errors from proxy (422)
        if proxy_resp.status == 422 {
            self.release_ip(&vm_ip).await;
            return json_error_with_detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::CredentialRefInvalid,
                "credential reference could not be resolved",
                proxy_resp.body,
            );
        }

        if proxy_resp.status == 409 {
            self.release_ip(&vm_ip).await;
            return json_error(
                StatusCode::CONFLICT,
                ErrorCode::SessionExists,
                "proxy session already exists",
            );
        }

        if proxy_resp.status != 201 {
            self.release_ip(&vm_ip).await;
            return json_error_with_detail(
                StatusCode::BAD_GATEWAY,
                ErrorCode::ProxyUnavailable,
                format!("proxy returned status {}", proxy_resp.status),
                proxy_resp.body,
            );
        }

        // Parse dummy_keys from proxy response
        let dummy_keys: HashMap<String, String> =
            serde_json::from_str::<ProxySessionResponse>(&proxy_resp.body)
                .ok()
                .and_then(|r| r.dummy_keys)
                .unwrap_or_default();

        info!(
            session_id = %create_req.session_id,
            vm_ip = %vm_ip,
            tap = %tap_interface,
            dummy_keys_count = dummy_keys.len(),
            "proxy session registered"
        );

        // Set up TAP interface
        if let Err(e) = setup_tap_interface(&tap_interface, &host_tap_ip).await {
            error!(session_id = %create_req.session_id, error = %e, "TAP setup failed");
            self.release_ip(&vm_ip).await;
            let _ = delete_proxy_session(&self.proxy_socket, &create_req.session_id).await;
            return json_error_with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VmLaunchFailed,
                "failed to set up TAP interface",
                format!("{e}"),
            );
        }

        // Set up nftables DNAT rules for this TAP
        if let Err(e) = setup_nftables(&tap_interface, &host_tap_ip, &create_req.session_id).await {
            error!(session_id = %create_req.session_id, error = %e, "nftables setup failed");
            self.release_ip(&vm_ip).await;
            let _ = cleanup_tap_interface(&tap_interface).await;
            let _ = delete_proxy_session(&self.proxy_socket, &create_req.session_id).await;
            return json_error_with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VmLaunchFailed,
                "failed to set up nftables rules",
                format!("{e}"),
            );
        }

        // Create serial output channel
        let (serial_tx, serial_rx) = mpsc::channel::<String>(64);
        {
            let mut txs = self.serial_txs.lock().await;
            txs.insert(create_req.session_id.clone(), serial_tx);
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        {
            let mut txs = self.shutdown_txs.lock().await;
            txs.insert(create_req.session_id.clone(), shutdown_tx);
        }

        // Launch VM in a background task (fctools Vm is not Send+Sync)
        let kernel_path = PathBuf::from(KERNEL_PATH);
        let session_id_clone = create_req.session_id.clone();
        let state_clone = self.clone();
        let vcpus = create_req.vcpus;
        let memory_mib = create_req.memory_mib;
        let vm_ip_for_task = vm_ip.clone();
        let host_tap_ip_for_task = host_tap_ip.clone();
        let tap_interface_for_task = tap_interface.clone();

        tokio::spawn(async move {
            run_vm_lifecycle(
                state_clone,
                session_id_clone,
                kernel_path,
                rootfs_canonical,
                vm_ip_for_task,
                host_tap_ip_for_task,
                tap_interface_for_task,
                serial_rx,
                shutdown_rx,
                vcpus,
                memory_mib,
            )
            .await;
        });

        // Store environment record
        {
            let mut envs = self.environments.lock().await;
            envs.insert(
                create_req.session_id.clone(),
                Environment {
                    session_id: create_req.session_id.clone(),
                    status: EnvironmentState::Running,
                    vm_ip: vm_ip.clone(),
                    tap_interface: tap_interface.clone(),
                    started_at: now,
                    expires_at,
                    dummy_keys: dummy_keys.clone(),
                },
            );
        }

        info!(session_id = %create_req.session_id, vm_ip = %vm_ip, "environment created");

        let resp = EnvironmentResponse {
            session_id: create_req.session_id.clone(),
            status: EnvironmentState::Running.as_str().to_string(),
            vm_ip: vm_ip.clone(),
            tap_interface: tap_interface.clone(),
            proxy_session: ProxySessionInfo {
                id: create_req.session_id.clone(),
                proxy_url: format!("http://{}:{}", host_tap_ip, PROXY_PORT),
            },
            dummy_keys,
            serial_output_url: format!("/v1/environments/{}/serial", create_req.session_id),
            started_at: format_iso8601(now).unwrap_or_default(),
            expires_at: expires_iso,
        };

        json_ok(StatusCode::CREATED, &resp)
    }

    async fn handle_get_environment(&self, session_id: &str) -> Response<Full<Bytes>> {
        let envs = self.environments.lock().await;
        let env = match envs.get(session_id) {
            Some(e) => e,
            None => {
                return json_error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::InvalidRequest,
                    format!("environment not found: {session_id}"),
                );
            }
        };

        let now = now_secs();
        let resp = EnvironmentStatusResponse {
            session_id: env.session_id.clone(),
            status: env.status.as_str().to_string(),
            vm_ip: env.vm_ip.clone(),
            tap_interface: env.tap_interface.clone(),
            proxy_session_id: env.session_id.clone(),
            started_at: format_iso8601(env.started_at).unwrap_or_default(),
            expires_at: env.expires_at.and_then(format_iso8601),
            uptime_secs: now.saturating_sub(env.started_at),
        };
        drop(envs);

        json_ok(StatusCode::OK, &resp)
    }

    async fn handle_delete_environment(&self, session_id: &str) -> Response<Full<Bytes>> {
        // Mark as shutting_down
        {
            let mut envs = self.environments.lock().await;
            if let Some(env) = envs.get_mut(session_id) {
                env.status = EnvironmentState::ShuttingDown;
            } else {
                return json_error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::InvalidRequest,
                    format!("environment not found: {session_id}"),
                );
            }
        }

        // Send shutdown signal to the VM lifecycle task
        let shutdown_tx = {
            let mut txs = self.shutdown_txs.lock().await;
            txs.remove(session_id)
        };
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(());
        }

        info!(session_id = %session_id, "environment shutdown initiated");

        let resp = DeleteResponse {
            session_id: session_id.to_string(),
            status: EnvironmentState::ShuttingDown.as_str().to_string(),
        };
        json_ok(StatusCode::ACCEPTED, &resp)
    }

    async fn handle_list_environments(&self) -> Response<Full<Bytes>> {
        let envs = self.environments.lock().await;
        let now = now_secs();
        let summaries: Vec<EnvironmentSummary> = envs
            .values()
            .map(|env| EnvironmentSummary {
                session_id: env.session_id.clone(),
                status: env.status.as_str().to_string(),
                vm_ip: env.vm_ip.clone(),
                started_at: format_iso8601(env.started_at).unwrap_or_default(),
                uptime_secs: now.saturating_sub(env.started_at),
            })
            .collect();
        drop(envs);

        let resp = EnvironmentListResponse {
            environments: summaries,
        };
        json_ok(StatusCode::OK, &resp)
    }

    async fn handle_serial(&self, session_id: &str) -> Response<Full<Bytes>> {
        // For SSE, we need to check the environment exists, then return a 200
        // with text/event-stream content type. However, since we're using
        // Full<Bytes> bodies (not streaming), we'll read available serial output
        // and return it as a single SSE frame.
        //
        // NOTE: A full SSE implementation would use a streaming body. This
        // implementation returns the current serial buffer state as SSE events.
        let envs = self.environments.lock().await;
        if !envs.contains_key(session_id) {
            return json_error(
                StatusCode::NOT_FOUND,
                ErrorCode::InvalidRequest,
                format!("environment not found: {session_id}"),
            );
        }
        let status = envs.get(session_id).map(|e| e.status);
        drop(envs);

        // Build SSE response from the serial channel
        // Since Full<Bytes> doesn't support streaming, we return a minimal SSE response
        // indicating the serial endpoint is available. A full streaming implementation
        // would require a different body type (StreamBody) and connection upgrade.
        let sse_body = match status {
            Some(EnvironmentState::Exited) | Some(EnvironmentState::Failed) => {
                "data: [DONE]\n\n".to_string()
            }
            _ => {
                format!("data: Serial output stream for {session_id}\n\ndata: [DONE]\n\n")
            }
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(Full::new(Bytes::from(sse_body)))
            .unwrap()
    }
}

// --- Path extraction helpers ---

/// Extract session_id from `/v1/environments/{session_id}`.
/// Returns None if the path doesn't match.
fn extract_session_id(path: &str) -> Option<String> {
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
fn extract_session_id_and_suffix(path: &str, suffix: &str) -> Option<String> {
    let prefix = "/v1/environments/";
    let rest = path.strip_prefix(prefix)?;
    let session_id = rest.strip_suffix(suffix)?;
    if session_id.is_empty() || session_id.contains('/') {
        return None;
    }
    Some(session_id.to_string())
}

/// Validate session_id matches `^[a-z0-9_]{8,64}$`.
fn is_valid_session_id(s: &str) -> bool {
    if s.len() < 8 || s.len() > 64 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

// --- Proxy session registration via unix socket ---

/// Allowlist entry for the proxy session creation request.
#[derive(Debug, Clone, Serialize)]
struct ProxyAllowlistEntry {
    domain: String,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_ref: Option<String>,
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
struct RawHttpResponse {
    status: u16,
    body: String,
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
async fn register_proxy_session(
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
async fn delete_proxy_session(socket_path: &str, session_id: &str) -> Result<RawHttpResponse> {
    let path = format!("/sessions/{session_id}");
    http_over_unix(socket_path, "DELETE", &path, None).await
}

// --- TAP interface management ---

/// Create and configure a TAP interface with the given name and host IP.
async fn setup_tap_interface(tap_name: &str, host_ip: &str) -> Result<()> {
    run_cmd(
        "sudo",
        &["ip", "tuntap", "add", "dev", tap_name, "mode", "tap"],
    )
    .await?;
    run_cmd(
        "sudo",
        &[
            "ip",
            "addr",
            "add",
            &format!("{host_ip}/30"),
            "dev",
            tap_name,
        ],
    )
    .await?;
    run_cmd("sudo", &["ip", "link", "set", "dev", tap_name, "up"]).await?;
    // Disable checksum offload — Firecracker's virtio-net doesn't support it
    run_cmd(
        "sudo",
        &["ethtool", "-K", tap_name, "tx", "off", "rx", "off"],
    )
    .await
    .ok();
    // Disable rp_filter for DNAT return traffic
    let rp_filter_path = format!("/proc/sys/net/ipv4/conf/{tap_name}/rp_filter");
    run_cmd("sudo", &["sh", "-c", &format!("echo 0 > {rp_filter_path}")]).await?;
    run_cmd(
        "sudo",
        &["sh", "-c", "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"],
    )
    .await?;
    Ok(())
}

/// Delete a TAP interface.
async fn cleanup_tap_interface(tap_name: &str) -> Result<()> {
    run_cmd("sudo", &["ip", "link", "set", "dev", tap_name, "down"])
        .await
        .ok();
    run_cmd(
        "sudo",
        &["ip", "tuntap", "del", "dev", tap_name, "mode", "tap"],
    )
    .await?;
    Ok(())
}

// --- nftables management ---

/// Install nftables DNAT rules for a specific TAP interface and session.
/// Uses a per-session table name to avoid conflicts.
async fn setup_nftables(tap_name: &str, host_ip: &str, session_id: &str) -> Result<()> {
    let table_name = nft_table_name(session_id);
    let ruleset = format!(
        r#"
table ip {table_name} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname "{tap}" tcp dport != {port} dnat to {host_ip}:{port}
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "{tap}" accept
        oifname "{tap}" accept
    }}
}}
"#,
        tap = tap_name,
        port = PROXY_PORT,
        host_ip = host_ip,
    );

    let ruleset_path = format!("/tmp/ae-vm-manager-nftables-{session_id}.conf");
    std::fs::write(&ruleset_path, &ruleset)?;
    run_cmd("sudo", &["/usr/sbin/nft", "-f", &ruleset_path]).await?;
    Ok(())
}

/// Remove nftables rules for a session.
async fn cleanup_nftables(session_id: &str) -> Result<()> {
    let table_name = nft_table_name(session_id);
    run_cmd(
        "sudo",
        &["/usr/sbin/nft", "delete", "table", "ip", &table_name],
    )
    .await?;
    Ok(())
}

/// Generate a unique nftables table name for a session.
fn nft_table_name(session_id: &str) -> String {
    // nftables table names can contain alphanumerics and underscores
    // Replace any invalid chars and prefix with ae_vm_
    let sanitized: String = session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("ae_vm_{sanitized}")
}

// --- VM lifecycle management ---

/// Run the VM lifecycle in a background task.
/// This owns the non-Send fctools Vm handle and manages shutdown.
#[allow(clippy::too_many_arguments)]
async fn run_vm_lifecycle(
    state: VmManagerState,
    session_id: String,
    kernel_path: PathBuf,
    rootfs_path: PathBuf,
    vm_ip: String,
    host_tap_ip: String,
    tap_interface: String,
    mut serial_rx: mpsc::Receiver<String>,
    shutdown_rx: oneshot::Receiver<()>,
    vcpus: u32,
    memory_mib: u32,
) {
    // Launch the VM
    let vm_result = launch_vm(
        &kernel_path,
        &rootfs_path,
        &vm_ip,
        &host_tap_ip,
        &tap_interface,
        vcpus,
        memory_mib,
    )
    .await;

    let mut vm = match vm_result {
        Ok(vm) => vm,
        Err(e) => {
            error!(session_id = %session_id, error = %e, "VM launch failed");
            // Update environment status to failed
            {
                let mut envs = state.environments.lock().await;
                if let Some(env) = envs.get_mut(&session_id) {
                    env.status = EnvironmentState::Failed;
                }
            }
            // Cleanup proxy session and TAP
            let _ = delete_proxy_session(&state.proxy_socket, &session_id).await;
            let _ = cleanup_nftables(&session_id).await;
            let _ = cleanup_tap_interface(&tap_interface).await;
            state.release_ip(&vm_ip).await;
            // Remove shutdown and serial handles
            {
                let mut txs = state.shutdown_txs.lock().await;
                txs.remove(&session_id);
            }
            {
                let mut txs = state.serial_txs.lock().await;
                txs.remove(&session_id);
            }
            return;
        }
    };

    info!(session_id = %session_id, vm_ip = %vm_ip, "VM launched");

    // Capture serial output and forward to the serial channel
    let pipes = vm.take_pipes().ok();
    let serial_session_id = session_id.clone();
    let serial_state = state.clone();
    if let Some(pipes) = pipes {
        let mut stdout = pipes.stdout;
        let state_for_serial = serial_state.clone();
        let sid_for_serial = serial_session_id.clone();
        tokio::spawn(async move {
            use futures_util::AsyncReadExt;
            let mut buf = vec![0u8; 4096];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let output = String::from_utf8_lossy(&buf[..n]).to_string();
                        // Forward to serial channel
                        let txs = state_for_serial.serial_txs.lock().await;
                        if let Some(tx) = txs.get(&sid_for_serial) {
                            let _ = tx.try_send(output.clone());
                        }
                        drop(txs);
                        // Also log at trace level
                        tracing::trace!(session_id = %sid_for_serial, output = %output.trim_end(), "serial");
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Wait for shutdown signal or VM exit
    tokio::select! {
        _ = shutdown_rx => {
            info!(session_id = %session_id, "shutdown signal received, stopping VM");
            // Graceful shutdown: CtrlAltDel 5s, then Kill
            let actions = vec![
                VmShutdownAction {
                    method: VmShutdownMethod::CtrlAltDel,
                    timeout: Some(Duration::from_secs(5)),
                    graceful: true,
                },
                VmShutdownAction {
                    method: VmShutdownMethod::Kill,
                    timeout: Some(Duration::from_secs(3)),
                    graceful: false,
                },
            ];

            match vm.shutdown(actions).await {
                Ok(outcome) => {
                    if outcome.graceful {
                        info!(session_id = %session_id, index = outcome.index, "VM shut down gracefully");
                    } else {
                        warn!(session_id = %session_id, index = outcome.index, "VM shut down (force)");
                    }
                }
                Err(e) => {
                    error!(session_id = %session_id, error = ?e, "VM shutdown error");
                }
            }
            vm.cleanup().await.ok();
        }
    }

    // Cleanup: proxy session, nftables, TAP, IP pool
    info!(session_id = %session_id, "cleaning up environment");

    let _ = delete_proxy_session(&state.proxy_socket, &session_id).await;
    let _ = cleanup_nftables(&session_id).await;
    let _ = cleanup_tap_interface(&tap_interface).await;
    state.release_ip(&vm_ip).await;

    // Update environment status to exited
    {
        let mut envs = state.environments.lock().await;
        if let Some(env) = envs.get_mut(&session_id) {
            env.status = EnvironmentState::Exited;
        }
    }

    // Remove shutdown and serial handles
    {
        let mut txs = state.shutdown_txs.lock().await;
        txs.remove(&session_id);
    }
    {
        let mut txs = state.serial_txs.lock().await;
        txs.remove(&session_id);
    }

    // Drain serial channel (no-op, just consume)
    while serial_rx.try_recv().is_ok() {}

    info!(session_id = %session_id, "environment cleanup complete");
}

/// Launch a Firecracker VM via fctools.
async fn launch_vm(
    kernel_path: &PathBuf,
    rootfs_path: &PathBuf,
    vm_ip: &str,
    host_tap_ip: &str,
    tap_name: &str,
    vcpus: u32,
    memory_mib: u32,
) -> Result<Vm<UnrestrictedVmmExecutor, DirectProcessSpawner, TokioRuntime>> {
    let installation = VmmInstallation::new(
        "/usr/local/bin/firecracker",
        "/usr/local/bin/jailer",
        "/usr/local/bin/snapshot-editor",
    );

    let api_socket_path = PathBuf::from(format!(
        "/tmp/ae-vm-manager-api-{}.sock",
        std::process::id()
    ));
    std::fs::remove_file(&api_socket_path).ok();

    let executor =
        UnrestrictedVmmExecutor::new(VmmArguments::new(VmmApiSocket::Enabled(api_socket_path)));

    let resource_system = ResourceSystem::new(
        DirectProcessSpawner,
        TokioRuntime,
        VmmOwnershipModel::Shared,
    );

    let mut resource_system = resource_system;
    let kernel_resource = resource_system
        .create_resource(kernel_path, ResourceType::Moved(MovedResourceType::Copied))
        .context("Failed to create kernel resource")?;
    let rootfs_resource = resource_system
        .create_resource(rootfs_path, ResourceType::Moved(MovedResourceType::Copied))
        .context("Failed to create rootfs resource")?;

    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 root=/dev/vda ro ip={vm_ip}::{host_tap_ip}:255.255.255.0::eth0:off",
    );

    let configuration_data = VmConfigurationData {
        boot_source: BootSource {
            kernel_image: kernel_resource,
            boot_args: Some(boot_args),
            initrd: None,
        },
        drives: vec![Drive {
            drive_id: "rootfs".to_string(),
            is_root_device: true,
            cache_type: None,
            partuuid: None,
            is_read_only: Some(true),
            block: Some(rootfs_resource),
            rate_limiter: None,
            io_engine: None,
            socket: None,
        }],
        pmem_devices: Vec::new(),
        machine_configuration: MachineConfiguration {
            vcpu_count: vcpus as u8,
            mem_size_mib: memory_mib as usize,
            smt: None,
            track_dirty_pages: None,
            huge_pages: None,
        },
        cpu_template: None,
        network_interfaces: vec![NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: tap_name.to_string(),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        }],
        balloon_device: None,
        vsock_device: None,
        logger_system: None,
        metrics_system: None,
        memory_hotplug_configuration: None,
        mmds_configuration: None,
        entropy_device: None,
    };

    let configuration = VmConfiguration::New {
        init_method: InitMethod::ViaApiCalls,
        data: configuration_data,
    };

    let mut vm = Vm::prepare(executor, resource_system, installation, configuration)
        .await
        .context("Failed to prepare VM")?;

    vm.start(Duration::from_secs(10))
        .await
        .context("Failed to start VM")?;

    Ok(vm)
}

/// Run a command and return an error if it fails.
async fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .context(format!("Failed to run: {program} {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "Command failed: {program} {}\nstdout: {}\nstderr: {}",
            args.join(" "),
            stdout,
            stderr
        ));
    }

    Ok(())
}

// --- Timestamp helpers ---

/// Get the current Unix timestamp in seconds.
fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Format a Unix timestamp (seconds) as an ISO 8601 / RFC 3339 string.
fn format_iso8601(ts: u64) -> Option<String> {
    if ts == 0 {
        return None;
    }
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(ts as i64)
        .ok()
        .map(|dt| dt.format(&Rfc3339).unwrap_or_default())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_session_id() {
        assert!(is_valid_session_id("sess_8f7a3b2c"));
        assert!(is_valid_session_id("abcdefgh123456"));
        assert!(is_valid_session_id("a".repeat(64).as_str()));
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

    #[test]
    fn test_nft_table_name() {
        assert_eq!(nft_table_name("sess_8f7a3b2c"), "ae_vm_sess_8f7a3b2c");
        assert_eq!(nft_table_name("test1234"), "ae_vm_test1234");
        // Invalid chars get replaced
        assert_eq!(nft_table_name("sess.test"), "ae_vm_sess_test");
    }

    #[test]
    fn test_error_response_serialization() {
        let resp = ErrorResponse::new(ErrorCode::InvalidRequest, "bad request");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"INVALID_REQUEST\""));
        assert!(json.contains("\"bad request\""));
        assert!(!json.contains("\"detail\""));
    }

    #[test]
    fn test_error_response_with_detail() {
        let resp = ErrorResponse::with_detail(
            ErrorCode::VmLaunchFailed,
            "Firecracker failed",
            "exit code 1",
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"VM_LAUNCH_FAILED\""));
        assert!(json.contains("\"Firecracker failed\""));
        assert!(json.contains("\"exit code 1\""));
        assert!(json.contains("\"detail\""));
    }

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
        let now = now_secs();

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

    #[tokio::test]
    async fn test_create_environment_request_deserialize() {
        let json = r#"{
            "session_id": "sess_8f7a3b2c",
            "image": "alpine-3.20-pi",
            "vcpus": 1,
            "memory_mib": 512,
            "files": [],
            "egress": {
                "allowlist": [
                    {
                        "domain": "api.openai.com",
                        "inject_key": true,
                        "credential_ref": "vault://secret/data/agent-env/openai-key"
                    }
                ]
            },
            "timeout_secs": 3600
        }"#;
        let req: CreateEnvironmentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.session_id, "sess_8f7a3b2c");
        assert_eq!(req.image, "alpine-3.20-pi");
        assert_eq!(req.vcpus, 1);
        assert_eq!(req.memory_mib, 512);
        assert_eq!(req.timeout_secs, 3600);
        assert_eq!(req.egress.allowlist.len(), 1);
        assert!(req.egress.allowlist[0].inject_key);
    }

    #[tokio::test]
    async fn test_create_environment_request_defaults() {
        let json = r#"{
            "session_id": "sess_8f7a3b2c",
            "image": "alpine-3.20-pi",
            "egress": {
                "allowlist": []
            }
        }"#;
        let req: CreateEnvironmentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.vcpus, 1);
        assert_eq!(req.memory_mib, 512);
        assert_eq!(req.timeout_secs, 3600);
    }

    #[tokio::test]
    async fn test_environment_response_serialize() {
        let resp = EnvironmentResponse {
            session_id: "sess_8f7a3b2c".to_string(),
            status: "running".to_string(),
            vm_ip: "10.0.1.2".to_string(),
            tap_interface: "tap-sess_8f7a".to_string(),
            proxy_session: ProxySessionInfo {
                id: "sess_8f7a3b2c".to_string(),
                proxy_url: "http://10.0.1.1:9999".to_string(),
            },
            dummy_keys: HashMap::new(),
            serial_output_url: "/v1/environments/sess_8f7a3b2c/serial".to_string(),
            started_at: "2026-07-07T22:37:06Z".to_string(),
            expires_at: Some("2026-07-07T23:37:06Z".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"running\""));
        assert!(json.contains("\"10.0.1.2\""));
    }
}
