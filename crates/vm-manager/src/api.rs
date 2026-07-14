//! HTTP server and request handlers for the VM Manager REST API.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::constants;
use crate::error::{ErrorCode, json_error, json_error_with_detail, json_ok};
use crate::helpers::{
    extract_session_id, extract_session_id_and_suffix, format_iso8601, is_valid_session_id,
    now_secs,
};
use crate::network::{add_dnat_rule, cleanup_tap_interface, setup_tap_interface};
use crate::proxy_client::{
    ProxyAllowlistEntry, delete_proxy_session, parse_dummy_keys, register_proxy_session,
};
use crate::state::{Environment, EnvironmentState, VmManagerState};
use crate::types::{
    CreateEnvironmentRequest, DeleteResponse, EnvironmentListResponse, EnvironmentResponse,
    EnvironmentStatusResponse, EnvironmentSummary, ProxySessionInfo,
};
use crate::vm::run_vm_lifecycle;

/// Start the VM Manager HTTP server on the given address.
pub async fn run_server(addr: SocketAddr, state: VmManagerState) -> anyhow::Result<()> {
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
        let dummy_keys: HashMap<String, String> = parse_dummy_keys(&proxy_resp.body);

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

        // Set up nftables DNAT rules for this TAP (shared table)
        if let Err(e) = add_dnat_rule(&tap_interface, &host_tap_ip).await {
            error!(session_id = %create_req.session_id, error = %e, "nftables DNAT rule setup failed");
            self.release_ip(&vm_ip).await;
            let _ = cleanup_tap_interface(&tap_interface).await;
            let _ = delete_proxy_session(&self.proxy_socket, &create_req.session_id).await;
            return json_error_with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VmLaunchFailed,
                "failed to set up nftables DNAT rule",
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
        let kernel_path = PathBuf::from(constants::KERNEL_PATH);
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
                proxy_url: format!("http://{}:{}", host_tap_ip, constants::PROXY_PORT),
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
