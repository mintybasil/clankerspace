//! Firecracker VM lifecycle management via fctools.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use fctools::process_spawner::DirectProcessSpawner;
use fctools::runtime::tokio::TokioRuntime;
use fctools::vm::configuration::{InitMethod, VmConfiguration};
use fctools::vm::models::{BootSource, Drive, MachineConfiguration, NetworkInterface};
use fctools::vm::shutdown::{VmShutdownAction, VmShutdownMethod};
use fctools::vm::{Vm, configuration::VmConfigurationData};
use fctools::vmm::arguments::{
    VmmApiSocket, VmmArguments,
    jailer::{JailerArguments, JailerCgroupVersion},
};
use fctools::vmm::executor::jailed::{FlatVirtualPathResolver, JailedVmmExecutor};
use fctools::vmm::id::VmmId;
use fctools::vmm::installation::VmmInstallation;
use fctools::vmm::ownership::VmmOwnershipModel;
use fctools::vmm::resource::system::ResourceSystem;
use fctools::vmm::resource::{MovedResourceType, ResourceType};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::network::{cleanup_tap_interface, remove_dnat_rule};
use crate::proxy_client::delete_proxy_session;
use crate::state::{EnvironmentState, VmManagerState};

/// Run the VM lifecycle in a background task.
/// This owns the non-Send fctools Vm handle and manages shutdown.
#[allow(clippy::too_many_arguments)]
pub async fn run_vm_lifecycle(
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
        &session_id,
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
            let _ = remove_dnat_rule(&tap_interface).await;
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
    if let Some(pipes) = pipes {
        let mut stdout = pipes.stdout;
        let state_for_serial = state.clone();
        let sid_for_serial = session_id.clone();
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
    let _ = remove_dnat_rule(&tap_interface).await;
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

/// Launch a Firecracker VM via fctools with jailing.
///
/// Uses `JailedVmmExecutor` with `FlatVirtualPathResolver` to run Firecracker
/// inside a jailer chroot with cgroup limits and non-root UID/GID.
#[allow(clippy::too_many_arguments)]
async fn launch_vm(
    session_id: &str,
    kernel_path: &PathBuf,
    rootfs_path: &PathBuf,
    vm_ip: &str,
    host_tap_ip: &str,
    tap_name: &str,
    vcpus: u32,
    memory_mib: u32,
) -> Result<Vm<JailedVmmExecutor<FlatVirtualPathResolver>, DirectProcessSpawner, TokioRuntime>> {
    let installation = VmmInstallation::new(
        "/usr/local/bin/firecracker",
        "/usr/local/bin/jailer",
        "/usr/local/bin/snapshot-editor",
    );

    // Unique API socket path per session (inside the jail's chroot)
    let api_socket_path = PathBuf::from(format!("/run/ae-vm-{session_id}.sock"));
    std::fs::remove_file(&api_socket_path).ok();

    // VmmId must be alphanumeric + dashes only, 5-60 chars.
    // session_id uses [a-z0-9_] — replace underscores with dashes.
    let jail_id_str = session_id.replace('_', "-");
    let jail_id = VmmId::new(&jail_id_str).context("invalid session_id for VmmId")?;

    // VMM arguments (API socket path is resolved within the jail)
    let vmm_arguments = VmmArguments::new(VmmApiSocket::Enabled(api_socket_path));

    // Jailer arguments: non-root UID/GID, cgroup v2 with CPU/memory/PID limits
    let jailer_arguments = JailerArguments::new(jail_id)
        .cgroup_version(JailerCgroupVersion::V2)
        .cgroup("cpu.max", format!("{} {}", vcpus * 100000, 100000)) // vcpus × 100ms per 100ms period
        .cgroup("memory.max", format!("{}", memory_mib as u64 * 1024 * 1024))
        .cgroup("pids.max", "64")
        .parent_cgroup("ae-vm-manager");

    let executor = JailedVmmExecutor::new(vmm_arguments, jailer_arguments, FlatVirtualPathResolver);

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
        .map_err(|e| anyhow::anyhow!("Failed to prepare VM: {e:?}"))?;

    vm.start(Duration::from_secs(10))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start VM: {e:?}"))?;

    Ok(vm)
}
