//! ae-poc — Integration PoC: Firecracker VM → nftables DNAT → MITM egress proxy → upstream API
//!
//! This binary integrates the two prior spikes (ae-egress-proxy and ae-fc-poc)
//! into a single end-to-end path:
//!
//!   1. Generate a MITM CA certificate.
//!   2. Build a rootfs with curl + the CA cert baked in (via build-rootfs.sh).
//!   3. Start the egress proxy on 0.0.0.0:9999 (receives VM traffic via nftables DNAT).
//!   4. Set up a TAP interface (tap0) and nftables DNAT rules.
//!   5. Launch a Firecracker VM via fctools with the rootfs.
//!   6. The VM's init script runs a test: curl through the proxy to a mock HTTPS server.
//!   7. The proxy MITMs TLS, injects an API key, and forwards to the mock server.
//!   8. Verify the response arrives back in the VM.
//!
//! The mock HTTPS server runs on the host (replacing a real LLM API) so the
//! test is fully self-contained — no external API keys needed.

mod certs;
mod proxy;
mod stream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use fctools::process_spawner::DirectProcessSpawner;
use fctools::runtime::tokio::TokioRuntime;
use fctools::vm::configuration::{InitMethod, VmConfiguration};
use fctools::vm::models::{BootSource, Drive, MachineConfiguration, NetworkInterface};
use fctools::vm::{
    Vm,
    configuration::VmConfigurationData,
    shutdown::{VmShutdownAction, VmShutdownMethod},
};
use fctools::vmm::arguments::{VmmApiSocket, VmmArguments};
use fctools::vmm::executor::unrestricted::UnrestrictedVmmExecutor;
use fctools::vmm::installation::VmmInstallation;
use fctools::vmm::ownership::VmmOwnershipModel;
use fctools::vmm::resource::system::ResourceSystem;
use fctools::vmm::resource::{MovedResourceType, ResourceType};

// --- Network constants ---
const VM_IP: &str = "10.0.0.2";
const HOST_TAP_IP: &str = "10.0.0.1";
const TAP_NAME: &str = "tap0";
const PROXY_PORT: u16 = 9999;
const MOCK_PORT: u16 = 9443;

// --- File paths ---
const KERNEL_PATH: &str = "vmlinux-5.10-new.bin";
const ROOTFS_PATH: &str = "rootfs.ext4";
const CA_PATH: &str = "proxy-ca.pem";
const BUILD_ROOTFS_SCRIPT: &str = "build-rootfs.sh";

#[tokio::main]
async fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  ae-poc — Integration: VM → nftables → Proxy → Upstream   ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // -- Phase 1: Generate CA --
    println!("[1/7] Generating MITM CA certificate...");
    let ca = Arc::new(certs::Ca::generate()?);
    let ca_pem = ca.ca_pem();
    std::fs::write(CA_PATH, &ca_pem)?;
    println!("      CA written to {CA_PATH}");

    // -- Phase 2: Build rootfs with CA baked in --
    println!("[2/7] Building rootfs with CA cert baked in...");
    build_rootfs().await?;
    println!("      rootfs built: {ROOTFS_PATH}");

    // -- Phase 3: Start mock HTTPS server (simulates LLM API) --
    println!("[3/7] Starting mock HTTPS server on port {MOCK_PORT}...");
    let mock_handle = start_mock_server();
    // Give the mock server time to start and generate its self-signed cert
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("      Mock server started (simulates api.openai.com)");

    // -- Phase 4: Start the egress proxy --
    println!("[4/7] Starting egress proxy on 0.0.0.0:{PROXY_PORT}...");
    let allowlist = vec!["api.openai.com".to_string()];
    let server_config = ca.server_config(&allowlist)?;
    let upstream_config = certs::Ca::upstream_client_config_no_verify()?;

    let proxy_state = proxy::ProxyState {
        server_config,
        upstream_config,
        allowlist,
        api_key: "sk-INJECTED-BY-PROXY".to_string(),
        upstream_port: MOCK_PORT, // redirect all upstream connections to the mock
        upstream_host: "127.0.0.1".to_string(), // mock server runs locally
        expected_vm_ip: VM_IP.to_string(),
    };

    let proxy_addr: SocketAddr = format!("0.0.0.0:{PROXY_PORT}").parse()?;
    let proxy_listener = tokio::net::TcpListener::bind(proxy_addr).await?;
    println!("      Proxy listening on {proxy_addr}");

    let proxy_state_clone = proxy_state.clone();
    let proxy_handle = tokio::spawn(async move {
        loop {
            match proxy_listener.accept().await {
                Ok((stream, _peer)) => {
                    let st = proxy_state_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = proxy::handle_connection(stream, st).await {
                            proxy::log(&format!("connection error: {e}"));
                        }
                    });
                }
                Err(e) => {
                    proxy::log(&format!("accept error: {e}"));
                    break;
                }
            }
        }
    });

    // -- Phase 5: Set up TAP interface and nftables --
    println!("[5/7] Setting up TAP interface and nftables DNAT rules...");
    setup_tap_interface().await?;
    setup_nftables().await?;
    println!("      TAP interface '{TAP_NAME}' ready ({HOST_TAP_IP}/24, VM={VM_IP})");
    println!("      nftables: DNAT {TAP_NAME} egress → {HOST_TAP_IP}:{PROXY_PORT}");

    // -- Phase 6: Launch the Firecracker VM --
    println!("[6/7] Launching Firecracker VM...");
    let kernel_path = PathBuf::from(KERNEL_PATH)
        .canonicalize()
        .context(format!("Kernel file '{KERNEL_PATH}' not found"))?;
    let rootfs_path = PathBuf::from(ROOTFS_PATH)
        .canonicalize()
        .context(format!("Rootfs file '{ROOTFS_PATH}' not found"))?;
    println!("      Kernel: {}", kernel_path.display());
    println!("      Rootfs: {}", rootfs_path.display());

    let mut vm = launch_vm(&kernel_path, &rootfs_path).await?;
    println!("      VM launched!\n");

    // Capture serial output
    let pipes = vm.take_pipes().ok();
    if let Some(pipes) = pipes {
        use futures_util::AsyncReadExt;
        let mut buf = vec![0u8; 4096];
        let mut stdout = pipes.stdout;
        tokio::spawn(async move {
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let output = String::from_utf8_lossy(&buf[..n]);
                        print!("{output}");
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // -- Phase 7: Wait for VM test to complete --
    println!("[7/7] Waiting for VM to boot and run integration test...");
    println!("      The VM's init script will:");
    println!("        - Verify the proxy CA is trusted");
    println!("        - Make an HTTPS request through the proxy to the mock API");
    println!("        - Verify the response contains the injected API key");
    println!();

    tokio::time::sleep(Duration::from_secs(60)).await;

    // Shutdown
    println!("\nShutting down VM...");
    shutdown_vm(vm).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Cleanup
    println!("Cleaning up nftables...");
    cleanup_nftables().await.ok();
    println!("Cleaning up TAP interface...");
    cleanup_tap_interface().await.ok();

    // Abort background tasks
    proxy_handle.abort();
    mock_handle.abort();

    println!("\n═══════════════════════════════════════════════════════════");
    println!("Integration test complete.");
    println!("Check the VM serial output above and proxy logs (stderr) for results.");
    println!("Key verification points:");
    println!("  - Proxy logs should show 'CONNECT from {VM_IP} — ✓ VM source IP'");
    println!("  - VM should show 'HTTP/1.1 200' response from the mock API");
    println!(
        "  - Mock server should show 'OK: Received auth header: Bearer sk-INJECTED-BY-PROXY...'"
    );
    println!("═══════════════════════════════════════════════════════════");

    Ok(())
}

/// Build the rootfs using the external build-rootfs.sh script.
/// The script bakes the proxy CA cert into the rootfs.
async fn build_rootfs() -> Result<()> {
    let script_path = PathBuf::from(BUILD_ROOTFS_SCRIPT)
        .canonicalize()
        .context("build-rootfs.sh not found")?;

    let output = tokio::process::Command::new("bash")
        .arg(&script_path)
        .arg(ROOTFS_PATH)
        .arg(CA_PATH)
        .output()
        .await
        .context("Failed to run build-rootfs.sh")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "build-rootfs.sh failed\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        ));
    }

    Ok(())
}

/// Start the mock HTTPS server as a background process.
fn start_mock_server() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let script = include_str!("mock_server.py");
        let tmp = std::env::temp_dir().join("ae-poc-mock-server.py");
        std::fs::write(&tmp, script).unwrap();

        // Inherit stderr so mock server output is visible alongside proxy logs
        use std::process::Stdio;
        let _ = tokio::process::Command::new("python3")
            .arg(&tmp)
            .arg(MOCK_PORT.to_string())
            .kill_on_drop(true)
            .stderr(Stdio::inherit())
            .output()
            .await;
    })
}

// --- TAP interface management (from ae-fc-poc) ---

async fn setup_tap_interface() -> Result<()> {
    run_cmd(
        "sudo",
        &["ip", "tuntap", "add", "dev", TAP_NAME, "mode", "tap"],
    )
    .await?;
    run_cmd(
        "sudo",
        &[
            "ip",
            "addr",
            "add",
            &format!("{HOST_TAP_IP}/24"),
            "dev",
            TAP_NAME,
        ],
    )
    .await?;
    run_cmd("sudo", &["ip", "link", "set", "dev", TAP_NAME, "up"]).await?;
    // Disable checksum offload — Firecracker's virtio-net doesn't support
    // hardware checksum offload, and the 4.14 kernel may not handle it
    // correctly for TLS-sized packets
    run_cmd(
        "sudo",
        &["ethtool", "-K", TAP_NAME, "tx", "off", "rx", "off"],
    )
    .await
    .ok();
    // Disable rp_filter — required for DNAT'd return traffic
    let rp_filter_path = format!("/proc/sys/net/ipv4/conf/{TAP_NAME}/rp_filter");
    run_cmd("sudo", &["sh", "-c", &format!("echo 0 > {rp_filter_path}")]).await?;
    run_cmd(
        "sudo",
        &["sh", "-c", "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"],
    )
    .await?;
    Ok(())
}

async fn cleanup_tap_interface() -> Result<()> {
    run_cmd("sudo", &["ip", "link", "set", "dev", TAP_NAME, "down"])
        .await
        .ok();
    run_cmd(
        "sudo",
        &["ip", "tuntap", "del", "dev", TAP_NAME, "mode", "tap"],
    )
    .await?;
    Ok(())
}

// --- nftables management (from ae-fc-poc, using dnat to tap_ip) ---

async fn setup_nftables() -> Result<()> {
    let ruleset = format!(
        r#"
table ip ae-poc {{
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
        tap = TAP_NAME,
        port = PROXY_PORT,
        host_ip = HOST_TAP_IP,
    );

    let ruleset_path = "/tmp/ae-poc-nftables.conf";
    std::fs::write(ruleset_path, &ruleset)?;
    run_cmd("sudo", &["/usr/sbin/nft", "-f", ruleset_path]).await?;
    Ok(())
}

async fn cleanup_nftables() -> Result<()> {
    run_cmd(
        "sudo",
        &["/usr/sbin/nft", "delete", "table", "ip", "ae-poc"],
    )
    .await?;
    Ok(())
}

// --- VM launch (from ae-fc-poc) ---

async fn launch_vm(
    kernel_path: &PathBuf,
    rootfs_path: &PathBuf,
) -> Result<Vm<UnrestrictedVmmExecutor, DirectProcessSpawner, TokioRuntime>> {
    let installation = VmmInstallation::new(
        "/usr/local/bin/firecracker",
        "/usr/local/bin/jailer",
        "/usr/local/bin/snapshot-editor",
    );

    let api_socket_path = PathBuf::from("/tmp/ae-poc-api.sock");
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
        "console=ttyS0 reboot=k panic=1 root=/dev/vda ro ip={vm_ip}::{host_ip}:255.255.255.0::eth0:off",
        vm_ip = VM_IP,
        host_ip = HOST_TAP_IP,
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
            vcpu_count: 1,
            mem_size_mib: 256,
            smt: None,
            track_dirty_pages: None,
            huge_pages: None,
        },
        cpu_template: None,
        network_interfaces: vec![NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: TAP_NAME.to_string(),
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

    println!("      VM prepared, starting boot...");
    vm.start(Duration::from_secs(10))
        .await
        .context("Failed to start VM")?;

    Ok(vm)
}

async fn shutdown_vm(
    mut vm: Vm<UnrestrictedVmmExecutor, DirectProcessSpawner, TokioRuntime>,
) -> Result<()> {
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
                println!("      VM shut down gracefully (action #{})", outcome.index);
            } else {
                println!("      VM shut down (force, action #{})", outcome.index);
            }
        }
        Err(e) => {
            eprintln!("      VM shutdown error: {e:?}");
        }
    }

    vm.cleanup().await.ok();
    Ok(())
}

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
