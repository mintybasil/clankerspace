//! TAP interface and nftables management.

use anyhow::{Context, Result, anyhow};

use crate::constants;

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

// --- TAP interface management ---

/// Create and configure a TAP interface with the given name and host IP.
pub async fn setup_tap_interface(tap_name: &str, host_ip: &str) -> Result<()> {
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
pub async fn cleanup_tap_interface(tap_name: &str) -> Result<()> {
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
pub async fn setup_nftables(tap_name: &str, host_ip: &str, session_id: &str) -> Result<()> {
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
        port = constants::PROXY_PORT,
        host_ip = host_ip,
    );

    let ruleset_path = format!("/tmp/ae-vm-manager-nftables-{session_id}.conf");
    std::fs::write(&ruleset_path, &ruleset)?;
    run_cmd("sudo", &["/usr/sbin/nft", "-f", &ruleset_path]).await?;
    Ok(())
}

/// Remove nftables rules for a session.
pub async fn cleanup_nftables(session_id: &str) -> Result<()> {
    let table_name = nft_table_name(session_id);
    run_cmd(
        "sudo",
        &["/usr/sbin/nft", "delete", "table", "ip", &table_name],
    )
    .await?;
    Ok(())
}

/// Generate a unique nftables table name for a session.
pub fn nft_table_name(session_id: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_table_name() {
        assert_eq!(nft_table_name("sess_8f7a3b2c"), "ae_vm_sess_8f7a3b2c");
        assert_eq!(nft_table_name("test1234"), "ae_vm_test1234");
        // Invalid chars get replaced
        assert_eq!(nft_table_name("sess.test"), "ae_vm_sess_test");
    }
}
