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

// --- nftables shared table ---

/// The shared nftables table name for all VM Manager DNAT rules.
const NFT_TABLE: &str = "ae-vm-manager";

/// Install the shared nftables table with DNAT and forward chains.
/// Called once at VM Manager startup. Per-interface rules are added/removed
/// dynamically via `add_dnat_rule` / `remove_dnat_rule`.
pub async fn install_nftables_base() -> Result<()> {
    let ruleset = format!(
        r#"
table ip {table} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
    }}
}}
"#,
        table = NFT_TABLE,
    );

    let ruleset_path = "/tmp/ae-vm-manager-base.conf";
    std::fs::write(ruleset_path, &ruleset)?;
    run_cmd("sudo", &["/usr/sbin/nft", "-f", ruleset_path]).await?;
    Ok(())
}

/// Remove the shared nftables table. Called at VM Manager shutdown.
pub async fn remove_nftables_base() -> Result<()> {
    run_cmd(
        "sudo",
        &["/usr/sbin/nft", "delete", "table", "ip", NFT_TABLE],
    )
    .await
    .ok();
    Ok(())
}

/// Add a DNAT rule for a specific TAP interface to the shared table.
/// Also adds forward accept rules for the interface.
pub async fn add_dnat_rule(tap_name: &str, host_ip: &str) -> Result<()> {
    // Add DNAT rule to prerouting chain
    let dnat_rule = format!(
        "iifname \"{tap}\" tcp dport != {port} dnat to {host_ip}:{port}",
        tap = tap_name,
        port = constants::PROXY_PORT,
        host_ip = host_ip,
    );
    run_cmd(
        "sudo",
        &[
            "/usr/sbin/nft",
            "add",
            "rule",
            "ip",
            NFT_TABLE,
            "prerouting",
            &dnat_rule,
        ],
    )
    .await?;

    // Add forward accept rules for this interface
    let fwd_in = format!("iifname \"{tap}\" accept", tap = tap_name);
    run_cmd(
        "sudo",
        &[
            "/usr/sbin/nft",
            "add",
            "rule",
            "ip",
            NFT_TABLE,
            "forward",
            &fwd_in,
        ],
    )
    .await?;

    let fwd_out = format!("oifname \"{tap}\" accept", tap = tap_name);
    run_cmd(
        "sudo",
        &[
            "/usr/sbin/nft",
            "add",
            "rule",
            "ip",
            NFT_TABLE,
            "forward",
            &fwd_out,
        ],
    )
    .await?;

    Ok(())
}

/// Remove all nftables rules for a specific TAP interface.
/// This removes the DNAT and forward rules by flushing and re-adding
/// rules for other interfaces — but since nftables doesn't support
/// deleting individual rules by content easily, we use a handle-based
/// approach: we add rules with a comment to identify them.
///
/// Alternative approach: use `nft delete rule` with rule handles.
/// For simplicity, we flush the chains and re-add rules for remaining
/// interfaces. But that requires knowing all active interfaces.
///
/// Simplest correct approach: use nftables `delete rule` by matching
/// the comment. We add rules with a comment identifying the tap interface.
pub async fn remove_dnat_rule(tap_name: &str) -> Result<()> {
    // Get rule handles from the prerouting chain that match this tap interface
    let list_output = tokio::process::Command::new("sudo")
        .args([
            "/usr/sbin/nft",
            "-a",
            "list",
            "chain",
            "ip",
            NFT_TABLE,
            "prerouting",
        ])
        .output()
        .await
        .context("failed to list nftables prerouting chain")?;

    let list_str = String::from_utf8_lossy(&list_output.stdout);
    let tap_pattern = format!("\"{tap_name}\"");

    // Find and delete rules matching this tap interface
    for line in list_str.lines() {
        if line.contains(&tap_pattern) {
            // Extract handle number
            if let Some(handle) = extract_handle(line) {
                run_cmd(
                    "sudo",
                    &[
                        "/usr/sbin/nft",
                        "delete",
                        "rule",
                        "ip",
                        NFT_TABLE,
                        "prerouting",
                        "handle",
                        &handle.to_string(),
                    ],
                )
                .await
                .ok();
            }
        }
    }

    // Also clean forward chain
    let fwd_output = tokio::process::Command::new("sudo")
        .args([
            "/usr/sbin/nft",
            "-a",
            "list",
            "chain",
            "ip",
            NFT_TABLE,
            "forward",
        ])
        .output()
        .await
        .context("failed to list nftables forward chain")?;

    let fwd_str = String::from_utf8_lossy(&fwd_output.stdout);
    for line in fwd_str.lines() {
        if line.contains(&tap_pattern)
            && let Some(handle) = extract_handle(line)
        {
            run_cmd(
                "sudo",
                &[
                    "/usr/sbin/nft",
                    "delete",
                    "rule",
                    "ip",
                    NFT_TABLE,
                    "forward",
                    "handle",
                    &handle.to_string(),
                ],
            )
            .await
            .ok();
        }
    }

    Ok(())
}

/// Extract the nftables rule handle from a line like:
/// `    iifname "tap-foo" tcp dport != 9999 dnat to 10.0.1.1:9999 handle 42`
fn extract_handle(line: &str) -> Option<u64> {
    line.split("handle").nth(1)?.trim().parse().ok()
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
    // Disable rp_filter per-interface (not globally) for DNAT return traffic
    let rp_filter_path = format!("/proc/sys/net/ipv4/conf/{tap_name}/rp_filter");
    run_cmd("sudo", &["sh", "-c", &format!("echo 0 > {rp_filter_path}")]).await?;
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

// --- nftables INPUT filter table (issue #19) ---

/// The nftables INPUT filter table name.
const NFT_FILTER_TABLE: &str = "ae-vm-manager-filter";

/// Install the INPUT filter table that restricts port 9999 to TAP interfaces.
/// Called once at startup. Uses `iifname "tap*"` wildcard so all dynamically
/// created TAP interfaces are automatically allowed.
pub async fn install_input_filter() -> Result<()> {
    let ruleset = format!(
        r#"
table inet {table} {{
    chain input {{
        type filter hook input priority 0; policy accept;
        ct state established,related accept
        iifname "tap*" tcp dport {proxy_port} accept
    }}
}}
"#,
        table = NFT_FILTER_TABLE,
        proxy_port = constants::PROXY_PORT,
    );

    let ruleset_path = "/tmp/ae-vm-manager-filter.conf";
    std::fs::write(ruleset_path, &ruleset)?;
    run_cmd("sudo", &["/usr/sbin/nft", "-f", ruleset_path]).await?;
    Ok(())
}

/// Remove the INPUT filter table. Called at shutdown.
pub async fn remove_input_filter() -> Result<()> {
    run_cmd(
        "sudo",
        &["/usr/sbin/nft", "delete", "table", "inet", NFT_FILTER_TABLE],
    )
    .await
    .ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_handle() {
        assert_eq!(
            extract_handle(
                r#"  iifname "tap-foo" tcp dport != 9999 dnat to 10.0.1.1:9999 handle 42"#
            ),
            Some(42)
        );
        assert_eq!(extract_handle("  no handle here"), None);
        assert_eq!(extract_handle("  rule with handle 9999"), Some(9999));
    }

    #[test]
    fn test_nft_table_constants() {
        assert_eq!(NFT_TABLE, "ae-vm-manager");
        assert_eq!(NFT_FILTER_TABLE, "ae-vm-manager-filter");
    }
}
