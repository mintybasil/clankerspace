//! File injection for VM environments.
//!
//! Prepares files from the `POST /v1/environments` request for injection
//! into the Firecracker VM. Files are staged in a temp directory, packed
//! into an ext4 disk image, and attached as a read-only drive.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use tracing::info;

use crate::types::FileEntry;

/// Directory on the host that `source: "path"` files are restricted to.
/// Prevents path traversal — only files under this directory can be injected.
const HOST_PATH_ALLOWLIST: &str = "/var/lib/ae-vm-manager/files/";

/// Prepared file injection state: the temp staging directory and the
/// list of (guest_path, staging_path) pairs.
pub struct FileInjection {
    /// Temp directory containing staged files. Cleaned up on drop.
    /// Kept alive (not read directly) to ensure temp files exist until
    /// the ext4 image is built and the VM launches.
    _staging_dir: tempfile::TempDir,
    /// Path to the ext4 disk image (created from staging_dir).
    pub disk_image: PathBuf,
}

impl FileInjection {
    /// Prepare files for injection into a VM.
    ///
    /// Creates a temp directory, stages all files, then builds an ext4
    /// disk image. The image can be attached as a read-only drive.
    pub async fn prepare(files: &[FileEntry], session_id: &str) -> Result<Option<Self>> {
        if files.is_empty() {
            return Ok(None);
        }

        let staging_dir = tempfile::tempdir().context("failed to create staging directory")?;

        for file in files {
            stage_file(staging_dir.path(), file).await?;
        }

        // Build ext4 image from the staging directory
        let disk_image = build_ext4_image(staging_dir.path(), session_id).await?;

        info!(
            session_id = %session_id,
            file_count = files.len(),
            image_path = %disk_image.display(),
            "file injection image prepared"
        );

        Ok(Some(Self {
            _staging_dir: staging_dir,
            disk_image,
        }))
    }
}

/// Stage a single file in the staging directory.
async fn stage_file(staging_dir: &Path, file: &FileEntry) -> Result<()> {
    // guest_path is absolute inside the VM (e.g., /home/agent/task.md)
    // We replicate the path structure inside the staging directory.
    let guest_path = Path::new(&file.guest_path);
    let dest = staging_dir.join(guest_path.strip_prefix("/").unwrap_or(guest_path));

    // Create parent directories
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    match file.source.as_str() {
        "inline" => {
            let content = file.content.as_ref().ok_or_else(|| {
                anyhow!(
                    "source=inline requires 'content' field for {}",
                    file.guest_path
                )
            })?;
            tokio::fs::write(&dest, content).await?;
            info!(guest_path = %file.guest_path, "staged inline file");
        }
        "git" => {
            let url = file.url.as_ref().ok_or_else(|| {
                anyhow!("source=git requires 'url' field for {}", file.guest_path)
            })?;
            let git_ref = file.git_ref.as_deref().unwrap_or("main");

            // Clone to a temp dir, then copy to dest
            let clone_dir = tempfile::tempdir()?;
            clone_repo(url, git_ref, clone_dir.path()).await?;

            // Copy the entire clone contents to dest
            copy_dir_all(clone_dir.path(), &dest)?;
            info!(
                guest_path = %file.guest_path,
                url = %url,
                git_ref = %git_ref,
                "staged git repo"
            );
        }
        "path" => {
            let src = file.path.as_ref().ok_or_else(|| {
                anyhow!("source=path requires 'path' field for {}", file.guest_path)
            })?;

            // Validate path is under the allowlisted directory
            let src_canonical = Path::new(src)
                .canonicalize()
                .with_context(|| format!("source path does not exist: {src}"))?;
            if !src_canonical.starts_with(HOST_PATH_ALLOWLIST) {
                return Err(anyhow!(
                    "path injection restricted to {HOST_PATH_ALLOWLIST} — got {}",
                    src_canonical.display()
                ));
            }

            let src_meta = tokio::fs::metadata(&src_canonical).await?;
            if src_meta.is_dir() {
                copy_dir_all(&src_canonical, &dest)?;
            } else {
                tokio::fs::copy(&src_canonical, &dest).await?;
            }
            info!(guest_path = %file.guest_path, host_path = %src_canonical.display(), "staged host path file");
        }
        other => {
            return Err(anyhow!("unknown file source type: {other}"));
        }
    }

    Ok(())
}

/// Clone a git repository at a specific ref.
async fn clone_repo(url: &str, git_ref: &str, dest: &Path) -> Result<()> {
    let output = tokio::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            git_ref,
            url,
            &dest.to_string_lossy(),
        ])
        .output()
        .await
        .context("failed to run git clone")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Try without --branch in case the ref is a commit SHA
        let output2 = tokio::process::Command::new("git")
            .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
            .output()
            .await
            .context("failed to run git clone (fallback)")?;

        if !output2.status.success() {
            let stderr2 = String::from_utf8_lossy(&output2.stderr);
            return Err(anyhow!(
                "git clone failed for {url} at {git_ref}\nfirst attempt: {stderr}\nfallback: {stderr2}"
            ));
        }

        // Checkout the specific ref if it's not the default branch
        let checkout = tokio::process::Command::new("git")
            .args(["-C", &dest.to_string_lossy(), "checkout", git_ref])
            .output()
            .await;
        // Ignore checkout errors — the clone may already be at the right ref
        let _ = checkout;
    }

    Ok(())
}

/// Recursively copy a directory (synchronous — file I/O only).
fn copy_dir_all(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_all(&entry_path, &dest_path)?;
        } else {
            std::fs::copy(&entry_path, &dest_path)?;
        }
    }
    Ok(())
}

/// Build an ext4 disk image from a directory.
async fn build_ext4_image(staging_dir: &Path, session_id: &str) -> Result<PathBuf> {
    let image_path = std::env::temp_dir().join(format!("ae-vm-files-{session_id}.img"));

    // Calculate image size (at least 1MB, or 2x the directory size, rounded up to 4MB)
    let dir_size = dir_size(staging_dir);
    let image_size = std::cmp::max(
        4 * 1024 * 1024,                                            // minimum 4MB
        (dir_size * 2).div_ceil(4 * 1024 * 1024) * 4 * 1024 * 1024, // round up to 4MB
    );

    // Create a sparse file of the right size
    let file = std::fs::File::create(&image_path)?;
    file.set_len(image_size as u64)?;

    // Format as ext4
    run_cmd("mkfs.ext4", &["-q", "-F", &image_path.to_string_lossy()]).await?;

    // Mount and copy files
    let mount_point = format!("/tmp/ae-vm-mount-{session_id}");
    tokio::fs::create_dir_all(&mount_point).await.ok();
    run_cmd(
        "sudo",
        &[
            "mount",
            "-o",
            "loop",
            &image_path.to_string_lossy(),
            &mount_point,
        ],
    )
    .await?;

    // Copy staging dir contents to mount point
    let staging_str = staging_dir.to_string_lossy();
    run_cmd(
        "sudo",
        &["cp", "-r", &*staging_str, &format!("{mount_point}/.")],
    )
    .await?;

    // Unmount
    run_cmd("sudo", &["umount", &mount_point]).await?;
    tokio::fs::remove_dir_all(&mount_point).await.ok();

    Ok(image_path)
}

/// Calculate the total size of a directory in bytes (synchronous).
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let file_type = entry.file_type().unwrap_or_else(|_| {
                std::fs::symlink_metadata(&entry_path)
                    .map(|m| m.file_type())
                    .unwrap_or_else(|_| {
                        std::fs::metadata(&entry_path)
                            .map(|m| m.file_type())
                            .unwrap_or_else(|_| {
                                let f = std::fs::File::open(&entry_path).unwrap();
                                f.metadata().unwrap().file_type()
                            })
                    })
            });
            if file_type.is_dir() {
                total += dir_size(&entry_path);
            } else {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
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
