#!/bin/bash
#
# build-image.sh — Reusable Firecracker rootfs image builder for the
# Agent Environment system.
#
# Produces an ext4 rootfs image containing:
#   - Alpine Linux 3.20 base
#   - curl + ca-certificates
#   - Proxy CA certificate in the system trust store
#   - Node.js + npm (optional, for Pi agent harness)
#   - Pi agent harness (optional)
#   - HTTP/HTTPS proxy environment variables
#   - Serial console, network config, and init system
#
# Usage:
#   ./build-image.sh [OPTIONS] <output-image>
#
# Options:
#   --ca-cert <path>       Proxy CA certificate (PEM). Required.
#   --image-name <name>    Image name (default: ae-image)
#   --hostname <name>     VM hostname (default: ae-vm)
#   --size <size>         Image size (default: 500M)
#   --packages <pkgs>     Extra Alpine packages to install (comma-separated)
#   --with-pi             Install Node.js + Pi agent harness
#   --pi-packages <pkgs>  Pi packages to install (comma-separated, requires --with-pi)
#   --proxy-host <ip>     Proxy host IP (default: 10.0.0.1)
#   --proxy-port <port>   Proxy port (default: 9999)
#   --no-proxy            Don't configure proxy env vars (for building without a proxy)
#   --alpine-version <v>  Alpine version (default: v3.20)
#   --help                Show this help
#
# Requirements: sudo, mke2fs (e2fsprogs), curl, tar, and optionally qemu-img
#
set -e

# ── Defaults ─────────────────────────────────────────────────────────
ARCH=$(uname -m)
ALPINE_VERSION="v3.20"
IMAGE_NAME="ae-image"
HOSTNAME="ae-vm"
IMAGE_SIZE="500M"
EXTRA_PACKAGES=""
INSTALL_PI=false
PI_PACKAGES=""
PROXY_HOST="10.0.0.1"
PROXY_PORT="9999"
CONFIGURE_PROXY=true
CA_CERT=""

OUTPUT_IMAGE=""

# ── Arg parsing ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-cert)       CA_CERT="$2"; shift 2 ;;
        --image-name)    IMAGE_NAME="$2"; shift 2 ;;
        --hostname)       HOSTNAME="$2"; shift 2 ;;
        --size)           IMAGE_SIZE="$2"; shift 2 ;;
        --packages)       EXTRA_PACKAGES="$2"; shift 2 ;;
        --with-pi)        INSTALL_PI=true; shift ;;
        --pi-packages)    PI_PACKAGES="$2"; shift 2 ;;
        --proxy-host)     PROXY_HOST="$2"; shift 2 ;;
        --proxy-port)     PROXY_PORT="$2"; shift 2 ;;
        --no-proxy)       CONFIGURE_PROXY=false; shift ;;
        --alpine-version) ALPINE_VERSION="$2"; shift 2 ;;
        --help)           grep '^#' "$0" | head -30; exit 0 ;;
        -*)               echo "Unknown option: $1"; exit 1 ;;
        *)                OUTPUT_IMAGE="$1"; shift ;;
    esac
done

if [ -z "$OUTPUT_IMAGE" ]; then
    echo "Usage: $0 [OPTIONS] <output-image>"
    echo "Run '$0 --help' for details."
    exit 1
fi

if [ -z "$CA_CERT" ]; then
    echo "ERROR: --ca-cert <path> is required."
    exit 1
fi

if [ ! -f "$CA_CERT" ]; then
    echo "ERROR: CA cert file '$CA_CERT' not found."
    exit 1
fi

# ── Setup ────────────────────────────────────────────────────────────
BUILD_DIR="/tmp/${IMAGE_NAME}-build"
MOUNTPOINT="/mnt/${IMAGE_NAME}"
TARBALL="/tmp/alpine-${ALPINE_VERSION}-rootfs.tar.gz"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  build-image.sh — Firecracker rootfs image builder         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "  Output:     $OUTPUT_IMAGE"
echo "  CA cert:    $CA_CERT"
echo "  Size:       $IMAGE_SIZE"
echo "  Alpine:     $ALPINE_VERSION ($ARCH)"
echo "  Pi:         $INSTALL_PI"
echo "  Proxy:      $([ "$CONFIGURE_PROXY" = true ] && echo "$PROXY_HOST:$PROXY_PORT" || echo "disabled")"
echo "  Extra pkgs: ${EXTRA_PACKAGES:-none}"
echo ""

# ── Step 1: Download Alpine mini rootfs ──────────────────────────────
echo "[1/6] Downloading Alpine mini rootfs..."
if [ ! -f "$TARBALL" ]; then
    ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-3.20.0-${ARCH}.tar.gz"
    curl -sL "$ALPINE_URL" -o "$TARBALL"
fi
echo "      Cached: $TARBALL"

# ── Step 2: Create ext4 image ───────────────────────────────────────
echo "[2/6] Creating ext4 disk image (${IMAGE_SIZE})..."
rm -f "$OUTPUT_IMAGE"
# Use truncate for sparse files (faster than dd)
truncate -s "$IMAGE_SIZE" "$OUTPUT_IMAGE"
# Try mke2fs on PATH first, then /usr/sbin/mke2fs (common on Debian)
MKE2FS=$(command -v mke2fs 2>/dev/null || echo "/usr/sbin/mke2fs")
"$MKE2FS" -t ext4 -F "$OUTPUT_IMAGE" 2>&1 | tail -1

# ── Step 3: Mount and extract ───────────────────────────────────────
echo "[3/6] Mounting and extracting Alpine rootfs..."
sudo -S -p '' mkdir -p "$MOUNTPOINT"
sudo -S -p '' mount -o loop "$OUTPUT_IMAGE" "$MOUNTPOINT"
sudo -S -p '' tar xzf "$TARBALL" -C "$MOUNTPOINT"

# Cleanup trap — ensure unmount even on failure
trap 'sudo -S -p '"'"''"'"' umount "'"$MOUNTPOINT"'" 2>/dev/null || true' EXIT

# ── Step 4: Configure base system ───────────────────────────────────
echo "[4/6] Configuring base system..."

# Hostname
echo "$HOSTNAME" | sudo -S -p '' tee "$MOUNTPOINT/etc/hostname" > /dev/null

# /etc/hosts — localhost only. Domain resolution for proxy domains
# is handled by /etc/hosts entries added per-session by the VM Manager,
# or by curl's --proxy mode (CONNECT resolves on the proxy side).
sudo -S -p '' tee "$MOUNTPOINT/etc/hosts" > /dev/null << 'EOF'
127.0.0.1   localhost
::1         localhost localhost.localdomain
EOF

# DNS — the proxy handles DNS resolution for CONNECT requests.
# For transparent mode, the VM needs DNS, but all traffic goes through
# the proxy anyway. Use the host's TAP IP as DNS forwarder if needed,
# or a public resolver as fallback.
echo "nameserver 8.8.8.8" | sudo -S -p '' tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null

# Serial console inittab — minimal init system for Firecracker
sudo -S -p '' tee "$MOUNTPOINT/etc/inittab" > /dev/null << 'EOF'
::sysinit:/sbin/mdev -s
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sysfs /sys
::sysinit:/bin/mount -t devtmpfs devtmpfs /dev
::sysinit:/bin/hostname -F /etc/hostname
::sysinit:/etc/init.d/network-config
::sysinit:/etc/init.d/agent-init
ttyS0::respawn:/bin/sh
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
EOF

# Network config — DHCP would be ideal but Firecracker's virtio-net
# needs static config via kernel boot args. This script configures
# eth0 based on the IP passed via kernel args (ip=... boot param).
# The VM Manager sets the actual IP at launch time.
sudo -S -p '' mkdir -p "$MOUNTPOINT/etc/init.d"
sudo -S -p '' tee "$MOUNTPOINT/etc/init.d/network-config" > /dev/null << 'NETEOF'
#!/bin/sh
# Network is configured by kernel boot args (ip=<vm_ip>::<host_ip>:...:eth0:off)
# but the interface needs to be brought up explicitly.
ip link set eth0 up 2>/dev/null || true
# If kernel didn't configure eth0 (e.g., no ip= boot arg), try DHCP
if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
    udhcpc -i eth0 -q 2>/dev/null || true
fi
NETEOF
sudo -S -p '' chmod +x "$MOUNTPOINT/etc/init.d/network-config"

# ── Step 5: Install packages ────────────────────────────────────────
echo "[5/6] Installing packages..."

# apk repositories
sudo -S -p '' tee "$MOUNTPOINT/etc/apk/repositories" > /dev/null << EOF
https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main
https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community
EOF

# Package build dirs and repo URLs
PKG_DIR="$BUILD_DIR/apk-pkgs"
mkdir -p "$PKG_DIR"
BASE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}"
BASE_COMM="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community/${ARCH}"

# Function to install packages via apk inside the chroot.
# This properly resolves dependencies (unlike manual tar extraction).
chroot_apk_add() {
    local pkgs=$1
    local repos_conf="$MOUNTPOINT/etc/apk/repositories"
    # Ensure repositories are configured
    if [ ! -f "$repos_conf" ]; then
        echo "      Repositories not configured, skipping apk install"
        return 1
    fi
    # Copy host resolv.conf but simplify it (musl doesn't support all glibc options)
    echo "nameserver 127.0.0.53" | sudo -S -p '' tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null
    # Also try 8.8.8.8 as fallback
    echo "nameserver 8.8.8.8" | sudo -S -p '' tee -a "$MOUNTPOINT/etc/resolv.conf" > /dev/null
    # Install packages via apk with proper dependency resolution
    sudo -S -p '' chroot "$MOUNTPOINT" /sbin/apk add --no-cache $pkgs 2>&1 | \
        grep -vE '^(OK:|Executing|Downloading|Installing|fetch|WARNING:)' | head -5
    local ret=${PIPESTATUS[0]}
    # Restore the Alpine resolv.conf (set later in config)
    echo "nameserver 8.8.8.8" | sudo -S -p '' tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null
    return $ret
}

# Function to download and extract an apk package manually (fallback).
# Used for core packages before apk is available, or for packages
# that need manual extraction.
install_apk_manual() {
    local pkg=$1
    local base=$2
    local url
    # The Alpine package directory listing URL-encodes special chars in href
    # attributes (e.g., libstdc++ → libstdc%2B%2B). We URL-encode the package
    # name for the href match, then fetch by the encoded href.
    local encoded_pkg
    encoded_pkg=$(echo "$pkg" | sed 's/+/%2B/g')
    local listing
    listing=$(curl -sL "${base}/" 2>/dev/null)
    url=$(echo "$listing" | grep -oP "href=\"${encoded_pkg}-[^\"]+\.apk\"" | head -1 | sed 's/href="//;s/"//')
    if [ -n "$url" ]; then
        curl -sL "${base}/${url}" -o "$PKG_DIR/$url"
        sudo -S -p '' tar xzf "$PKG_DIR/$url" -C "$MOUNTPOINT/" 2>/dev/null
        echo "      ✓ $pkg (manual)"
    else
        echo "      ✗ $pkg (not found in $base)"
    fi
}

# Core packages always installed via apk (with dependency resolution)
echo "      Installing core packages..."
CORE_PACKAGES="curl ca-certificates"
chroot_apk_add "$CORE_PACKAGES"

# Extra packages from --packages flag
if [ -n "$EXTRA_PACKAGES" ]; then
    echo "      Installing extra packages: $EXTRA_PACKAGES"
    chroot_apk_add "$EXTRA_PACKAGES"
fi

# Node.js + npm (for Pi)
if [ "$INSTALL_PI" = true ]; then
    echo "      Installing Node.js + npm..."
    chroot_apk_add "nodejs npm"

    # Install Pi agent harness via npm (needs network access from the chroot)
    # The chroot uses the host's network, so npm can reach the npm registry.
    # Ensure DNS is configured for the chroot.
    echo "      Installing Pi agent harness..."
    if [ -x "$MOUNTPOINT/usr/bin/node" ]; then
        # Set up DNS for the chroot
        echo "nameserver 127.0.0.53" | sudo -S -p '' tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null
        echo "nameserver 8.8.8.8" | sudo -S -p '' tee -a "$MOUNTPOINT/etc/resolv.conf" > /dev/null

        sudo -S -p '' chroot "$MOUNTPOINT" /bin/sh -c "
            export PATH=/usr/bin:/bin
            export HOME=/root
            npm install -g @earendil-works/pi-coding-agent 2>&1 | tail -5
        " || echo "      ⚠ Pi install failed (npm may need network or proxy config)"

        # Restore the Alpine resolv.conf
        echo "nameserver 8.8.8.8" | sudo -S -p '' tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null
    else
        echo "      ⚠ node binary not found, skipping Pi install"
    fi

    # Install Pi packages if specified
    if [ -n "$PI_PACKAGES" ]; then
        echo "      Installing Pi packages: $PI_PACKAGES"
        IFS=',' read -ra PKGS <<< "$PI_PACKAGES"
        for pkg in "${PKGS[@]}"; do
            sudo -S -p '' chroot "$MOUNTPOINT" /bin/sh -c "
                export PATH=/usr/bin:/bin
                export HOME=/root
                pi install '$pkg' 2>&1 | tail -2
            " || echo "      ⚠ Pi package '$pkg' install failed"
        done
    fi
fi

# ── Step 5b: Install proxy CA certificate ────────────────────────────
echo "      Installing proxy CA certificate..."
sudo -S -p '' mkdir -p "$MOUNTPOINT/usr/local/share/ca-certificates"
sudo -S -p '' cp "$CA_CERT" "$MOUNTPOINT/usr/local/share/ca-certificates/ae-proxy-ca.crt"

# Append to system CA bundle so curl/OpenSSL trusts the proxy
sudo -S -p '' mkdir -p "$MOUNTPOINT/etc/ssl/certs"
if [ -f "$MOUNTPOINT/etc/ssl/certs/ca-certificates.crt" ]; then
    sudo -S -p '' sh -c "cat '$CA_CERT' >> '$MOUNTPOINT/etc/ssl/certs/ca-certificates.crt'"
else
    sudo -S -p '' cp "$CA_CERT" "$MOUNTPOINT/etc/ssl/certs/ca-certificates.crt"
fi
echo "      ✓ CA cert at /usr/local/share/ca-certificates/ae-proxy-ca.crt"
echo "      ✓ CA cert appended to /etc/ssl/certs/ca-certificates.crt"

# ── Step 5c: Configure proxy environment variables ──────────────────
if [ "$CONFIGURE_PROXY" = true ]; then
    echo "      Configuring proxy environment variables..."
    PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"

    # Write proxy config to /etc/profile.d so all shells get it
    sudo -S -p '' mkdir -p "$MOUNTPOINT/etc/profile.d"
    sudo -S -p '' tee "$MOUNTPOINT/etc/profile.d/proxy.sh" > /dev/null << PROXYEOF
#!/bin/sh
# Proxy environment — all outbound traffic goes through the egress proxy.
# The proxy handles TLS MITM for allowlisted API domains and transparent
# tunneling for other allowlisted domains. Non-allowlisted domains are
# dropped.
export http_proxy="${PROXY_URL}"
export https_proxy="${PROXY_URL}"
export HTTP_PROXY="${PROXY_URL}"
export HTTPS_PROXY="${PROXY_URL}"
# no_proxy for local traffic (loopback, TAP interface)
export no_proxy="localhost,127.0.0.1"
export NO_PROXY="localhost,127.0.0.1"
PROXYEOF
    sudo -S -p '' chmod +x "$MOUNTPOINT/etc/profile.d/proxy.sh"
    echo "      ✓ Proxy: ${PROXY_URL}"
fi

# ── Step 6: Install agent init script ────────────────────────────────
echo "[6/6] Installing agent init script..."

# The agent-init script is the VM's entry point. It runs on boot
# and starts the agent harness (or any custom command).
sudo -S -p '' tee "$MOUNTPOINT/etc/init.d/agent-init" > /dev/null << 'INITEOF'
#!/bin/sh
# Agent init script — runs on VM boot.
# Override this file in the rootfs to customize agent startup behavior.
# The VM Manager can also inject a custom agent-init script at launch
# time via fctools ResourceSystem.

echo "[agent-init] VM booted, network configured."

# Print network status
IP=$(ip addr show eth0 2>/dev/null | grep "inet " | awk '{print $2}')
echo "[agent-init] eth0: ${IP:-not configured}"

# If Pi is installed, start it
if command -v pi >/dev/null 2>&1; then
    echo "[agent-init] Pi agent harness found at $(which pi)"
    echo "[agent-init] To start an agent session, run: pi"
else
    echo "[agent-init] Pi not installed. Install with: npm install -g @earendil-works/pi-coding-agent"
fi

echo "[agent-init] Ready."
INITEOF
sudo -S -p '' chmod +x "$MOUNTPOINT/etc/init.d/agent-init"

# ── Finalize ────────────────────────────────────────────────────────
echo ""
sudo -S -p '' umount "$MOUNTPOINT"
trap - EXIT

echo "=== Image build complete: $OUTPUT_IMAGE ==="
echo "Size: $(du -h "$OUTPUT_IMAGE" | cut -f1)"
echo ""
echo "Contents:"
echo "  - Alpine Linux ${ALPINE_VERSION} minimal rootfs"
echo "  - curl + ca-certificates"
echo "  - Proxy CA cert in system trust store"
if [ "$CONFIGURE_PROXY" = true ]; then
    echo "  - Proxy env vars: http(s)_proxy=${PROXY_HOST}:${PROXY_PORT}"
fi
if [ "$INSTALL_PI" = true ]; then
    echo "  - Node.js + npm"
    echo "  - Pi agent harness"
    if [ -n "$PI_PACKAGES" ]; then
        echo "  - Pi packages: $PI_PACKAGES"
    fi
fi
if [ -n "$EXTRA_PACKAGES" ]; then
    echo "  - Extra packages: $EXTRA_PACKAGES"
fi
echo "  - Serial console on ttyS0"
echo "  - Network: eth0 via kernel boot args or DHCP fallback"
echo "  - Agent init script at /etc/init.d/agent-init"