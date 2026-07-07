#!/bin/bash
#
# Build a minimal Alpine rootfs for the ae-poc integration test.
#
# This script:
# 1. Downloads the Alpine mini rootfs tarball
# 2. Creates an ext4 disk image
# 3. Mounts it and extracts Alpine into it
# 4. Installs curl and its dependencies
# 5. Bakes the proxy CA certificate into the rootfs trust store
# 6. Configures serial console, networking, and an integration test script
#
# Usage: build-rootfs.sh <output-image> <ca-cert-pem>
#
# Requirements: sudo, mke2fs (e2fsprogs), curl, tar
#
set -e

ARCH=$(uname -m)
ALPINE_VERSION="v3.20"
ROOTFS_DIR="/tmp/ae-poc-rootfs-build"
ROOTFS_IMG="${1:-rootfs.ext4}"
CA_PEM="${2:-proxy-ca.pem}"
ROOTFS_SIZE="200M"

echo "=== Building Alpine rootfs for ae-poc integration ==="
echo "Architecture: $ARCH"
echo "Alpine version: $ALPINE_VERSION"
echo "Output image: $ROOTFS_IMG"
echo "CA cert: $CA_PEM"
echo ""

# Verify CA cert exists
if [ ! -f "$CA_PEM" ]; then
    echo "ERROR: CA cert file '$CA_PEM' not found."
    exit 1
fi

# Step 1: Download Alpine mini rootfs
echo "[1/7] Downloading Alpine mini rootfs..."
TARBALL="/tmp/alpine-rootfs.tar.gz"
if [ ! -f "$TARBALL" ]; then
    curl -sL "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-3.20.0-${ARCH}.tar.gz" -o "$TARBALL"
fi
echo "      Downloaded: $TARBALL"

# Step 2: Create ext4 image
echo "[2/7] Creating ext4 disk image (${ROOTFS_SIZE})..."
rm -f "$ROOTFS_IMG"
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=200 2>/dev/null
mke2fs -t ext4 -F "$ROOTFS_IMG" 2>&1 | tail -1

# Step 3: Mount and extract
echo "[3/7] Mounting and extracting Alpine rootfs..."
MOUNTPOINT="/mnt/ae-poc-rootfs"
sudo -S -p '' mkdir -p "$MOUNTPOINT"
sudo -S -p '' mount -o loop "$ROOTFS_IMG" "$MOUNTPOINT"
sudo -S -p '' tar xzf "$TARBALL" -C "$MOUNTPOINT"

# Step 4: Configure the rootfs
echo "[4/7] Configuring rootfs..."

# Serial console inittab
sudo -S -p '' tee "$MOUNTPOINT/etc/inittab" > /dev/null << 'EOF'
::sysinit:/sbin/mdev -s
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sysfs /sys
::sysinit:/bin/mount -t devtmpfs devtmpfs /dev
::sysinit:/bin/hostname -F /etc/hostname
::sysinit:/etc/init.d/network-config
::sysinit:/etc/init.d/integration-test
ttyS0::respawn:/bin/sh
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
EOF

# Hostname
echo "ae-poc-vm" | sudo -S -p '' tee "$MOUNTPOINT/etc/hostname" > /dev/null

# DNS — point to the host's TAP IP (we don't need real DNS; the proxy
# handles domain routing, and curl uses the proxy's CONNECT which resolves
# the domain on the proxy side)
echo "nameserver 8.8.8.8" | sudo -S -p '' tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null

# /etc/hosts — map api.openai.com to the host's TAP IP.
# nftables DNAT redirects ALL TCP from tap0 to the proxy on port 9999.
# So curl connects to 10.0.0.1:443, nftables redirects to 10.0.0.1:9999.
sudo -S -p '' tee "$MOUNTPOINT/etc/hosts" > /dev/null << 'EOF'
127.0.0.1   localhost
10.0.0.1    api.openai.com evil.com
EOF

# Network config script
sudo -S -p '' mkdir -p "$MOUNTPOINT/etc/init.d"
sudo -S -p '' tee "$MOUNTPOINT/etc/init.d/network-config" > /dev/null << 'EOF'
#!/bin/sh
ip link set eth0 up
ip addr add 10.0.0.2/24 dev eth0
ip route add default via 10.0.0.1 2>/dev/null || true
EOF
sudo -S -p '' chmod +x "$MOUNTPOINT/etc/init.d/network-config"

# Step 5: Bake the proxy CA certificate into the rootfs
echo "[5/7] Installing proxy CA certificate..."

# Create the CA cert directory
sudo -S -p '' mkdir -p "$MOUNTPOINT/usr/local/share/ca-certificates"

# Copy the CA cert into the rootfs
sudo -S -p '' cp "$CA_PEM" "$MOUNTPOINT/usr/local/share/ca-certificates/ae-poc-proxy-ca.crt"

# Also place it where curl's CA bundle can find it
# Alpine uses /etc/ssl/certs/ca-certificates.crt as the system CA bundle
# We append our CA to the system bundle so curl trusts it
sudo -S -p '' mkdir -p "$MOUNTPOINT/etc/ssl/certs"
if [ -f "$MOUNTPOINT/etc/ssl/certs/ca-certificates.crt" ]; then
    sudo -S -p '' sh -c "cat '$CA_PEM' >> '$MOUNTPOINT/etc/ssl/certs/ca-certificates.crt'"
else
    sudo -S -p '' cp "$CA_PEM" "$MOUNTPOINT/etc/ssl/certs/ca-certificates.crt"
fi

# Also create a symlink for the cert hash (Alpine's update-ca-certificates style)
# But since we don't have the ca-certificates package, direct bundle append is sufficient
echo "      CA cert installed at /usr/local/share/ca-certificates/ae-poc-proxy-ca.crt"
echo "      CA cert appended to /etc/ssl/certs/ca-certificates.crt"

# Step 6: Integration test script (auto-runs on boot)
echo "[6/7] Creating integration test script..."
sudo -S -p '' tee "$MOUNTPOINT/etc/init.d/integration-test" > /dev/null << 'TESTEOF'
#!/bin/sh
echo ""
echo "============================================"
echo "  ae-poc Integration Test"
echo "============================================"
echo ""

echo "VM IP address:"
ip addr show eth0 2>/dev/null | grep "inet " || echo "eth0 not configured"
echo ""

# The proxy runs on 10.0.0.1:9999 (the host's TAP IP)
# We use it as an explicit HTTP proxy
PROXY="http://10.0.0.1:9999"
API_URL="https://api.openai.com/v1/models"

echo "=== Test 1: HTTPS through proxy with key injection ==="
echo "Request: GET $API_URL (direct, transparent proxy via nftables DNAT)"
echo "curl will send 'Authorization: Bearer PLACEHOLDER'"
echo "Proxy should strip it and inject 'sk-INJECTED-BY-PROXY'"
echo ""

# Quick connectivity test first
echo "--- Quick connectivity test (HTTP via proxy) ---"
curl -sv --connect-timeout 3 --max-time 5 --proxy "$PROXY" \
    http://api.openai.com/v1/models 2>&1 || echo "curl HTTP exit: $?"
echo ""

# Test if curl can do TLS at all
echo "--- curl HTTPS via explicit proxy ---"
curl -sv --connect-timeout 5 --max-time 10 --proxy "$PROXY" \
    --cacert /usr/local/share/ca-certificates/ae-poc-proxy-ca.crt \
    -H "Authorization: Bearer PLACEHOLDER" \
    "$API_URL" 2>&1
CURL_EXIT=$?
echo ""
echo "curl exit code: $CURL_EXIT"

if echo "$RESULT" | grep -q '"gpt-4o"'; then
    echo "TEST 1 PASS: Received valid JSON response from mock API"
    echo "  → Proxy MITM'd TLS, injected key, forwarded to upstream"
elif echo "$RESULT" | grep -q "401"; then
    echo "TEST 1 FAIL: Got 401 — key injection may have failed"
elif echo "$RESULT" | grep -q "SSL certificate verify"; then
    echo "TEST 1 FAIL: TLS verification issue — CA cert not trusted?"
    echo "$RESULT" | grep "SSL certificate verify"
else
    echo "TEST 1 FAIL: Unexpected response (curl exit: $CURL_EXIT)"
fi
echo ""

echo "=== Test 2: SSE streaming through proxy ==="
echo "Request: POST /v1/chat/completions (stream=true)"
echo ""

SSE_RESULT=$(curl -sN --connect-timeout 5 --max-time 15 --proxy "$PROXY" \
    --cacert /usr/local/share/ca-certificates/ae-poc-proxy-ca.crt \
    -H "Authorization: Bearer PLACEHOLDER" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}' \
    "https://api.openai.com/v1/chat/completions" 2>&1)

if echo "$SSE_RESULT" | grep -q "data: \[DONE\]"; then
    echo "TEST 2 PASS: SSE stream received with [DONE] marker"
    CHUNK_COUNT=$(echo "$SSE_RESULT" | grep -c "^data:")
    echo "  → Received $CHUNK_COUNT SSE events"
else
    echo "TEST 2 FAIL: SSE stream not received"
    echo "$SSE_RESULT"
fi
echo ""

echo "=== Test 3: Non-allowlisted domain blocked ==="
BLOCKED=$(curl -sv --connect-timeout 5 --max-time 10 --proxy "$PROXY" \
    --cacert /usr/local/share/ca-certificates/ae-poc-proxy-ca.crt \
    "https://evil.com/" 2>&1)
if echo "$BLOCKED" | grep -q "403"; then
    echo "TEST 3 PASS: evil.com blocked (403 Forbidden)"
else
    echo "TEST 3 FAIL: evil.com was not blocked"
    echo "$BLOCKED" | head -5
fi
echo ""

echo "============================================"
echo "  Integration Test Complete"
echo "============================================"
TESTEOF
sudo -S -p '' chmod +x "$MOUNTPOINT/etc/init.d/integration-test"

# apk repositories
sudo -S -p '' tee "$MOUNTPOINT/etc/apk/repositories" > /dev/null << 'EOF'
https://dl-cdn.alpinelinux.org/alpine/v3.20/main
https://dl-cdn.alpinelinux.org/alpine/v3.20/community
EOF

# Step 7: Install curl
echo "[7/7] Installing curl..."
PKG_DIR="/tmp/apk-pkgs-build"
mkdir -p "$PKG_DIR"
BASE="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}"

download_apk() {
    local pkg=$1
    local url=$(curl -sL "${BASE}/" | grep -oP "href=\"${pkg}-[^\"]+\.apk\"" | head -1 | sed 's/href="//;s/"//')
    if [ -n "$url" ]; then
        curl -sL "${BASE}/${url}" -o "$PKG_DIR/$url"
        sudo -S -p '' tar xzf "$PKG_DIR/$url" -C "$MOUNTPOINT/" 2>/dev/null
        echo "      Installed: $url"
    fi
}

for pkg in curl libcurl brotli-libs c-ares libidn2 libunistring libpsl zstd-libs xz-libs libssl3 libcrypto3 nghttp2-libs; do
    download_apk "$pkg"
done

# Unmount
sudo -S -p '' umount "$MOUNTPOINT"
echo ""
echo "=== Rootfs build complete: $ROOTFS_IMG ==="
echo "Size: $(du -h "$ROOTFS_IMG" | cut -f1)"
echo ""
echo "Contents:"
echo "  - Alpine Linux 3.20 minimal rootfs"
echo "  - curl installed"
echo "  - Proxy CA cert at /usr/local/share/ca-certificates/ae-poc-proxy-ca.crt"
echo "  - Proxy CA cert appended to /etc/ssl/certs/ca-certificates.crt"
echo "  - Serial console on ttyS0"
echo "  - Network: eth0 configured as 10.0.0.2/24 via init script"
echo "  - Integration test script at /etc/init.d/integration-test"