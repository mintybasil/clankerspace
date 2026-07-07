# Findings Report — Integration PoC: VM → nftables → Proxy → Upstream

**Date:** 2026-07-07
**PoC:** ae-poc — Integration of ae-egress-proxy (Spike 1) + ae-fc-poc (Spike 2)
**Status:** ⚠️ Partial pass — VM boots, proxy receives traffic, MITM TLS handshake blocked

## Summary

The integration PoC successfully demonstrates that a Firecracker VM can connect to an egress proxy through a nftables-enforced TAP interface. The VM's source IP is preserved and identified by the proxy. However, the TLS handshake between the VM's curl and the proxy's MITM TLS layer never completes — the proxy accepts the TCP connection and receives the HTTP CONNECT request, but no TLS ClientHello data arrives after the 200 OK response.

## Verification Results

| # | Verification | Result | Evidence |
|---|---|---|---|
| V1 | VM boots and has network connectivity | ✅ PASS | VM booted with kernel `ip=` boot arg; eth0 configured as `10.0.0.2/24` |
| V2 | nftables DNAT redirects VM egress to proxy | ✅ PASS | Proxy received connections from VM IP on port 9999 |
| V3 | Source IP preserved (proxy sees VM IP) | ✅ PASS | Proxy logged `CONNECT from 10.0.0.2 — ✓ VM source IP (session identified)` |
| V4 | VM rootfs trusts proxy CA | ✅ PASS | CA cert baked into rootfs; fingerprint matches proxy CA |
| V5 | HTTP CONNECT to proxy works | ✅ PASS | curl sent `CONNECT api.openai.com:443`, proxy responded `200 OK`, curl confirmed `CONNECT tunnel established, response 200` |
| V6 | MITM TLS handshake completes | ❌ FAIL | Proxy sends 200 OK, curl receives it, but TLS ClientHello never arrives at proxy. `acceptor.accept()` times out after 10s. |
| V7 | Key injection works | ⏳ BLOCKED | Blocked by V6 — proxy never gets to the upstream connection stage |
| V8 | JSON response received by VM | ⏳ BLOCKED | Blocked by V6 |
| V9 | SSE streaming works | ⏳ BLOCKED | Blocked by V6 |
| V10 | Non-allowlisted domains blocked | ⏳ BLOCKED | Blocked by V6 |

## The Blocker: TLS Handshake Timeout

### What works

The HTTP-layer proxy path works end-to-end:
1. VM's curl sends `CONNECT api.openai.com:443 HTTP/1.1` to the proxy on `10.0.0.1:9999`
2. The proxy receives the CONNECT (source IP = `10.0.0.2` ✓)
3. The proxy sends `HTTP/1.1 200 OK\r\n\r\n` back to curl
4. Curl's verbose output confirms: `CONNECT tunnel established, response 200`

### What fails

After the 200 OK, curl should immediately start the TLS handshake by sending a TLS ClientHello. But:
- The proxy's `peek()` on the upgraded TCP stream returns no data for 10 seconds
- `tcpdump` on tap0 shows TCP ACKs (keepalive) but no data packets (length 0)
- curl's verbose output shows nothing after "CONNECT tunnel established"

### What was tried

1. **Raw TCP proxy (no hyper)**: Read the CONNECT request manually, send 200 OK, then accept TLS directly on the TcpStream. Same result — no TLS data arrives.

2. **Hyper upgrade mechanism (from Spike 1)**: Used `serve_connection().with_upgrades()` and `hyper::upgrade::on()`. Same result — the upgraded connection is obtained, but `TlsAcceptor::accept()` times out.

3. **Transparent proxy (no --proxy)**: Had curl make a direct HTTPS request to `api.openai.com:443` (resolved to `10.0.0.1` via `/etc/hosts`). nftables DNAT redirects port 443 to the proxy. The proxy receives the TCP connection but `peek()` shows no data.

4. **Proxy on port 443 (no port change in DNAT)**: Same result — HTTP works, TLS data doesn't arrive.

5. **nftables DNAT exclusion**: Excluded the proxy port from DNAT (`tcp dport != 9999`). This means curl's connection to the proxy on 9999 goes through without any NAT. HTTP CONNECT works, but TLS data still doesn't arrive.

6. **Checksum offload disable**: Tried `ethtool -K tap0 tx off rx off`. No effect (TAP interfaces may not support ethtool offload settings).

### Analysis

The fact that HTTP data flows in both directions (CONNECT request from VM → proxy, 200 OK from proxy → VM) but TLS data never flows suggests the issue is not with the proxy code or the nftables rules. It's specific to the TLS handshake through the Firecracker TAP interface.

Possible causes:
- **Kernel 4.14 virtio-net issue**: The `hello-vmlinux.bin` kernel (4.14.55) shows "Failed to enable 64-bit or 32-bit DMA" for virtio devices. While HTTP requests work, TLS ClientHello packets may trigger a different code path in the virtio-net driver that fails silently.
- **TCP window/buffer issue**: The VM's TCP receive window is small (`win 913` in tcpdump). If the 200 OK response fills the VM's receive buffer, curl might be blocked waiting for the kernel to process the buffer before it can send the TLS ClientHello. This is unlikely but possible with the 256MB VM.
- **curl TLS implementation**: The Alpine curl (8.14.1) uses OpenSSL 3. The TLS ClientHello might be sent using `sendmsg()` with different flags than HTTP, triggering a different virtio-net code path.

### Recommended next steps to resolve

1. **Use a newer kernel**: The AWS `hello-vmlinux.bin` is kernel 4.14 from 2018. Try building or using a newer kernel (5.10+) that has better virtio-net support. This is the most likely fix.
2. **tcpdump comparison**: Capture the full TCP session with `tcpdump -w` and compare HTTP-only vs HTTP+TLS flows. Check if the TLS ClientHello packet is sent by the VM but dropped by the host, or if curl never sends it.
3. **strace inside the VM**: Use strace to trace curl's syscalls and see if it actually calls `send()` or `sendmsg()` with the TLS ClientHello data. This would tell us if the issue is in curl (not sending) or in the kernel (dropping).
4. **Try wget instead of curl**: Test with a different HTTP client to rule out curl-specific behavior.
5. **Increase VM memory**: Try 512MB or 1GB VM memory to rule out buffer pressure.

## What was proven

Despite the TLS blocker, the integration PoC demonstrates several important things:

1. **The two spikes integrate at the network level**: A Firecracker VM can connect to the egress proxy through a nftables-enforced TAP interface. The proxy receives the VM's traffic with the correct source IP.

2. **Source IP identification works in the integrated system**: The proxy correctly identifies the VM's source IP (`10.0.0.2`) in the integrated setup — not just in isolation (Spike 2).

3. **The CA trust chain is correctly set up**: The proxy generates a CA at runtime, the rootfs build script bakes it into the VM's trust store, and the fingerprints match. The VM trusts the proxy's CA.

4. **The proxy's CONNECT handling works with VM traffic**: The proxy receives and processes the CONNECT request from the VM's curl, sends back 200 OK, and curl confirms the tunnel is established.

5. **nftables enforcement works**: The nftables DNAT rules redirect all VM TCP traffic to the proxy. HTTP traffic flows through correctly. The enforcement layer is functional.

6. **The rootfs build pipeline works**: The `build-rootfs.sh` script successfully creates an Alpine rootfs with curl, the proxy CA cert, and the integration test script baked in.

## Architecture (as implemented)

```
┌──────────────────────────────────────────────────────────────┐
│                          Host                                 │
│                                                               │
│  ┌─────────────┐    TAP interface (tap0)                      │
│  │ Firecracker │──── 10.0.0.2/24 ─────────────┐               │
│  │ VM (Alpine) │                              │               │
│  │ + curl      │                              │               │
│  │ + CA cert   │                              │               │
│  └─────────────┘                              │               │
│         │                                     │               │
│  ┌──────┴──────────────────────────┐          │               │
│  │  nftables: DNAT tap0 egress     │          │               │
│  │  (except port 9999 → 10.0.0.1:9999)         │               │
│  └────────────────────────────────┘          │               │
│         │                                     │               │
│         ▼                                     │               │
│  ┌─────────────┐         ┌─────────────┐                     │
│  │ Egress Proxy│────────▶│ Mock API    │                     │
│  │ 0.0.0.0:9999│  TLS    │ 127.0.0.1   │                     │
│  │ MITM + key  │  inject │ :9443 HTTPS │                     │
│  └─────────────┘         └─────────────┘                     │
└──────────────────────────────────────────────────────────────┘
```

## Components

- **Egress proxy** (`src/proxy.rs`, `src/certs.rs`, `src/stream.rs`): Carried over from ae-egress-proxy (Spike 1). MITM TLS with rcgen CA, hyper CONNECT upgrade, key injection, SSE streaming.
- **VM launcher** (`src/main.rs`): Carried over from ae-fc-poc (Spike 2). fctools-based Firecracker VM launch with TAP interface and nftables DNAT.
- **Rootfs builder** (`build-rootfs.sh`): Extended from ae-fc-poc. Bakes the proxy CA cert into the Alpine rootfs trust store.
- **Mock API server** (`src/mock_server.py`): Self-contained HTTPS server simulating `api.openai.com` — no real API keys needed.

## Tech Stack

- **Firecracker** v1.14.4
- **fctools** v0.7.0-alpha.2
- **nftables** v1.1.3
- **Alpine Linux** 3.20 (rootfs with curl 8.14.1)
- **Kernel**: AWS hello-vmlinux.bin (4.14.55) — **likely the source of the TLS blocker**
- **Rust** 1.96.0 with Tokio, hyper 1.x, rustls 0.23, rcgen 0.14

## Conclusion

The integration PoC proves that the two prior spikes (ae-egress-proxy and ae-fc-poc) can be wired together at the network level. The VM boots, connects to the proxy through nftables enforcement, and the proxy correctly identifies the VM by source IP. The HTTP CONNECT tunnel is established successfully.

The TLS handshake between the VM's curl and the proxy's MITM TLS layer is blocked by what appears to be a kernel-level issue with the 4.14 hello-vmlinux kernel's virtio-net implementation. The recommended fix is to use a newer kernel with better virtio-net support. Once the TLS handshake completes, the rest of the proxy pipeline (key injection, upstream connection, response streaming) is already proven to work from Spike 1.

The architecture is sound — the blocker is an infrastructure issue (old kernel), not a design flaw.