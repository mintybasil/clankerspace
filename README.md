# ae-poc — Integration PoC: VM → nftables → Proxy → Upstream

Integration of the two prior spikes ([ae-egress-proxy](https://github.com/mintybasil/ae-egress-proxy) and [ae-fc-poc](https://github.com/mintybasil/ae-fc-poc)) into a single end-to-end path. See [FINDINGS.md](FINDINGS.md) for the full results.

**Status:** ✅ All verifications pass — full end-to-end path works (VM → nftables → proxy → upstream API with key injection + SSE streaming). Requires Firecracker CI 5.10 kernel (4.14 kernel has a virtio-net TLS bug).

```
 Firecracker VM → nftables DNAT → MITM Egress Proxy → Mock API (upstream)
      │                 │                │                   │
   10.0.0.2          tap0           0.0.0.0:9999         127.0.0.1:9443
   (Alpine+curl)   (DNAT all TCP)  (MITM TLS +          (self-signed cert,
                                   key injection)       simulates LLM API)
```

This proves the full chain works as a system: a Firecracker VM running curl makes an HTTPS request to `api.openai.com`, nftables forces it through the egress proxy, the proxy MITMs TLS (using a CA the VM trusts), strips the placeholder auth header, injects a real API key, connects to the upstream mock API, and streams the response back.

## How it works

1. **CA generation:** The binary generates a self-signed MITM CA certificate and writes it to `proxy-ca.pem`.
2. **Rootfs build:** `build-rootfs.sh` creates an Alpine rootfs with curl and the proxy's CA cert baked into the trust store.
3. **Mock API:** A Python HTTPS server simulates `api.openai.com` — it returns JSON for `/v1/models` and SSE chunks for `/v1/chat/completions`. It verifies the `Authorization` header to confirm key injection.
4. **Egress proxy:** The proxy from Spike 1 listens on `0.0.0.0:9999`. It receives VM traffic via nftables DNAT, logs the source IP for verification, and handles MITM + key injection.
5. **TAP + nftables:** A TAP interface (`tap0`) connects the VM. nftables DNAT redirects all VM TCP egress to the proxy. Source IP is preserved (no masquerade).
6. **VM launch:** fctools launches a Firecracker VM with the rootfs. The VM's init script runs the integration test automatically on boot.

## Prerequisites

- Linux x86_64 with KVM (`/dev/kvm`)
- `nftables` (`nft` binary)
- `iproute2` (`ip` command)
- `sudo` access (for TAP interface and nftables)
- Rust 1.88+ (edition 2024)
- Python 3 + OpenSSL (for the mock server)
- Firecracker v1.14+ at `/usr/local/bin/firecracker`
- `mke2fs` (e2fsprogs), `curl`, `tar`
- **Firecracker CI 5.10 kernel** (not the 4.14 hello-vmlinux — it has a virtio-net TLS bug):
  ```bash
  curl -sL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260107-89702a77e4c2-0/x86_64/vmlinux-5.10.245" -o vmlinux-5.10.bin
  ```

## Build

```bash
cargo build --release
```

## Run

```bash
# Download the Firecracker CI 5.10 kernel
curl -sL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260107-89702a77e4c2-0/x86_64/vmlinux-5.10.245" -o vmlinux-5.10-new.bin

# Run the integration test (needs sudo for TAP + nftables)
sudo ./target/release/ae-poc
```

The binary does everything else automatically:
1. Generates the MITM CA
2. Builds the rootfs with the CA baked in
3. Starts the mock HTTPS server
4. Starts the egress proxy
5. Sets up TAP + nftables
6. Launches the VM
7. Waits for the VM's integration test to complete
8. Cleans up

## Verification

The VM's serial console output (printed to stdout) shows the test results:

| # | Test | Pass criteria |
|---|---|---|
| V1 | Proxy receives VM traffic with original source IP | Proxy logs `CONNECT from 10.0.0.2 — ✓ VM source IP` |
| V2 | MITM TLS works (VM trusts proxy CA) | curl shows `SSL certificate verify ok` |
| V3 | Key injection works | Mock server logs `OK: auth: Bearer sk-INJECTED-BY-PROXY` |
| V4 | JSON response received | VM test shows `TEST 1 PASS` |
| V5 | SSE streaming works | VM test shows `TEST 2 PASS` |
| V6 | Non-allowlisted domain blocked | VM test shows `TEST 3 PASS` |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                          Host                                 │
│                                                               │
│  ┌─────────────┐    TAP interface (tap0)                      │
│  │ Firecracker │──── 10.0.0.2/24 ─────────────┐               │
│  │ VM (Alpine) │                              │               │
│  │ + curl      │                              │               │
│  └─────────────┘                              │               │
│         │                                     │               │
│  ┌──────┴──────────────────────────┐          │               │
│  │  nftables: DNAT tap0 egress     │          │               │
│  │  → 10.0.0.1:9999 (proxy)       │──────────┘               │
│  │  (no masquerade — src IP kept) │                          │
│  └────────────────────────────────┘                          │
│         │                                                     │
│         ▼                                                     │
│  ┌─────────────┐         ┌─────────────┐                     │
│  │ Egress Proxy│────────▶│ Mock API    │                     │
│  │ 0.0.0.0:9999│  TLS    │ 127.0.0.1   │                     │
│  │ MITM + key  │  inject │ :9443 HTTPS │                     │
│  └─────────────┘         └─────────────┘                     │
└──────────────────────────────────────────────────────────────┘
```

## Source layout

```
src/
├── main.rs          — orchestrator: CA gen, rootfs build, proxy, TAP, nftables, VM launch
├── certs.rs         — CA + leaf cert generation (from ae-egress-proxy)
├── proxy.rs         — MITM TLS proxy, CONNECT handler, key injection (from ae-egress-proxy)
├── stream.rs        — Bidirectional byte copy with flush (from ae-egress-proxy)
└── mock_server.py   — Mock HTTPS API server (simulates LLM API)
build-rootfs.sh      — Builds Alpine rootfs with CA cert + curl + test script
```

## Related

- [Agent Environment Design](../agent-environment/Agent%20Environment%20Design.md) — the design doc
- [ae-egress-proxy](https://github.com/mintybasil/ae-egress-proxy) — Spike 1: egress proxy PoC
- [ae-fc-poc](https://github.com/mintybasil/ae-fc-poc) — Spike 2: Firecracker + nftables PoC

## License

MIT