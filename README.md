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
├── proxy.rs         — MITM TLS proxy, CONNECT handler, key injection, REST session API
├── session.rs       — Session store: SQLite persistence + in-memory stats
├── stream.rs        — Bidirectional byte copy with flush (from ae-egress-proxy)
├── vault.rs         — SecretStore trait + MockSecretStore for credential fetching
└── mock_server.py   — Mock HTTPS API server (simulates LLM API)
build-rootfs.sh      — Builds Alpine rootfs for integration test (PoC-specific)
build-image.sh       — Reusable image builder (step #3: image building pipeline)
images/
├── EXAMPLES.md          — Image build command examples
└── agent-init-template.sh — Custom agent init script template
```

## Proxy REST API

The proxy exposes a REST API for session management on the same port as the CONNECT proxy (port 9999). HTTP method inspection distinguishes: `POST`/`DELETE`/`GET` → session management; `CONNECT` → proxy traffic.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/sessions` | Register a session (source_ip, allowlist, credential_refs) |
| `GET` | `/sessions/{id}` | Get session details + request stats |
| `DELETE` | `/sessions/{id}` | Delete session (drops in-memory credentials) |
| `GET` | `/sessions` | List all sessions |
| `GET` | `/health` | Health check (includes CA cert SHA-256 fingerprint) |

### Examples

```bash
# Register a session
curl -X POST http://localhost:9999/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "sess_abc12345",
    "source_ip": "10.0.1.42",
    "allowlist": [
      {"domain": "api.openai.com", "mode": "mitm", "credential_ref": "vault://secret/data/agent-env/openai-key"},
      {"domain": "dl-cdn.alpinelinux.org", "mode": "tunnel"}
    ]
  }'

# Get session details (includes request stats)
curl http://localhost:9999/sessions/sess_abc12345

# List all sessions
curl http://localhost:9999/sessions

# Delete a session
curl -X DELETE http://localhost:9999/sessions/sess_abc12345

# Health check (includes CA fingerprint for rootfs verification)
curl http://localhost:9999/health
```

All errors use a standard envelope:
```json
{"error": {"code": "ERROR_CODE", "message": "Human-readable summary", "detail": "optional technical detail"}}
```

## Image Builder

`build-image.sh` is a standalone, reusable script for building Firecracker rootfs images. It generalizes the PoC's `build-rootfs.sh` into a production image builder.

### Quick start

```bash
# Generate a proxy CA cert first (or use one from the running proxy)
# The ae-poc binary writes one to proxy-ca.pem on startup

# Build a minimal image (curl + CA cert only)
./build-image.sh --ca-cert proxy-ca.pem --size 200M images/minimal.ext4

# Build a Pi agent image (Node.js + Pi + CA cert + proxy config)
./build-image.sh --ca-cert proxy-ca.pem --with-pi --size 500M images/pi-agent.ext4

# Build with extra tools
./build-image.sh --ca-cert proxy-ca.pem --with-pi \
    --packages "git,jq,python3" --size 800M images/pi-dev.ext4
```

### What it installs

| Component | Always | Optional | Location in rootfs |
|---|---|---|---|
| Alpine Linux 3.20 base | ✅ | | `/` |
| curl + ca-certificates | ✅ | | `/usr/bin/curl` |
| Proxy CA cert | ✅ | | `/usr/local/share/ca-certificates/ae-proxy-ca.crt` + `/etc/ssl/certs/ca-certificates.crt` |
| Proxy env vars | ✅ | `--no-proxy` | `/etc/profile.d/proxy.sh` |
| Serial console (ttyS0) | ✅ | | `/etc/inittab` |
| Network config (eth0) | ✅ | | `/etc/init.d/network-config` |
| Agent init script | ✅ | | `/etc/init.d/agent-init` |
| Node.js + npm | | `--with-pi` | `/usr/bin/node`, `/usr/bin/npm` |
| Pi agent harness | | `--with-pi` | `/usr/bin/pi` (via `npm install -g`) |
| Pi packages | | `--pi-packages` | `~/.pi/agent/` |
| Extra Alpine packages | | `--packages` | varies |

### Proxy configuration

The builder writes proxy environment variables to `/etc/profile.d/proxy.sh`:

```sh
export http_proxy="http://10.0.0.1:9999"
export https_proxy="http://10.0.0.1:9999"
export HTTP_PROXY="http://10.0.0.1:9999"
export HTTPS_PROXY="http://10.0.0.1:9999"
export no_proxy="localhost,127.0.0.1"
export NO_PROXY="localhost,127.0.0.1"
```

Pi and curl respect these environment variables. When Pi makes an API call to `api.openai.com`, curl uses the proxy via CONNECT. The proxy MITMs TLS, strips the placeholder key, injects the real key, and forwards upstream. Pi doesn't need to know about the injection mechanism.

### Custom agent init

The default `/etc/init.d/agent-init` prints a "ready" message and starts Pi if installed. For custom agent workflows, inject a custom init script at VM launch time via fctools `ResourceSystem` (replacing `/etc/init.d/agent-init`). See [`images/agent-init-template.sh`](images/agent-init-template.sh) for a template.

### Build examples

See [`images/EXAMPLES.md`](images/EXAMPLES.md) for 6 example build commands covering minimal, Pi, dev tools, custom proxy, and no-proxy scenarios.

## Related

- [Agent Environment Design](../agent-environment/Agent%20Environment%20Design.md) — the design doc
- [ae-egress-proxy](https://github.com/mintybasil/ae-egress-proxy) — Spike 1: egress proxy PoC
- [ae-fc-poc](https://github.com/mintybasil/ae-fc-poc) — Spike 2: Firecracker + nftables PoC

## License

MIT