# AGENTS.md — Agent Environment (ae-poc)

## Project Overview

This repo contains the Agent Environment system: secure, ephemeral Firecracker
MicroVM sandboxes for AI agents, with a MITM egress proxy for API key injection
and domain allowlisting.

**Design doc:** `../ob-vault-agents/agent-environment/Agent Environment Design.md`
**API contracts:** `../ob-vault-agents/agent-environment/API Contracts.md`

## Architecture

```
Orchestrator → VM Manager → (fctools → Firecracker VM)
                ↓
            Egress Proxy (MITM TLS + key injection)
                ↓
            Upstream APIs (allowlisted domains only)
```

Two core components plus a shared infrastructure layer:

1. **VM Manager** — launches/destroys Firecracker VMs, manages TAP interfaces
   and nftables rules, registers proxy sessions.
2. **Egress Proxy** — MITM TLS proxy on the host. Intercepts VM outbound traffic,
   injects API keys, enforces domain allowlisting.
3. **Image Builder** (`build-image.sh`) — builds Alpine rootfs images with Pi,
   curl, CA certs, and proxy configuration baked in.

## Key Design Decisions

- **Rust** for both VM Manager and Egress Proxy (single toolchain, memory safety).
- **Alpine Linux 3.20** rootfs base (proven in Spikes 2 & 3).
- **Firecracker CI 5.10 kernel** required (4.14 has a virtio-net TLS bug).
- **nftables DNAT** (not `redirect`) to TAP IP, with `rp_filter` disabled.
- **Source IP** is the session identifier — no custom headers or protocols.
- **Proxy CA** baked into rootfs trust store at build time.
- **Pi** configured via `HTTP_PROXY`/`HTTPS_PROXY` env vars — no explicit proxy config needed.

## Repo Layout

```
src/
├── main.rs          — integration PoC orchestrator
├── certs.rs         — CA + leaf cert generation (rcgen/rustls)
├── proxy.rs         — MITM TLS proxy (hyper CONNECT upgrade) + REST session API
├── session.rs       — Session store: SQLite persistence + in-memory stats
├── stream.rs        — Bidirectional byte copy with per-chunk flush
├── vault.rs         — SecretStore trait + MockSecretStore for credential fetching
└── mock_server.py   — Mock HTTPS API for testing
build-image.sh       — Reusable rootfs image builder
build-rootfs.sh      — PoC-specific rootfs builder (deprecated)
images/              — Image builder examples and templates
```

## Build & Run

```bash
# Build the Rust binary
cargo build --release

# Build a rootfs image
./build-image.sh --ca-cert proxy-ca.pem --with-pi --size 500M images/pi-agent.ext4

# Run the integration test (needs KVM, sudo, nftables)
sudo ./target/release/ae-poc
```

## Testing

- **Unit tests:** `cargo test` — proxy allowlist, header rewrite, cert chain.
- **Integration test:** `sudo ./target/release/ae-poc` — boots a real Firecracker
  VM, runs curl through the proxy, verifies key injection and SSE streaming.
- **Image build test:** `./build-image.sh --ca-cert proxy-ca.pem --size 200M /tmp/test.ext4`

## Coding Conventions

- Rust edition 2024.
- Error handling: `anyhow::Result` for application code, `thiserror` for library errors.
- Async: `tokio` runtime throughout.
- Logging: `eprintln!("[proxy] ...")` in the PoC; switch to `tracing` in production.
- Shell scripts: `set -e`, `shellcheck` clean, no `bash`-isms in init scripts (Alpine uses busybox `ash`).

## Component Status

| Component | Status |
|---|---|
| Egress proxy (MITM + key injection) | PoC proven (Spike 1 + 3) |
| Firecracker VM launch + nftables | PoC proven (Spike 2 + 3) |
| Integration (full chain) | ✅ All 10 verifications pass |
| Image builder | ✅ Working (minimal + Pi images) |
| API contracts | ✅ Defined |
| Session management REST API | ✅ Implemented (POST/GET/DELETE /sessions, GET /health) |
| Credential fetching (SecretStore) | ✅ Trait + mock; Vault impl pending |
| Proxy productionization | 📋 Issues created |
| VM Manager productionization | 📋 Issues created |