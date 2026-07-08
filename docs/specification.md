# Agent Environment Specification

## Guiding Principles

These are high-level principles that apply universally to all components.

1. **Do one thing, and do it well.**
   Every component should focus on a single task. Monoliths are harder to maintain and keep secure; smaller composable components are more likely to be correct, auditable, and replaceable.

2. **Re-use > re-implement.**
   Use existing components whenever possible. Avoid implementing things that could be imported or adapted from existing sources. Every line of code is a liability — the less code we write and maintain, the better.

3. **Build for users, even when there are none.**
   Good software requires more than just good code. Even when building internal tools or libraries, interfaces must be thoughtfully designed, documented, and tested.

4. **Compute what you can, reason when you must.**
   Any problem that can be solved programmatically should be. Leveraging LLM reasoning should be done sparingly, and only when absolutely necessary.

---

## Overview

The Agent Environment system deploys, manages, and interacts with secure ephemeral environments for AI agents to operate in. Agents run inside Firecracker MicroVMs with no real credentials — all API keys are injected by a host-side MITM egress proxy that intercepts outbound traffic.

```
 ┌──────────────────────────────────────────────────────────┐
 │                        Host                               │
 │                                                          │
 │  ┌─────────────┐         ┌──────────────┐               │
 │  │  VM Manager │  launch │  Agent       │               │
 │  │  (Firecracker│────────▶│  Harness     │               │
 │  │   /fctools) │         │  (Pi)        │               │
 │  └─────────────┘         └──────┬───────┘               │
 │         │                       │                        │
 │         │  ① register session   │ outbound traffic       │
 │         │──────────────────▶    ▼                        │
 │         │              ┌──────────────────┐               │
 │         │              │  Egress Proxy    │               │
 │         │              │  + Key Injection │──────▶ Internet
 │         │              └──────────────────┘    (allowlisted
 │         │                       │                domains only) │
 │  ┌──────┴──────────────────────┴──────────────────────┐  │
 │  │  nftables: DNAT all VM egress → proxy            │  │
 │  │  (to TAP IP, src IP preserved → proxy maps IP→session)│  │
 │  └───────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Sandboxed Environment (MicroVM)

Ephemeral environments for agents, created and destroyed programmatically. Each environment contains all the tools an agent may need.

**Backend:** [Firecracker](https://github.com/firecracker-microvm/firecracker) — purpose-built for lightweight, fast-booting, secure sandbox VMs.

**Orchestration:** [fctools](https://github.com/rust-firecracker/fctools) — Rust SDK for Firecracker VM lifecycle. fctools 0.7.x requires Firecracker 1.14+ and Rust 1.88+.

**Kernel:** Firecracker CI 5.10 kernel (or newer). The 4.14 hello-vmlinux kernel has a virtio-net bug that prevents TLS data from flowing through the TAP interface. Download:
```bash
curl -sL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260107-89702a77e4c2-0/x86_64/vmlinux-5.10.245" -o vmlinux-5.10.bin
```

**Capabilities:**
- User-provided image support (custom rootfs images for different agent toolsets)
- File injection at launch time (via fctools `ResourceSystem`)
- Network access controls (restricting what the VM can talk to)
- API for programmatic launch/destroy by other services

**Image format:** Firecracker raw rootfs ext4 images. [Kata Containers](https://katacontainers.io/) was evaluated for OCI image support but rejected — it primarily targets Kubernetes deployments, and at our small deployment scale the additional layer isn't justified.

**File injection:** Init-time injection via fctools `ResourceSystem` with `ResourceType::Moved(MovedResourceType::Copied)`. Files (scripts, data, config) are provided at VM launch and injected into the guest filesystem. No virtio-vsock or ongoing host↔guest channel is needed for the base case.

**VM serial output:** fctools' `vm.take_pipes()` provides access to the Firecracker process's stdout/stderr (serial console output). This enables real-time boot message capture and agent output observation.

**Agent chaining:** How to pass the output of one agent to the next is a deployment detail, not an architectural one. Options include an ephemeral artifact store, chained VM launch with scoped extraction, or shared block device snapshots. Deferred until a limitation is reached in practice.

### 2. Agent Harness

A minimal, customizable agent harness that adapts to different use cases while minimizing security vulnerabilities.

**Choice:** [Pi](https://pi.dev/) — widely used, highly customizable, and lightweight. Pi provides cost/token tracking for model API calls natively, so per-session API cost attribution is handled at the harness layer.

**Proxy configuration:** Pi uses HTTP client libraries that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables. No explicit Pi proxy config needed — the image builder writes proxy env vars to `/etc/profile.d/proxy.sh`, sourced by all shells.

### 3. Egress Proxy & Secret Injection

#### Problem

Agents inside the sandbox need to call external APIs (LLM providers, search, etc.) that require real authentication tokens. Real API tokens must never be placed inside the VM — the VM is the least trusted component in the system. The VM's outbound traffic must also be restricted to explicitly approved domains.

#### Requirements

- **No real secrets in the VM.** The VM image, filesystem, and runtime environment must never contain production API keys. A compromised VM yields zero usable credentials.
- **Domain allowlisting.** Only explicitly approved domains are reachable. Everything else is dropped.
- **Transparent key injection.** The agent harness should not know about the injection mechanism — it should "just work" with placeholder or no credentials.
- **Per-VM scoping.** Each VM session gets a scoped set of credentials. When the VM is destroyed, its credential mapping is destroyed too.
- **Auditability.** All outbound requests are logged (destination, timing, success/failure) for post-hoc analysis.
- **Streaming support.** The proxy handles SSE and WebSocket connections.
- **No response caching.** Correctness over performance. Caching is a future optimization.

#### Design: MITM Forward Proxy

A forward proxy runs on the host (outside the VM). All VM outbound traffic is forced through it via nftables DNAT rules — the VM cannot bypass it.

- For **allowlisted API domains** (`mode: mitm`): the proxy terminates TLS, strips any placeholder token the agent sent, injects the real API key, and re-establishes TLS upstream.
- For **other allowlisted domains** (`mode: tunnel`): the proxy does a transparent CONNECT tunnel with no interception.
- For **non-allowlisted domains**: the proxy drops the request with `403 Forbidden`.

The VM image ships with a custom CA certificate that trusts the proxy for the specific API domains only. This is acceptable because we control the VM image.

#### Implementation: Custom Rust Proxy

**Building blocks:**
- `hyper` 1.x — HTTP server/client. CONNECT handled natively via `serve_connection` + `with_upgrades()`.
- `tokio` — async runtime.
- `rustls` 0.23 — TLS termination and upstream connections. Upstream verification is strict by default (the proxy is the only party that sees plaintext, but upstream connections must still be authenticated).
- `rcgen` 0.14 — on-the-fly certificate generation for MITM.
- `hyper_util::rt::TokioIo` — bridges hyper 1.x `Upgraded` I/O traits to tokio's `AsyncRead`/`AsyncWrite`.
- `rusqlite` — session persistence (SQLite).
- `vaultrs` — HashiCorp Vault client for credential storage.

**Rationale:** Go was considered (slightly more ready-made MITM proxy libraries like `elazarl/goproxy`), but the re-use advantage is narrow — MITM forward proxying requires assembling from primitives in either language. Rust is preferred because Firecracker and fctools are both Rust (single toolchain, shared types), and memory safety is critical in a path that processes untrusted traffic and handles API keys.

**Streaming:** SSE streaming uses a `tokio::select!` loop that reads from the upstream TLS stream and writes to the client TLS stream, calling `flush()` after every successful read. This ensures each SSE chunk is forwarded immediately without being buffered by the TLS layer, kernel TCP socket, or any intermediate HTTP framing.

**Cert generation:** CA created with `rcgen` using `is_ca = IsCa::Ca(BasicConstraints::Unconstrained)`. Leaf certs are signed via `signed_by()` and registered in a `ResolvesServerCertUsingSni` at startup. Multi-domain support works by calling `resolver.add()` per domain.

**HTTP parsing:** Production should use the `httparse` crate instead of manual byte-by-byte parsing for correctness with pipelined requests, malformed headers, and arbitrary body encodings.

**TLS 1.3:** Works transparently — no special handling needed for 0-RTT, session tickets, or post-handshake authentication. rustls prefers TLS 1.3 by default.

#### Session Management

**Registration:** The proxy exposes a REST API (`POST /sessions`, `DELETE /sessions/{id}`). At VM launch, the VM Manager registers a session with: session ID, VM source IP, allowlisted domains, and credential references (keys stored in the secret store, not passed inline). See [API Contracts](api-contracts.md).

**Identification:** nftables DNAT rules preserve the original source IP of the VM's traffic. Each VM gets its own TAP interface with a unique IP. The proxy looks up `source IP → session` on every incoming request — a simple in-memory map, no harness cooperation needed, no custom headers, fully transparent.

**Persistence:** Session state is persisted to a local SQLite database. On restart, sessions are recovered from disk. No external service dependency.

#### Network Enforcement

Three critical nftables implementation details:

1. **Use `dnat to <tap_ip>:<port>`, not `redirect` or `dnat to 127.0.0.1`.** The `redirect` target requires an explicit transport protocol match. DNAT to `127.0.0.1` doesn't work because Linux doesn't route `127.0.0.0/8` from non-loopback interfaces (`route_localnet=0` by default). DNAT to the TAP interface's own IP works without extra sysctl configuration.
2. **Bind the proxy on `0.0.0.0` or the TAP IP** — not `127.0.0.1`. DNAT'd traffic arrives on the TAP interface and won't reach a loopback-bound listener.
3. **Disable `rp_filter` on TAP interfaces** (`net.ipv4.conf.tap0.rp_filter=0`) — required for DNAT'd return traffic to pass kernel validation.

**No masquerade/SNAT:** The postrouting chain is intentionally empty. This preserves the VM's original source IP. Adding a masquerade rule would break the session identification model.

#### Secret Storage

[HashiCorp Vault](https://www.vaultproject.io/) for credential storage on the host. The proxy fetches keys at session registration time and holds them in memory only. Keys are never written to disk on the host in plaintext. On proxy restart, sessions are recovered from SQLite but keys must be re-fetched from Vault.

#### Out of Scope

- **Rate-limiting per VM session** — deferred. Pi's cost/token tracking provides visibility in the interim.
- **Response caching** — future optimization, not a current requirement.

---

## Image Building

Rootfs images are built with `build-image.sh` — a standalone script that produces Firecracker ext4 rootfs images. See the [Image Builder](../images/EXAMPLES.md) examples.

Each image contains:
- Alpine Linux 3.20 base
- curl + ca-certificates
- Proxy CA certificate in the system trust store (`/usr/local/share/ca-certificates/ae-proxy-ca.crt` + appended to `/etc/ssl/certs/ca-certificates.crt`)
- Proxy env vars in `/etc/profile.d/proxy.sh` (`http_proxy`/`https_proxy`/`no_proxy`)
- Serial console on ttyS0
- Network config via kernel boot args or DHCP fallback
- Agent init script at `/etc/init.d/agent-init` (customizable)

Optional:
- Node.js + npm + Pi agent harness (`--with-pi`)
- Extra Alpine packages (`--packages`)
- Pi packages (`--pi-packages`)

---

## Observability

All components emit metrics and logs. Target stack: **Grafana + Prometheus**.

- **VM Manager:** VM count, uptime, launch/destroy latency, error rates.
- **Agent Harness (Pi):** Agent activity metrics, cost/token tracking (provided natively by Pi).
- **Egress Proxy:** Request count by domain, request latency, injection success/failure, dropped requests, active session count.

Structured logging (JSON) is preferred for machine consumption.

---

## Multi-Tenant Isolation

**Policy: deny-by-default.** VMs cannot communicate with each other. Each VM's egress is restricted to the proxy only (via nftables), and the proxy only forwards to allowlisted external domains. There is no VM-to-VM path.

---

## Open Questions

1. **Agent chaining:** How to pass output from one agent to the next without extracting to the host. Deferred — no architectural changes needed for any of the candidate approaches.
2. **Authentication on the VM Manager API:** Host-local, so auth may be unnecessary (filesystem permissions on unix socket). If network exposure is needed, bearer token or mTLS.
3. **Proxy restart strategy for keys:** Re-fetch from Vault (simpler, adds startup dependency) vs. encrypted-at-rest with SQLCipher (no Vault dependency, adds key management burden). Re-fetch recommended initially.