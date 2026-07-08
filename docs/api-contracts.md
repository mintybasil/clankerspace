# API Contracts

Concrete API definitions for the Agent Environment system. These contracts define the boundaries between components, enabling parallel implementation.

**Related:** [Specification](specification.md)

---

## System Boundaries

```
                          ┌─────────────────┐
                    caller │  Orchestrator    │
                          │  (user/system)   │
                          └────────┬────────┘
                                   │
                          ┌────────▼────────┐
                          │  VM Manager     │  ← API 1: VM lifecycle
                          └───┬─────────┬───┘
                              │         │
              API 2: Session  │         │ fctools
              registration    │         │ (launch VM)
                    ┌─────────▼───┐     │
                    │ Egress Proxy│     │
                    │ + Key Inject│     │
                    └─────────────┘     │
                                        │
                    ┌───────────────────▼──────┐
                    │  Firecracker MicroVM      │
                    │  (nftables → proxy)       │
                    └──────────────────────────┘
```

Two service boundaries:

1. **VM Manager API** (API 1) — called by an orchestrator or user to launch, inspect, and destroy agent environments.
2. **Egress Proxy Session API** (API 2) — called by the VM Manager to register and tear down proxy sessions scoped per VM.

---

## API 1: VM Manager

The VM Manager is the system's entry point. It owns the Firecracker VM lifecycle, TAP interface management, nftables rule installation, and proxy session registration.

**Transport:** HTTP/1.1 over a unix socket or local TCP port. Not exposed to the network — this is a host-local control plane.

**Base URL:** `http://127.0.0.1:8080` (or `unix:///run/ae-vm-manager.sock`)

### `POST /v1/environments`

Launch a new agent environment. This is the primary entry point.

**Request:**

```json
{
  "session_id": "sess_8f7a3b2c",
  "image": "alpine-3.20-pi",
  "vcpus": 1,
  "memory_mib": 512,
  "files": [
    {
      "guest_path": "/home/agent/task.md",
      "source": "inline",
      "content": "Fix the failing tests in src/auth.rs"
    },
    {
      "guest_path": "/home/agent/repo",
      "source": "git",
      "url": "https://github.com/mintybasil/example-repo",
      "ref": "main"
    }
  ],
  "egress": {
    "allowlist": [
      {
        "domain": "api.openai.com",
        "inject_key": true,
        "credential_ref": "vault://secret/data/agent-env/openai-key"
      },
      {
        "domain": "dl-cdn.alpinelinux.org",
        "inject_key": false
      }
    ]
  },
  "timeout_secs": 3600
}
```

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | yes | Unique session identifier. Used as the VM's label and the proxy session key. Must match `^[a-z0-9_]{8,64}$`. |
| `image` | string | yes | Rootfs image name. The VM Manager resolves this to a rootfs path on the host. |
| `vcpus` | u32 | no (default 1) | Number of vCPUs for the Firecracker VM. |
| `memory_mib` | u32 | no (default 512) | VM memory in MiB. |
| `files` | array | no | Files to inject at launch time via fctools `ResourceSystem`. |
| `files[].guest_path` | string | yes | Absolute path inside the VM where the file/directory will be placed. |
| `files[].source` | enum | yes | `inline`, `git`, or `path` (host path, copied into VM). |
| `files[].content` | string | if source=inline | File content (UTF-8 text). |
| `files[].url` | string | if source=git | Git URL to clone. |
| `files[].ref` | string | if source=git | Git ref (branch, tag, or commit SHA). |
| `files[].path` | string | if source=path | Host filesystem path to copy from. |
| `egress` | object | yes | Egress configuration for this session. |
| `egress.allowlist` | array | yes | List of allowed domains. All other domains are blocked. |
| `egress.allowlist[].domain` | string | yes | Domain name (e.g., `api.openai.com`). |
| `egress.allowlist[].inject_key` | bool | no (default false) | If true, the proxy MITMs TLS and injects the API key from `credential_ref`. If false, the proxy transparently tunnels (CONNECT) without interception. |
| `egress.allowlist[].credential_ref` | string | if inject_key=true | Reference to the secret in the secret store (e.g., `vault://secret/data/agent-env/openai-key`). The proxy fetches the key at session registration time. Keys are never passed inline through this API. |
| `timeout_secs` | u32 | no (default 3600) | Maximum VM runtime. The VM Manager auto-destroys the environment after this duration. |

**Response:** `201 Created`

```json
{
  "session_id": "sess_8f7a3b2c",
  "status": "running",
  "vm_ip": "10.0.1.42",
  "tap_interface": "tap-sess-8f7a",
  "proxy_session": {
    "id": "sess_8f7a3b2c",
    "proxy_url": "http://10.0.1.1:9999"
  },
  "serial_output_url": "/v1/environments/sess_8f7a3b2c/serial",
  "started_at": "2026-07-07T22:37:06Z",
  "expires_at": "2026-07-07T23:37:06Z"
}
```

**Error responses:**

| Status | Code | Description |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed request body, missing required fields, invalid session_id format. |
| 404 | `IMAGE_NOT_FOUND` | The specified image does not exist on the host. |
| 409 | `SESSION_EXISTS` | A session with this ID is already running. |
| 422 | `CREDENTIAL_REF_INVALID` | The credential reference could not be resolved in the secret store. |
| 500 | `VM_LAUNCH_FAILED` | Firecracker failed to launch the VM (see error detail). |

**Example error:**

```json
{
  "error": {
    "code": "VM_LAUNCH_FAILED",
    "message": "Firecracker process exited with code 1",
    "detail": "VFS: Cannot open root device \"vda\" or unknown-block(0,0): error -6"
  }
}
```

### `GET /v1/environments/{session_id}`

Get the status of an environment.

**Response:** `200 OK`

```json
{
  "session_id": "sess_8f7a3b2c",
  "status": "running",
  "vm_ip": "10.0.1.42",
  "tap_interface": "tap-sess-8f7a",
  "proxy_session_id": "sess_8f7a3b2c",
  "started_at": "2026-07-07T22:37:06Z",
  "expires_at": "2026-07-07T23:37:06Z",
  "uptime_secs": 142
}
```

**Status enum:** `running`, `shutting_down`, `exited`, `failed`

### `GET /v1/environments/{session_id}/serial`

Stream the VM's serial console output. This is a server-sent events (SSE) stream that carries the raw serial output as it arrives from fctools' `vm.take_pipes()`.

**Response:** `200 OK` (Content-Type: `text/event-stream`)

```
data: [    0.000000] Linux version 5.10.245+ ...

data: ae-poc Integration Test

data: TEST 1 PASS: Received valid JSON response

data: [DONE]
```

When the VM exits, the stream sends a final `data: [DONE]` event and closes.

### `DELETE /v1/environments/{session_id}`

Destroy an environment. Tears down the VM, removes the TAP interface, removes nftables rules, and deletes the proxy session.

**Query parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `force` | bool | false | If true, kill the Firecracker process immediately (no graceful shutdown). |

**Response:** `202 Accepted`

```json
{
  "session_id": "sess_8f7a3b2c",
  "status": "shutting_down"
}
```

The VM Manager sends CtrlAltDel first (graceful, 5s timeout), then Kill. After teardown completes, a `GET` on the same session returns `status: "exited"` until the session record is garbage-collected.

### `GET /v1/environments`

List all active environments.

**Response:** `200 OK`

```json
{
  "environments": [
    {
      "session_id": "sess_8f7a3b2c",
      "status": "running",
      "vm_ip": "10.0.1.42",
      "started_at": "2026-07-07T22:37:06Z",
      "uptime_secs": 142
    }
  ]
}
```

---

## API 2: Egress Proxy Session Management

The proxy exposes a small REST API for session lifecycle, on the same port as the CONNECT proxy (port 9999). HTTP method inspection distinguishes: `POST`/`DELETE`/`GET` → session management; `CONNECT` → proxy traffic.

**Base URL:** `http://10.0.1.1:9999` (the TAP interface IP, reachable from the VM Manager on the host)

### `POST /sessions`

Register a new session. Called by the VM Manager at launch time, **before** the VM starts booting (so the proxy is ready when the VM's first request arrives).

**Request:**

```json
{
  "session_id": "sess_8f7a3b2c",
  "source_ip": "10.0.1.42",
  "allowlist": [
    {
      "domain": "api.openai.com",
      "mode": "mitm",
      "credential_ref": "vault://secret/data/agent-env/openai-key"
    },
    {
      "domain": "dl-cdn.alpinelinux.org",
      "mode": "tunnel"
    }
  ],
  "expires_at": "2026-07-07T23:37:06Z"
}
```

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | yes | Unique session identifier. Must match the VM Manager's session ID. |
| `source_ip` | string | yes | The VM's IP on its TAP interface. The proxy uses this to identify which session an incoming CONNECT belongs to. |
| `allowlist` | array | yes | Allowed domains for this session. All other domains are rejected with 403. |
| `allowlist[].domain` | string | yes | Domain name (e.g., `api.openai.com`). |
| `allowlist[].mode` | enum | yes | `mitm` — proxy terminates TLS, injects key, re-establishes TLS upstream. `tunnel` — proxy transparently tunnels without interception (for package mirrors, etc.). |
| `allowlist[].credential_ref` | string | if mode=mitm | Reference to the secret in the secret store. The proxy fetches the actual key at registration time and holds it in memory only. |
| `expires_at` | string | no | ISO 8601 timestamp. If set, the proxy auto-deletes the session after this time. |

**Response:** `201 Created`

```json
{
  "session_id": "sess_8f7a3b2c",
  "source_ip": "10.0.1.42",
  "allowlist": [
    { "domain": "api.openai.com", "mode": "mitm" },
    { "domain": "dl-cdn.alpinelinux.org", "mode": "tunnel" }
  ],
  "created_at": "2026-07-07T22:37:06Z",
  "expires_at": "2026-07-07T23:37:06Z"
}
```

**Error responses:**

| Status | Code | Description |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed body, missing required fields. |
| 409 | `SESSION_EXISTS` | A session with this ID already exists. |
| 422 | `CREDENTIAL_REF_INVALID` | The credential reference could not be resolved. The proxy returns the Vault error in the detail field. |

### `GET /sessions/{session_id}`

Get session details.

**Response:** `200 OK`

```json
{
  "session_id": "sess_8f7a3b2c",
  "source_ip": "10.0.1.42",
  "allowlist": [
    { "domain": "api.openai.com", "mode": "mitm" },
    { "domain": "dl-cdn.alpinelinux.org", "mode": "tunnel" }
  ],
  "created_at": "2026-07-07T22:37:06Z",
  "expires_at": "2026-07-07T23:37:06Z",
  "stats": {
    "requests_total": 47,
    "requests_mitm": 12,
    "requests_tunnel": 35,
    "requests_dropped": 2,
    "bytes_upstream": 24832,
    "bytes_downstream": 145920
  }
}
```

**Error responses:**

| Status | Code | Description |
|---|---|---|
| 404 | `SESSION_NOT_FOUND` | No session with this ID. |

### `DELETE /sessions/{session_id}`

Delete a session. The proxy removes the session from its in-memory map and SQLite store. The credential held in memory for this session is dropped.

**Response:** `204 No Content`

**Error responses:**

| Status | Code | Description |
|---|---|---|
| 404 | `SESSION_NOT_FOUND` | No session with this ID. |

### `GET /sessions`

List all active sessions.

**Response:** `200 OK`

```json
{
  "sessions": [
    {
      "session_id": "sess_8f7a3b2c",
      "source_ip": "10.0.1.42",
      "created_at": "2026-07-07T22:37:06Z",
      "expires_at": "2026-07-07T23:37:06Z"
    }
  ]
}
```

### `GET /health`

Health check. Used by the VM Manager to verify the proxy is ready before launching VMs.

**Response:** `200 OK`

```json
{
  "status": "ok",
  "ca_cert_sha256": "bf:e1:8c:3a:a6:4a:59:1c:d2:82:ac:a9:4e:61:f8:1a:a8:11:54:bf",
  "active_sessions": 1,
  "uptime_secs": 842
}
```

The `ca_cert_sha256` field lets the VM Manager verify that the proxy's CA cert matches the one baked into the rootfs before launching a VM.

---

## Proxy CONNECT Protocol

Not a REST endpoint — this is protocol behavior when the proxy receives a `CONNECT host:port` request:

1. **Source IP → session lookup:** If the source IP matches a registered session, proceed. If not, return `403 Forbidden`.
2. **Domain allowlist check:** If the target domain is in the session's allowlist, proceed. If not, return `403 Forbidden`.
3. **Mode dispatch:**
   - `mitm` mode: Send `200 OK`, upgrade to TLS (MITM with CA), read inner HTTP request, strip `Authorization` header, inject the session's API key, connect upstream with TLS, forward, and stream response back.
   - `tunnel` mode: Send `200 OK`, connect upstream (raw TCP, no TLS termination), and bidirectionally copy bytes. No header inspection or modification.

---

## Sequence: Launch Flow

The ordering of API calls during a VM launch:

```
Orchestrator                VM Manager                Egress Proxy
     │                          │                          │
     │── POST /v1/environments ─▶                          │
     │                          │                          │
     │                          │  Create TAP interface    │
     │                          │  Set up nftables DNAT    │
     │                          │                          │
     │                          │── POST /sessions ────────▶
     │                          │   (source_ip, allowlist, │
     │                          │    credential_refs)      │
     │                          │◀──── 201 Created ────────│
     │                          │   (proxy ready)          │
     │                          │                          │
     │                          │  Launch Firecracker VM   │
     │                          │  (fctools, rootfs+CA)    │
     │                          │                          │
     │◀── 201 Created ──────────│                          │
     │   (vm_ip, status=running)│                         │
     │                          │                          │
```

**Critical ordering:** The proxy session is registered **before** the VM starts booting. This ensures the proxy is ready to handle the VM's first outbound request. If the VM boots before the session is registered, the proxy returns `403` for all traffic (deny-by-default).

---

## Sequence: Teardown Flow

```
Orchestrator                VM Manager                Egress Proxy
     │                          │                          │
     │── DELETE /v1/envs/{id} ──▶                          │
     │                          │                          │
     │                          │  Send CtrlAltDel to VM   │
     │                          │  (graceful, 5s timeout) │
     │                          │  Then Kill if needed     │
     │                          │                          │
     │                          │── DELETE /sessions/{id} ─▶
     │                          │   (drop credentials)     │
     │                          │◀──── 204 No Content ─────│
     │                          │                          │
     │                          │  Remove nftables rules   │
     │                          │  Delete TAP interface    │
     │                          │  Cleanup VM resources    │
     │                          │                          │
     │◀── 202 Accepted ─────────│                          │
     │   (status=shutting_down) │                          │
```

**Critical ordering:** The proxy session is deleted **before** nftables rules are removed. This ensures that if the VM makes any final network requests during shutdown, they are still handled by the proxy (or dropped if the session is gone). After nftables rules are removed, the VM's TAP interface is deleted and no traffic can flow.

---

## Data Model: Session (SQLite Schema)

The proxy persists sessions to SQLite for restart resilience.

```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    source_ip    TEXT NOT NULL UNIQUE,
    allowlist    TEXT NOT NULL,  -- JSON array of {domain, mode, credential_ref}
    created_at   INTEGER NOT NULL,  -- Unix timestamp
    expires_at   INTEGER            -- Unix timestamp, NULL = no expiry
);

CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
```

**Key storage:** API keys are NOT persisted to SQLite. They are held in memory only during the session's lifetime and re-fetched from Vault on proxy restart. Storing plaintext keys in SQLite on disk violates the "no real secrets on the host in plaintext" requirement.

---

## Error Code Conventions

All errors use a consistent envelope:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable summary",
    "detail": "Optional technical detail (stack trace, upstream error, etc.)"
  }
}
```

| Code | HTTP Status | Used by | Description |
|---|---|---|---|
| `INVALID_REQUEST` | 400 | Both | Malformed body, missing required fields. |
| `UNAUTHORIZED` | 401 | Both | Invalid or missing auth token (if auth is enabled on the control plane). |
| `SESSION_NOT_FOUND` | 404 | Both | Session ID does not exist. |
| `SESSION_EXISTS` | 409 | Both | Session ID already in use. |
| `IMAGE_NOT_FOUND` | 404 | VM Manager | Requested rootfs image not found on host. |
| `CREDENTIAL_REF_INVALID` | 422 | Both | Secret store reference could not be resolved. |
| `VM_LAUNCH_FAILED` | 500 | VM Manager | Firecracker failed to launch. |
| `PROXY_UNAVAILABLE` | 502 | VM Manager | Could not register session with proxy (proxy down or unreachable). |
| `INTERNAL_ERROR` | 500 | Both | Unexpected internal error. |

---

## Open Design Decisions

These are deferred and do not block implementation:

1. **Authentication on the VM Manager API:** The control plane is host-local, so auth may be unnecessary (rely on filesystem permissions on the unix socket). If network exposure is needed, a bearer token or mTLS.

2. **Session ID generation:** The orchestrator provides the session ID. Alternatively, the VM Manager could generate it and return it in the response (POST with no session_id → 201 with generated ID). Both approaches work; the current contract requires the caller to provide one.

3. **File injection via `path` source:** The `path` source type copies files from the host filesystem into the VM. This requires careful path validation to prevent the VM Manager from being used to read arbitrary host files (path traversal). The implementation must restrict source paths to an allowlisted directory (e.g., `/var/lib/ae-vm-manager/files/`).

4. **Serial output as SSE vs. WebSocket:** SSE is simpler and sufficient for one-way output. If bidirectional serial interaction is needed (sending input to the VM's console), WebSocket would be required. For now, SSE is sufficient — the VM runs autonomously.

5. **Proxy restart strategy for keys:** If the proxy crashes and restarts, sessions are recovered from SQLite. But keys must be re-fetched from Vault on restart. This adds a startup dependency on Vault availability. Alternatively, keys could be encrypted-at-rest with SQLCipher, removing the Vault dependency at restart but adding a key management burden. The simpler approach (re-fetch from Vault) is recommended initially.