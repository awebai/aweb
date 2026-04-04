# awid / aw Boundary Specification

**Status (2026-03-12):** Foundation for the awid extraction (epic aw-9sf).
Defines which code belongs in awid (protocol client + identity + runtime)
vs aw (coordination application).

---

## 1. Guiding Principle

**awid** is the open-source protocol client and agent runtime.
It owns everything needed for an agent to exist, communicate, and run
without coordination infrastructure.

**aw** is the coordination application. It uses awid as a library and
adds workspace management, task dispatch, project roles, and claims.

The boundary test: "Can an agent that only depends on awid initialize an
identity, send mail, receive chat, run a provider loop, and respond to control
signals?" If yes, the boundary is correct.

---

## 2. Current Client Architecture

Today the codebase has a **single `Client` struct** with a **single
`baseURL`**. Both protocol endpoints (served by atext) and coordination
endpoints (served by aweb-cloud) are called through the same client.

The extraction must decide:

- **Option A:** Two clients — `awid.Client` for protocol, `aw.Client`
  for coordination — each with its own base URL.
- **Option B:** Single gateway URL, with the package split being purely
  about code organization (the server routes internally).

This decision depends on deployment topology and is deferred to
implementation of aw-9sf.2.

---

## 3. File Assignments — Root Package

### Protocol (→ awid)

| File | Domain | Key Endpoints |
|------|--------|---------------|
| `client.go` | HTTP client infrastructure | All — shared transport |
| `sse.go` | SSE stream decoder | — |
| `util.go` | URL escaping, UUID generation | — |
| `alias_prefix.go` | Alias prefix suggestion | `GET /v1/agents/suggest-alias-prefix` |
| `auth.go` | Authentication utilities | `GET /v1/auth/introspect` |
| `init.go` | Workspace identity initialization | `POST /v1/workspaces/init` |
| `create_project.go` | Project creation bootstrap | `POST /api/v1/create-project` |
| `spawn.go` | Spawn invite create/list/revoke/accept | `POST/GET/DELETE /api/v1/spawn/*` |
| `agents.go` | Identity listing/patching | `GET /v1/agents`, `PATCH /v1/agents/{id}` |
| `mail.go` | Local project mail | `POST /v1/messages` |
| `chat.go` | Chat sessions/messages | `GET/POST /v1/chat/*` |
| `network.go` | Network directory | `GET /v1/network/directory` |
| `contacts.go` | Contact management | `GET/POST /v1/contacts` |
| `namespace.go` | Namespace listing | `GET /api/v1/auth/namespaces` |
| `events.go` | SSE event stream | `GET /v1/events/stream` |
| `control.go` | Control signals (send) | `POST /v1/agents/{alias}/control` |
| `agent_log.go` | Agent activity log | `GET /v1/agents/*/log` |
| `network_address.go` | Network address parsing | — |
| `didkey.go` | DID:key computation | — |
| `signing.go` | Message signing | — |
| `verify.go` | Signature verification | — |
| `identity.go` | Identity resolvers | `GET /v1/agents/resolve/{ns}/{alias}` |
| `pinstore.go` | TOFU pin storage | — |
| `deregister.go` | Ephemeral identity delete transport | `DELETE /v1/agents/me`, `DELETE /v1/agents/{ns}/{alias}` |
| `rotate.go` | Key rotation | `PUT /v1/agents/me/rotate` |

### Coordination (→ aw)

| File | Domain | Key Endpoints |
|------|--------|---------------|
| `coordination.go` | Coordination status | `GET /v1/status` |
| `workspaces.go` | Workspace management | `POST /v1/workspaces/register`, `/attach`, `GET /v1/workspaces/team` |
| `project roles transport` | Project roles retrieval | `GET /v1/roles/active` |
| `projects.go` | Project info | `GET /v1/projects/current` |
| `claims.go` | Bead claims | `GET /v1/claims` |
| `tasks.go` | Task CRUD | `GET/POST/PATCH/DELETE /v1/tasks/*` |
| `reservations.go` | Resource locks | `POST /v1/reservations/*` |

### Edge Cases

- **`control.go`** → awid. Sends control signals to `POST /v1/agents/{alias}/control`,
  an atext endpoint. Control is protocol, not coordination.
- **`reservations.go`** → aw. Resource locks are coordination state for workspace
  contention, not protocol operations.
- **`tasks.go`** → aw. Tasks are coordination state (aweb), not protocol.
  The SSE work_available/claim_update/claim_removed events will move from
  the atext event stream to an aweb coordination event surface.

---

## 4. File Assignments — `run/` Package

The entire `run/` package moves to awid. It is the agent runtime.

| File | Purpose |
|------|---------|
| `types.go` | Event, Provider, ControlEvent types |
| `provider.go` | Provider interface |
| `provider_claude.go` | Claude provider adapter |
| `provider_codex.go` | Codex provider adapter |
| `loop.go` | Main run loop |
| `screen.go` | Terminal UI (viewport, input, status) |
| `format.go` | Output formatting |
| `control.go` | Control command parsing (`/` commands) |
| `prompt.go` | Prompt building, input handling |
| `config.go` | User run configuration |
| `init.go` | Config initialization |
| `services.go` | External service supervision |
| `services_proc_unix.go` | Unix process services |
| `services_proc_windows.go` | Windows process services |
| `wake.go` | Wake stream (SSE consumption + retry) |

### Wake Stream Boundary

`wake.go` already defines `AgentEventSource` as an interface, which is
the right shape. The extraction requires:

1. awid's `AgentEvent` types drop work_available, claim_update,
   claim_removed (those are coordination events).
2. awid's `ClientWakeStream` remains the protocol event stream.
3. aw adds a `CoordinationEventSource` that yields work/claim events
   from its own aweb-cloud endpoint.
4. The runtime's `Loop` accepts an `EventSource` interface that the
   coordination layer can compose (merging protocol + coordination streams).

---

## 5. File Assignments — `awconfig/` Package

Mixed — needs splitting.

### Protocol config (→ awid)

- `global_config.go` — Account struct fields: `Server`, `APIKey`, `IdentityID`,
  `IdentityHandle`, `NamespaceSlug`, `DID`, `StableID`, `SigningKey`,
  `Custody`, `Lifetime`, `Email`
- `keys.go` — Keypair generation, storage, loading
- `keys_scan.go` — Key scanning (recovery)
- `selection.go` — Account resolution
- `lock_unix.go`, `lock_windows.go` — Config file locking

### Coordination config (→ aw)

- `workspace.go` — `.aw/workspace.yaml` management
- `context.go` — Worktree context (maps servers → accounts per directory)

### Shared

- `global_config.go` — The `GlobalConfig` and `Server` structs are used by
  both layers. The config file itself (`~/.config/aw/config.yaml`) is shared.
  Design decision: awid owns the config file format; aw reads/writes through
  awid's API.

---

## 6. File Assignments — `cmd/aw/`

All CLI commands stay in aw (the application), but protocol commands
delegate to the awid library.

### Protocol commands (delegate to awid)

| File | Commands |
|------|----------|
| `init.go` | `aw init` |
| `connect.go` | `aw connect` |
| `mail.go` | `aw mail send`, `aw mail inbox` |
| `chat.go` | `aw chat *` |
| `network.go` | `aw directory` |
| `agents.go` | `aw identities`, `aw id access-mode`, `aw id reachability`, `aw id delete` |
| `contacts.go` | `aw contacts` |
| `id_create.go` | `aw id create` |
| `did.go` | `aw id log`, `aw id rotate-key`, `aw id register`, `aw id show`, `aw id resolve`, `aw id verify`, `aw id namespace` |
| `heartbeat.go` | `aw heartbeat` |
| `introspect.go` | `aw whoami` |
| `reset.go` | `aw reset` |
| `upgrade.go` | `aw upgrade` |
| `log.go` | `aw log` |
| `commlog.go` | `aw commlog` |

### Coordination commands (stay in aw)

| File | Commands |
|------|----------|
| `workspace.go` | `aw workspace *` |
| `roles.go` | `aw roles *`, `aw role-name *` |
| `project.go` | `aw project *` |
| `work.go` | `aw work *` |
| `lock.go` | `aw lock *` |

### Integration point

| File | Commands |
|------|----------|
| `run.go` | `aw run` — wires awid runtime + aw dispatch rules |

---

## 7. SSE Event Type Boundary

### Protocol events (awid — from atext)

| Event | Category |
|-------|----------|
| `connected` | Connection |
| `mail_message` | Wake |
| `chat_message` | Wake |
| `control_pause` | Control |
| `control_resume` | Control |
| `control_interrupt` | Control |
| `error` | Diagnostic |

### Coordination events (aw — from aweb-cloud)

| Event | Category |
|-------|----------|
| `work_available` | Wake |
| `claim_update` | Wake |
| `claim_removed` | Wake |

These currently share the `AgentEvent` struct and arrive on the same SSE
stream. The extraction splits them: awid defines protocol events; aw
defines coordination events and provides its own event source.

---

## 8. Identity System

Entirely protocol (→ awid). The identity system is the foundation of
agent authentication and message trust:

- DID:key computation (Ed25519 → multicodec → base58btc)
- Message signing (canonical JSON + Ed25519)
- Signature verification
- TOFU pin storage and checking
- Identity resolvers (DIDKey, Server, Pin, Chain)
- Key rotation announcements
- Identity lifecycle primitives (init, resolve, deregister, rotation, replacement verification)

---

## 9. Constants and Shared Types

Types that both layers need (e.g., `LifetimePersistent`, `CustodySelf`,
`VerificationStatus`) should be defined in awid. The coordination layer
imports them.
