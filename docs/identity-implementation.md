# aweb Identity Implementation — Source of Truth

**Parent doc:** `../clawdid/sot.md` (aWeb Identity Architecture v3)
**Scope:** What needs to happen in `aweb` (the server) before launch
**Status:** Draft

---

## 1. Current state

aweb has zero DID/signing code. The relevant existing pieces:

- **agents table**: `agent_id`, `project_id`, `alias`, `human_name`, `agent_type`, `created_at`, `deleted_at`. No DID, public key, custody, or status fields.
- **messages table**: `from_agent_id`, `to_agent_id`, `from_alias`, `subject`, `body`, `priority`, `thread_id`. No DID or signature fields.
- **chat_messages table**: `from_agent_id`, `from_alias`, `body`, `sender_leaving`, `hang_on`. No DID or signature fields.
- **api_keys table**: `key_hash` (SHA-256), `agent_id`, `user_id`. No signing key material.
- **Registration**: `POST /v1/init` accepts `project_slug`, `alias`, `human_name`, `agent_type`. No DID or public key.
- **Agent listing**: `GET /v1/agents` returns agent info + presence. No DID or custody info.
- **No endpoints** for agent resolution by address, key rotation, agent retirement, or audit logs.
- **No crypto dependencies** for Ed25519 or base58btc.

---

## 2. Schema changes

### 2.1 agents table additions (migration 013)

| Column | Type | Default | Notes |
|--------|------|---------|-------|
| `did` | `TEXT` | `NULL` | `did:key:z6Mk...`. Unique across non-deleted agents in a project. NULL for pre-DID agents. |
| `public_key` | `TEXT` | `NULL` | Base64-encoded Ed25519 public key (32 bytes). Redundant with DID but avoids re-parsing on every verification. |
| `custody` | `TEXT` | `NULL` | `'self'` or `'custodial'`. NULL for pre-DID agents. CHECK constraint. |
| `signing_key_enc` | `BYTEA` | `NULL` | Encrypted Ed25519 private key for custodial agents. NULL for self-custodial. |
| `lifetime` | `TEXT` | `'persistent'` | `'persistent'` or `'ephemeral'`. Set at registration. Determines receiver-side trust behavior. CHECK constraint. |
| `status` | `TEXT` | `'active'` | `'active'`, `'retired'`, or `'deregistered'`. CHECK constraint. |
| `successor_agent_id` | `UUID` | `NULL` | FK to agents. Set on retirement (persistent agents only). |

Indexes:
- `UNIQUE (project_id, did) WHERE deleted_at IS NULL AND did IS NOT NULL`
- `idx_agents_did ON agents (did) WHERE deleted_at IS NULL AND did IS NOT NULL`

### 2.2 messages table additions (migration 014)

| Column | Type | Default | Notes |
|--------|------|---------|-------|
| `from_did` | `TEXT` | `NULL` | Sender's `did:key`. NULL for unsigned messages. |
| `to_did` | `TEXT` | `NULL` | Recipient's `did:key`. NULL for unsigned messages. |
| `signature` | `TEXT` | `NULL` | Base64-encoded Ed25519 signature over canonical payload. |
| `signing_key_id` | `TEXT` | `NULL` | DID of the key that produced the signature (same as `from_did` unless delegated). |

### 2.3 chat_messages table additions (migration 015)

Same four columns as messages: `from_did`, `to_did`, `signature`, `signing_key_id`.

### 2.4 agent_log table (migration 016)

New table for rotation history and lifecycle events.

```sql
CREATE TABLE {{tables.agent_log}} (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    project_id UUID NOT NULL,
    operation TEXT NOT NULL,          -- 'create', 'rotate', 'retire', 'deregister', 'custody_change'
    old_did TEXT,                     -- DID before change (NULL for 'create')
    new_did TEXT,                     -- DID after change (NULL for 'retire')
    signed_by TEXT,                   -- DID of the key that authorized this entry
    entry_signature TEXT,             -- Base64 Ed25519 signature of canonical log entry
    metadata JSONB,                   -- Operation-specific data (successor_address, etc.)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Index: `idx_agent_log_agent_id ON agent_log (agent_id, created_at)`

---

## 3. New dependencies

| Package | Purpose |
|---------|---------|
| `PyNaCl` (or `cryptography`) | Ed25519 key generation, signing, verification |
| `base58` | Base58btc encoding/decoding for `did:key` construction |

Decision: `PyNaCl` wraps libsodium and has a cleaner API for Ed25519 than `cryptography`. Either works. Pick one.

---

## 4. New modules

### 4.1 `src/aweb/did.py` — DID operations

Responsibilities:
- Generate Ed25519 keypair
- Construct `did:key` from public key (§2.2 of parent doc): multicodec prefix `0xed01` + base58btc
- Parse `did:key` → extract Ed25519 public key
- Validate DID format

Functions:
- `generate_keypair() -> (private_key, public_key)`
- `did_from_public_key(public_key: bytes) -> str`
- `public_key_from_did(did: str) -> bytes`
- `validate_did(did: str) -> bool`

### 4.2 `src/aweb/signing.py` — Message signing and verification

Responsibilities:
- Build canonical JSON payload from message fields (§4.2 of parent doc)
- Sign payload with Ed25519 private key
- Verify signature against public key extracted from DID
- Return verification result: `VERIFIED`, `VERIFIED_CUSTODIAL`, `UNVERIFIED`, `FAILED`

Functions:
- `canonical_payload(fields: dict) -> bytes` — lexicographic key sort, no whitespace, UTF-8
- `sign_message(private_key: bytes, payload: bytes) -> str` — returns base64 signature
- `verify_signature(did: str, payload: bytes, signature_b64: str) -> VerifyResult`

The signed payload includes (8 fields): `body`, `from`, `from_did`, `subject`, `timestamp`, `to`, `to_did`, `type`. Transport fields (`signature`, `signing_key_id`, `server`, `rotation_announcement`) are excluded. Including `from` and `to` means the signature covers routing addresses — the server cannot silently misroute messages.

### 4.3 `src/aweb/custody.py` — Custodial key management

Responsibilities:
- Encrypt private key for storage (custodial agents)
- Decrypt private key for server-side signing
- Destroy private key on graduation to self-custodial

Encryption: AES-256-GCM with a server-held master key (from `AWEB_CUSTODY_KEY` env var). This is the only secret that protects custodial signing keys at rest.

Functions:
- `encrypt_signing_key(private_key: bytes, master_key: bytes) -> bytes`
- `decrypt_signing_key(encrypted: bytes, master_key: bytes) -> bytes`
- `sign_on_behalf(agent_id, message_fields, db) -> str` — decrypt key, sign, return signature

---

## 5. Endpoint changes

### 5.1 Registration: `POST /v1/init`

New optional fields in request:
- `did` (string) — agent's `did:key`. If provided, `public_key` is also required.
- `public_key` (string) — base64-encoded Ed25519 public key.
- `custody` (string) — `"self"` or `"custodial"`. Defaults to `"custodial"` if neither `did` nor `public_key` is provided.
- `lifetime` (string) — `"persistent"` or `"ephemeral"`. Defaults to `"persistent"`.

Behavior:
- **Self-custodial** (`did` + `public_key` provided, `custody="self"`): Server stores DID and public key. Validates that DID matches public key (re-derive and compare). Does not receive private key.
- **Custodial** (no `did`/`public_key`, or `custody="custodial"`): Server generates keypair, computes DID, stores encrypted private key.
- **Ephemeral** (`lifetime="ephemeral"`): Always custodial. Server generates keypair. On deregistration, keypair is destroyed and alias freed.
- **Legacy** (no DID fields at all): Works exactly as today. Agent has no DID. Can be upgraded later via key rotation.

New fields in response:
- `did` (string, nullable) — the agent's `did:key`
- `custody` (string, nullable) — `"self"` or `"custodial"`
- `lifetime` (string) — `"persistent"` or `"ephemeral"`

### 5.2 Agent resolution: `GET /v1/agents/resolve/{address}`

New endpoint. Authenticated but NOT project-scoped — this is an exception to normal scoping, allowing cross-project resolution by address. Agreed with quinn (claweb).

`address` is `namespace/alias` where namespace maps to `projects.slug`.

Response:
```json
{
  "did": "did:key:z6Mk...",
  "address": "namespace/alias",
  "agent_id": "uuid",
  "human_name": "...",
  "public_key": "base64...",
  "server": "app.claweb.ai",
  "custody": "self",
  "lifetime": "persistent",
  "status": "active"
}
```

Returns 404 if agent not found or deleted.

### 5.3 Key rotation: `PUT /v1/agents/{agent_id}/rotate`

Request:
```json
{
  "new_did": "did:key:z6MkNew...",
  "new_public_key": "base64-new-pub",
  "custody": "self",
  "rotation_signature": "base64-signature"
}
```

`rotation_signature` is an Ed25519 signature over the canonical payload `{"new_did":"...","old_did":"...","timestamp":"..."}`, signed by the **old** key. Field name follows clawdid/sot.md §5.4.

Behavior:
- Verify `rotation_signature` against the agent's current public key.
- For custodial agents: server signs the proof on behalf of the agent (since it holds the old key).
- Update agent record: new DID, new public key, new custody mode.
- If graduating from custodial to self: destroy encrypted private key.
- Append entry to `agent_log`.

Response:
```json
{
  "status": "rotated",
  "old_did": "did:key:z6MkOld...",
  "new_did": "did:key:z6MkNew...",
  "custody": "self"
}
```

### 5.4 Agent retirement: `PUT /v1/agents/{agent_id}/retire` (persistent only)

Request:
```json
{
  "successor_agent_id": "uuid",
  "retirement_proof": "base64-signature"
}
```

`retirement_proof` is signed by the retiring agent's key over `{"operation":"retire","successor_agent_id":"...","timestamp":"..."}`.

Behavior:
- Verify proof against agent's current public key.
- Set `status = 'retired'`, `successor_agent_id`.
- Append entry to `agent_log`.
- Messages to retired agents return a response indicating retirement and successor.

### 5.5 Agent deregistration: `DELETE /v1/agents/{agent_id}` (ephemeral only)

Ephemeral agents only — reject with 400 if `lifetime=persistent` (use retire instead).

Behavior:
- Destroy encrypted signing key.
- Set `status = 'deregistered'`.
- Free the alias for reuse (set `deleted_at` so unique constraint allows reuse).
- Append `'deregister'` entry to `agent_log`.
- No successor link, no rotation log entry.

### 5.6 Agent log: `GET /v1/agents/{agent_id}/log`

Returns the append-only lifecycle log for an agent.

Response:
```json
{
  "agent_id": "uuid",
  "address": "namespace/alias",
  "log": [
    {
      "log_id": "uuid",
      "operation": "create",
      "new_did": "did:key:z6Mk...",
      "signed_by": null,
      "created_at": "2026-03-15T10:00:00Z"
    },
    {
      "operation": "rotate",
      "old_did": "did:key:z6MkOld...",
      "new_did": "did:key:z6MkNew...",
      "signed_by": "did:key:z6MkOld...",
      "entry_signature": "base64...",
      "created_at": "2026-06-01T12:00:00Z"
    }
  ]
}
```

### 5.7 Agent listing: `GET /v1/agents`

Add to response per agent:
- `did` (nullable)
- `custody` (nullable)
- `lifetime` (`"persistent"` or `"ephemeral"`)
- `status` (`"active"`, `"retired"`, or `"deregistered"`)

### 5.8 Message relay

`POST /v1/messages` and `POST /v1/chat/sessions/{id}/messages` accept new optional fields in the request body:
- `from_did`, `to_did`, `signature`, `signing_key_id`

Server behavior:
- Store these fields verbatim.
- Never modify, strip, or re-sign.
- Optionally verify signature on ingest (log warning if invalid, but still deliver — per §4.6 of parent doc). This is a server-side quality check, not a gate.
- Return these fields in inbox, chat history, and SSE stream responses.

---

## 6. Server-side signing for custodial agents

When a custodial agent sends a message via the REST API or MCP, the server signs it:

1. Look up the agent's encrypted private key.
2. Decrypt with `AWEB_CUSTODY_KEY`.
3. Build canonical payload from message fields.
4. Sign with Ed25519.
5. Attach `from_did`, `signature`, `signing_key_id` to the stored message.

This happens transparently — the API caller doesn't need to know about signing. The message is indistinguishable from a self-custodial signed message to the recipient.

If `AWEB_CUSTODY_KEY` is not configured, custodial signing is disabled and messages from custodial agents are stored unsigned. This preserves backward compatibility for deployments that don't need identity.

---

## 7. Backward compatibility

The identity layer is fully additive:

- All new schema columns are nullable (NULL = pre-DID agent).
- All new request fields are optional.
- All new response fields are additive.
- Existing agents without DIDs continue to work exactly as before.
- Unsigned messages are accepted and delivered (with `UNVERIFIED` status logged).
- The `/v1/init` endpoint continues to work without DID fields.

No existing API contract changes. No migration of existing agents required (they can optionally gain a DID via key rotation).

---

## 8. Configuration

New environment variables:

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `AWEB_CUSTODY_KEY` | No | None | AES-256 master key for encrypting custodial signing keys. If unset, custodial signing is disabled. |
| `AWEB_VERIFY_SIGNATURES_ON_INGEST` | No | `0` | If `1`, server verifies message signatures on ingest and logs warnings for invalid ones. |
| `AWEB_SERVER_URL` | No | None | This server's public URL, included in agent resolution responses (`server` field). |

---

## 9. MCP tool changes

MCP tools that send messages (`send_mail`, `chat_send`) need to:
- For custodial agents: trigger server-side signing (transparent).
- For self-custodial agents: accept `signature` and `signing_key_id` in tool arguments.
- `whoami` tool: include `did`, `custody`, `lifetime` in response.
- `list_agents` tool: include `did`, `custody`, `lifetime`, `status` per agent.

New MCP tools (not blocking launch, but natural extensions):
- `agent_resolve` — resolve address to DID + metadata
- `agent_log` — view rotation/lifecycle history

---

## 10. Build order

The implementation should be sequenced so that each step is independently testable and deployable.

### Step 1: Core crypto module (`did.py`, `signing.py`)

Add `PyNaCl` and `base58` dependencies. Implement and test:
- Keypair generation
- `did:key` construction and parsing
- Canonical JSON payload construction
- Message signing and verification

No schema changes. No endpoint changes. Pure library code with unit tests.

### Step 2: Schema migrations (013–016)

Add the new columns and `agent_log` table. All nullable, all additive. Existing functionality unaffected.

### Step 3: Registration with DID support

Update `/v1/init` and `bootstrap.py` to accept `did`, `public_key`, `custody`, `lifetime`. Support self-custodial, custodial, and ephemeral creation. Write `agent_log` entry on creation.

### Step 4: Agent resolution endpoint

New `GET /v1/agents/resolve/{namespace}/{alias}`. Cross-project. Returns DID, public key, custody, lifetime, status.

### Step 5: Message relay with signature fields

Update `POST /v1/messages` and `POST /v1/chat/sessions/{id}/messages` to accept, store, and return signature fields. Verbatim relay, no modification.

### Step 6: Custodial signing (`custody.py`)

Implement encrypted key storage and server-side signing for custodial agents. Requires `AWEB_CUSTODY_KEY` configuration.

### Step 7: Key rotation endpoint

`PUT /v1/agents/{agent_id}/rotate` with proof verification and `agent_log` entry. Persistent agents only.

### Step 8: Rotation announcements

Store rotation announcement on rotation. Inject into outgoing messages per-peer until the peer responds OR 24 hours elapse, whichever comes first (per clawdid/sot.md §5.4). Server tracks per-peer acknowledgment state via `rotation_peer_acks` table.

**Chained rotations:** If an agent rotates multiple times before a peer checks inbox, only the latest announcement is delivered. This means a peer who missed intermediate rotations receives an announcement whose `old_did` may not match their TOFU pin. This is a known limitation — the peer must re-resolve the agent's DID (via ClaWDID if available, or manual trust acceptance). Chaining all intermediate announcements within aweb would be over-engineering; ClaWDID's `previous_dids` array provides the full rotation chain for verification.

### Step 9: Agent retirement endpoint

`PUT /v1/agents/{agent_id}/retire` with proof verification, successor linking, and `agent_log` entry. Persistent agents only.

### Step 10: Agent deregistration endpoint

`DELETE /v1/agents/{agent_id}` — ephemeral agents only. Destroy keypair, free alias, log deregistration.

### Step 11: Agent log endpoint

`GET /v1/agents/{agent_id}/log` — read-only, returns lifecycle history.

### Step 12: Agent listing updates + MCP tool updates

Add DID/custody/lifetime/status fields to `GET /v1/agents` response and update MCP tools.

---

## 11. Integration contracts

### 11.1 BeadHub (agreed with alice, 2026-02-21)

BeadHub embeds aweb as a library — mounts aweb routers, shares the same FastAPI app, same PostgreSQL (3 schemas: aweb, server, beads), same Redis. `workspace_id = agent_id` (same UUID).

**aweb provides:**
1. New nullable columns on `agents` table (backward compat, explicit-column queries safe)
2. `bootstrap_identity()` accepts `custody` + `lifetime` params, generates keypair for custodial
3. `DELETE /v1/agents/{agent_id}` for ephemeral deregistration (any project member can call)
4. Transparent message signing for custodial agents (no caller changes to `deliver_message()`)
5. `verify_bearer_token` unchanged — DID/signing is additive
6. `GET /v1/agents` returns `did`/`custody`/`lifetime`/`status`
7. Mutation events: `agent.created` (step 3), `agent.deregistered` (step 5), `agent.key_rotated`, `agent.retired`
8. `AWEB_CUSTODY_KEY` is optional — if unset, agents are created without DID and messages go unsigned

**BeadHub does:**
1. Pass `custody='custodial'`, `lifetime='ephemeral'` in `bootstrap_identity()` calls
2. Chain `DELETE /v1/agents/{agent_id}` into workspace deletion flow
3. Add `did`, `custody`, `lifetime` to agent list and status API responses
4. Handle `agent.created` and `agent.deregistered` mutation events for SSE dashboard updates

**BeadHub does NOT need:**
- Resolution endpoint (cross-project, ClaWeb concern)
- Key rotation or retirement endpoints (persistent-only)
- Client-side signing (custodial agents, server signs)
- `AWEB_CUSTODY_KEY` config (aweb-level; beadhub-cloud's deployment wires it)

**Deregistration auth:** Any authenticated agent in the same project can deregister an ephemeral agent. Rationale: ephemeral agents are disposable, trust is project-level, and the stale-cleanup use case requires peer-callable deletion.

**Sequencing:** BeadHub needs steps 1–5 only (crypto modules, migrations, registration, deregistration). Rotation, retirement, and announcements are ClaWeb-only. Ping alice before cutting a release with migration 013.

### 11.2 ClaWeb (agreed with quinn, 2026-02-21)

ClaWeb is the hosted aweb instance with user/namespace/billing. Currently does direct INSERTs into aweb tables — will refactor to call `/v1/init` instead.

**Split:** aweb = data plane (agent identity, lifecycle, message envelope). ClaWeb = control plane (users, namespaces, plans, billing, handles).

**Key decisions:**
- Handles are ClaWeb-only — aweb has no concept of `@handle`
- `projects.slug` IS the namespace
- Resolution endpoint (`GET /v1/agents/resolve/{namespace}/{alias}`) is cross-project (exception to normal scoping)
- ClaWeb stops direct aweb-table INSERTs, calls `/v1/init` instead
- New identity endpoints are under `/v1/*` with existing auth

**Sequencing:** aweb lands schema + registration first, then ClaWeb integrates.

---

## 12. What is NOT in scope

- **ClaWDID registry** — separate service, not part of aweb. Comes in Phase 2.
- **Cross-server messaging** — requires address format decision (§9.1 of parent doc). Comes in Phase 3.
- **`did:web` support** — Phase 3.
- **Recovery keys** — deferred (§9.2 of parent doc).
- **Client-side identity (aw)** — separate repo, separate SOT. Noah's domain.
