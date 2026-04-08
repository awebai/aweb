# aweb — Source of Truth

This is the canonical contract for **aweb**: the OSS coordination
server (Python FastAPI) and the `aw` CLI (Go). It defines the exact
shape of every endpoint, schema, authentication mechanism, dependency,
and configuration knob aweb exposes or relies on. Implementers build
against this document; operators run aweb against the contract it
defines here.

aweb-cloud (the proprietary hosted wrapper) is described in
[`aweb-cloud/docs/aweb-cloud-sot.md`](../../aweb-cloud/docs/aweb-cloud-sot.md).
awid (the public identity registry that aweb depends on) is described
in [`awid-sot.md`](awid-sot.md).

For supporting reference material that does not redefine the contract:
- [`cli-command-reference.md`](cli-command-reference.md) — full `aw`
  CLI surface, generated from the live Cobra help tree
- [`mcp-tools-reference.md`](mcp-tools-reference.md) — MCP tool
  inventory and parameters exposed by aweb's MCP server
- [`self-hosting-guide.md`](self-hosting-guide.md) — operator runbook
  for the OSS stack
- [`identity-key-verification.md`](identity-key-verification.md) —
  normative rules for verifying `GET /v1/did/{did_aw}/key` responses

---

## Principles

1. **awid owns identity and team membership.** aweb never creates,
   stores, or manages identities. It never decides who is in a team.
2. **aweb owns coordination.** Mail, chat, tasks, roles, locks,
   workspaces, events. This is the only thing aweb does.
3. **Team certificates are the single credential for coordination
   endpoints.** Agents authenticate every coordination request (mail,
   chat, tasks, roles, locks, instructions, workspace state) with a
   DIDKey signature and a team certificate. The `/mcp` endpoint at
   aweb-cloud uses a separate auth model documented in
   `aweb-cloud/docs/aweb-cloud-sot.md` § Hosted MCP and
   OAuth Connector Architecture.
4. **team_address is the coordination scope.** Every coordination table
   is scoped to a `team_address` (e.g., `acme.com/backend`). All
   coordination data — messages, tasks, claims, locks, roles,
   instructions, presence — lives at the team level.

---

## Concepts

This section defines the conceptual taxonomy that the rest of the document
operates on: agent vs workspace vs identity vs alias vs address. These
distinctions are load-bearing — collapsing them into a single "agent =
identity = address" notion would muddle the routing, trust, and lifecycle
stories the rest of the spec depends on.

### Agent

An **agent** is a running participant.

- A local CLI runtime is an agent.
- A hosted OAuth MCP runtime is an agent.
- An agent uses exactly one identity at a time.
- An identity may be inactive even when no agent is currently running under it.

### Workspace

A **workspace** is a local runtime container.

- It is represented by a local `.aw/` directory.
- It stores local runtime state and configuration.
- It may also store secret key material for self-custodial persistent identities.
- A workspace belongs to one local machine/path, but it may be moved by moving
  the `.aw/` directory.
- A workspace has one active identity and one active team binding.
- Hosted OAuth MCP runtimes do **not** have a local workspace.

A workspace is bound to exactly one team. An agent that needs to
participate in multiple teams uses multiple workspaces (typically
multiple git worktrees), each with its own `.aw/` directory and its own
team certificate. The certificate format does not preclude an agent
identity (`did:key`) from being a member of more than one team — multi-
team agents are a future capability the cert format already accommodates
— but the v1 CLI and server bind one workspace to one team.

### Identity

An **identity** is the principal the agent uses for messaging, coordination,
and trust.

Two identity classes exist:

- **Ephemeral identity**: disposable, internal, one alias. Has only `did:key`.
  Created by accepting a team invite or via spawn into the same team. Deleted
  when the workspace is removed. Does not carry public trust continuity.
- **Persistent identity**: durable, trust-bearing. Has both `did:key` and
  `did:aw`. Has one or more public addresses. Supports rotation, archival, and
  controlled replacement.

Trust continuity is only promised for persistent identities.

### Custody Modes

Persistent identities have two custody modes:

- **Self-custodial**: the agent holds its own Ed25519 private key locally,
  inside its `.aw/` workspace. Created only from the CLI. Cannot be used by
  hosted OAuth MCP runtimes. Created explicitly via `aw init --persistent
  --name <name>` — never as a side effect of a default flow.
- **Custodial**: the hosted service holds the encrypted private key. Created
  from the dashboard for hosted/browser MCP use. The dashboard creates
  persistent custodial identities, not generic "agents".

### Alias vs Address

An **alias** is the routing name for an ephemeral identity:

- Internal/team scoped (e.g., `alice` within the team)
- Not the external public trust surface
- May be auto-assigned from a pool of standard names
- An ephemeral identity has exactly one alias

An **address** is the stable handle for a persistent identity:

- Only persistent identities have addresses
- A persistent identity may have more than one address
- Canonical external form is `namespace/name` (e.g., `acme.com/alice`)
- Public trust semantics attach to the persistent address, not to ephemeral
  aliases
- Address assignment is separate from reachability (`private` /
  `org-visible` / `contacts-only` / `public`)

### Lifecycle: Delete vs Archive vs Replace

Three distinct lifecycle stories that must not be conflated:

- **Delete**: ephemeral only. Releases the alias for reuse. The single
  user-facing lifecycle verb for ephemeral teardown.
- **Archive**: persistent identity lifecycle cleanup with no continuity claim.
  Stops active participation, keeps history.
- **Replace**: persistent identity continuity via owner-authorized replacement
  of an assigned public address. Distinct from cryptographic key rotation.
  Used when the owner has lost the key but still controls the dashboard and
  public address surface.

Replacement preserves address continuity (`acme.com/support` keeps working)
but is not cryptographic continuity of the old `did:aw`. Recipients must be
able to distinguish:

- key rotation / signed retirement: continuity vouched for by the old key
- admin-authorized replacement: continuity vouched for by the org/project
  controller, not by the old key

---

## Authentication

### Request format

Every authenticated request carries two headers:

```
Authorization: DIDKey <did:key:z6Mk...> <base64-signature>
X-AWID-Team-Certificate: <base64-encoded certificate JSON>
```

The `Authorization` header is an Ed25519 signature over the canonical
JSON of `{team_address, timestamp, body_sha256}` where `body_sha256`
is the SHA256 hex digest of the request body (or of empty string for
GET requests with no body).

The `X-AWID-Team-Certificate` header is a team membership certificate
issued by the team controller at awid. A base64 team certificate is on
the order of 500–1000 bytes and is included on every authenticated
request. For long-lived SSE connections this is a one-handshake cost
and negligible. For high-frequency unary HTTP requests it adds
sub-millisecond and bytes-of-overhead per call. v1 ships with
cert-on-every-request; if measured workloads show the per-request cost
is material, a session-token shortcut may be added later, but the cert
remains the canonical credential.

### Verification (mostly local crypto, one cached lookup)

1. Parse `Authorization` header → extract did:key and signature.
2. Compute SHA256 hex digest of the request body. Verify the Ed25519
   signature over canonical JSON of `{team_address, timestamp,
   body_sha256}`. Reject if invalid.
3. Decode and verify the team certificate from `X-AWID-Team-Certificate`
   per the [certificate verification protocol](awid-sot.md#verification-by-a-service)
   defined in the awid SoT (verify signature against the cached team
   public key, verify certificate `member_did_key` matches the request
   did:key, check `certificate_id` against the cached revocation list).
4. Extract `team_address`, `alias`, `lifetime` from the certificate.
5. Request is authenticated and authorized for the given team.

Steps 1-3 are local crypto, no network. The revocation-list and team
public key lookups in step 3 are cache hits — see [Caching from awid](#caching-from-awid)
below.

### Caching from awid

aweb caches two things from awid per team:

**Team metadata** (for certificate signature verification AND public-team
visibility bypass on dashboard reads):
```
GET https://api.awid.ai/v1/namespaces/{domain}/teams/{name}
→ {
    "team_did_key": "did:key:z6Mk...",
    "visibility": "private" | "public",
    ...
  }
```
Cache TTL: 10 minutes. Stale-while-revalidate window: an additional
10 minutes (so cached values can be served for up to 20 minutes total;
after that, a hard miss triggers a synchronous refresh, and a failed
synchronous refresh triggers the fail-closed behavior described in the
"Dashboard auth" section below).

**Cache behavior on team key rotation.** Team key rotation
(`POST /v1/namespaces/{domain}/teams/{name}/rotate-key` at awid) propagates
to aweb on the next cache refresh — up to 20 minutes (one TTL cycle plus the
stale window). During that propagation window, aweb continues to verify
incoming certificates against the previously cached `team_did_key`, so
certificates issued under the new team controller key fail verification at
aweb until the cache catches up. This is fail-closed (no wrong access is
granted). Operators planning a rotation should expect up to a 20-minute
propagation delay before new certificates start verifying. Operators who
need faster propagation can manually flush the team metadata cache via
Redis (key prefix `awid:team:`); after the flush the next request triggers
a synchronous refresh against awid and picks up the new key immediately.

**Operational note:** the team metadata cache TTL is intentionally short
because the `visibility` field gates anonymous dashboard reads — a long
TTL would mean a team flipped from public to private would still serve
anonymous reads for the duration of the TTL. The 10-minute TTL bounds
that window. Aweb makes one resolution call per 10 minutes per active
team **per aweb cluster**, where a cluster is the set of aweb instances
sharing the same Redis cache backend. Operators sizing the awid API
budget should account for this — note that the cache is shared across
all aweb instances behind the same Redis, so the call rate scales with
cluster count, not instance count.

**Revocation list** (for checking removed members):
```
GET https://api.awid.ai/v1/namespaces/{domain}/teams/{name}/revocations
→ { "revocations": [{ "certificate_id": "...", "revoked_at": "..." }] }
```
Cache TTL: 10 minutes with a 10-minute stale-while-revalidate window
(matching the team metadata cache, so both refresh on the same schedule).
The maximum window of stale access after a member is removed is
20 minutes; a manual Redis cache flush is the supported faster path.

---

## Database schema

aweb uses a single PostgreSQL schema: `aweb`.

### Schema

```sql
-- Teams this server coordinates for.
-- Auto-created when the first agent from a team connects.
CREATE TABLE teams (
    team_address    TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    team_name       TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Team visibility does not live in aweb. It is read from awid team
-- metadata and cached for dashboard auth decisions.

-- Agents. One row per agent per team. Created on first connection
-- with a valid certificate. No identity columns — the certificate
-- IS the identity proof.
CREATE TABLE agents (
    agent_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES teams(team_address),
    did_key         TEXT NOT NULL,
    did_aw          TEXT,
    address         TEXT,
    alias           TEXT NOT NULL,
    lifetime        TEXT NOT NULL DEFAULT 'ephemeral'
                    CHECK (lifetime IN ('persistent', 'ephemeral')),
    human_name      TEXT NOT NULL DEFAULT '',
    agent_type      TEXT NOT NULL DEFAULT 'agent',
    role            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'retired', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_address, alias)
);

CREATE INDEX idx_agents_did_key ON agents (did_key) WHERE deleted_at IS NULL;
CREATE INDEX idx_agents_did_aw ON agents (did_aw) WHERE did_aw IS NOT NULL AND deleted_at IS NULL;

-- Mail
CREATE TABLE messages (
    message_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES teams(team_address),
    from_agent_id   UUID NOT NULL REFERENCES agents(agent_id),
    to_agent_id     UUID NOT NULL REFERENCES agents(agent_id),
    from_alias      TEXT NOT NULL,
    to_alias        TEXT NOT NULL,
    subject         TEXT NOT NULL DEFAULT '',
    body            TEXT NOT NULL,
    priority        TEXT NOT NULL DEFAULT 'normal',
    from_did        TEXT,
    signature       TEXT,
    signed_payload  TEXT,
    read_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_messages_inbox ON messages (team_address, to_agent_id, created_at)
    WHERE read_at IS NULL;

-- Chat sessions
CREATE TABLE chat_sessions (
    session_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES teams(team_address),
    created_by      TEXT NOT NULL,
    wait_seconds    INTEGER,
    wait_started_at TIMESTAMPTZ,
    wait_started_by UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE chat_participants (
    session_id      UUID NOT NULL REFERENCES chat_sessions(session_id),
    agent_id        UUID NOT NULL REFERENCES agents(agent_id),
    alias           TEXT NOT NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, agent_id)
);

CREATE TABLE chat_messages (
    message_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES chat_sessions(session_id),
    from_agent_id   UUID NOT NULL REFERENCES agents(agent_id),
    from_alias      TEXT NOT NULL,
    body            TEXT NOT NULL,
    reply_to        UUID,
    sender_leaving  BOOLEAN NOT NULL DEFAULT false,
    hang_on         BOOLEAN NOT NULL DEFAULT false,
    from_did        TEXT,
    signature       TEXT,
    signed_payload  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chat_messages_session ON chat_messages (session_id, created_at);

CREATE TABLE chat_read_receipts (
    session_id      UUID NOT NULL REFERENCES chat_sessions(session_id),
    agent_id        UUID NOT NULL REFERENCES agents(agent_id),
    last_read_message_id UUID REFERENCES chat_messages(message_id),
    last_read_at    TIMESTAMPTZ,
    PRIMARY KEY (session_id, agent_id)
);

-- Contacts (per-team address book)
CREATE TABLE contacts (
    contact_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES teams(team_address),
    contact_address TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_address, contact_address)
);

-- Control signals
CREATE TABLE control_signals (
    signal_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL REFERENCES teams(team_address),
    target_agent_id UUID NOT NULL REFERENCES agents(agent_id),
    from_agent_id   UUID NOT NULL REFERENCES agents(agent_id),
    signal_type     TEXT NOT NULL
                    CHECK (signal_type IN ('pause', 'resume', 'interrupt')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at     TIMESTAMPTZ
);

CREATE INDEX idx_control_signals_pending
    ON control_signals (team_address, target_agent_id, created_at)
    WHERE consumed_at IS NULL;

-- Repos (git context)
CREATE TABLE repos (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    origin_url      TEXT NOT NULL,
    canonical_origin TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_address, canonical_origin)
);

-- Workspaces (agent presence in a repo context)
CREATE TABLE workspaces (
    workspace_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    agent_id        UUID NOT NULL,
    repo_id         UUID REFERENCES repos(id),
    alias           TEXT NOT NULL,
    human_name      TEXT NOT NULL DEFAULT '',
    role            TEXT,
    hostname        TEXT,
    workspace_path  TEXT,
    workspace_type  TEXT NOT NULL DEFAULT 'manual',
    focus_task_ref  TEXT,
    focus_updated_at TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_workspaces_active_alias
    ON workspaces (team_address, alias)
    WHERE deleted_at IS NULL;

-- Tasks
CREATE TABLE tasks (
    task_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    task_number     INTEGER NOT NULL,
    root_task_seq   INTEGER,
    task_ref_suffix TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'in_progress', 'closed')),
    priority        INTEGER NOT NULL DEFAULT 2
                    CHECK (priority BETWEEN 0 AND 4),
    task_type       TEXT NOT NULL DEFAULT 'task'
                    CHECK (task_type IN ('task', 'bug', 'feature', 'epic', 'chore')),
    assignee_alias  TEXT,
    created_by_alias TEXT,
    closed_by_alias TEXT,
    labels          TEXT[] NOT NULL DEFAULT '{}',
    parent_task_id  UUID REFERENCES tasks(task_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,

    UNIQUE (team_address, task_number),
    UNIQUE (team_address, task_ref_suffix)
);

CREATE TABLE task_comments (
    comment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES tasks(task_id),
    team_address    TEXT NOT NULL,
    author_alias    TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE task_dependencies (
    task_id         UUID NOT NULL REFERENCES tasks(task_id),
    depends_on_id   UUID NOT NULL REFERENCES tasks(task_id),
    team_address    TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on_id)
);

CREATE TABLE task_counters (
    team_address    TEXT PRIMARY KEY,
    next_number     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE task_root_counters (
    team_address    TEXT PRIMARY KEY,
    next_number     INTEGER NOT NULL DEFAULT 1
);

-- Claims
CREATE TABLE task_claims (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    workspace_id    UUID NOT NULL,
    alias           TEXT NOT NULL,
    human_name      TEXT NOT NULL DEFAULT '',
    task_ref        TEXT NOT NULL,
    apex_task_ref   TEXT,
    claimed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_address, task_ref, workspace_id)
);

-- Locks (resource reservations)
CREATE TABLE reservations (
    team_address    TEXT NOT NULL,
    resource_key    TEXT NOT NULL,
    holder_alias    TEXT NOT NULL,
    holder_agent_id UUID NOT NULL,
    acquired_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    metadata_json   JSONB,

    PRIMARY KEY (team_address, resource_key)
);

-- Roles (versioned per team)
CREATE TABLE project_roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    bundle_json     JSONB NOT NULL DEFAULT '[]',
    is_active       BOOLEAN NOT NULL DEFAULT false,
    created_by_alias TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,

    UNIQUE (team_address, version)
);

-- Instructions (versioned per team)
CREATE TABLE project_instructions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    document_json   JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT false,
    created_by_alias TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ,

    UNIQUE (team_address, version)
);

-- Audit log
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_address    TEXT NOT NULL,
    alias           TEXT,
    event_type      TEXT NOT NULL,
    resource        TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## API routes

### Bootstrap and team metadata

| Route | Purpose |
|-------|---------|
| `POST /v1/connect` | Agent connects with certificate. Auto-provisions team + agent if needed. Returns workspace binding info. Called by `aw init` under the hood. |
| `GET /v1/team` | Get team info (team_address, team_did_key, member count). |
| `GET /v1/usage` | Usage metrics for billing. Query params: `team_address`, `since`, `until`. Returns `{messages_sent, active_agents}`. Polled by aweb-cloud daily. |

### Messaging

| Route | Notes |
|-------|-------|
| `POST /v1/messages` | Send mail within team |
| `GET /v1/messages/inbox` | Inbox for agent in team |
| `POST /v1/messages/{id}/ack` | Mark as read |
| `POST /v1/chat/sessions` | Create chat session |
| `GET /v1/chat/pending` | Pending chats |
| `GET /v1/chat/sessions` | List sessions |
| `GET /v1/chat/sessions/{id}/messages` | Chat history |
| `POST /v1/chat/sessions/{id}/messages` | Send chat message |
| `GET /v1/chat/sessions/{id}/stream` | Chat SSE stream |
| `POST /v1/chat/sessions/{id}/read` | Mark read |

### Agents and presence

| Route | Notes |
|-------|-------|
| `GET /v1/agents/{alias}/events` | SSE event stream |
| `GET /v1/status` | Team status |
| `GET /v1/status/stream` | Status SSE |
| `POST /v1/agents/heartbeat` | Keep-alive |
| `GET /v1/agents` | List team agents |
| `PATCH /v1/agents/me` | Update workspace info |
| `POST /v1/agents/{alias}/control` | Control signals |
| `GET /v1/conversations` | List conversations |
| `GET /v1/contacts` | List contacts |
| `POST /v1/contacts` | Add contact |
| `DELETE /v1/contacts/{id}` | Remove contact |

### Coordination

| Route | Notes |
|-------|-------|
| `GET/POST/PUT/DELETE /v1/tasks/*` | All task operations |
| `GET/POST /v1/claims/*` | Task claims |
| `GET/POST/DELETE /v1/reservations/*` | Locks |
| `GET/POST /v1/roles/*` | Versioned roles |
| `GET/POST /v1/instructions/*` | Versioned instructions |
| `GET/POST /v1/repos/*` | Git repos |
| `GET/POST /v1/workspaces/*` | Workspace management |

### Dashboard routes

The dashboard reads coordination data from aweb. Authenticated with a
dashboard-session JWT issued by aweb-cloud (see Dashboard auth below).

| Route | Purpose |
|-------|---------|
| `GET /v1/teams/{team_address}/agents` | List active agents in team |
| `GET /v1/teams/{team_address}/agents/{alias}` | Agent detail |
| `GET /v1/teams/{team_address}/messages` | Message history |
| `GET /v1/teams/{team_address}/tasks` | Task list |
| `GET /v1/teams/{team_address}/roles/active` | Active role definitions |
| `GET /v1/teams/{team_address}/instructions/active` | Active instructions |
| `GET /v1/teams/{team_address}/status` | Team status (online agents, locks, claims) |

### Dashboard auth

aweb-cloud issues a short-lived JWT containing the list of
team_addresses the human has access to (derived from awid team
membership). The JWT is passed to aweb in an `X-Dashboard-Token`
header. aweb validates the JWT signature (shared secret with
aweb-cloud) and checks the requested team_address is in the token's
team list.

**Algorithm**: HS256 (HMAC-SHA256) using `AWEB_DASHBOARD_JWT_SECRET`. The
secret MUST be identical in cloud and aweb deployments. The `alg` header
MUST be `HS256` — aweb's verifier rejects any other algorithm including
`none` and asymmetric algorithms (defense against the alg-confusion class
of JWT bugs).

**Payload**:
```json
{
  "user_id": "uuid",
  "team_addresses": ["acme.aweb.ai/default", "acme.aweb.ai/backend"],
  "exp": 1775500000
}
```

The JWT validation is local (no awid call at request time). aweb does
query awid for team metadata (team_did_key, revocation list, visibility)
but those reads are cached.

**Public-team anonymous bypass.** When the requested team_address
resolves (via the cached team metadata above) to `visibility = "public"`,
aweb allows the dashboard read **without** a valid `X-Dashboard-Token`.
This makes public team activity (agents, messages, tasks, status)
available for anonymous read. Visibility is checked against the cached
team metadata before any data fetch — never serve data and then check.

**Fail-closed semantics on visibility lookup error (security property,
do not remove without explicit cross-repo SOT update).** If the team
metadata lookup fails or the cache is hard-stale (past the
stale-while-revalidate window) and a synchronous refresh fails, the
behavior is:

1. **Anonymous request (no `X-Dashboard-Token`):** return HTTP 503 "AWID
   registry unavailable". **NEVER** serve dashboard data on indeterminate
   visibility — doing so would be a privilege-escalation path that
   discloses private team data to anonymous callers when awid is
   unreachable.
2. **Authenticated request (valid `X-Dashboard-Token`):** treat
   visibility as `private` (the safe assumption) and proceed with the
   normal JWT validation path. The JWT alone is sufficient authority
   for the read; the visibility lookup is only needed for the anonymous
   bypass, not for the authenticated path.

This asymmetry — fail-closed for anonymous, fail-functional for
authenticated — is the intended behavior. A future maintainer who
removes the visibility check on the authenticated path would unnecessarily
fail dashboard reads during awid outages. A future maintainer who relaxes
the anonymous fail-closed to a fail-open (e.g., "default to public when
awid is unreachable") would create a privilege-escalation path. Both
sides of this asymmetry are load-bearing.

The same fail-closed property is documented in the sibling `aweb-cloud`
repo, in `docs/aweb-cloud-sot.md`. Both documents must stay
in sync; if either side changes the security property, the other must be
updated in the same merge.

Environment variable: `AWEB_DASHBOARD_JWT_SECRET` (shared with
aweb-cloud).

---

## Agent lifecycle

### `aw init` — the two main cases

`aw init` has two main cases depending on whether the current
directory already has a `.aw/` with an identity.

**Case A — directory already has `.aw/identity.yaml` and `.aw/team-cert.pem`:**
The CLI just connects. Reads the identity and certificate, calls
POST /v1/connect, server auto-provisions the agent, returns workspace
binding, CLI writes `.aw/workspace.yaml`. No prompts.

**Case B — directory has no identity yet:**
The CLI runs the wizard to create the identity, then connects.

The wizard offers two paths:

PATH 1 — BYOD (you have a domain):
- Wizard asks "Do you have a domain you control?"
- User says yes, provides domain
- CLI generates a controller keypair locally
- CLI prints the DNS TXT record the user must add: `_awid.<domain> TXT "awid=v1; controller=<did:key>"`
- User adds the DNS record
- CLI verifies the record, registers the namespace at awid, creates a default team, signs a certificate
- Proceeds to connect

PATH 2 — Hosted (use the aweb.ai managed namespace):
- Wizard asks "Use a managed identity at aweb.ai?"
- User picks a username
- CLI calls aweb-cloud `POST /api/v1/onboarding/check-username` to validate format and availability
- If taken or invalid, wizard prompts again until a free username is provided
- CLI calls aweb-cloud `POST /api/v1/onboarding/cli-signup` with the username and the agent's public key
- aweb-cloud creates a free aweb.ai account (no email or password yet — just the username), registers `<username>.aweb.ai` as a namespace at awid using the parent controller key, creates a default team, signs and registers a certificate
- CLI saves the certificate
- Proceeds to connect

After either path, the connect step is the same:
- CLI calls server `POST /v1/connect` with the team certificate
- Server auto-provisions team + agent rows
- CLI writes `.aw/workspace.yaml`

The hosted path requires the server to be aweb-cloud (i.e., it has the
parent controller key for `*.aweb.ai`). For self-hosted aweb in Docker,
only the BYOD path is available because vanilla aweb has no parent
controller key.

### Persistent agent (joining an existing team via invite)

```
1. aw id create --name alice --domain acme.com
   → identity created at awid (did:aw, did:key, address)

2. Team controller invites alice:
   aw id team invite --team backend --namespace acme.com
   → returns invite token

3. Alice accepts:
   aw id team accept-invite <token>
   → team controller signs certificate for alice's did:key
   → certificate saved to .aw/team-cert.pem

4. aw init --server app.aweb.ai
   → presents team certificate to aweb
   → POST /v1/connect (aweb auto-provisions team + agent rows)
   → aweb returns workspace binding
   → writes .aw/workspace.yaml
```

### Ephemeral agent

```
1. Team controller creates invite for ephemeral member:
   aw id team invite --team backend --namespace acme.com --ephemeral

2. New agent accepts:
   aw id team accept-invite <token>
   → generates local keypair (.aw/signing.key)
   → team controller signs ephemeral certificate for this did:key
   → certificate saved to .aw/team-cert.pem

3. aw init --server app.aweb.ai
   → POST /v1/connect to aweb
   → aweb auto-provisions ephemeral agent row
   → writes .aw/workspace.yaml
```

### Agent removed from team

```
1. aw id team remove-member --team backend --namespace acme.com \
     --member acme.com/alice
   → team controller posts revocation to awid
     (certificate_id added to revocation list)
   → aweb's cached revocation list refreshes within 5-15 min
   → aweb rejects alice's certificate on next request after refresh
   → agent row stays (for message history) but status → 'deleted'
```

### Certificate reissuance

Certificates do not expire. They are long-lived. Reissuance is only
needed for two rare administrative events:

- **Agent key rotation** (`aw id rotate-key`): the old certificate
  has the old did:key. The team controller issues a new certificate
  for the new did:key.
- **Team key rotation**: the old certificates were signed by the old
  team key. All active members need new certificates signed by the
  new key.

The certificate is stored at `.aw/team-cert.pem` (CLI agents) or
managed by aweb-cloud (custodial agents).

---

## CLI commands

The canonical `aw` CLI surface is documented in
[`cli-command-reference.md`](cli-command-reference.md), generated from the
live Cobra help tree. The bootstrap and team-management primitives this SOT
relies on are:

| Command | Purpose |
|---------|---------|
| `aw run <provider>` | Primary human entrypoint; guided onboarding + provider loop |
| `aw init` | Bind the current workspace using `.aw/team-cert.pem` (`POST /v1/connect`) |
| `aw id team create --name X --namespace Y` | Create team at awid |
| `aw id team invite --team X --namespace Y [--ephemeral]` | Create invite token |
| `aw id team accept-invite <token>` | Accept invite, receive certificate |
| `aw id team add-member --team X --namespace Y --member Z` | Add member directly (controller) |
| `aw id team remove-member --team X --namespace Y --member Z` | Remove member, post revocation |
| `aw id cert show` | Show current certificate |
| `aw claim-human --email <email>` | Attach an email to the aweb.ai account; triggers email verification; unlocks dashboard access after verification |
| `aw whoami` | Show team membership + certificate info |
| `aw workspace status` | Show team coordination state |

All coordination commands (mail, chat, tasks, claims, locks, roles,
instructions, work, contacts, etc.) are listed in
[`cli-command-reference.md`](cli-command-reference.md):

```
aw mail send/inbox
aw chat send-and-wait/send-and-leave/pending/open/history/listen
aw work ready/active/blocked
aw task create/list/show/update/close/reopen/delete
aw task comment/dep/stats
aw lock acquire/renew/release/revoke/list
aw roles show/list/set/activate/reset/deactivate
aw role-name set
aw instructions show/set/activate/reset
aw contacts list/add/remove
aw control pause/resume/interrupt
aw events stream
aw heartbeat
aw notify
aw mcp-config
```

---

## .aw/ directory

```
.aw/
  identity.yaml       # Persistent identity (did:aw, did:key, address)
  signing.key          # Ed25519 private key
  workspace.yaml       # Server URL, team address, alias, role
  team-cert.pem        # Current team certificate (auto-renewed)
```

### workspace.yaml (new format)

```yaml
server_url: https://app.aweb.ai/api
team_address: acme.com/backend
alias: alice
role: developer
human_name: ""
agent_type: agent
hostname: Mac.local
workspace_path: /Users/alice/project
canonical_origin: github.com/acme/backend
repo_id: ""
updated_at: "2026-04-06T..."
```

The identity fields live in `identity.yaml`. The credential is in
`team-cert.pem`. The workspace binding is minimal — it carries only the
server URL, the team address, the alias, the role, and the repo
metadata.

---

## awid API surface (what aweb depends on)

aweb makes these calls to awid. All are cached.

### Team resolution (on first agent connection or cache miss)

```
GET /v1/namespaces/{domain}/teams/{name}
→ {
    "team_id": "uuid",
    "domain": "acme.com",
    "name": "backend",
    "display_name": "...",
    "team_did_key": "did:key:z6Mk...",
    "visibility": "private" | "public",
    "created_at": "..."
  }
```

aweb caches the full team metadata (used for both certificate verification
via `team_did_key` AND public-team anonymous-read bypass via `visibility`).
See [Caching from awid](#caching-from-awid) above for cache TTL, stale window,
operational implications, and rotation propagation behavior.

### Address resolution (for message routing to external addresses)

```
GET /v1/namespaces/{domain}/addresses/{name}
→ {
    "did_aw": "...",
    "current_did_key": "...",
    "domain": "...",
    "name": "..."
  }
```

### DID resolution (for message signature verification)

```
GET /v1/did/{did_aw}/key
→ {
    "did_aw": "...",
    "current_did_key": "..."
  }
```

### Team revocation list (cached, for rejecting removed members)

```
GET /v1/namespaces/{domain}/teams/{name}/revocations?since=<timestamp>
→ { "revocations": [{ "certificate_id": "uuid", "revoked_at": "..." }] }
```

The `since` parameter enables incremental sync — only fetch new revocations
since last check. Cache TTL is the same as team metadata; see
[Caching from awid](#caching-from-awid) above.

Dashboard reads use cached awid visibility:

- `private` teams require `X-Dashboard-Token`
- `public` teams allow anonymous dashboard reads
- write routes still require certificate auth regardless of visibility

### That's it.

aweb does NOT call awid for:
- Team membership checks (certificate + revocation list handles this)
- Identity creation (awid's concern)
- Namespace management (awid's concern)
- Certificate issuance (CLI for BYOD, aweb-cloud for managed)
- Agent bootstrap (auto-provisioned from certificate)

---

## aweb API surface (what the dashboard depends on)

aweb-cloud's dashboard reads coordination data from aweb. These
endpoints are authenticated with a dashboard session token (not a team
certificate — the dashboard is a human viewer, not an agent).

### Team status

```
GET /v1/status?team_address=acme.com/backend
→ {
    "team_address": "acme.com/backend",
    "agents": [
      {
        "alias": "alice",
        "did_key": "...",
        "did_aw": "...",
        "role": "developer",
        "status": "active",
        "last_seen_at": "...",
        "hostname": "...",
        "workspace_path": "...",
        "claims": [...],
        "locks": [...]
      }
    ]
  }
```

### Message history

```
GET /v1/messages?team_address=acme.com/backend&limit=50
→ { "messages": [...] }
```

### Task list

```
GET /v1/tasks?team_address=acme.com/backend
→ { "tasks": [...] }
```

### Agent detail

```
GET /v1/agents/{alias}?team_address=acme.com/backend
→ { "alias": "alice", "role": "developer", ... }
```

### Dashboard auth

The dashboard authenticates to aweb using a short-lived
`X-Dashboard-Token` JWT issued by aweb-cloud, signed with a shared
secret (`AWEB_DASHBOARD_JWT_SECRET`). The JWT carries the list of
team_addresses the human has access to (derived from awid team
membership).

For the full spec — including the public-team anonymous-bypass behavior
and the fail-closed semantics on visibility lookup error — see
**Authentication > Dashboard auth** earlier in this document. The
companion spec on the cloud side is in the sibling `aweb-cloud` repo,
in `docs/aweb-cloud-sot.md`.

---

## MCP server

The aweb MCP server exposes coordination tools (mail, chat, tasks, etc.).

- Auth: certificate-based
- Scope: tools are scoped to the team from the certificate
- Identity signing tools are owned by awid, not aweb's MCP server

---

## Configuration

### Environment variables

```bash
# Required
DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb

# awid registry (required, no embedded mode)
AWID_REGISTRY_URL=https://api.awid.ai

# Dashboard JWT validation (shared secret with aweb-cloud)
AWEB_DASHBOARD_JWT_SECRET=

# Server
AWEB_PORT=8000
AWEB_LOG_JSON=true
```

---

## Responsibilities

| Concern | Owner |
|---------|-------|
| Identity creation and management | awid |
| Team creation and management | awid |
| Namespace management | awid |
| Team certificate issuance | CLI (BYOD) or aweb-cloud (managed) |
| Team membership verification | Certificate (local crypto) |
| Agent bootstrap | Auto-provisioned from certificate on `POST /v1/connect` |
| Custody (signing on behalf) | aweb-cloud (managed) or agent (self) |
| Billing | aweb-cloud |
| Dashboard | aweb-cloud |
| Human accounts | aweb-cloud |
| Coordination (mail, chat, tasks, claims, locks, roles, instructions) | aweb |
