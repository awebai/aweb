# aweb Server & CLI — Team Architecture Source of Truth

This document defines the exact shape of the aweb server and aw CLI
after the transition to awid teams. It is the implementation spec.

---

## Principles

1. **awid owns identity and team membership.** aweb never creates,
   stores, or manages identities. It never decides who is in a team.
2. **aweb owns coordination.** Mail, chat, tasks, roles, locks,
   workspaces, events. This is the only thing aweb does.
3. **Team certificates are the single credential.** No API keys.
   Agents authenticate every request with a DIDKey signature and a
   team certificate.
4. **team_address replaces project_id.** Every coordination table is
   scoped to a team_address (e.g., `acme.com/backend`). The concept
   of "project" as an aweb entity goes away.

---

## Authentication

### Request format

Every authenticated request carries two headers:

```
Authorization: DIDKey <did:key:z6Mk...> <base64-signature>
X-AWID-Team-Certificate: <base64-encoded certificate JSON>
```

The `Authorization` header is an Ed25519 signature over the canonical
JSON of the request payload + timestamp (same as today's DIDKey auth).

The `X-AWID-Team-Certificate` header is a team membership certificate
issued by the team controller at awid.

### Verification (mostly local crypto, one cached lookup)

1. Parse `Authorization` header → extract did:key and signature.
2. Extract public key from did:key.
3. Verify Ed25519 signature over canonical JSON payload. Reject if invalid.
4. Decode team certificate from `X-AWID-Team-Certificate`.
5. Verify certificate signature against the team's public key
   (cached from awid). Reject if invalid.
6. Verify certificate `member_did_key` matches the did:key from step 1.
7. Check certificate `certificate_id` against cached revocation list
   (fetched from awid periodically, TTL 5-15 min). Reject if revoked.
8. Extract team_address, alias, lifetime from certificate.
9. Request is authenticated and authorized for the given team.

Steps 1-6 are local crypto, no network. Step 7 is a cache lookup
(revocation list fetched periodically from awid).

### Caching from awid

aweb caches two things from awid per team:

**Team public key** (for certificate signature verification):
```
GET https://api.awid.ai/v1/namespaces/{domain}/teams/{name}
→ { "team_did_key": "did:key:z6Mk...", ... }
```
Cache TTL: 24 hours. Invalidated on team key rotation.

**Revocation list** (for checking removed members):
```
GET https://api.awid.ai/v1/namespaces/{domain}/teams/{name}/revocations
→ { "revocations": [{ "certificate_id": "...", "revoked_at": "..." }] }
```
Cache TTL: 5-15 minutes. This is the maximum window of stale access
after a member is removed.

### No API keys

The `api_keys` table is removed. There is no `aw_sk_*` token. The
team certificate is the sole credential. This eliminates:
- API key generation during bootstrap
- API key storage and lookup on every request
- API key rotation and revocation
- The key_prefix/key_hash columns and indices

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

### Tables removed (vs today)

| Removed table | Why |
|---------------|-----|
| `projects` | Replaced by `teams` |
| `api_keys` | Replaced by certificate auth |
| `spawn_invite_tokens` | Invites move to awid |
| `agents.did` column | awid owns identity |
| `agents.public_key` column | Embedded in did:key |
| `agents.custody` column | aweb-cloud manages custody for managed namespaces |
| `agents.signing_key_enc` column | aweb-cloud holds custodial signing keys |
| `agents.stable_id` column | Stored as `did_aw` (reference only) |
| `agents.program` column | Unused |
| `agents.context` column | Unused |
| `agents.access_mode` column | Team membership is the access control |
| `rotation_announcements` | awid audit log handles this |
| `rotation_peer_acks` | Gone with rotation_announcements |
| `agent_log` | awid audit log handles this |

### Tables simplified

| Table | Change |
|-------|--------|
| `agents` | 15 columns → 12 columns. No identity management. |
| `messages` | `project_id` → `team_address`. Drop `recipient_project_id`. |
| `chat_sessions` | `project_id` → `team_address`. |
| `tasks` | `project_id` → `team_address`. Assignee by alias, not agent_id. |
| `workspaces` | `project_id` → `team_address`. |
| All other tables | `project_id` → `team_address`. |

---

## API routes

### Removed routes

| Route | Why |
|-------|-----|
| `POST /v1/workspaces/init` | Replaced by certificate-based auto-provisioning |
| `POST /api/v1/create-project` | Teams created at awid |
| `POST /v1/spawn/create-invite` | Invites at awid |
| `POST /v1/spawn/accept-invite` | Invites at awid |
| `GET /v1/spawn/invites` | Invites at awid |
| `DELETE /v1/spawn/invites/{id}` | Invites at awid |
| `POST /v1/agents/register` | Agent auto-provisioned on first cert auth |
| `PUT /v1/agents/me/identity` | awid manages identity |
| `POST /v1/agents/me/identity/reset` | awid manages identity |
| `PUT /v1/agents/me/rotate` | `aw id rotate-key` at awid |
| `PUT /v1/agents/me/retire` | Team membership removal at awid |
| `PUT /v1/agents/{id}/retire` | Team membership removal at awid |
| `GET /v1/agents/me/log` | awid audit log |
| `POST /v1/custody/sign` | Moves to aweb-cloud (custody is aweb-cloud's concern) |
| All `/v1/did/*` routes | awid routes, no longer mounted |
| All `/v1/dns/*` routes | awid routes, no longer mounted |
| `POST /v1/agents/suggest-alias-prefix` | Alias comes from address or is auto-generated |
| `GET /v1/projects/current` | No projects, team info from certificate |

### Unchanged routes (team_address replaces project_id in scope)

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

### Unchanged coordination routes

| Route | Notes |
|-------|-------|
| `GET/POST/PUT/DELETE /v1/tasks/*` | All task operations |
| `GET/POST /v1/claims/*` | Task claims |
| `GET/POST/DELETE /v1/reservations/*` | Locks |
| `GET/POST /v1/roles/*` | Versioned roles |
| `GET/POST /v1/instructions/*` | Versioned instructions |
| `GET/POST /v1/repos/*` | Git repos |
| `GET/POST /v1/workspaces/*` | Workspace management |

### New routes

| Route | Purpose |
|-------|---------|
| `POST /v1/connect` | Agent connects with certificate. Auto-provisions team + agent if needed. Returns workspace binding info. Called by `aw init` under the hood. |
| `GET /v1/team` | Get team info (team_address, team_did_key, member count). |
| `GET /v1/usage` | Usage metrics for billing. Query params: `team_address`, `since`, `until`. Returns `{messages_sent, active_agents}`. Polled by aweb-cloud daily. |

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
team list. No awid call at request time.

Environment variable: `AWEB_DASHBOARD_JWT_SECRET` (shared with
aweb-cloud).

### Auth middleware change

Today: `get_actor_agent_id_from_auth()` extracts agent_id from API key.

New: `verify_team_certificate()` extracts team_address, did_key, alias
from the certificate. Looks up agent_id from `agents` table by
(team_address, did_key). If no agent row exists, auto-provisions one
(for the `POST /v1/connect` flow, the agent row is created; for other
routes, 401 if not connected).

---

## Agent lifecycle

### Permanent agent

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

### Removed

| Command | Why |
|---------|-----|
| `aw project create` | Teams created at awid |
| `aw spawn create-invite` | Team invites at awid |
| `aw spawn accept-invite` | Team invites at awid |
| `aw spawn list-invites` | Team invites at awid |
| `aw spawn revoke-invite` | Team invites at awid |
| `aw claim-human` | Dashboard reads from awid |
| `aw namespace add/verify/list/delete` | Namespaces at awid |
| `aw identity rotate-key` | `aw id rotate-key` (already exists) |
| `aw identity delete` | Team membership removal at awid |
| `aw identity access-mode` | Team membership controls access |
| `aw identity reachability` | awid address property |
| `aw identities` | `aw id show` covers this |

### New

| Command | Purpose |
|---------|---------|
| `aw id team create --name X --namespace Y` | Create team at awid |
| `aw id team invite --team X --namespace Y` | Create invite token |
| `aw id team invite --team X --namespace Y --ephemeral` | Create ephemeral invite |
| `aw id team accept-invite <token>` | Accept invite, receive certificate |
| `aw id team add-member --team X --namespace Y --member Z` | Add member directly (controller) |
| `aw id team remove-member --team X --namespace Y --member Z` | Remove member, post revocation |
| `aw id cert show` | Show current certificate |

### Changed

| Command | Change |
|---------|--------|
| `aw init` | No longer needs API key. Uses team certificate. |
| `aw init --server URL` | Presents certificate, auto-provisions at aweb. |
| `aw init --team X --ephemeral` | Creates ephemeral agent with temp cert. |
| `aw run` | Uses team certificate for auth. |
| `aw whoami` | Shows team membership + certificate info. |
| `aw workspace status` | team_address instead of project. Shows team info. |

### Unchanged

All coordination commands stay exactly the same:

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
  identity.yaml       # Permanent identity (did:aw, did:key, address)
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

Removed fields: `api_key`, `project_id`, `project_slug`,
`namespace_slug`, `identity_id`, `identity_handle`, `did`,
`stable_id`, `signing_key`, `custody`, `lifetime`.

The identity fields are in `identity.yaml`. The credential is in
`team-cert.pem`. The workspace binding is minimal.

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
    "team_did_key": "did:key:z6Mk...",
    "created_at": "..."
  }
```

aweb caches `team_did_key` for certificate verification. TTL: 24 hours.

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

Cache TTL: 5-15 minutes. The `since` parameter enables incremental
sync — only fetch new revocations since last check.

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

The dashboard authenticates to aweb using a session-scoped mechanism
(JWT or similar) that maps the human user to the teams they have
access to. The human's team access is determined by awid (the human
is a team member or a namespace controller). aweb-cloud handles this
mapping — aweb just checks that the dashboard token is valid for the
requested team_address.

Exact mechanism TBD by Alice in the aweb-cloud SOT.

---

## MCP server

The aweb MCP server stays. It exposes the same coordination tools
(mail, chat, tasks, etc). Changes:

- Auth: certificate-based instead of API key
- Tool: `sign` tool removed from aweb MCP (moves to awid MCP or
  standalone awid signing service)
- Scope: tools are scoped to the team from the certificate

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

Removed:
- `AWEB_CUSTODY_KEY` — custody is aweb-cloud's concern
- `AWEB_MANAGED_DOMAIN` — namespaces are awid's concern
- `AWEB_NAMESPACE_CONTROLLER_KEY` — namespaces are awid's concern
- `AWEB_API_KEY` / any API key config — certificates replace API keys

---

## What aweb does NOT do (and who does)

| Concern | Owner |
|---------|-------|
| Create/manage identities | awid |
| Create/manage teams | awid |
| Issue team certificates | CLI (BYOD) or aweb-cloud (managed) |
| Manage namespaces | awid |
| Verify team membership | Certificate (local crypto) |
| Manage API keys | Nobody (gone) |
| Bootstrap agents | Auto-provisioned from certificate |
| Custody (signing on behalf) | aweb-cloud (managed) or agent (self) |
| Billing | aweb-cloud |
| Dashboard | aweb-cloud |
| Human accounts | aweb-cloud |
