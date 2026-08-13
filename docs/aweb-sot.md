# aweb — Source of Truth

Status: **canonical normative contract for shipped aweb protocol, trust, and
security behavior**.

This is the canonical contract for the OSS coordination server (Python FastAPI)
and the `aw` CLI (Go). Implementers and operators must preserve its normative
authentication, identity, routing, delivery, and compatibility rules.

> **Mechanical inventory contract:** the current application-table and top-level
> REST-router inventories below are checked against ordered migrations and the
> FastAPI application mount source. Endpoint tables in this document describe
> selected normative routes, not an exhaustive OpenAPI listing. The live
> FastAPI `/docs` surface and live `aw <command> --help` remain the mechanical
> endpoint and command inventories. This distinction does not weaken the
> normative protocol or security rules in this contract.

awid (the public identity registry that aweb depends on) is described
in [`awid-sot.md`](awid-sot.md). The public hosted instance of aweb
runs at <https://app.aweb.ai>; anyone can self-host the same OSS server
against any awid registry.

For supporting reference material that does not redefine the contract:
- [`cli-command-reference.md`](cli-command-reference.md) — generated `aw` CLI
  reference; live `aw <command> --help` is direct command authority when
  generation lags
- [`mcp-tools-reference.md`](mcp-tools-reference.md) — MCP tool
  inventory and parameters exposed by aweb's MCP server
- [`self-hosting-guide.md`](self-hosting-guide.md) — operator runbook
  for the OSS stack
- [`identity-key-verification.md`](identity-key-verification.md) —
  normative rules for verifying `GET /v1/did/{did_aw}/key` responses
- [`global-local-identity-routing.md`](global-local-identity-routing.md) —
  supporting SOT for the shipped route-level global/local messaging contract
  and the legacy reachability/conversation-auth cleanup path
- [`product-authority-sot.md`](product-authority-sot.md) — supporting SOT for
  identity custody, addressability, team authority, runtime hosting, app
  portability, and the supported terminal/browser composition paths
- The aweb server's REST API is documented by the live FastAPI
  `/docs` OpenAPI viewer, auto-generated from route signatures.
  There is no hand-maintained `server-api-reference.md` — a previous
  version was deleted as stale drift and should not be recreated.
  Any future need for a human-readable API reference should be
  satisfied by pointing at the `/docs` endpoint.

---

## Principles

1. **awid owns identity and serves verification primitives for team
   membership** (team public keys and revocation list). Cert holders
   carry their own certificates and present them to any verifier. The aweb
   server never creates, stores, or manages identity private keys and never
   decides who is in a team — it verifies presented certs against the team's
   public key + revocation list. The `aw` CLI may orchestrate AWID identity and
   membership operations, but that does not transfer identity authority or key
   custody to the coordination server.
2. **aweb owns coordination.** Mail, chat, tasks, roles, locks,
   workspaces, events. This is the only thing aweb does.
3. **Team certificates are the credential for team-scoped coordination
   endpoints.** Agents authenticate tasks, roles, locks, instructions,
   workspace state, and other team-scoped requests with a DIDKey signature and
   team certificate. Identity-scoped mail/chat uses identity-only auth instead;
   a shared-team certificate is delivery authority only where the recipient's
   policy requires it. aweb's MCP server uses team-certificate auth on its local
   CLI mount. Hosted operators may layer additional auth modes (OAuth, opaque
   bearer tokens, etc.) on top of their own MCP surface, but those are
   operator-specific and outside the aweb OSS contract.
4. **team_id is the coordination scope for non-messaging state.** Tasks,
   claims, locks, roles, instructions, and presence are scoped to a
   `team_id` (e.g., `backend:acme.com`). **Messaging is
   identity-scoped, not team-scoped.** First contact to a global recipient uses
   a concrete address route (`domain/name`); continuations use stored
   participant route state. Delivery succeeds or fails based on the recipient's
   explicit `inbound_mode`: teams are not the routing scope for delivery, but
   verified same-team membership is delivery authority when the recipient uses
   `team_and_contacts`. See the Messaging section below for the full model.

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
- It may also store secret key material for a self-custodial global identity.
- A workspace belongs to one local machine/path, but it may be moved by moving
  the `.aw/` directory.
- A workspace has one active identity. A global-identity workspace may retain
  multiple team membership certificates and aweb workspace bindings, with one
  `active_team` default. A local identity remains single-team.
- Hosted OAuth MCP runtimes do **not** have a local workspace.

Multi-team membership for global identities is shipped behavior.
`.aw/teams.yaml` stores the membership list and active selection;
`.aw/workspace.yaml` stores the matching
per-team coordination bindings. `aw id team list`, `switch`, and `leave` manage
that state, `aw workspace status --all` reads across local memberships, and
most coordination commands accept `--team` as a one-command override without
changing `active_team`. Server-side coordination data remains team-scoped, so a
request still presents the certificate for the selected team rather than
combining authority across memberships.

### Identity

An **identity** is the principal the agent uses for messaging, coordination,
and trust.

Two identity scopes exist:

- **Local identity**: team-local and single-team. Has only `did:key`; it has no
  `did:aw` or public address. A local identity may remain durable across
  sequential runtime sessions. Removing a workspace path does not itself retire
  the membership certificate or release the member name.
- **Global identity**: durable, trust-bearing. Has both `did:key` and
  `did:aw`. It may have zero, one, or many public addresses; DID registration is
  independent of address assignment. Supports rotation, archival, and
  controlled replacement.

Trust continuity is only promised for global identities.

### Custody Modes

Global identities have two custody modes:

- **Self-custodial**: the agent holds its own Ed25519 private key locally,
  inside its `.aw/` workspace. Created only from the CLI. Cannot be used by
  hosted OAuth MCP runtimes. Created explicitly via `aw init --global
  --name <name>` — never as a side effect of a default flow.
- **Custodial**: the hosted service holds the encrypted private key. Created
  from the dashboard for hosted/browser MCP use. The dashboard creates
  global custodial identities, not generic "agents".

### Hosted vs BYOT Authority

Customer onboarding has exactly two supported authority shapes:

- **Fully Hosted**: a hosted operator owns namespace/team authority under its
  managed base domain, such as `*.aweb.ai`. That operator may create hosted
  namespaces, team certificates, addresses, and custodial identities. The OSS
  aweb server receives membership/runtime facts when a certified member calls
  `POST /v1/connect`; any additional operator projection adapter is outside the
  OSS server contract.
- **BYOT**: the customer brings the DNS-backed namespace and AWID team. The
  customer holds the namespace controller private key and team controller
  private key. A certified member projects into the OSS aweb server through
  `POST /v1/connect`; neither that path nor aweb stores or uses the customer
  namespace/team controller keys.

Identity custody remains independent of namespace/team authority. A BYOT
customer may use an operator-custodial agent identity, but the operator then
holds only the agent identity signing key. The customer must still authorize that identity into
the BYOT team and namespace with customer-held controllers.

The full onboarding and authority contract lives in
[`byot-onboarding-contract.md`](byot-onboarding-contract.md).

### Membership Facts vs Runtime Projections

AWID is the source of truth for identity, team, and certificate facts.
Aweb stores operational projections of those facts so an identity can
coordinate, receive messages, hold workspace state, and appear in dashboards.

One AWID identity may be a member of multiple AWID teams. Aweb therefore
keeps one `agents` row per team membership projection, not one global row per
`did:key` or `did:aw`. The same identity in two teams has separate team-scoped
aliases, policies, workspace projections, and lifecycle state. Identity-scoped
mail/chat still routes by the authenticated identity and stored participant
route; it must not guess one of those team rows.

The shipped OSS projection path is `POST /v1/connect`:

1. Verify the request signature and presented AWID team certificate against the
   current team public key and revocation view.
2. Ensure the local `teams` projection for the certificate's `team_id`.
3. Find or create the active `agents` projection by `(team_id, did_key)`,
   requiring its alias to match the certificate.
4. Find or create the corresponding team-scoped workspace projection and return
   its binding.

The uniqueness and conflict checks are target-team scoped. The same identity
can therefore connect to another team under that team's valid certificate, but
a different alias for an already active `(team_id, did_key)` or an alias held by
another active key in that team is a conflict. `aw id team add-member` changes
AWID certificate state only; it does not create aweb runtime state until the
member connects. Hosted or self-hosted operators may orchestrate the same
public AWID and connect primitives, but the aweb server does not receive a
namespace/team controller private key or gain certificate-signing authority.

### Alias vs Address

An **alias** is the routing name for a local identity:

- Internal/team scoped (e.g., `alice` within the team)
- Not the external public trust surface
- May be auto-assigned from a pool of standard names
- A local identity has exactly one alias

An **address** is the stable handle for a global identity:

- Only global identities have addresses
- A global identity may have more than one address
- Canonical external form is `namespace/name` (e.g., `acme.com/alice`)
- Public trust semantics attach to the global address, not to local
  aliases
- Address assignment is separate from delivery authorization; aweb delivery is
  controlled by `inbound_mode=open|team_and_contacts`

### Lifecycle: Delete vs Archive vs Replace

Three distinct lifecycle stories that must not be conflated:

- **Delete**: local workspace-path teardown. It does not by itself retire the
  identity's team membership, revoke its certificate, or release its member
  name; those require an explicit team-authorized retirement operation.
- **Archive**: global identity lifecycle cleanup with no continuity claim.
  Stops active participation, keeps history.
- **Replace**: global identity continuity via owner-authorized replacement
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

aweb has three authentication classes:

- **Team-certificate auth** for coordination and team-scoped routes:
  `Authorization`, `X-AWEB-Timestamp`, `X-AWID-Team-Certificate`, and,
  for request-bound v2, `X-AWEB-Signed-Payload`.
- **Identity-only auth** for identity-scoped messaging routes:
  `Authorization`, `X-AWEB-Timestamp`, and optional `X-AWEB-DID-AW`. A
  global caller must send its `did:aw`; a local caller omits the header.
- **Identity-grant auth** for messaging routes only: a session key acting
  as a durable identity under a scoped, expiring, revocable grant.
  `Authorization: AWEB-Grant DIDKey <session did:key> <sig>`,
  `X-AWEB-Grant-ID`, `X-AWEB-Timestamp`, and a **mandatory** request-bound
  `X-AWEB-Signed-Payload` (canonical JSON `{v: 1, auth: "identity-grant",
  method, path, grant_id, body_sha256, timestamp, aud}`). The server
  requires the grant row (`identity_session_grants`) to be unrevoked and
  unexpired, the session `did:key` to match the registered
  `grant_did_key`, and the request to fall inside the grant's scopes
  (`mail.read`, `mail.send`, `chat.read`, `chat.send`; `GET /v1/agents`
  is allowed for recipient resolution). Everything else — including
  minting or revoking grants — is refused. Actions resolve to the subject
  identity for attribution; `certificate_id` carries `grant:<grant_id>`
  provenance. Grants are minted and revoked only under team-certificate
  auth via `/v1/identity-grants`.

```
Authorization: DIDKey <did:key:z6Mk...> <base64-signature>
X-AWEB-Timestamp: <RFC 3339 UTC timestamp, e.g. 2026-04-09T08:47:23Z>
X-AWID-Team-Certificate: <base64-encoded certificate JSON; team auth only>
X-AWEB-Signed-Payload: <optional base64url canonical JSON for team-auth v2>
X-AWEB-DID-AW: <optional did:aw; global identity-only auth only>
```

Team-certificate routes accept two signed envelopes:

- **Compact v1 compatibility:** canonical JSON of `{team_id, timestamp,
  body_sha256}`.
- **Request-bound v2:** canonical JSON containing `v: 2`, `aud`, `method`,
  the raw request `path` including query, `team_id`, `body_sha256`, and
  `timestamp`, carried byte-for-byte in `X-AWEB-Signed-Payload`.

The server verifies v2's audience, method, path, team, timestamp, and body hash
against the live request. Both versions use the signed timestamp's 300-second
skew window and have no nonce store, so they are request-integrity envelopes,
not replay-proof envelopes: an identical signed request can be replayed inside
the accepted window.

For identity-only auth, the signed canonical JSON is
`{did_aw, timestamp, body_sha256}`. `did_aw` is exactly the trimmed
`X-AWEB-DID-AW` value, or the empty string when the header is absent. A global
caller sends the header; the server resolves that DID through AWID and requires
its current `did:key` to match `Authorization`. A local caller omits it, signs
the empty value, and remains bound by its `did:key` plus an unambiguous local
runtime projection. These messaging routes do not require a team certificate.

Identity-scoped messaging routes route by authenticated DID and address, not
by local team membership. If a global `did:aw` has multiple active local
team rows, messaging by DID/address must proceed without selecting a team
context. Team-scoped operations and alias-scoped coordination still require a
team certificate or another unambiguous team selector, and must reject
ambiguous identity-only context rather than guessing a team.

The `X-AWEB-Timestamp` header carries the signed request timestamp in
RFC 3339 UTC format. Servers reject requests outside the allowed clock-skew
window of +/-300 seconds against the server wall clock.

Canonical JSON means:

- keys sorted lexicographically
- compact separators with no extra whitespace
- UTF-8 encoded bytes

The `Authorization` signature bytes are base64 encoded using the
standard RFC 4648 alphabet with no `=` padding.

The `X-AWID-Team-Certificate` header is a team membership certificate
issued by the team controller at awid. A base64 team certificate is on
the order of 500–1000 bytes and is included on every request that uses
team-certificate auth, not identity-only requests. For long-lived SSE
connections this is a one-handshake cost
and negligible. For high-frequency unary HTTP requests it adds
sub-millisecond and bytes-of-overhead per call. v1 ships with
cert-on-every-request; if measured workloads show the per-request cost
is material, a session-token shortcut may be added later, but the cert
remains the canonical credential.

### Verification (local crypto plus registry reads)

1. Parse `Authorization` → extract did:key and signature, then enforce the
   signed timestamp's ±300-second skew.
2. Compute the request-body SHA256 digest.
3. For team-certificate auth, select compact v1 when
   `X-AWEB-Signed-Payload` is absent; otherwise decode canonical v2 and bind all
   request fields listed above. Verify the Ed25519 signature over the selected
   canonical bytes.
4. Decode `X-AWID-Team-Certificate`; resolve the current team public key from
   AWID; verify the controller signature; require
   `certificate.member_did_key` to match the signing did:key; and reject a
   certificate listed in AWID revocations.
5. For identity-only auth, verify canonical JSON of `{did_aw, timestamp,
   body_sha256}`. A non-empty `did_aw` must resolve to the signing key and binds
   a global caller; an empty value binds a local caller by `did:key`, with local
   projection lookup required to be unambiguous. No team certificate is
   required for that path.
6. Team-certificate routes extract coordination `team_id`, alias, identity
   scope, and certificate id from the verified certificate. They then resolve
   the matching active aweb runtime projection.

Signature and certificate checks are local crypto. Team-key and revocation
reads use AWID; they are Redis-backed cache reads only when aweb was started
with Redis, as described below.

### Caching from awid

Current standalone and library application startup requires Redis and constructs
AWID's `CachedRegistryClient`, sharing entries across every aweb instance using
that backend. The internal client builder has an uncached fallback for direct
library/testing use, but no standard server startup mode omits Redis; operators
must plan around the cache policy below.

The cached client applies the same policy to the two team-auth inputs:

- **Team metadata** from
  `GET /v1/namespaces/{domain}/teams/{name}` supplies the current
  `team_did_key` and dashboard `visibility`.
- **Revocations** from
  `GET /v1/namespaces/{domain}/teams/{name}/revocations` supplies revoked
  certificate ids.

Both entries are fresh for **600 seconds (10 minutes)** and remain available
for one additional **600-second stale-while-revalidate window**. A read during
that second window returns the stale value and schedules a background refresh.
After 1,200 seconds the Redis entry has expired; the request performs a
synchronous AWID read, and a failed read follows the route's fail-closed/error
behavior. These values come from `_TEAM_METADATA_CACHE_TTL_SECONDS`,
`_TEAM_REVOCATIONS_CACHE_TTL_SECONDS`, and `_STALE_MULTIPLIER` in
`awid/src/awid/registry.py`. The checked source facts are:

<!-- BEGIN SOURCE INVENTORY: aweb-awid-cache -->
- `team_metadata_fresh_seconds=600`
- `team_metadata_stale_seconds=600`
- `team_revocations_fresh_seconds=600`
- `team_revocations_stale_seconds=600`
<!-- END SOURCE INVENTORY: aweb-awid-cache -->

Identity-only auth uses separate Redis entries for the current `did:aw` key and
its reverse address list. Each is fresh for 300 seconds and retained for one
additional 300-second stale window. A fresh key-and-address cache hit makes zero
AWID HTTP requests. During the existing stale window, a previously verified key
may continue to authenticate only when it equals the request's signing key;
refresh runs in the background, and an upstream 429 does not widen the window.
Once Redis expires the entry at 600 seconds, an unsuccessful refresh fails the
request. A signing key that differs from the cached binding always forces a
foreground current-key read; 429 or registry unavailability on that read fails
closed and never turns the differing key into an accepted binding. Thus stale
handling can extend an already verified binding within the shipped bound, but
cannot accept a new binding.

When `AWID_SERVICE_TOKEN` is configured, the aweb RegistryClient sends it in
`X-AWID-Service-Token` only to the exact configured home registry. AWID may use
it to exempt the `did_key` and `did_addresses` reads from public IP limits. The
client never forwards it to DNS-discovered external registries. A missing token
emits `awid_service_credential_missing` once at aweb startup and uses public
limits; AWID emits `awid_service_credential_rejected` when a presented token is
wrong. Operators count those stable events through log/Sentry telemetry.
Rotating this shared secret is a coordinated two-service configuration change.

**Team-key rotation.** AWID rotates a team key at
`POST /v1/namespaces/{domain}/teams/{name}/rotate`. With the Redis cache, aweb
may continue reading the old key for up to 20 minutes. Old-key certificates may
continue to verify during that stale interval, while certificates signed by the
new key fail closed until refresh. Deleting that team's exact metadata and
revocation cache entries is the operator's immediate invalidation mechanism;
this contract does not promise a broad key-prefix flush command.

**Revocation.** A newly revoked certificate may continue to verify for up to
the same 20-minute maximum. This cache window is the only supported timing
claim; no narrower refresh interval is promised.

---

## Database schema

aweb uses a single PostgreSQL schema: `aweb`.

### Migrations

Migrations live at `server/src/aweb/migrations/aweb/NNN_name.sql`.
The `pgdbm` migration manager applies them in order against the
`aweb` schema with `module_name='aweb-aweb'`. Each applied
migration is recorded in `aweb.schema_migrations` with its
filename and a checksum of the file contents.

**Deployed migrations are immutable.** Once a migration has been
applied to any database (staging, prod, or even just landed on a
branch ahead of you), the checksum is recorded. Editing the file
trips pgdbm's checksum guard on the next apply attempt — the
manager refuses to apply, and the only path off that state is a
destructive schema cutover.

The recovery path for any post-apply adjustment is **always a new
forward migration**, never editing an existing one. Concrete cases:

- **Constraint addition fails** because pre-existing data violates
  the constraint: file `NNN+1_repair_then_constrain.sql` that
  data-repairs offending rows first, then adds the constraint.
- **Migration partially applied** (e.g., DDL succeeded but a row
  insert mid-way failed): file a new migration to complete the
  intended state. Don't try to edit the failed one to "patch up."
- **Default value needs to change** for an already-applied column:
  file a new migration with `ALTER COLUMN ... SET DEFAULT`.
- **Table or column needs renaming**: file a new migration with
  the rename. Don't edit the original CREATE TABLE.

The principle holds across every deployment using pgdbm (the aweb server,
AWID service, and any hosted operator schema). Once shipped, immutable.

### Current table inventory

The following list is exhaustive for current **aweb application tables declared
by** the ordered component migration chain. It intentionally excludes pgdbm's
manager-created `schema_migrations` metadata table.
`scripts/check_sot_source_inventories.py` derives the list from
`server/src/aweb/migrations/aweb/*.sql`, applies `CREATE`/`DROP` events,
preserves first-creation order, and deduplicates guarded repeated creation
(currently `chat_message_reads` in the orphan guard and its canonical
migration). Column, constraint, and index
authority remains the ordered SQL itself; this SOT does not duplicate that DDL.

<!-- BEGIN SOURCE INVENTORY: aweb-tables -->
- `teams`
- `agents`
- `conversations`
- `conversation_participants`
- `messages`
- `chat_sessions`
- `chat_participants`
- `chat_messages`
- `chat_read_receipts`
- `contacts`
- `control_signals`
- `repos`
- `workspaces`
- `tasks`
- `task_comments`
- `task_dependencies`
- `task_counters`
- `task_root_counters`
- `task_claims`
- `reservations`
- `team_roles`
- `team_instructions`
- `audit_log`
- `federated_message_deliveries`
- `agent_encryption_keys`
- `app_registry_apps`
- `app_registry_entries`
- `team_app_installs`
- `app_registry_event_types`
- `app_registry_emit_keys`
- `app_events`
- `app_event_subscriptions`
- `session_admission_leases`
- `chat_message_reads`
- `lifecycle_side_effect_outbox`
- `federation_did_checkpoints`
- `federation_address_authority_cohorts`
- `federation_authority_fences`
- `federation_authority_leases`
- `federation_authority_results`
- `federation_authority_permits`
- `federation_authority_token_buckets`
- `message_ingress_receipts`
- `federation_mutation_outbox`
- `identity_session_grants`
<!-- END SOURCE INVENTORY: aweb-tables -->

---

## API routes

### Mounted REST router inventory

The exhaustive top-level REST router inventory below is derived from
`app.include_router(...)` calls in `server/src/aweb/api.py` and checked by
`scripts/check_sot_source_inventories.py`. Names are module/family names, not a
promise that the selected endpoint tables later in this document list every
operation. `/mcp` is an ASGI mount and therefore is intentionally not a REST
router entry.

<!-- BEGIN SOURCE INVENTORY: aweb-routers -->
- `agents`
- `apps`
- `connect`
- `chat`
- `dashboard`
- `claims`
- `contacts`
- `conversations`
- `events`
- `federation`
- `identity_grants`
- `messages`
- `reservations`
- `session_leases`
- `service_registration`
- `status`
- `instructions`
- `roles`
- `tasks`
- `workspaces`
- `repos`
<!-- END SOURCE INVENTORY: aweb-routers -->

### Bootstrap and team metadata

| Route | Purpose |
|-------|---------|
| `POST /v1/connect` | Agent connects with certificate. Auto-provisions team + agent if needed. Returns workspace binding info. Called by `aw init` under the hood. |
| `GET /v1/team` | Get team info (team_id, team_did_key, member count). |
| `GET /v1/usage` | Per-team usage metrics. Query params: `team_id`, `since`, `until`. Returns `{messages_sent, active_agents}`. Auth: dashboard JWT via `X-Dashboard-Token`, not team certificate. Intended for operator billing and metering rather than agent traffic. |

### Messaging

Messaging is **identity-scoped**: global first contact uses a concrete
address route (`domain/name`), and continuations use stored participant route
state. The sender proves their identity via a DIDKey signature. Delivery
succeeds or fails based on the recipient's explicit `inbound_mode`; verified
shared team membership authorizes delivery when the recipient uses
`team_and_contacts`.

**Two independent layers control addressing and delivery:**

1. **Address resolution (awid):** can the sender resolve the recipient's
   concrete address to `did:aw`, current `did:key`, and address-route delivery
   origin? Legacy address visibility metadata is compatibility/audit state only
   and is not live delivery authorization.

2. **Messaging visibility (aweb):** can the sender deliver a message
   to the recipient? Gated by the recipient's `inbound_mode` field.
   `open` accepts valid senders after identity/route binding;
   `team_and_contacts` accepts verified same-team members plus exact active
   identity contacts for the verified sender address.

**Strict cross-registry sender authority:** the receiver's configured home AWID
client continues to serve its own identities, teams, and ordinary same-registry
reads. A global sender from an external registry is verified through a separate
strict external-address path selected only by the client-signed sender address.
Wrapper registry hints, the home client's fallback, general caches, TOFU pins,
and bare `did:aw` never select external authority. The path verifies DNS
controller, exact namespace/address/DID/key/origin, and a genesis-anchored DID
log before PostgreSQL compare-and-swap commits the checkpoint and complete
address-authority cohort. `POST /v1/federation/messages` is the single inbound
route for plaintext-v1 and encrypted-v2. It verifies protected sender bytes
before external work: plaintext uses `signed_payload.from`, encrypted-v2 uses
`encrypted_envelope.from.address`, and any wrapper address must match. A missing
wrapper is filled only for a protected `domain/name`; a historical protected DID
continues only through its exact stored participant locator. Sender origin is
derived from verified evidence when absent and must match that evidence when
present.

A committed cohort may be reused for at most 60 seconds. The setting
`AWEB_FEDERATION_AUTHORITY_REUSE_SECONDS` defaults to 60 and accepts only 1..60.
Expiry forces the complete DNS/namespace/address/key-or-log/origin read.
This is only a receiver reuse ceiling: it is not a revocation, reassignment,
rotation-detection, or global freshness SLA. DNS or registry authority can
suppress an unseen transition indefinitely by continuing to serve an old but
cryptographically valid state. PostgreSQL is the shared authorization and
coordination store; Redis and process-local caches are not an outage fallback,
so coordination failure fails cross-registry ingress closed.

Same-registry outbound resolution first checks locally visible recipients and
keeps the signed address/DID/key/origin contract before registry resolution.
Local `did:key` continuation remains compatible only through an exact active
conversation/session participant and learned route; unknown local first contact,
route injection, and incompatible target current keys fail closed. Target
registry dependency failure returns
`federation_authority_coordination_unavailable` (503, retryable) with exception
logging preserved.

**Receiver-wide replay identity:** every accepted local or federated mail/chat,
plaintext or encrypted, claims one `message_ingress_receipts` row keyed solely
by `message_id`. An exact federated canonical-envelope retry returns the stored
established result with no duplicate effects. Local-path and historical receipts
are `legacy_unreplayable`: they are never federation/cross-kind replay authority
and permanently block a later insert claim after message deletion. Existing
local API idempotency may still return its row before attempting an insert.
Reusing the UUID with any different kind, sender, target,
conversation/session, signature, signed payload, or protected encrypted bytes
returns `federation_message_replay_conflict`. Receipt, message,
conversation/session, participant, contact, route, and durable
`federation_mutation_outbox` effects commit atomically. Historical backfill that
cannot reconstruct the original envelope records `legacy_unreplayable`; any
attempt that reaches a new receipt claim conflicts, and an existing historical
mail/chat UUID collision stops migration for explicit operator repair. Receipt
permanence prevents UUID reuse after message GC. The historical `federated_message_deliveries` table may remain for
compatibility but receives no new claims and is not replay authority after
activation.

**Read semantic (authoritative): mail is marked read when it is PRESENTED to
the agent — never on transport-send alone, and never withheld under a
never-ack policy.** Presentation is surface-specific but always concrete: the
Claude MCP channel notification is the presentation (ack at notification); Pi
acks after `pi.sendMessage` accepts the injection; native `aw run` acks after a
successful provider run. The failure mode is a rare host-drop between
transport-send and presentation, and it splits into two sub-cases that recover
differently. If the transport send itself fails, the ack is skipped, the message
stays unread, and the next reconnect re-fetches it (the inbox pulls unread only)
— auto-recovered. If the transport send succeeds and the ack fires but the
process dies before the harness presents the message, the message is already
read server-side, so an unread-only reconnect does NOT re-fetch it and it is
absent from the unread inbox; its content is still on the server and reachable
via `aw mail show --message-id <id>` or a read-inclusive view, but it is not
auto-recovered.
(Auto-surfacing that second sub-case on reconnect was considered and
deliberately rejected: re-delivering already-read mail would reopen the
replay/double-action hazard, and a crashed agent recovers procedurally on
restart, so singling out one message would dress a general crash up as a
delivery defect. See default-aaka.) Acking before presentation (the original defect) risks
silent message loss; never acking (manual-only) leaves mail unread so the server
re-delivers it on every reconnect — the replay burst regression (default-aajy).
`aw mail ack` is the authenticated recipient-side read transition. For unread
recipient mail, the endpoint idempotently sets `read_at`; that removes the
message from unread inbox and actionable reconnect delivery, and emits
`message.acknowledged` only when the state changes. The command does not itself
prove downstream presentation, so a harness must call it at the correct
post-presentation acknowledgement point. It is not a sender-owned receipt API.

**Contacts** are stored per-identity in aweb. Contacts management:
`POST/GET/DELETE /v1/contacts`. For display and address-book UX, a contact may
carry labels or handle metadata. For delivery authorization, stale
exact-contact-only compatibility input maps to `team_and_contacts`; contacts
authorize non-team delivery only through an exact active identity contact bound
to the owner identity, verified sender's concrete `domain/name` address, and
sender `did:aw`. Domain-level entries, pending contacts, handle contacts, and
labels/display names do not authorize delivery.

Address-only legacy contacts have no `contact_did_aw` and remain inert for
cross-registry authorization until the authenticated owner explicitly binds
them after fresh strict resolution with `POST /v1/contacts/{contact_id}/bind`.
A binding is either all-null legacy state or a complete `contact_did_aw`,
`binding_controller_did`, and `binding_accepted_at` tuple. Creating a new contact
is explicit acceptance of the resolved address/DID/controller binding. Accepted
global-to-global ingress creates that identity-bound sender contact atomically
only when no contact already occupies the owner/address; it never rewrites an
address-only or differently bound row. Moving an existing contact from an old
DID to a new address holder additionally requires exact old DID, current
namespace-controller-signed old/new/address/timestamp proof, strict authority
for the new DID/controller, exact-old compare-and-swap,
`accept_reassignment=true`, and authenticated owner acceptance. Address
reassignment or remove/recreate never silently transfers the old contact or
conversation.

**Auth for messaging endpoints:** the sender authenticates with a
DIDKey signature over `{body_sha256, did_aw, timestamp}`. A global sender puts
its `did:aw` in `X-AWEB-DID-AW`; a local sender omits the header and signs an
empty `did_aw`. A team certificate is not required for messaging. The server
resolves a supplied global identity through AWID; local identity-only auth
requires an unambiguous active local projection. Delivery then evaluates the
recipient's `inbound_mode` against the verified sender identity/address and any
verified shared-team authority.

**Recipient resolution:** first-contact global mail/chat uses an address
(`domain/name`) resolved via awid. A bare external `did:aw` is an identity
binding, not a delivery route, and first-contact delivery fails closed unless an
existing conversation/session supplies stored participant route state. Aliases
within a shared team remain backwards-compatible local shorthand.

Global address resolution is governed by the cross-service
[`identity-messaging-contract.md`](identity-messaging-contract.md). Stable
failure bodies and exact HTTP/retryability compatibility are generated in
[`federation-error-reference.md`](federation-error-reference.md). In short:
awid is authoritative for `domain/name` address bindings, current keys, and
address-route delivery metadata. Legacy reachability/visibility request fields
are accepted and ignored at AWID compatibility boundaries; migration 003
removed the corresponding stored columns, so they are not live delivery
authority or current registry state. Aweb cached global
identity rows are routing/cache state, not address authority. If a global
direct-address send cannot be resolved through awid, aweb may use a local
cached global row only when the client supplied a signed recipient binding that
matches that row. Bare local fallback must fail closed.

**Signed payload integrity:** if a messaging request carries
`signed_payload`, the route enforces that the signed envelope and the
outer request agree on all behavior-shaping fields. This includes
mail/chat content and routing fields (`body`, `subject`, `priority`,
`type`, `from_did`, `from_stable_id`, `to`, `to_did`, `to_stable_id`,
`message_id`, `timestamp`) plus chat modifiers (`reply_to`,
`leaving`, `hang_on`, `wait_seconds`). Any mismatch returns HTTP 422.

**Recipient binding validation:** if a sender supplies more than one
recipient identifier (`to_stable_id`, `to_did`, `to_address`,
`to_agent_id`, `to_alias`), all provided selectors must resolve to the
same target agent. Conflicting bindings return HTTP 422 instead of
silently choosing one selector by precedence.

**Mutation event attribution:** aweb mutation contexts backfill and
carry the authenticated caller's canonical `did:aw`
(`actor_did_aw` / `from_did_aw` / `holder_did_aw`) so downstream event
consumers and billing attribution operate on the stable identity, not a
transient `did:key`.

| Route | Notes |
|-------|-------|
| `POST /v1/messages` | Send mail by address first contact, stored-route continuation, or local alias. Auth: DIDKey signature. Delivery gated by recipient `inbound_mode`. Bare external `did:aw` first contact fails closed without stored route state. |
| `GET /v1/messages/inbox` | Newest-first inbox page for the authenticated agent (across all teams). Returns `has_more` and `next_cursor`; pass `cursor` to continue. Auth: DIDKey signature. |
| `GET /v1/messages/{id}` | Read one exact message as its authenticated sender or recipient without changing read state. Unrelated and absent ids both return 404. |
| `POST /v1/messages/{id}/ack` | Recipient-only mark as read; sender and unrelated callers receive 404. |
| `POST /v1/chat/sessions` | Create chat session by address first contact, stored-route continuation, or local alias; bare external `did:aw` first contact fails closed without stored route state |
| `GET /v1/chat/pending` | Pending chats for the authenticated agent |
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
| `POST /v1/agents/suggest-alias-prefix` | Suggest the next available classic alias prefix |
| `GET /v1/agents` | List team agents |
| `PATCH /v1/agents/me` | Update workspace info |
| `POST /v1/agents/{alias}/replace-key` | Compare-and-swap a local identity key and append the audit record; auth is a request signature by the team's controller `did:key`, not member team-cert auth |
| `POST /v1/agents/{alias}/control` | Control signals |
| `GET /v1/conversations` | List conversations visible to the authenticated identity across mail and chat. Auth: MessagingAuth (identity-scoped, not team-scoped). |
| `GET /v1/contacts` | List contacts |
| `POST /v1/contacts` | Add an identity-bound contact after strict resolution |
| `POST /v1/contacts/{contact_id}/bind` | Bind an inert contact or explicitly accept a controller-proved reassignment |
| `DELETE /v1/contacts/{id}` | Remove contact; deletion does not transfer its trust binding |

`POST /v1/agents/suggest-alias-prefix` uses the normal team-certificate
auth for coordination routes. The request body is empty (`{}`). On
success it returns `{ team_id, name_prefix }`. If no classic alias
is available, it returns HTTP 409 with detail `alias_exhausted`.

`PATCH /v1/agents/me` may carry `repo_origin` as mutable workspace metadata.
The server canonicalizes the origin, ensures the team-scoped repo row, binds
the calling workspace to it, transitions stored `workspace_type` to `agent`
(rendered as `repo_worktree` context), and returns `repo_id` plus
`canonical_origin`. Omitting `repo_origin` preserves both repo binding and
workspace type; empty or invalid origins are rejected, and there is no repo
unbind operation in this path. The CLI uses this path during heartbeat to
repair stale or missing repo
bindings. `aw heartbeat` reports `repo_status` (`repaired`, `current`,
`unavailable`, or `repair_failed`) and the canonical binding when available so
the repair is observable. Repo association remains workspace state.

`POST /v1/connect` also retains a `repo_origin` compatibility field. When it is
non-empty, the server canonicalizes it, ensures the team-scoped repo row, and
binds that repo to the workspace; a newly created workspace is typed `agent`.
An invalid origin returns HTTP 422. Omitting the field leaves an existing repo
binding unchanged and creates a new workspace as `manual`. The current `aw
init` client intentionally omits `repo_origin`; heartbeat's
`PATCH /v1/agents/me` path performs the normal observable binding/repair.

`POST /v1/agents/{alias}/replace-key` is deliberately controller-authorized.
Its signed payload binds team, alias, expected old and proposed new `did:key`,
old/new certificate ids, operation, and timestamp. The server updates only a
`local` agent row with an exact-old-key compare-and-swap and writes
`local_identity_key_replaced` to `audit_log` in the same database transaction.
An exact controller-authorized replay (all DID and certificate fields match)
returns the original audit result, so a lost committed response can be safely
reconciled; a different request for the already-installed new key conflicts.
A member key — including the old key — cannot authorize this route.

### Coordination

| Route | Notes |
|-------|-------|
| `GET/POST/PUT/DELETE /v1/tasks/*` | All task operations |
| `GET/POST /v1/claims/*` | Task claims |
| `GET/POST/DELETE /v1/reservations/*` | Locks |
| `GET/POST /v1/roles/*` | Versioned roles |
| `GET/POST /v1/instructions/*` | Versioned instructions |
| `GET/POST /v1/repos/*` | Git repos |
| `GET/POST/DELETE /v1/workspaces/*` | Workspace management |

`GET /v1/workspaces/team` is a bounded coordination roster. Active presence
ranks ahead of offline workspace history; recency ranks next, and claims are a
tiebreaker rather than evidence that an offline workspace is currently
relevant. When more matching workspaces exist than the requested limit, the
response sets `has_more=true`. Human CLI output must state plainly when this
bounded response is incomplete.

Task claims have no time-based expiry or implicit lease in v1.
`GET /v1/tasks/active` includes `owner_last_seen_at` for claim-backed tasks.
Active-work reads report claim age together with the claimant workspace's last
activity; workspace status also exposes claim age alongside workspace presence
recency.
`aw work active` human and JSON output use neutral evidence bands: `under a
day` (<24 hours), `days` (<7 days), `weeks` (<30 days), `months` (30 days or
more), or `unknown`. These boundaries are display groupings, not ownership or
release policy. Claim age alone never makes a claim stale: an old claim held by
a live or recently active workspace is not a review candidate merely because
of its age. The coordinating role considers claim age and claimant inactivity
together, contacts the claimant when practical, and records the disposition in
a task comment before any explicit status or assignment change. This lifecycle
is visibility-only: no request, heartbeat, scheduled job, or read path
silently releases claims.

Any future automatic release requires a separate policy amendment defining an
explicit per-claim renewal signal, grace and notification behavior, human
override, a durable actor-and-reason audit record, and atomic updates to claim,
task status, assignment, and workspace focus. Display age bands must not be
reused as automatic-release thresholds.

`DELETE /v1/workspaces/{workspace_id}` soft-deletes a gone local
workspace and its bound agent row, plus releases any task claims held by
the workspace. It returns `409` if the bound agent is global
(global identities outlive workspaces) or if `last_seen_at` is
within the 30-minute presence TTL and the workspace is not yet
considered gone. The caller must present a team certificate for the same
`team_id` as the target workspace.

Lifecycle Redis effects are driven by `lifecycle_side_effect_outbox`, not by
reconstructing deleted claim rows. Claim release captures workspace/team
unclaim events, chat-waiting cleanup, and presence cleanup in the same
PostgreSQL transaction as the lifecycle mutation. A nested cascade therefore
makes no Redis effect visible when its savepoint is released: rows become
replayable only after the caller's outer transaction commits, and outer
rollback leaves no durable intent to publish. Plain database-handle cascades
commit and attempt replay before returning. A transaction-handle cascade
returns its `LifecycleCascadeResult.outbox_operation_id`; an outer caller that
requires synchronous post-commit effects invokes the canonical
`replay_lifecycle_side_effects(..., operation_id=...)` only after its own
transaction exits.

Replay locks pending rows and records each delivered effect so an ordinary
retry does not publish it twice. Chat-waiting delivery uses a strict Redis path;
failures remain pending rather than inheriting the best-effort SSE-disconnect
semantics. Failed global rows receive a persisted, bounded exponential retry
schedule, and recovery selects only due rows in bounded batches so a full
failed batch cannot starve later healthy work. Operation-specific replay may
retry its own rows immediately after an outer commit. Delivery is at-least-once
across a process crash: a crash after Redis accepted an effect but before
`delivered_at` commits may replay it. Lifecycle events remain wake/state-change
hints; consumers read PostgreSQL state as truth. Failed rows stay durable for a
later request/startup replay, and startup/embedded request paths trigger
canonical replay without a host-specific outbox protocol.

### Dashboard routes

These routes let an external dashboard service read team-scoped
coordination data on behalf of a human user. Authenticated with a
short-lived JWT in the `X-Dashboard-Token` header (see Dashboard auth
below). The dashboard service is opaque to aweb — it can be any
upstream operator that holds `AWEB_DASHBOARD_JWT_SECRET`.

| Route | Purpose |
|-------|---------|
| `GET /v1/teams/{team_id}/agents` | List active agents in team |
| `GET /v1/teams/{team_id}/agents/{alias}` | Agent detail |
| `GET /v1/teams/{team_id}/messages` | Message history |
| `GET /v1/teams/{team_id}/tasks` | Task list with query params `status`, `assignee_alias`, `task_type`, `priority` (`P0`-`P4`), `labels`, `q`, `limit`, and `cursor`. Returns `{tasks, has_more, next_cursor}`. |
| `GET /v1/teams/{team_id}/claims` | Active task claims |
| `GET /v1/teams/{team_id}/events/stream` | Dashboard SSE stream. Subscribe to `team-events:{team_id}` before building the initial snapshot, then stream dashboard-shaped events `task.created`, `task.status_changed`, `task.claimed`, `task.unclaimed`, `message.sent`, `agent.online`, and `agent.offline`. First frames are `connected` then `snapshot` with current `online_aliases` and `active_claims`. |
| `GET /v1/teams/{team_id}/roles/active` | Active role definitions |
| `GET /v1/teams/{team_id}/instructions/active` | Active instructions |
| `GET /v1/teams/{team_id}/status` | Team status (online agents, locks, claims) |

### Dashboard auth

aweb verifies a short-lived JWT in the `X-Dashboard-Token` header on
every dashboard read. The JWT is minted by an upstream dashboard
service (any operator that has provisioned a human-account layer on
top of aweb) and signed with a secret shared between that service and
aweb. The token carries the list of `team_ids` the human is
authorized to read; aweb checks the requested `team_id` against
that list.

**Algorithm**: HS256 (HMAC-SHA256) using `AWEB_DASHBOARD_JWT_SECRET`.
The secret MUST be identical between aweb and whichever upstream
service mints the dashboard tokens. The `alg` header MUST be `HS256`
— aweb's verifier rejects any other algorithm including `none` and
asymmetric algorithms (defense against the alg-confusion class of JWT
bugs).

**Payload**:
```json
{
  "user_id": "uuid",
  "team_ids": ["default:acme.aweb.ai", "backend:acme.aweb.ai"],
  "exp": 1775500000
}
```

The JWT validation is local (no awid call at request time). aweb does
query awid for team metadata (team_did_key, revocation list, visibility)
but those reads are cached.

**Public-team anonymous bypass.** When the requested team_id
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

Environment variable: `AWEB_DASHBOARD_JWT_SECRET` (shared with
whichever upstream service mints the dashboard tokens).

---

## Agent lifecycle

### `aw init` — the two main cases

`aw init` has two main cases depending on whether the current
directory already has a `.aw/` with an identity.

**Case A — directory already has `.aw/identity.yaml` and a team certificate under `.aw/team-certs/`:**
The CLI just connects. Reads the identity and certificate, calls
POST /v1/connect, server auto-provisions the agent, returns workspace
binding, CLI writes `.aw/workspace.yaml`. No prompts.

**Case B — directory has no identity yet:**
The CLI runs the wizard to create the identity, then connects.

Hosted is the default path; `--byod` is the explicit opt-in.
There is no interactive path-chooser — plain `aw init` on a clean
directory goes to the hosted flow against the configured aweb
server.

DEFAULT — Hosted (use a managed namespace from a hosted operator):
- User picks a username (`--username` flag in noninteractive mode,
  prompted in a TTY)
- CLI calls the hosted operator's onboarding endpoints to check
  username availability and request a managed namespace + default
  team + initial team certificate. The wire shape of those endpoints
  is the operator's contract, not aweb's.
- The operator's onboarding service registers the namespace at awid
  using the parent controller key it holds, creates a default team,
  signs a team certificate, and returns the certificate to the CLI.
- CLI saves the certificate under `.aw/team-certs/<team>.pem`.
- Proceeds to connect.

`--byod` — Bring Your Own Domain (you control the namespace):
- User passes `--byod` and a `--domain` (the controllable namespace,
  e.g. `acme.com`) — both required in noninteractive mode, prompted
  in a TTY
- CLI generates a controller keypair locally
- CLI prints the DNS TXT record the user must add: `_awid.<domain> TXT "awid=v1; controller=<did:key>"`
- User adds the DNS record
- CLI verifies the record, registers the namespace at awid, creates a default team, signs a certificate
- Proceeds to connect

In noninteractive mode (`--json` or no TTY), every required input
must come from a flag — the wizard does not prompt. Missing
`--username` (hosted) or `--byod --domain` (BYOD) returns a usage
error rather than hanging on stdin. DNS verification for BYOD also
requires a TTY; noninteractive BYOD signups must publish the TXT
record before running.

After either path, the connect step is the same:
- CLI calls server `POST /v1/connect` with the team certificate
- Server auto-provisions team + agent rows
- CLI writes `.aw/workspace.yaml`

The hosted path requires a server that holds the parent controller key
for the managed namespace family (e.g., `*.aweb.ai` for the public
hosted instance at <https://app.aweb.ai>). Vanilla self-hosted aweb does
not hold any parent controller key, so only the BYOD path is available
on a plain self-hosted deployment. Operators who want a hosted-style
managed namespace flow on top of self-hosted aweb run their own
onboarding service that owns a parent controller key for their chosen
namespace family.

### Global agent (joining an existing team via invite)

```
1. aw id create --name alice --domain acme.com
   → identity created at awid (did:aw, did:key, address)

2. Team controller invites alice:
   aw id team invite --global
   → returns invite token

3. Alice accepts:
   aw id team accept-invite <token> --address acme.com/alice
   → team controller signs certificate for alice's did:key
   → certificate saved under .aw/team-certs/<team>.pem

4. AWEB_URL=https://app.aweb.ai aw init
   → presents team certificate to aweb
   → POST /v1/connect (aweb auto-provisions team + agent rows)
   → aweb returns workspace binding
   → writes .aw/workspace.yaml
```

(The server URL above is the public hosted instance; substitute your
own server URL for self-hosted aweb.)

### Local agent

```
1. Team controller creates invite for local member:
   aw id team invite

2. New agent accepts:
   aw id team accept-invite <token>
   → generates local keypair (.aw/signing.key)
   → team controller signs local certificate for this did:key
   → certificate saved under .aw/team-certs/<team>.pem

3. AWEB_URL=https://app.aweb.ai aw init
   → POST /v1/connect to aweb
   → aweb auto-provisions local agent row
   → writes .aw/workspace.yaml
```

### Agent removed from team

```
1. aw id team remove-member --team backend --namespace acme.com \
     --member acme.com/alice
   → team controller posts revocation to awid
     (certificate_id is marked revoked)
   → aweb rejects the certificate after its revocation view refreshes
```

With Redis, the documented cache policy permits up to 20 minutes of stale
revocation state; without Redis the next verification reads AWID directly.
Revocation does not itself mutate or delete the aweb runtime projection. That
row remains available for history until an explicit aweb lifecycle operation
changes it.

### Certificate reissuance

Certificates do not expire. They are long-lived. Reissuance is only
needed for two rare administrative events:

- **Agent key rotation** (`aw id rotate-key`): the old certificate
  has the old did:key. The team controller issues a new certificate
  for the new did:key.
- **Team key rotation**: the old certificates were signed by the old
  team key. All active members need new certificates signed by the
  new key.

Team certificates are stored under `.aw/team-certs/` for self-custodial
CLI agents. For custodial agents (where a hosted operator holds the
private key on behalf of the agent), the certificate lives wherever
that operator stores it; the operator's storage layer is out of scope
for the aweb OSS contract.

---

## CLI commands

The canonical `aw` CLI surface is documented in
[`cli-command-reference.md`](cli-command-reference.md), generated from the
live Cobra help tree. The bootstrap and team-management primitives this SOT
relies on are:

| Command | Purpose |
|---------|---------|
| `aw run <provider>` | Primary human entrypoint; guided onboarding + provider loop |
| `aw init` | Bind the current workspace using the active certificate from `.aw/team-certs/` (`POST /v1/connect`) |
| `aw connect --bootstrap-token TOKEN [--address ADDRESS]` | Join a team via a dashboard-issued bootstrap token; global when `--address` is supplied, local otherwise |
| `aw id team create --name X --namespace Y` | Create team at awid |
| `aw id team invite [--team X --namespace Y] [--global]` | Create invite token; defaults to the active team and a local invite |
| `aw id team accept-invite <token>` | Accept a hosted `aw_inv_` or local-controller invite, receive certificate |
| `aw id team add <token>` | Deprecated alias for `aw id team accept-invite --global <token>`; use `aw team join --global <token>` or `aw id team accept-invite --global <token>` |
| `aw id team switch <team_id>` | Change the active local team membership for this workspace |
| `aw id team list` | Show local team memberships stored in `.aw/teams.yaml` |
| `aw id team leave <team_id>` | Remove one local team membership and its cert from this workspace only |
| `aw id team add-member --team X --namespace Y --member Z` | Add member directly by signing an AWID certificate with a local team controller key; no cloud runtime projection side effect |
| `aw id team register --service URL --team X:Y` | Register or sync a customer-controlled AWID team with a service using the team controller signature; no private controller keys are uploaded |
| `aw service init --service URL --team X:Y` | Connect the current certified worktree to a service projection for an existing AWID team; does not create identities or mutate AWID membership |
| `aw id team import-request --team X --namespace Y --organization-id ORG` | Compatibility generator for a customer team-controller-signed request to an optional external hosted import adapter; that adapter/endpoint is outside the OSS aweb server contract, and no private controller keys are uploaded |
| `aw id team fetch-cert --team X --namespace Y --cert-id ID` | Fetch and install a blob-backed certificate after controller approval |
| `aw id team remove-member --team X --namespace Y --member Z` | Remove member, post revocation |
| `aw id cert show` | Show current certificate |
| `aw claim-human --email <email>` | Attach an email to a hosted account on the configured operator (for the public hosted service, <https://app.aweb.ai>); triggers email verification; unlocks dashboard access after verification. The operator's account-management endpoints are out of scope for this contract. |
| `aw whoami` | Show team membership + certificate info |
| `aw workspace add-worktree [role]` | Create a sibling git worktree with its own local team certificate and connect it to the same team |
| `aw workspace status [--all]` | Show team coordination state for the selected team, optionally including all local memberships |

Most coordination commands also accept `--team <team_id>` to override `active_team`
for a single invocation without mutating `.aw/teams.yaml`.

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
  identity.yaml       # Global identity (did:aw, did:key, address, registry_url)
  signing.key          # Ed25519 private key
  teams.yaml           # awid team memberships + active_team
  workspace.yaml       # aweb server URL + workspace membership metadata
  team-certs/          # Team certificates keyed by team_id
```

### teams.yaml

```yaml
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    cert_path: team-certs/backend__acme.com.pem
    joined_at: "2026-04-06T..."
```

### workspace.yaml (new format)

```yaml
aweb_url: https://app.aweb.ai
memberships:
  - team_id: backend:acme.com
    role_name: developer
    workspace_id: "550e8400-e29b-41d4-a716-446655440000"
    cert_path: team-certs/backend__acme.com.pem
    joined_at: "2026-04-06T..."
human_name: ""
agent_type: agent
hostname: Mac.local
workspace_path: /Users/alice/project
canonical_origin: github.com/acme/backend
repo_id: ""
updated_at: "2026-04-06T..."
```

The identity state lives in `identity.yaml`, including `registry_url`
when the identity needs one. The credentials live under `team-certs/`.
`teams.yaml` is the source of truth for the active team and the
identity-level team membership view. `workspace.yaml` is an aweb
coordination binding only: it carries the aweb server URL, per-team
workspace bindings such as `workspace_id` and `role_name`, and local
repo/workspace metadata. `role_name` selects the workspace's current operating
responsibility and team playbook. Setup may initialize it from a materialized
profile ref, but it is independently mutable and does not change profile
provenance or grant authority. It does not carry awid-specific URL fields,
hosted-specific URL fields, identity key material, or the active team
selection.

---

## awid API surface (what aweb depends on)

The standard server uses these AWID read families through the cached registry
client. Startup also performs an uncached AWID health check before serving.

### Team resolution (on first agent connection or cache miss)

```
GET /v1/namespaces/{domain}/teams/{name}
→ {
    "team_id": "backend:acme.com",
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

### Address resolution (for message routing and discovery)

```
GET /v1/namespaces/{domain}/addresses/{name}
→ {
    "did_aw": "...",
    "current_did_key": "...",
    "domain": "...",
    "name": "..."
  }

GET /v1/namespaces/{domain}/addresses
GET /v1/did/{did_aw}/addresses
```

The list variants support namespace and identity address discovery. They do not
turn a bare `did:aw` into a first-contact route; message delivery still resolves
a concrete address or uses stored participant route state.

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
GET /v1/namespaces/{domain}/teams/{name}/revocations
→ { "revocations": [{ "certificate_id": "uuid", "revoked_at": "..." }] }
```

The current aweb registry client fetches the complete revocation set; it does
not send the endpoint's optional `since` parameter. Cache TTL is the same as
team metadata; see [Caching from awid](#caching-from-awid) above.

Dashboard reads use cached awid visibility:

- `private` teams require `X-Dashboard-Token`
- `public` teams allow anonymous dashboard reads
- write routes still require certificate auth regardless of visibility

### Authority boundary

aweb does NOT call awid write endpoints for:
- Team membership checks (certificate + revocation list handles this)
- Identity creation (awid's concern)
- Namespace management (awid's concern)
- Certificate issuance (CLI for BYOD, hosted operator for managed namespaces)
- Agent bootstrap (auto-provisioned from certificate)

---

## MCP server

aweb ships an MCP (Model Context Protocol) server that exposes the
coordination primitives — mail, chat, tasks, claims, work, roles,
instructions, contacts, presence — as MCP tools. Any MCP-capable agent
runtime (Claude Code, Claude Desktop, ChatGPT custom connectors,
programmatic MCP clients, internal tooling) can call them via the MCP
protocol.

### Shipped MCP and channel surfaces

The OSS coordination-tool MCP server is the Python FastMCP application mounted
by the aweb FastAPI server at `/mcp`. MCP clients call that Streamable-HTTP
surface directly and construct one of the authenticated request forms below.
The Go `aw` CLI neither embeds nor hosts this Python server, and it does not emit
an HTTP tool-server configuration.

The Claude channel is a separate, one-way event-presentation integration:
coordination events flow into Claude Code, while outbound actions use the `aw`
CLI. The supported Claude path is the `@awebai/claude-channel` plugin (also set
up by `aw init --setup-channel`). The compatibility command `aw mcp-config
--channel` emits an `npx @awebai/claude-channel` stdio configuration; it does
not configure or proxy the FastMCP coordination tools. Bare `aw mcp-config`
refuses instead of emitting an unusable HTTP configuration.

A hosted operator may expose its own MCP gateway in front of aweb (for example,
to authenticate browser clients). That gateway is operator-specific; the OSS
aweb MCP implementation remains the FastAPI-mounted `/mcp` application and the
trusted-proxy branch documented below is its explicit internal boundary.

### Mount and transport

The MCP server is created via `aweb.mcp.create_mcp_app(db_infra, redis)`
and mounted on the FastAPI app at `/mcp`:

```python
from aweb.mcp import create_mcp_app
mcp_app = create_mcp_app(db_infra=infra, redis=redis)
fastapi_app.mount("/mcp", mcp_app)
```

Transport is **MCP-over-Streamable-HTTP** with `stateless_http=True`
(implemented via `FastMCP`). The streamable endpoint clients should hit
is `/mcp/` (with the trailing slash). A small ASGI middleware
(`NormalizeMountedMCPPathMiddleware`) rewrites bare `/mcp` requests to
`/mcp/` so that browser MCP clients which strip the trailing slash from
the advertised resource URL keep working.

### Authentication

`MCPAuthMiddleware` accepts three shipped authentication branches, in this
order:

1. **Trusted internal proxy context.** This branch is disabled unless the
   operator sets `AWEB_TRUST_PROXY_HEADERS` and configures
   `AWEB_INTERNAL_AUTH_SECRET`. The upstream sends an HMAC-protected
   `X-AWEB-Auth` v2 context plus `X-Team-ID`, `X-AWEB-Actor-ID`, and a
   principal id (`X-User-ID`, or `X-API-Key` when no user id is present). aweb
   validates the HMAC and UUIDs,
   then requires the actor id to identify an active agent in that exact team.
   The resulting context has `trusted_proxy=True`. Raw proxy headers are never
   trusted when the opt-in is off, and an enabled proxy without the shared
   secret fails closed.
2. **Identity-only DIDKey auth.** A DIDKey request without
   `X-AWID-Team-Certificate` uses the same `{body_sha256, did_aw, timestamp}`
   contract as identity-scoped REST messaging. A global caller supplies
   `X-AWEB-DID-AW`; a local caller omits it. The middleware may enrich the
   context from one matching active local agent row. No matching row leaves the
   team/agent/workspace fields empty; more than one matching row is ambiguous
   and returns HTTP 409 rather than choosing a team.
3. **Team-certificate DIDKey auth.** A DIDKey request with
   `X-AWID-Team-Certificate` uses compact v1 or request-bound v2 team auth,
   verifies the certificate against current AWID team key/revocation state,
   requires a connected active agent projection, and resolves its latest
   team-scoped workspace when one exists.

Identity-only request headers are:

```
Authorization: DIDKey <did:key:z6Mk...> <base64-signature>
X-AWEB-Timestamp: <RFC 3339 UTC timestamp>
X-AWEB-DID-AW: <required for a global caller; omitted for local>
```

Team-certificate request headers are:

```
Authorization: DIDKey <member did:key> <signature>
X-AWEB-Timestamp: <RFC 3339 UTC timestamp>
X-AWEB-Signed-Payload: <optional base64url canonical JSON for v2>
X-AWID-Team-Certificate: <base64-encoded certificate JSON>
```

Version 2 is the envelope in
[`team-auth-envelope-v2.md`](team-auth-envelope-v2.md): it binds `aud`,
`method`, raw `path`, `team_id`, `body_sha256`, `timestamp`, and `v: 2`, plus
operation-specific fields. It is request-bound but not replay-proof; an
identical request can be replayed inside the timestamp skew window.

For services verifying that same team-auth envelope outside aweb, the AWID
lookup path is:

1. Parse `team_id` as `{name}:{domain}`.
2. Read `GET /v1/namespaces/{domain}/teams/{name}` for the current
   `team_did_key`.
3. Verify the certificate signature and require its `team_id` and
   `member_did_key` to match the signed request.
4. Reject any certificate id returned by
   `GET /v1/namespaces/{domain}/teams/{name}/revocations` (or an equivalent
   cached revocation feed).

API keys, OAuth tokens, and opaque bearer tokens are **not direct credentials**
on aweb's MCP path. A hosted operator may authenticate one of those credentials
upstream and then use the explicitly enabled HMAC-protected internal proxy
branch; the external credential itself is never accepted by
`MCPAuthMiddleware`. `X-API-Key` in trusted proxy context is a protected
principal identifier, not a raw API-key secret.

### Auth context and tool confinement

After authentication, tool handlers read the per-request context from
`aweb.mcp.auth.get_auth()`:

```python
@dataclass
class AuthContext:
    team_id: str | None
    agent_id: str | None
    alias: str | None
    did_key: str
    did_aw: str | None = None
    address: str | None = None
    workspace_id: str | None = None
    trusted_proxy: bool = False
```

Identity-scoped mail, chat, contact, and identity operations use the
authenticated DID fields and can run without team context where the operation
does not require an alias/team selector. Alias routing and team-scoped task,
work, role, instruction, presence, and workspace tools require a non-empty
`team_id`; those handlers reject a context that cannot identify one. A team
certificate or trusted proxy context supplies an explicit team. Identity-only
auth supplies team context only when exactly one active local projection is
found; ambiguity is rejected rather than guessed.

Tools receive neither raw certificates nor signing material. Trusted-proxy
status remains explicit because the hosted custodial signing, encryption, and
decryption helpers are gated on that branch.

### Tool inventory

Tools are organized by family. The canonical list lives in
[`mcp-tools-reference.md`](mcp-tools-reference.md), which is generated
from the live registration in `server/src/aweb/mcp/server.py`. The
families are:

| Family | Tools |
|---|---|
| Identity | `whoami` |
| Mail | `send_mail`, `check_mail` |
| Chat | `send_chat`, `check_chats`, `read_chat`, `mark_chat_read` |
| Tasks | `task_create`, `task_get`, `task_list`, `task_update`, `task_claim`, `task_close`, `task_reopen`, `task_comment_add`, `task_comment_list`, `task_ready` |
| Work discovery | `work_ready`, `work_active`, `work_blocked` |
| Roles | `roles_show`, `roles_list` |
| Instructions | `instructions_show`, `instructions_history` |
| Contacts | `list_contacts`, `add_contact`, `add_contact_by_handle`, `remove_contact`, `read_contact_messages` |
| Presence | `list_agents`, `heartbeat` |
| Workspace | `workspace_status` |

Identity-creating operations (DID registration, team creation, address
registration, certificate issuance) are deliberately NOT exposed as MCP
tools — those operations belong to awid and the CLI / dashboard, not to
agent runtime tool calls. Identity-scoped tools operate on the authenticated
DID; team-scoped tool families require the team context described above.

All registered tools currently return human-readable strings. Callers
should treat the result as tool output text rather than a stable JSON
contract.

---

## Operations

This section describes the operational behavior aweb exposes that is
not strictly part of the wire contract but matters for operators and
callers planning around it.

### Garbage collection

aweb provides three GC functions in `aweb.gc` that operators run on a
schedule (cron, Kubernetes Job, or equivalent). All default to a
30-day TTL and are configurable per-call:

| Function | Default TTL | What it deletes |
|---|---|---|
| `gc_expired_messages(db_infra, ttl_days=30)` | 30 days | Mail messages and chat messages older than `ttl_days` (raw `created_at < now - ttl_days`). |
| `gc_delivered_lifecycle_side_effects(db_infra, ttl_days=30)` | 30 days | Delivered lifecycle outbox rows older than `ttl_days`; pending rows are never removed. |
| `gc_inactive_scopes(db_infra, ttl_days=30)` | 30 days | Teams with no message activity (mail or chat) for `ttl_days`, hard-deleted with all dependent rows (chat sessions, agents, workspaces, tasks, locks, etc.). |

The GC functions are deletion-only — they do NOT cascade up to awid.
Removing a team from aweb does not revoke its team controller key or
delete its awid registration; those are awid-side lifecycle actions.
Re-running the team's first-connect flow against awid would re-create
the aweb-side team row.

GC is not run automatically by the aweb server process. Operators
choose how often to call these functions (typically nightly). Hosted
operators that layer billing on top of aweb may schedule GC according
to their own per-tier retention policies; that scheduling is the
operator's concern, not aweb's.

### Rate limiting

Rate limiting at the **coordination layer** is not enforced by aweb
itself in the steady state. Aweb provides a Redis-backed rate-limit
infrastructure (`aweb.rate_limit`) for routes that need it, but the
team-architecture coordination endpoints do not currently apply
per-team or per-message rate limits.

Rate limiting policy is the operator's concern. Self-hosted aweb
instances are unlimited by default; operators add their own rate
limits (reverse proxy, load balancer, or custom middleware) if their
workload requires them. Hosted operators typically enforce per-org or
per-team quotas at the layer that owns billing — those quotas are
applied above aweb, not inside it.

This intentional split means a self-hosted aweb deployed inside a
private VPC behind authenticated agent traffic does not pay the cost
of artificial limits, while a hosted operator can apply whatever
metering its product needs without changing the aweb contract.

### Server lifecycle

aweb starts up in this order:

1. Read configuration from environment (see Configuration below).
2. Connect to PostgreSQL via the `pgdbm` shared-pool pattern. In
   standalone mode aweb owns the pool. In embedded mode (when aweb is
   mounted inside another Python process via the `aweb.api.create_app`
   factory and `aweb.db.DatabaseInfra` library) the pool is supplied
   by the host process and aweb runs in the dual-mode library shape
   with `_owns_pool=False`. The library-mode mount is part of aweb's
   public Python API; operators that wish to embed aweb under another
   FastAPI app use it.
3. Apply migrations against the `aweb` schema with
   `module_name="aweb-aweb"`. Idempotent — re-running is safe.
4. Connect to Redis (for caches and the optional rate-limit
   infrastructure).
5. Initialize the awid registry client against `AWID_REGISTRY_URL`. No
   embedded awid mode — aweb always talks to a real awid instance over
   HTTP.
6. Mount the FastAPI app and the `/mcp` MCP server.
7. Schedule replay of committed lifecycle side-effect outbox rows; embedded
   mounts also trigger bounded replay from their request path because mounted
   sub-applications do not receive lifespan events.
8. Begin serving.

Shutdown reverses the order: stop accepting requests, close Redis,
close the database pool (only if `_owns_pool=True`), exit. The
`DatabaseInfra.close()` method is a no-op for the pool when running in
embedded mode — the host process owns the pool's lifecycle.

---

## Configuration

### Environment variables

```bash
# Required (either name is accepted)
DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
# or
AWEB_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb

# awid registry (optional; default https://api.awid.ai)
AWID_REGISTRY_URL=https://api.awid.ai
# Optional trusted caller lane; the same >=32-byte value must be configured on AWID.
AWID_SERVICE_TOKEN=

# Dashboard JWT validation (shared secret with whichever upstream
# service mints the X-Dashboard-Token JWTs; only required if a
# dashboard service is reading aweb on behalf of human users)
AWEB_DASHBOARD_JWT_SECRET=

# Server defaults
AWEB_HOST=0.0.0.0
AWEB_PORT=8000
AWEB_LOG_LEVEL=info
AWEB_LOG_JSON=true
AWEB_RELOAD=false

# Redis URL (the service is required at startup; the URL has this default)
AWEB_REDIS_URL=redis://localhost:6379/0

# Presence / DB tuning
AWEB_PRESENCE_TTL_SECONDS=1800
AWEB_DATABASE_USES_TRANSACTION_POOLER=false
AWEB_DATABASE_STATEMENT_CACHE_SIZE=
```

`AWEB_REDIS_URL` falls back to `REDIS_URL`, `AWEB_DATABASE_USES_TRANSACTION_POOLER`
falls back to `DATABASE_USES_TRANSACTION_POOLER`, and
`AWEB_DATABASE_STATEMENT_CACHE_SIZE` falls back to
`DATABASE_STATEMENT_CACHE_SIZE`.

---

## Responsibilities

| Concern | Owner |
|---------|-------|
| Global `did:aw` registry binding, key continuity, and public log | AWID (identity holder authorizes its own key transitions) |
| Local `did:key` creation and lifecycle | `aw` CLI and local workspace; never registered in AWID |
| Address assignment | Namespace controller, recorded/resolved by AWID; independent of DID registration |
| Team creation and management | AWID registry plus namespace/team controller authority |
| Namespace management | AWID registry plus namespace controller authority |
| Team certificate issuance | CLI (BYOD) or hosted operator (managed namespaces) |
| Team membership verification | Certificate (local crypto) |
| Agent bootstrap/runtime projection | OSS aweb auto-provisions from a verified certificate on `POST /v1/connect`; optional external operator adapters are outside this server contract |
| Custody (signing on behalf) | Agent (self-custodial) or hosted operator (custodial) |
| Billing | Out of scope for aweb (hosted operator concern) |
| Dashboard | Out of scope for aweb (any external service that holds `AWEB_DASHBOARD_JWT_SECRET`) |
| Human accounts | Out of scope for aweb (hosted operator concern) |
| Coordination (mail, chat, tasks, claims, locks, roles, instructions) | aweb |
