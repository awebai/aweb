# aweb Restructuring SOT — Core Authority Substrate + Agent Apps

Status: **ready for Juan's review.** Date: 2026-06-15.
Authors: coordinator, with aweb-consultant. Grounded in exact, file:line code
inventories of `aweb`, `ac`, `atext`, and `folio`.
aweb-consultant signed off 2026-06-16 (architecture lens): no architectural
objections; remaining items are the Juan decisions in §13 and implementation task
scoping. cli/ execution team (aw-coordinator) concurred 2026-06-16 (execution
lens, grounded in the channel-stack + cli-go maps): three-way cut confirmed, no
boundary redrawn; their sharpenings folded in — "opaque = parse-discipline"
(§3.1), the messaging fusion sub-checklist (§12.10), staged 8a/8b overlay+FK
removal (§8), manifest as a core contract + interpretation conformance suite +
origin/host-injection guard (§7), and `contacts` → core (§13.7).

This is the single destination-architecture document — the shape we are
building toward, not a chain of revisions. It is a proposal, not yet task work;
§13 lists the decisions that are Juan's.

## 1. Problem and north star

aweb.ai today explains identity, teams, orgs, billing, MCP, coordination, and
messaging all at once. Cold arrivals do not convert; there is too much to say.

**North star:** a much simpler aweb and an *especially* much simpler `ac` —
smaller, independently-deployable containers, and a core that is crystal-clear.

**Product sentence (the framing everything serves):**

> **aweb.ai is where humans create and manage agent teams. Agents use apps.**

**Homepage value proposition:**

> **Create and manage teams of AI agents.** Give agents verifiable identities,
> connect them to the apps they use, and manage access, activity, and billing
> from one place.

The first screen should make three things obvious:

- **Identity and authority:** every agent has a verifiable identity and belongs
  to a managed team/web.
- **One human control plane:** humans manage teams, agents, permissions,
  OAuth/MCP connections, usage, and billing from `aweb.ai`.
- **Apps for agent work:** agents use apps like Folio, Tasks, Messages, Secrets,
  KPI, and Dev through the same identity and permissions.

Do not lead the homepage with protocols, BYOT, MCP, A2A, federation, or custody.
Those are proof and depth, not the first message.

**Organizing principle (the cut that does the work):**

> **Core = the runtime *authority* substrate every agent and app depends on.**
> Everything with *domain semantics* — tasks, documents, secrets, even mail and
> chat — is an **app**.

(We will rename "anapp"/"agent-native app" later — it is awkward. This document
says **app** / **agent app**.)

## 2. The three layers

| Layer | What it is | Auth | Hosted revenue |
|---|---|---|---|
| **Core substrate** (`awid` + `aweb`; OSS, self-hostable) | AWID-based authority: identity, authority, addressability, **app-auth** (verify signed envelopes), the **event/SSE channel**, the **app registry**, **app grants**, and **protocol transport for signed app envelopes**. Plus roles + instructions (runtime team facts), the signed-request primitive, and `aw` plugin dispatch | the certificate / signed envelope | free / open |
| **Hosted control plane + gateway** (`aweb.ai`, today's `ac`, evolved) | the **one human site**: create/manage teams, accounts/orgs, billing + quota + entitlements, namespace/address allocation, **custody management**; **and** the hosted **identity/MCP gateway**: custodial identities, connector grants, **dynamic manifest-driven MCP tool composition**, signs-as-identity, forwards to apps/core | human login + connector grants | paid: hosted convenience |
| **Apps** (first-party + third-party) | one domain each; declare a manifest; team-scoped data; report mutations | gateway-signed or direct cert-auth | bundled mutation quota |

**Apps (first-party):** `messages` + `chat` (the bundled default comms app —
split out *last*; see §12), `tasks`, `dev`, `folio` (flagship), `secrets`,
`kpi`. Plus third-party apps.

**Dependency graph:**

- **core** ← everything.
- **control plane + gateway** reads the core app registry/grants, holds
  custodial keys, signs as identities, and is where humans live.
- **apps** depend on core transport + app-auth + event channel + registry.
  `tasks` ← `dev` (dev consumes tasks). `messages`/`chat` ← core transport.
  `folio`/`secrets`/`kpi` ← core only.

## 3. The core substrate — exact definition (the redefinition)

The core is **not** a messaging system. It is the authority and delivery
substrate that apps share so they do not each reinvent identity, federation, and
wake-ups.

**Core owns:**

- **Identity & authority** — DIDs, certs, revocation, roster (AWID).
- **Addressability** — resolve `did:aw` / address / handle to a reachable
  target; contacts (address book).
- **App-auth** — verify the v2 team-auth signed-request envelope (the
  relying-party primitive `atext`/`folio` already implement).
- **Event/SSE channel** — the shared wake mechanism (`events.py`); apps *emit*
  events, agents *subscribe* through core, so no app builds its own. **Today it
  is not yet app-generic** — `events.py` hard-codes mail/chat/control kinds and
  does not emit the work/claim kinds `channel-core` already defines; making it
  emit arbitrary app event kinds is part of milestone 3. See
  [`restructuring/archive/channel-stack-map.md`](restructuring/archive/channel-stack-map.md) (archived snapshot).
- **App registry + app grants** — what apps exist, and which apps a team has
  installed and with what scopes.
- **Protocol transport for signed app envelopes** — the federated delivery
  primitive (§3.1).
- **Roles & instructions** — runtime team facts (read at agent boot via MCP;
  `get_active_team_roles(... bootstrap_if_missing=True)`, registered in
  `mcp/server.py`). `aweb.ai` edits them; agents never need the dashboard to
  *read* them.
- **Encryption-key discovery** — identity-bound `agent_encryption_keys`; apps
  use them, core publishes them.
- The **signed-request primitive** and **`aw` plugin dispatch**.

### 3.1 The transport primitive (consultant's framing — use this wording)

Core keeps **"protocol transport for signed app envelopes,"** *never* "messaging."

> Deliver a signed envelope from identity A to **app X** for target
> identity/team/address B.

- **Core owns:** identity resolution, app-target resolution, federation routing,
  signature/auth verification, idempotency + delivery attempts, and event
  emission. It routes on `app_id`/`type`/`body_hash`. Core may track
  transport-level delivery state.
- **"Opaque" = a parse-discipline boundary, not format purity.** Core does not
  **parse or depend on** payload semantics (subject, thread, chat-session,
  read-receipt, inbox UX, search, retention) — those are app concerns. It is
  *not* a claim that the payload is structureless. Verified: today the message
  envelope signature already covers semantic fields — `SignMessage` signs
  `CanonicalJSON` over the full `MessageEnvelope` incl. `Subject`/`Type`/
  `ConversationID`/`ReplyTo` (`cli/go/awid/signing.go:87-119`). So milestone-3
  transport extraction proceeds **with today's envelope unchanged** — core
  verifies signature + body_hash and routes on `app_id`/`type`, never parsing
  those fields even though they sit in the signed bytes. Purifying the envelope
  *format* (removing semantic fields from the signed payload) is an *optional*
  later concern tied to the messaging split (§12.10), **not** a prerequisite for
  m3 — conflating the two would chicken-and-egg the transport extraction.

This is what makes `messages`/`chat` (and any future messaging app) possible
*without* every app reinventing federation. `messages` and `chat` are
**first-party apps layered on this transport**.

### 3.2 The open network — A2A interoperability (the global-network pillar)

A2A (**Agent2Agent**) is the standard interoperability protocol for agents to
**discover** each other (Agent Cards) and **call** each other (JSON-RPC
`SendMessage`/`GetTask`/`ListTasks`/`CancelTask`). It is *not* aweb mail/chat and
*not* org-to-org federation — it is how aweb identities become first-class
participants in the **open agent web** (including non-aweb agents and
frameworks). It is the concrete realization of the core's "open/global network"
pillar; see `docs/a2a.md` and `docs/a2a-awid-publication-contract.md`.

The bare A2A standard leaves identity, naming continuity, and trust open — and
**that gap is exactly what AWID supplies**. So A2A splits across the layers:

- **Core / AWID owns** the durable layer: A2A **publication assertions**
  (address → card URL / digest / route / delegation), directory/discovery facts,
  signer/key-history verification, gateway-delegation authority, and the
  stronger **aweb-aware verification profile**. Core is *not* the runtime card
  host and makes **no E2EE claim** for gateway traffic. Design principle: *normal
  A2A for generic clients; stronger verification for aweb-aware clients* (who can
  check the active AWID publication, card digest, route/delegation, and current
  signer).
- **Hosted control plane / gateway owns** `aweb-a2a-gw` (§6): exposes aweb agents
  as standard A2A agents, serves/points to Agent Cards, handles the JSON-RPC
  methods, and translates standard A2A requests into **signed aweb actions** for
  the addressed identity via custodial or delegated authority. This is
  bridge/control-plane infrastructure, **not a domain app**.
- **CLI owns** `aw a2a` (§10): card verification/publication and **outbound**
  calls to external A2A agents.

**Guardrail — do not conflate A2A with:** aweb chat/mail, app manifests, MCP tool
publication (§7), or org federation. They are separate contracts. (App manifests
and Agent Cards may relate later, but are distinct today.)

## 4. Exact current → target inventory (mechanical)

Verified against `server/src/aweb/`. Counts are exact.

### 4.1 Tables — 26 total

| Target | Tables |
|---|---|
| **Core (authority/addressability/control)** | `teams`, `agents`, `agent_encryption_keys`, `contacts`, `control_signals`, `team_roles`, `team_instructions` |
| **Core transport (idempotency/delivery)** | `federated_message_deliveries` |
| **→ messages/chat app** *(stays in core during transition)* | `conversations`, `conversation_participants`, `messages`, `chat_sessions`, `chat_participants`, `chat_messages`, `chat_read_receipts` |
| **→ tasks app** | `tasks`, `task_comments`, `task_dependencies`, `task_counters`, `task_root_counters`, `task_claims` |
| **→ dev app (git-specific)** | `repos` |
| **Split** | `workspaces` — core keeps identity/location/role/last_seen; `focus_task_ref`/`focus_updated_at` → tasks/dev |
| **Drop-or-dev** | `reservations` (locks) |
| **Control-plane / observability** | `audit_log` |

### 4.2 MCP tools — 43 total (32 canonical + 11 legacy aliases)

Under the reframe the hosted MCP surface is **composed dynamically from app
manifests** (§6), not a static list. The current static tools reclassify as:

- **Core / gateway-provided:** `whoami`, `list_agents`, `heartbeat`,
  `list_contacts`/`add_contact`/`add_contact_by_handle`/`remove_contact`,
  `roles_show`/`roles_list`, `instructions_show`/`instructions_history`.
- **→ messages/chat app manifest:** `send_mail`, `check_mail`, `send_chat`,
  `check_chats`, `read_chat`, `mark_chat_read`, `read_contact_messages`.
- **→ tasks app manifest:** `task_create`/`task_list`/`task_ready`/`task_get`/
  `task_close`/`task_update`/`task_reopen`/`task_claim`/`task_comment_add`/
  `task_comment_list`, `work_ready`/`work_active`/`work_blocked`.
- **Split:** `workspace_status` (core presence read; the claims part →
  tasks/dev — note: it reads `task_claims` but **not** `reservations`).
- **11 legacy aliases** (`check_inbox`, `chat_send`, `chat_pending`,
  `chat_history`, `chat_read`, `contacts_list`, `contacts_add`,
  `contacts_remove`, `add_contact_by_email`, `send_message_to_contact`,
  `read_messages_from_contact`): keep behind an explicit **deprecation window**;
  remove after migration. Do not carry silently.

### 4.3 Routers `api.py` includes — 18 total

- `routes/` (13): `agents`, `connect`, `chat`, `claims`, `contacts`,
  `conversations`, `events`, `federation`, `messages`, `reservations`,
  `service_registration`, `status`, `dashboard`.
- `coordination/routes/` (5) — **this set was missing from the first draft**:
  `team_instructions` (**core**), `team_roles` (**core**), `repos`
  (**→ dev**, git-specific — *not* silently core), `tasks` (**→ tasks**),
  `workspaces` (**split**).

Router targets: core/authority → `agents`, `connect`, `contacts`, `events`,
`team_roles`, `team_instructions`; core transport → `federation` only (becomes
the signed-envelope transport); messages/chat app → `chat`, `messages`,
`conversations` (semantic read state — `conversation_type`/subject/participants/
unread; stays in core during transition); tasks app → `tasks`, `claims`; dev →
`repos`, `dashboard` (visibility); split → `workspaces`, `status`; drop-or-dev →
`reservations`; drop/fold-to-control-plane → `service_registration`.

## 5. The prune list and the status/workspace split

- **→ tasks:** `tasks`/`task_*`/`task_claims`, task + work MCP tools, `claims`.
- **Drop-or-dev — locks (`reservations`):** isolated (no MCP tool), but surfaced
  by `aw lock` (CLI), `aw workspace status`, `aw doctor`, `GET /v1/status`
  (`locks` array), and the dashboard (`active_locks`). Verdict: drop from core;
  rebuild in `dev` **only** with a real integration, else delete — **with an
  explicit CLI/API deprecation + compat path** for `aw lock` and the
  doctor/status output, or it breaks dogfooding even though MCP is clean.
- **Reservations split (do not misclassify identity as workflow):** OSS
  resource/work reservations = locks → above. **Namespace / address /
  team-name / identity reservations** (AWID atomic-claim) = **core/control-plane
  identity allocation**, never coordination workflow.
- **Status/workspace split (required, not optional):**
  - **Core presence read** returns identity / workspace / presence / role /
    last_seen only.
  - **tasks/dev augmented read** returns claims, focus task, locks, repo/dev
    context.
  - Evidence: `GET /v1/status` currently reads `task_claims` + `reservations` +
    `focus_task_ref` + `repos`; `workspace_status` reads `task_claims` (not
    `reservations`); `GET /v1/workspaces/team` reads `task_claims` + focus (not
    `reservations`). CLI composes both during transition.
- **`repos` → dev** (git-specific: `origin_url`/`canonical_origin`; never touched
  by the identity/messaging path). Not core unless we deliberately generalize it
  to non-git environment context — decide explicitly, don't default it core.
- **`service_registration` → drop** / fold into control-plane admin.

## 6. Authority, custody, and the hosted gateway

This is where humans, identities, and the gateway meet. It has three independent
authority concepts that the destination model keeps cleanly separate — they are
already present in the code but not elevated as orthogonal axes; the SOT makes
them first-class. **All of this lives in the control plane / gateway; none of it
leaks into the core transport or the app contract.**

### 6.1 Two custody axes (keep them orthogonal)

1. **Team/web authority custody** — *who holds the controller key that admits/
   revokes members and signs team certificates.* **Hosted:** the cloud holds it
   (`server.teams.aweb_team_controller_key_ciphertext`). **BYOT:** the customer
   holds it externally; the cloud only *verifies* signatures against the AWID
   team controller DID (`routers/teams.py:1906-1928`) — it never holds the key.
2. **Agent identity custody** — *who holds the agent's DID signing key.*
   **self:** the actor (`.aw/signing.key`). **custodial:** hosted aweb
   generates/encrypts/stores/signs on the actor's behalf
   (`agents.signing_key_enc`, `assertion_custody` ∈ {self, hosted_custodial}).

These are genuinely independent: a BYOT team can contain custodial identities,
and a hosted team can contain self-custodial CLI/local agents. The existing
`byot-onboarding-contract.md:54-66` ("Identity Custody Is Independent") already
states this — the SOT promotes it to a named, first-class model.

### 6.2 Hosted vs BYOT team authority — capability states and delegation

`aweb.ai` is where humans create and manage teams in **both** modes; the
difference is only *who holds the controller authority*.

- **Hosted (default product path):** the control plane creates teams, admits
  hosted custodial identities, **issues/revokes certs**, installs apps, connects
  OAuth/MCP, manages quota/payment. Easy MCP: it can mint certs because it holds
  team authority.
- **BYOT:** authority lives outside aweb.ai. The cloud can connect/display and
  operate **only within authority the external controller explicitly grants**.
  **It cannot mint a BYOT team cert** — verified in code: cloud only verifies the
  customer's signature; the customer signs locally (`aw id team add-member` /
  `import-request`) and the cloud imports it.

**BYOT must not feel like broken hosted.** Today it does (binary `hosted|byot`,
same `TeamPage`, no state flags). The SOT defines explicit **team capability
states** that drive the UI/API:

| State | Meaning | Today? |
|---|---|---|
| `hosted-managed` | cloud holds controller; full management | yes |
| `byot-connected` | read-only projection; cloud verifies/displays; custodial identities only via **customer-signed** admission+import | partial (no flag) |
| `byot-delegated` | customer granted cloud **limited, scoped, revocable** authority to admit identities / issue certs on its behalf | **no — future** |
| `migrated-to-hosted` | customer rotated controller authority to the cloud at AWID (`aw id namespace rotate-controller`) | no |

**Hosted MCP on a BYOT team — delegation object:**

- **v1: no new object needed.** The existing path is enough — the cloud creates a
  *pending* custodial identity (`byot_custodial_identity_authorizations`, state
  `pending`), the **customer admits it** (`aw id team add-member` /
  `import-request`, signed with their controller), and the cloud imports the
  customer-signed cert and flips the row to `active`. That table **is** the
  authorization object; it just requires one customer signing step. So hosted MCP
  on BYOT works in v1 via **certificate pickup after external admission**.
- **v2: a real delegation grant** (the `byot-delegated` state) lets the customer
  grant cloud limited, scoped, revocable authority to admit identities without
  per-identity signing. Model it like a connector grant (§6.4), subject = *team
  controller authority*, scopes-limited and revocable. **Invariant: the raw BYOT
  controller key never reaches the cloud in either case** — delegation is a
  scoped capability the customer signs, not key handover.

### 6.3 Agent identity custody is not billing (correction)

Custody (§6.1, axis 2) is a *key mode*. **Billing / ownership / quota** attach to
the **org/team / control plane** around the identity, *not* to custody. The
control plane manages both; the model and docs keep them separate. (Hosted
custodial does not imply "paid"; self-custodial does not imply "free.")

### 6.4 Connector grants — one concept, per-method adapters

A connector grant is the uniform fact: *"external runtime X may act as hosted
custodial identity Y within scopes S until revoked. The raw identity key never
leaves the hosted control plane and never reaches apps."* Fields: subject
(custodial identity), scopes, status, expiry, audit. The **binding method** is a
small verification adapter, not a table per method: `oauth`, `api_key`,
`oidc_workload`, `signed_webhook`, `service_account`, `delegated_token`,
`device_code`, `admin_connector`. Generalize today's `mcp_oauth_*` and `api_keys`
under it.

Keep the grant **axes** distinct: **app grant** (a team installs an app with
scopes) vs **connector/identity grant** (a runtime may act as an identity) vs the
**BYOT delegation grant** (§6.2, a customer delegates limited team authority).
The gateway *intersects* them: a connector grant yields an identity; that
identity's team has app grants; the tool surface = tools of granted apps,
filtered by connector scopes.

### 6.5 The hosted gateway and dynamic MCP composition

**The use case that drives this:** a human uses claude.ai / chatgpt.com, where
the agent cannot hold an aweb signing key. The human OAuths to the aweb.ai MCP
endpoint; aweb.ai binds the grant to a hosted **addressed, custodial** identity,
exposes the **right tools** for that identity/team/installed-apps/scopes/quota,
and **signs tool calls as that identity** when forwarding to core/apps.

**~80% already exists in `ac`** (a reframe + generalization, not a rewrite):
hosted MCP app mounted at `/mcp` (`main.py:496-535`);
`mcp_oauth_grants`/`mcp_oauth_clients`/`mcp_oauth_access_tokens`; custodial keys
(`cloud_custodial_keys`, `agents.signing_key_enc`, `agents.team_cert_blob`); an
auth bridge that already signs proxy headers as the agent identity.

**What's new — dynamic tool composition.** Today the gateway mounts the OSS
server's static MCP tool list (43 tools). Target: the gateway reads the team's **installed
apps** from the **core app registry + app grants**, fetches each app's
**manifest** (§7), filters tools by the connector grant's **scopes/quota**,
presents them as the MCP surface, and on call **signs as the custodial identity**
and forwards to the app's mapped endpoint, **counting mutations** (§9).

- **Where it lives:** the hosted gateway (`aweb.ai`). Not core (core stays
  authority/transport), not apps (apps only *declare* tools).
- **Monolith guard:** the gateway *composes, auths, signs, forwards, meters* —
  and nothing else. It must never absorb app logic.

The same hosted-gateway tier also runs **`aweb-a2a-gw`** (§3.2) — the A2A bridge
that exposes aweb agents as standard A2A agents and translates external A2A
JSON-RPC into signed aweb actions. Note these are **two distinct bridges** the
gateway hosts: the **MCP** surface (inbound tools for keyless runtimes like
claude.ai, composed from app manifests) and the **A2A** surface (inbound/outbound
Agent2Agent interop, driven by AWID publication). Same tier, separate contracts —
do not fuse them.

### 6.6 Apps do not care whether a team is hosted or BYOT

Apps trust AWID / certs / app grants; the verification path is identical in both
modes (the `atext` spine already proves this). The entire hosted/BYOT distinction
stays in the control plane and gateway — it must **not** leak into the app
contract or the core transport. This is both a simplification and a leak guard.

### 6.7 App emit-key custody (SELF-CUSTODIAL — Juan, 2026-06-18; supersedes the 2026-06-17 platform-managed lock)

App emit keys are **self-custodial by default.** The app **generates its own**
event-emit keypair (the m3.2 `event_emitters` did:key), **holds the private seed
in its own runtime** (alongside its DB/API secrets), and declares only the
**public `did_key`** in its manifest `event_emitters`. The platform manages
**registration, not custody:** the control plane (AC) **registers the public key
+ grant at install** (its team-custodial-identity job) and **never mints, holds,
or provisions any app's private seed.**

- **Hosted or self-hosted — same model:** the app's own runtime holds its own
  seed; the app operator sets the self-generated seed in the app's deployment env
  (like any app secret). The platform only ever sees public keys.
- **Verifier is the authority** (unchanged): core binds
  `app_id + team_id + kid + did_key` to the installed-app grant **scoped to the
  team's pinned manifest digest**, and rejects inactive/rotated keys (m3.2
  digest-scoping in `009_app_events.sql`).
- **The signed-credential WIRE is unchanged** — only *who generates/holds the
  seed* changes (app, not platform). The m3.2 / aaaj.7 byte-parity vectors are
  unaffected.
- **Rotation:** the app generates a new keypair + re-registers the public key.
- A central **gateway/KMS custody** mode (platform holds the key for apps that
  want it) is an **optional stricter mode** (rides aaaj.6), **not the default.**

**Why self-custodial (Juan, 2026-06-18):** (1) it deletes the entire per-app
seed-provisioning apparatus — no platform minting, no encrypted-seed storage, no
seed-injection (the Option C / GPG / Render-token dance is unnecessary); the seed
never leaves the app's server. (2) Ecosystem scalability: ANY app joins by
self-generating a keypair + registering its public key at install — no per-app
key-provisioning ceremony in the control plane. AC holds public keys + grants,
never app secrets → smaller blast radius (an AC compromise leaks no app seeds),
matching trust-model.md's self-custodial mode + aweb's self-sovereign identity
philosophy.

**Guardrails:** per-app / per-`kid` keys only; **never** reuse an agent
identity, team-controller, namespace-controller, or A2A-gateway key as an app
emit key.

**Implementation consequence:** the AC-side emit-key custody (mint/store/
provision/inject private seeds) is removed entirely — **registration lives in
core's `app_registry_emit_keys`** (custody-agnostic), and **AC holds NO emit-key
tables.** At install the control plane verifies the exact manifest bytes,
requires one manifest-declared public `{kid, did_key}`, validates its shape, and
**forwards it to core**, which records it in `app_registry_emit_keys`. No
private-seed material anywhere in the platform. folio self-generates its
keypair, its operator sets the seed in folio's runtime env, folio declares the
public `did_key`, the control plane forwards it, core registers it.

## 7. App manifest and the app contract

**Manifest (minimal, declarative).** Per contributed tool: `name`,
`description`, input JSON schema, the app-API `method`+`path` it maps to,
required `scopes`, and a **`mutation` flag** (for the §9 quota). Plus app
`id`/`version`/`origin` and `/llms.txt` + `/skills` pointers. This is just *MCP
tool definitions + how to call the app + scope/mutation tags*.

**Param placement is explicit, never inferred.** Each `inputSchema` field
declares where it maps in the request — `path` / `query` / `body`. The dispatcher
and the gateway both consume this; neither may guess placement, or the two
front-ends drift. (Hard constraint from the cli/ team's dispatch read.)

**The manifest schema is a CORE contract, not gateway-private** — the CLI
dispatcher (which has no gateway) must consume it identically to the gateway.
Co-equal consumers; core owns the schema.

**One declaration, three front-ends:** the same manifest drives (a) the gateway's
MCP tool composition, (b) the `aw <app>` CLI plugin verbs (a generic
manifest-driven dispatcher over the existing `aw id request --team-auth`
signed-request backend; an external `aw-<name>` binary is the escape hatch for
custom client logic), and (c) the aweb.ai hub listing. **Because two consumers
interpret the same manifest, they need a shared manifest-interpretation
conformance suite** (`manifest + verb + args → exact method/url/body/headers`) —
the manifest analog of the auth conformance vectors — or the CLI and gateway
drift. **Security constraint (in that suite):** dispatch builds the target from
the granted app **origin + relative path only**; reject any host/scheme override
in a manifest. `aw id request` signs `aud`+`path` from the absolute URL it's
handed, so a host-injecting manifest would redirect a signed, authenticated
request.

**App contract (freeze first):** gateway-signed or direct cert-auth; **no
app-local accounts**; every row team-scoped. **Stable subject:** the canonical
protocol claim stays **`team_id`** for v1 — product/marketing may say
network/web, but apps store the *stable protocol subject*, not display
vocabulary. Structured 401/402/quota responses. **Conformance vectors first**
(reuse `aweb/test-vectors/`); a shared versioned verifier library is extracted
**only after** the contract stabilizes across ≥2 real apps (`atext` + `folio`).
Non-negotiable: conformance + versioning, not packaging on day one.

## 8. `ac` decomposition — stop embedding everything (the smaller-containers win)

**Current coupling (what makes the container big):**

- `from aweb.api import create_app` + `app.mount("/api", aweb_app)`
  (`main.py:33,432-483`) and the hosted MCP mount at `/mcp` — the OSS server runs
  **in-process**.
- One Postgres pool spans **three runtime schemas** (`aweb_cloud`, `server`,
  `aweb`). **`awid` is the external HTTP registry** (`api.awid.ai`), *not* a
  same-pool schema in production — a same-pool `awid` manager appears only in
  tests (ac-team survey, 2026-06-17; corroborated: no FK references `awid`). So
  m8's awid decoupling is **packaging** (stop compiling `awid` into
  `Dockerfile.release`), not FK/schema cleanup.
- **30 cross-boundary foreign keys** lock the schemas into one deployable
  (representative: `aweb_cloud.* → server.teams`, `aweb_cloud.* → aweb.workspaces`,
  `aweb_cloud.* → aweb.agents`, `a2a_gateway_routes → server.teams`,
  `cloud_custodial_encryption_keys → aweb.workspaces`; plus overlay FKs
  `aweb.* → server.teams`/`aweb.agents`). Full inventory in the appendix
  (§8.1).
- **The `aweb_overlay` migration mutates the core `aweb` schema**: 11 cloud
  columns on `aweb.agents` (`server_team_id`, `did`, `public_key`, `stable_id`,
  `custody`, `signing_key_enc`, `team_cert_blob`, …), `signing_key_id` on
  `aweb.messages` + `aweb.chat_messages`, and **alters `aweb.tasks.parent_task_id`
  to DEFERRABLE** (for cloud restore/cutover). It also creates 7 tables *inside*
  the `aweb` schema (`did_aw_mappings`, `did_aw_log`, `dns_namespaces`,
  `public_addresses`, `api_keys`, `spawn_invite_tokens`,
  `replacement_announcements`).
- `Dockerfile.release` compiles sibling `aweb` + `awid` into the image
  (`:48-56`).

**Target:** core `aweb` + `awid` run as their own small services (own images),
reached over HTTP; `aweb.ai` (control plane + gateway) carries **no embedded
OSS**; apps are separate small services.

**Decoupling work:**

1. **Dismantle `aweb_overlay` — in two stages (it is not self-contained).** The
   overlay touches identity tables (`aweb.agents`, 11 cols), namespace/identity
   tables, **and** messaging tables (`signing_key_id` on `messages`/
   `chat_messages`), and alters `aweb.tasks.parent_task_id`. The messaging
   columns cannot be removed while messages/chat are still in core. So:
   **8a** dismantles the identity/namespace/non-messaging overlay now; **8b** the
   messaging columns ride with the messaging split (§12.10). Cloud columns/tables
   move into control-plane-owned tables or projections.
2. **Remove or convert the 30 cross-boundary FKs** to logical references
   (`aweb_team_id` becomes an API/identity reference, not a DB FK). Staged: logical
   refs + backfill + verification before dropping FKs. **FKs touching the
   split-last messaging tables and the split `workspaces` table are 8b** (gated by
   their splits); the rest are 8a. The FK appendix tags each entry
   **doable-at-8a** vs **gated-by-later-split**. **Preserve the
   `aweb.tasks.parent_task_id` DEFERRABLE behavior** wherever the tasks schema
   lands (§12.7).
3. **Separate DB pools / databases** per service.
4. **Replace the `/api` + `/mcp` mounts** with network calls / reverse proxy to
   the standalone core + the gateway.
5. **Retire the thin-proxy/overlay routers** (`oss_admin`, `oss_public`,
   `oss_workspaces`, `dashboard`/`chat`/`messages` wrappers) — once core is
   external and cert/gateway-authed directly.

**`ac` shrink goals (success criteria):** fewer cross-boundary imports; **no
overlaid/copied core migrations** (`aweb_overlay` gone); smaller images;
independently deployable services; one preserved local-dev story.

### 8.1 Appendix — cross-boundary FK inventory

The 30 FKs and every `aweb_overlay` alteration are enumerated (file:line) in
[`restructuring/ac-cross-boundary-fk-inventory.md`](restructuring/ac-cross-boundary-fk-inventory.md).
The OSS-core inventory backing §4–§5 is in
[`restructuring/oss-core-inventory.md`](restructuring/oss-core-inventory.md).
This is the **highest-risk mechanical step** in the plan; the SOT does not
understate it.

## 9. Billing and quota — bundled mutation model

- **`awid` unmetered. Self-hosted unmetered.** Hosted is free up to **one bundled
  mutation quota**; paid tiers raise the quota and resource-class limits.
- **Mutation = a successful hosted state change** (send a message, store/update a
  task, append a doc version, mint a present-link). **Not** reads, auth failures,
  failed validation, or idempotent retries. Pinned in the app contract so every
  app — including third parties — counts identically.
- **Enforcement semantics:** **soft** for normal ops — apps cache plan/limits and
  report usage **async**; v1 quotas are deliberately soft for normal mutations.
  For **expensive / high-abuse** mutation classes, use a **central synchronous
  counter or a leased signed budget** (apps lease a small budget from the control
  plane and report spend). Auth fails closed; billing fails **soft** to free-tier
  (reads always free; expensive ops hit conservative free caps).
- **Resource-class guardrails** are separate from the mutation count: storage,
  media/video, retention, bandwidth, audit/export.
- **A2A (decided, not a special case):** hosted **A2A gateway** operations
  (§3.2) are hosted mutations under the bundled quota like any other; there is
  **no separate A2A entitlement bit**. A2A is *defined* independently of billing
  in §3.2 — this is only its billing treatment, not its definition.
- **Entitlement service:** thin control-plane module; boring API (`team_id`,
  `sku/plan`, `limits`, `effective_until`, `signature/version`, `usage`). Seed:
  `services/message_metering_hook.py` (wraps `on_mutation`),
  `middleware/message_limits.py`, `models/billing.py:TIER_LIMITS` — generalize
  from "messages/day" to "bundled mutations/period," and from an in-process hook
  to a queryable service.

## 10. CLI / plugin

kubectl/gh external-binary dispatch (`aw <name>` → `aw-<name>`; context via env;
auth stays in `aw` via `aw id request --team-auth`; `aw plugin
list/install/remove`). **Prerequisite** for the `aw tasks`/`aw folio`/`aw dev`
story. Until it lands, apps run on raw `aw id request --team-auth` + `/skills` +
`/llms.txt`; keep compat aliases (incl. `aw task`, `aw lock`) through the
transition.

Distinct from app plugins: **`aw a2a`** (§3.2) is the outbound A2A client +
card verification/publication helper — it speaks the external Agent2Agent
protocol, not the app-manifest dispatch path.

## 11. OSS vs private boundary

- **OSS / self-hostable:** `awid` + the core authority/transport substrate;
  `atext` (public sample).
- **Repo organization:** `aweb` stays the core/protocol/reference repo. First
  party apps should normally live in their own repos and expose their own
  manifests/origins. Do not place every app inside `aweb` just to inherit the
  core repo's stars; use the `aweb` README/docs, GitHub org pins, app manifests,
  and an app index for discovery.
- **Case by case:** apps may be OSS or private (`folio` may stay private).
  Audit/logs and secrets need OSS/self-hostable cores because customers may need
  to own retention, compliance, and secret custody. Commercial hosted wrappers,
  provider integrations, and managed retention/KMS can remain hosted/private
  where appropriate.
- **Hosted metering applies only to hosted services**; self-host is unmetered.

### Self-hosted app with hosted core

The app architecture should allow a customer to self-host one app while using
hosted aweb core for the rest. The existing app registry/grants model already
points in this direction: an installed app is identified by `(app_id, origin,
digest, granted_scopes)`, and tool dispatch targets the installed app origin.

What works under the current contracts:

- a self-hosted app can serve `/.well-known/aweb-app.json`;
- a hosted team can install that origin/digest and grant scopes;
- CLI/gateway dispatch can call that app origin using team-auth;
- the app can emit app events back into core with an installed app emit key.

What does **not** exist yet:

- a core signed/hash-chained team audit ledger;
- `audit:read` or equivalent scoped access to all core protocol facts;
- a pull/export API or webhook feed for an external audit app;
- a verifiable event checkpoint contract a self-hosted audit app can store and
  prove independently.

Therefore, "self-host audit/logs while using hosted aweb core" is a target
contract, not a finished capability. The correct split is:

```text
core aweb
  owns verified protocol facts and signed/hash-chained audit events
logs.aweb.ai or self-hosted logs app
  owns storage, views, export, retention, and compliance workflows
```

For v1, prefer **pull** over push: a self-hosted audit app calls a hosted-core
audit export endpoint with a team grant, verifies server signatures and the team
hash chain, and stores its own copy. Webhook delivery can come later after the
pull contract is stable.

## 12. Migration and sequencing (revised order)

**Principle:** split product/docs/CLI UX **before** schema/service surgery; keep
compat aliases while this team keeps dogfooding; move boundaries only after
product + CLI behavior are stable. Treat existing mail/chat as the **bundled
default comms app** during the whole transition (code stays in core a while).

1. **App contract + manifest schema + conformance vectors** (`atext`/`folio`
   reference).
2. **`aw` plugin dispatch + `aw plugin` management** (prerequisite).
3. **Core platform formalization:** app **registry** + app **grants**; make the
   **event channel app-generic** (emit arbitrary app event kinds, not the
   hard-coded mail/chat/control set — see the archived `restructuring/archive/channel-stack-map.md`); and the
   **signed-envelope transport** primitive (extracted from `federation`;
   messages/chat keep using it but stay put).
4. **Hosted gateway:** static → **dynamic manifest composition**; unify
   **connector grants** over `mcp_oauth_*`/`api_keys`; **custody/billing
   separation** cleanup; surface explicit **BYOT capability states** (§6.2) so
   BYOT stops feeling like broken hosted. Hosted-MCP-on-BYOT ships via customer
   admission + cert pickup (existing `byot_custodial_identity_authorizations`);
   the `byot-delegated` grant is deferred to v2.
5. **Bundled-mutation entitlement service** (generalize `ac` metering).
6. **`folio.aweb.ai` flagship.**
7. **`tasks.aweb.ai` + `aw tasks`**; move tasks/work/claims out of core behind
   compat aliases; **drop locks** (or `dev`). **Trap:** the overlay alters
   `aweb.tasks.parent_task_id`; decide where the task-schema + that FK transform
   lands **before** promising overlay retirement — keep a temporary core-owned
   task compat patch until tasks moves.
8. **`ac` decomposition:** stop embedding OSS; separate services/images.
   ← the smaller-containers payoff. **This step is NOT self-contained** — the
   overlay/FK removal is partially gated by later splits, so it stages in two:
   - **8a (now):** dismantle the non-messaging overlay (identity/namespace cols on
     `aweb.agents`, the overlay's identity/namespace tables) and remove/convert
     the FKs *not* touching the split-last messaging tables or the split
     `workspaces` table.
   - **8b (rides with m10):** the overlay's messaging columns
     (`signing_key_id` on `messages`/`chat_messages`) and FKs touching messaging
     can only be undone once messaging moves. The FK appendix tags each
     FK/overlay-column **doable-at-8a** vs **gated-by-later-split**.

   (Preserve `aweb.tasks.parent_task_id` DEFERRABLE wherever tasks lands — §12.7.)
9. **`dev.aweb.ai`** (consumes tasks; dashboard/visibility; locks rebuilt only if
   real).
10. **LAST / deepest cut:** split `messages`/`chat` **semantics** from the
    transport → first-party messaging apps. Done early this destabilizes
    federation/events/E2EE, which are currently fused — so it goes last. It is
    **not** "move tables + add manifest". It carries a **fusion sub-checklist**
    (grounded read with file refs in
    [`restructuring/messaging-as-app-seam.md`](restructuring/messaging-as-app-seam.md)):
    (i) **converge only the REQUEST auth** off the bespoke identity-messaging path
    (`/v1/messages*`,`/v1/chat*`, DIDKey + `X-AWEB-DID-AW`) onto v2 app-auth, and
    **require** app-auth (don't keep identity auth as an equal route, and don't
    reuse `channel-core`'s compact-legacy team headers) — the **inner
    message/E2EE envelope signature stays payload semantics**, not replaced;
    (ii) optionally **purify the envelope format** (§3.1); (iii) **generalize E2EE
    decrypt** into a messages/chat app hydrator (today shells `aw mail show`/`aw
    chat history`); the **events stream stays core** (it just gains app
    id/type/resource refs — same work as m3); (iv) move the **8b overlay
    messaging columns**; (v) **decide global-identity ↔ team-scoped app
    mutations** — app mutations likely require an active team/app grant while core
    addressability still resolves recipients (the one real design call here).

`secrets`/`kpi` follow as focused apps. This coordinator/developer/reviewer team
keeps running throughout; we migrate our own usage last.

## 13. Open decisions for Juan

1. **A2A — DECIDED (Juan):** A2A is the open-agent-interoperability protocol
   (§3.2), *not* messaging and *not* a billing special-case. Billing = bundled
   mutations; hosted A2A gateway ops consume the bundled quota, no capability bit.
2. **`dev` shape:** own service consuming `tasks` via API (clean boundary,
   +1 container) vs a dev-mode surface sharing the `tasks` backend (fewest
   containers). Default: separate service; decide when we build it.
3. **Rename "anapp"** (awkward) — and the timing of the network/web vocabulary
   shift (note: `team_id` stays the protocol subject regardless).
4. **Pricing** numbers/tiers.
5. **Which apps are OSS vs private.**
6. **Hosted agents:** explicit **out-of-scope for v1** strategic fork (runtime
   hosting = different compute/sandboxing/billing). Architecture must not
   preclude it; connector grants already generalize toward it.
7. **`contacts`:** **resolved → core** (execution-team read: the trust/registry
   layer / `SenderTrustManager` depends on it, so it's core addressability, not a
   comms-app surface). Recorded as decided unless you object.
8. **BYOT delegation timing:** v1 ships hosted-MCP-on-BYOT via certificate pickup
   after **customer admission** (no new object); the `byot-delegated` grant
   (§6.2) is v2. Confirm that v1 scope (one customer signing step per identity) is
   acceptable, or whether delegation must come sooner.
9. **BYOT capability states** (§6.2, `hosted-managed` / `byot-connected` /
   `byot-delegated` / `migrated-to-hosted`): confirm this is the state set the
   UI/API should expose so BYOT stops feeling like broken hosted.

## 14. Risks

- **Cross-schema FK removal (30) + `aweb_overlay` dismantling** = the
  highest-risk mechanical step. Stage it: logical refs + backfill + verify before
  dropping FKs; preserve the `tasks.parent_task_id` DEFERRABLE behavior.
- **Messaging-as-app destabilization** if attempted early (federation/events/E2EE
  are fused) → sequence last.
- **Gateway monolith risk** → keep it a gateway (compose/auth/sign/forward/meter
  only).
- **Transport ballooning back into messaging** → wording + scope discipline:
  core moves opaque signed bytes + events; apps own meaning.
- **Verifier drift** across many apps → conformance vectors gate; library only
  once stable.
- **Transition valley** until plugin dispatch lands → compat aliases.
- **App proliferation re-confusing users** → the catalog, "one identity, many
  apps," bundled (not per-app) billing, and the single human site.
- **Re-monolith trap** → do not fold billing + accounts + coordination + app
  logic into one service.
- **BYOT authority leakage** → the hosted/BYOT distinction must stay in the
  control plane/gateway and never reach the app contract or core transport (apps
  trust AWID/certs/grants only). The raw BYOT controller key must never reach the
  cloud — `byot-delegated` (v2) is a scoped, revocable, customer-signed
  capability, not key handover. Building delegation is real authority-design work;
  do not let it block v1, which works via customer admission + cert pickup.

---

*Next: aweb-consultant's final validation pass (incl. the FK appendix); then the
coordinator cuts the first epic (milestones 1–2: app contract/manifest +
conformance vectors, and `aw` plugin dispatch) into scoped tasks with acceptance
criteria. Nothing here is task work until Juan approves.*
