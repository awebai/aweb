# Audit substrate: aw-hooks and logs.aweb.ai

Status: **D-hooks proposal, aweb-acgh.1, awaiting the D1 lead's v2 fit check,
an independent review, Athena and Juan.** This is a design, not a claim that any
interface here ships. No implementation is part of it. Every default below is a
recommendation to Juan; scope cuts are proposals, never decisions.

Inputs: Juan's private naapp specs, cited by section and never quoted.
**hooks-spec** is the private aw-hooks spec, not the public
`docs/aw-hooks-sot.md`. **logs-spec** is the audit-logs spec. **secrets-spec**
is the secrets and `aw do` spec, including §14. Where this design relies on a
private section, it states the content it uses. D1 (`docs/design/agent-pages.md`
on branch `agents/aweb-protocol-expert-pages-design`, 8ef61170a70f) owns
manifest v2 (C3),
installation authority (F6), task integration (C2) and hosted MCP (L2). This
design fills the C3 `hooks` slot that D1 reserves and does not fork D1. Where a
need falls on D1, it is stated as a request to the D1 lead. Three sibling
tasks are reused, not re-specified:

- **aweb-acgh.7** owns the generic app → team-server API: server discovery,
  purpose-split app authentication, grant status and hook resolution. §A4
  states only what hooks require of it.
- **aweb-acgh.3 (B1)** is the shared naapp-lib team-auth verifier.
- **aweb-acgh.4 (B2+B3)** is the approval primitive and WebAuthn.

Following Juan's direction, no runtime code repeats across naapps: §C marks
every component as shared `aweb_naapp` or app-local.

There is one generic architecture. Shared pieces are built once, in
`aweb_naapp`, the OSS server or a hosted operator, never as per-app special
cases, and core gets no naapp-specific code. Where a hosted operator must
provide something, this doc states it as a generic requirement on "a custodial
deployment" (§2, §B4, §A9).

## Summary for Juan

- **A hook is a named, versioned extension point.** An installed app registers
  a hook-only tool as its target, and only the team owner can activate that
  registration. Activation pins the exact manifest digest, the installation
  generation, the resolved tool and the catalog version. An ordinary admin
  install leaves hooks pending.
- **The layer that effects an action fires its hook, exactly once, as one
  logical event.** Core, a naapp server or `aw` fires it, in disjoint classes.
  Server-fired hooks are the audit guarantee. `aw`-fired hooks are cooperative
  and recorded as agent-reported.
- **Every event is a canonical, redacted envelope signed by its producer.** The
  producer commits it to its own durable outbox in the same transaction as the
  effect, then delivers it at least once to each active target. Audit-critical
  hooks fail closed: no committed event means no effect.
- **logs.aweb.ai is an ordinary naapp** with its own database. Its `ingest`
  tool is hook-only. It verifies provenance, dedups, and appends to a per-team
  hash chain with signed checkpoints and signed receipts. Only the owner and
  owner-designated humans with passkeys can read the log. It has no edit or delete API, and
  retention and erasure purge content while the chain still verifies.
- **Self-hosting means activating a different logs installation as the target.**

## 1. Evidence at baseline A

**A = aweb origin/main b423415a92bf** (the same baseline as D1). Every
`path:line` below refers to A.

| Observation at A | Evidence |
| --- | --- |
| The only hook seam is the in-process `on_mutation` callback. It is awaited after the route's state change, outside its transaction, and its exceptions are swallowed. It can be missed if the process dies between commit and callback. | `server/src/aweb/hooks.py:15`–`:27`; `docs/aw-hooks-sot.md:42`–`:50` |
| `on_mutation` call sites are pinned by a source-derived inventory of 23 rows. A build guard rejects added, removed or non-literal sites. | `docs/vectors/mutation-hook-call-sites-v1.json`; `scripts/check-extension-docs.py:134`, `:275`, `:544`–`:553` |
| Several catalogued mutations are not transactional. Mail send is autocommit unless attachments are present. Ack, task comment, dependency and `connect` are bare statements. | `server/src/aweb/messaging/messages.py:353`; `server/src/aweb/messaging/attachment_service.py:89`–`:112`; `server/src/aweb/coordination/tasks_service.py:1201`–`:1213`; `server/src/aweb/routes/connect.py:357` |
| Task create and update are transactional, and the hook fires after the transaction. | `server/src/aweb/coordination/tasks_service.py:205`; `server/src/aweb/coordination/routes/tasks.py:118` |
| MCP task tools fire no mutation hook. MCP mail and chat do. | `server/src/aweb/mcp/tools/tasks.py:20`–`:196`; `server/src/aweb/mcp/tools/mail.py:176`; `server/src/aweb/mcp/tools/chat.py:864` |
| A transactional outbox precedent exists. Lifecycle side effects are inserted in the cascade transaction, drained with `SKIP LOCKED`, retried with backoff and documented as at-least-once. | `server/src/aweb/migrations/aweb/013_lifecycle_side_effect_outbox.sql`; `server/src/aweb/lifecycle.py:896`, `:969`–`:1091` |
| The install route records the supplied digest and scopes for any authenticated member. It has no admin gate and does not fetch the manifest. | `server/src/aweb/routes/apps.py:104`–`:132`; `docs/app-registry.md:24`–`:29`, `:84`–`:89` |
| One app id has one origin across a registry. | `docs/app-registry.md:79` |
| The app-emit credential is request-bound (aud/method/path/body hash/key). It is not a content signature. | `docs/app-events.md:100`–`:147`; `server/src/aweb/app_events.py:82`–`:155`; `cli/go/internal/conformance/vectors/app-emit-credential-v1.json` |
| Canonical JSON is sorted keys, no whitespace and UTF-8. | `awid/src/awid/signing.py:44`; `cli/go/awid/signing.go:141` |
| Team-auth v2 binds one request to a member certificate. Extra payload fields are signed and ignored by the auth layer. It is not replay-proof. | `docs/team-auth-envelope-v2.md:34`–`:38`, `:95`–`:105` |
| Team-auth v2 proves neither custody mode nor a human principal. | `docs/team-auth-envelope-v2.md:3`–`:6`; `docs/product-authority-sot.md:114`–`:130` |
| Membership authority is the team controller's signature. AWID records certificate register and revoke, has no outbox or push feed, and exposes pull reads. Managed teams' controller key is held by the hosted deployment. | `docs/awid-sot.md:36`–`:49`, `:541`–`:563`, `:615`–`:620`, `:681`–`:690`; `awid/src/awid_service/routes/teams.py:840`, `:1172`, `:1194` |
| Core caches AWID revocations for authentication only. It persists no membership-revocation effect. | `server/src/aweb/team_auth_deps.py:355`; `server/src/aweb/messaging/sender_membership.py:35`–`:59` |
| Identity grant revoke writes the legacy `audit_log` in-transaction. That table has no chain and is not part of this design. | `server/src/aweb/routes/identity_grants.py:278`–`:313`; `server/src/aweb/migrations/aweb/001_initial.sql:469` |
| No `trace_id` exists. The CLI sets `X-Request-ID` only on AWID and A2A calls. | `cli/go/awid/registry_client.go:612`; `cli/go/a2a/client.go:156` |

## 2. Governing model

Authority comes before mechanism:

- **Producers effect actions.** Core effects coordination state. A naapp server
  (secrets, folio, linear) effects its own state and its brokered external
  calls. `aw` effects purely local state: keys, certificates on disk, local
  approval catalogs and grant snapshots. Only the effecting layer can state
  what happened, so only it produces the event.
- **The owner authorizes where events go.** A hook target receives redacted
  but sensitive activity. An agent-registered target would be an exfiltration
  channel (hooks-spec §2), so target activation is an owner act, not an
  install side effect. Producer activation is also an owner act, because a
  producer's events are trusted by the log.
- **"Owner" means the holder of team controller authority.** That is the same
  authority that alone can register and revoke team certificates. This design
  proposes one domain-separated artifact, `aweb.owner-act/1`, signed by the
  current AWID team key (§A3). For BYOT the owner signs it locally with `aw`.
  For a managed team the custodial deployment holds the controller key, so it
  signs only for the owner's own gesture behind its install UI, as D1 records
  it. **Requirement on the custodial deployment:** that gesture must be an
  interactive owner session with fresh step-up (passkey or re-authentication).
  It must never be an API key, an MCP OAuth token or any other credential an
  agent can hold. Otherwise an agent with owner-scoped API access could
  activate an exfiltration target, revoke logs or erase. A working credential,
  a role label or a domain string is not owner authority. This is an
  identity-path change and needs Juan's explicit approval.
- **The controller key is governance-only.** Owner acts activate and revoke
  bindings, designate readers and set retention or erasure. They are rare
  governance events, never routine read credentials (§B5).
- **Who the hosted operator can override.** The custodian of a managed team's
  controller key can mint *any* owner act: activate or revoke targets,
  designate itself a reader, set retention and erase. For managed teams the
  log therefore protects against agents and other apps, **not against the
  operator**. Only BYOT controller custody, together with a self-hosted logs,
  removes the operator from the trust base (§B3, §B7). Product copy must say
  so.
- **What a signature proves.** A producer signature proves *who emitted* an
  event. A logs chain proves *nothing was later dropped, reordered or altered*
  inside logs. Neither proves that the actor was human or how the actor's key
  is held (§B4).

## Part A — aw-hooks

### A1. Terms

- **Catalog**: a versioned list of named hooks, each with a firing class,
  producer kinds, a strict payload schema and an audit-critical flag. The id is
  `aweb.hooks` and v1 is §A2.
- **Binding**: an owner-activated record in the core team registry. A
  *registration* binds a target app's hook-only tool to a hook. A *production*
  authorizes an installed app to emit a hook.
- **Event**: one logical firing, the signed envelope of §A6, with a stable
  `event_id`.
- **Delivery**: one attempt sequence from a producer's outbox to one active
  registration.

### A2. The catalog, v1

| Hook | Class | Producer | Audit-critical | Fires for |
| --- | --- | --- | --- | --- |
| `post-secret-use-hook` | server | an app with an active production (secrets) | **yes** | Every brokered use, refusal, approval request and decision, dispatch, result and outcome-unknown/reconciliation of a secret-mediated operation. |
| `post-governance-hook` | server | any app with an active production | **widening acts yes; narrowing acts never gated** | App-side governance: role designation (approver, reader, owner-approver), passkey and contact enrolment and recovery, grant and resource lifecycle, policy changes, runner registration, and installation-wide disable. The catalog fixes each act as widening or narrowing; the producer does not choose. Narrowing acts are always enqueued in their own transaction, but they are never refused for audit availability, because containment must not wait. It is generic and shared by secrets, logs, pages and any naapp. |
| `post-manifest-command-hook` | server | an app with an active production, serving its own tool | no | Every admitted mutation tool call and every attributable refusal. Reads fire only for tools the production lists (§A3). |
| `post-mutation-hook` | server | core | no (see §A7) | The demo-critical core mutations listed in §A10. |
| `post-command-hook` | client | `aw`, signed by the member | no; cooperative | Local effects of an `aw` command that reaches no server for that effect (§A5). |

Rules:

- **One effect, one hook.** A more specific hook supersedes the generic one for
  the same effect. A tool call whose effect is a secret use fires only
  `post-secret-use-hook`, and one whose effect is a governance act fires only
  `post-governance-hook`. Neither also fires `post-manifest-command-hook`,
  which covers only the tool calls that no specific hook covers. The catalog records precedence
  explicitly.
- **Payloads are allowlists.** Each hook has a strict schema with unknown-field
  rejection and no free-text fields. Redaction is structural: a producer cannot
  leak through an extra field, because consumers reject it. Values are refs,
  ids, enums, digests and bounded integers, never secret values, message
  bodies, subjects, previews, task titles or comment text.
- **Versioning.** A binding names `(catalog id, version, hook)`. Any payload
  change, including an addition, is a new catalog version, matching manifest
  v1's strictness (`docs/app-manifest.md:353`–`:359`). Unknown catalog ids,
  versions or hooks cannot be activated and are rejected at ingest. If a
  producer can no longer emit a bound version, the binding shows
  `incompatible` to the owner. It never silently stops.
- **Blocking `pre-*` hooks are deferred** (recommendation). A blocking hook
  makes the guard's availability part of every action's availability and is a
  new authorization path. The approval primitive already covers human gating
  for secrets. The catalog and binding shapes leave room for a later
  `class: "blocking"` hook whose default is fail-closed, decided when it is
  introduced (hooks-spec §6).

Per-hook payloads, beyond the common envelope:

| Hook | Payload fields |
| --- | --- |
| `post-secret-use-hook` | Defined here, and the secrets design cites it. See the flat allowlist below. |
| `post-governance-hook` | `act` (catalog enum: `role.designated`, `role.revoked`, `credential.enrolled`, `credential.recovered`, `credential.revoked`, `grant.created`, `grant.changed`, `grant.revoked`, `resource.created`, `resource.version_added`, `resource.disabled`, `resource.enabled`, `resource.replaced`, `policy.changed`, `runner.registered`, `runner.deregistered`, `installation.disabled`, `installation.enabled`); `direction` (`widening` or `narrowing`, fixed per act by the catalog and checked at ingest); `role`, `resource_type` (bounded app-local tokens matching `^[a-z][a-z0-9_.-]{0,63}$`); `subject_ref`, `resource_ref`, optional `before_ref`/`after_ref` (opaque); `authority` (`owner_act`, `passkey_session`, `team_cert`); optional `owner_act_sha256` (owner-act-rooted acts), `approval_evidence_sha256` (passkey-confirmed acts), `approval_id`, `policy_digest`, `reason_code`. A governance act that cannot enqueue does not commit. |

**`post-secret-use-hook` payload, v1** (one flat allowlist, with no nested
objects and no free text). The hooks catalog vector records it.

| Field | Content |
| --- | --- |
| `action` | `refused`, `approval_requested`, `approval_decided`, `admitted`, `dispatching`, `completed`, `not_sent`, `outcome_unknown`, `reconciled`. `dispatching` is the durable intent committed before any external call. |
| `op_kind` | `broker` or `run_job` |
| `secret_id`, `secret_ref`, `secret_version`, `secret_kind`, `secret_backend`, `secret_sensitivity` | Refs and enums. Never a value, never a fingerprint. |
| `target_method`, `target_host`, `target_port`, `target_path_template` | Broker. Open requests carry host plus path template only, never a concrete path or query. |
| `operation_id`, `operation_digest` | Named operations. |
| `runner_id`, `job_id`, `job_digest` | Runner jobs. |
| `request_sha256`, `params_sha256` | The agent's frozen request and parameters, **before credential injection**. |
| `grant_id`, `policy_digest` | The secrets grant and the policy evaluated. |
| `approval_id`, `approval_assurance`, `approver_id`, `approval_credential_id`, `approval_evidence_sha256`, `approval_decision` | Present only when there is an approval. |
| `dispatch_id`, `dispatch_state` | |
| `upstream_status_code`, `upstream_bytes`, `upstream_truncated`, `upstream_response_hmac` | The HMAC is producer-keyed and optional. There is no unsalted response digest. |
| `returned_hmac` | A producer-keyed HMAC of the bytes returned to the agent, after projection and redaction. It is absent when the result is `withheld`. It is an HMAC and not a plain hash, because returned bytes may still carry a credential (`returned_credential`, or one that redaction missed). |
| `disposition`, `derived_secret_id` | `returned`, `withheld`, `stored_as_secret` or `returned_credential`, on `completed`. |
| `undeclared_credential` | Boolean, on `completed`: the response carried a credential that was not declared. |
| `redaction_count`, `refusal_code` | `refusal_code` is a fixed enum that the secrets design supplies, recorded in the catalog vector. |

A withheld value and an undeclared credential are properties of the
`completed` event, not separate events: one effect, one event.
`installation_id`, generation and the principal are carried by the envelope's
`producer` and `actor` (§A6). **Digest rule (security):** no payload digest is
ever unsalted over bytes that contain or may echo a credential.
| `post-manifest-command-hook` | `app_id`, `tool`, `operation_kind` (`mutation`, `read`, `refusal`), `request_sha256` over the canonical request bytes of the manifest mapping, declared opaque `resource_refs`, `http_status`, optional `result_ref`. Parameter values are not copied; the digest commits to them. |
| `post-mutation-hook` | `mutation_type` (§A10), `target_ref`, optional `before_ref`/`after_ref` (revision or state refs), and the per-type fields in the catalog (status values, assignee identities, `content_mode`). Never bodies, subjects, previews or titles. |
| `post-command-hook` | `command` (canonical command path), `flags` (names only, plus values of catalog-declared enum flags), `local_effects` (enumerated, e.g. `identity_key_created`, `team_certificate_stored`, `app_approval_recorded`, `grant_minted`), `exit_status`. |

### A3. Registration and owner activation

**Manifest slot (C3), as D1 specifies it** (`agent-pages.md` §5 "Versioned
hooks slot and invocation contexts" and `contracts.md` "Hook registration
slot", D1 8ef61170a70f): the manifest declares
`hooks: {registration_version: 1, registrations: [{catalog: {id, version},
hook, tool, scopes}], productions: [{catalog: {id, version}, hook, reads?}]}`.

- `tool` is local to that manifest, and the target tool declares
  `invocation_contexts: ["hook"]`, so CLI, MCP, L2 and surfaces never list or
  call it.
- `productions` are the hooks an app may emit, bounded to at most 64 like
  registrations. Without owner-activated productions, any installed app could
  forge, for example, secret-use events into the log.
- `reads` is a list of distinct local tool names in the same manifest, each
  non-mutating. An unknown or mutating name refuses the manifest. Their reads
  fire `post-manifest-command-hook` (§A2), and activation shows the list to
  the owner.
- Keys come from D1's v2 `app_keys: [{kid, did_key, purposes}]`. A v1
  `event_emitters` entry reads as `app-event` only. A verifier accepts a key
  only for a purpose that key declares. This design defines two purposes
  declared on a key: `hook-event` (the envelope content signature, §A6) and
  `hook-delivery` (the transport credential, §A7). `hook-resolve` belongs to
  acgh.7. Hook purposes stay inactive until owner activation.

**Why use the team install record.** Bindings are child rows of the team
install record, keyed by D1's `installation_id` and generation (F6). A
binding's validity is exactly the installation's validity: the same digest,
generation, update and uninstall fence. A separate registry would duplicate
that state and let the two diverge. Only the activation authority differs
(owner, not admin), so the binding carries its own state, not a flag on the
install. This needs a new ordered core migration (`app_hook_bindings`) and
no change to existing migrations. **Dependency:** at A the install record keys
only `(team_id, app_id)`
(`server/src/aweb/migrations/aweb/008_app_registry_grants.sql:42`–`:60`). The
`installation_id` and generation come from D1's F6, and activation refuses
until F6 adds them. Logs trusts a production's keys to accept events, so
owner activation of a **production** also refuses until the server derives
its registered keys from manifest bytes that hash to the pinned digest. That
is acgh.7's key-registration fix, which needs F6 first.

**Binding state.** Install or update creates each declared binding as `pending`.
An owner act moves it to `active`. Revocation, uninstall or a new generation
moves it to `revoked`/`superseded`. A new generation never inherits activation,
even when bytes look similar: the owner re-activates against the new digest.
A binding record holds `binding_id`, `kind` (registration or production),
`team_id`, `installation_id`, generation, `app_id`, origin, digest, catalog id
and version, hook, `tool`, the resolved `method` and raw `path` from that
digest's tool mapping, scopes, `reads`, state, `active_from`, `revoked_at`, and
the SHA-256 of the owner acts that changed it.

**Owner act.** Activation and revocation take an `aweb.owner-act/1`. The
signing bytes are the literal `aweb.owner-act/1` plus a newline, followed by
canonical JSON of `{v, type: "aweb.owner-act", act, team_id, aud,
team_key_did, subject, issued_at, expires_at, nonce}`. For a binding, `act` is
`hook-binding.activate` or `hook-binding.revoke`, and `subject` is
`{installation_id, generation, app_id, origin, digest, kind, catalog, hook,
tool, method, path, scopes, reads}`. The approving client fetched and hashed
the exact manifest bytes and resolved the tool. The server compares the
subject with the stored pending binding; it does not fetch.

The prefix is unique to this artifact, so no other team-key-signed object can
verify as an owner act, nor an owner act as one of them. That covers team
certificates and AWID controller envelopes, which are both canonical JSON
without this prefix.

The verifier checks, in order:

- the signature against the *current* AWID team key, fetched fresh (cache of
  at most 60 s), so a rotated-out key stops working promptly;
- `aud` in its configured public origins;
- a lifetime of at most ten minutes;
- a nonce unused in a stored table (this artifact is rare, so unlike team-auth
  v2 it is single-use);
- `act` within **that verifier's closed vocabulary**, with its defined subject.
  Core accepts only `hook-binding.activate` and `hook-binding.revoke`. Naapps
  accept the generic app-governance acts below plus their own closed list
  (logs: §B6). A valid act of another type or audience is refused;
- an exact subject match with the pending row and current generation.

Any mismatch refuses with a distinct error, and an admin or member signature is
refused (`owner_required`).

**The owner act is every naapp's root of trust for governance.** `aweb_naapp`
defines three generic app-governance acts, with subject `{app_id,
installation_id, role, subject_ref}`:

- `app-role.designate` names a holder of an app-local role, such as a logs
  `reader`, a secrets `approver` or an `owner-approver`;
- `app-role.revoke` removes one;
- `app-credential.recover` authorizes re-enrolment after a lockout.

Bootstrapping the first holder of any such role, and recovery after a lockout,
use these acts and never install or admin authority. Enrolment then follows
acgh.4. A narrowing request authenticated by team-auth alone cannot remove the
*last* holder of an owner-designated role: it refuses, or starts the app's
cooling-off. Each act produces a `post-governance-hook` event.

The owner act is itself a governance event: core emits `post-mutation-hook`
`hook_binding.activated` and `.revoked`. **Revocation:**

- The revoked target receives `hook_binding.revoked` as its final entry, then
  it is cut off, so its chain ends with an explanation instead of just
  stopping.
- Its other undelivered backlog is cancelled; the cut is the exfiltration
  remedy.
- The remaining registrations receive a governance event recording the
  cancelled count and per-producer `seq` range, so their `verify` shows an
  explained gap.
- Producers stop delivering within the freshness bound (§A4). The target's
  operator may therefore see redacted activity for up to `max_age` after
  revocation, and the owner copy states this.

**`active_from`.** Activation sets `active_from = activated_at + max_age`, the
resolution freshness bound (60 s, §A4). From `active_from` on, every producer
is guaranteed to have refreshed and to deliver. Events that occurred earlier
are never delivered to that binding, so a new target is never back-fed
history.

### A4. Server-side target resolution: requirements on aweb-acgh.7

An effecting naapp learns a team's registered targets through acgh.7's generic
app → team-server API. That API also handles server discovery, its own
purpose-split credential (`hook-resolve`) and grant status. This design does
not specify the endpoint, credential or discovery. It requires the following,
and has sent them to the acgh.7 seat:

1. **Two queries per `(team, catalog id, catalog version, hook)`.** One lists
   active **registrations**: the producer's question of where to deliver. One
   lists active **productions** with their keys: the consumer's question of
   whether a producer is approved and which key it may sign with.
2. **Authorization by binding, not by membership.** An app may list
   registrations for hook H only while it holds an active production for H in
   that team, and may list productions for H only while it holds an active
   registration for H. Any app may read **its own bindings**, of both kinds,
   by `binding_id` or by hook: that is how logs confirms the registration a
   delivery names (§B2). A member authenticated by team-auth v2 (through B1)
   may list registrations for **client-class** hooks only, which is how `aw`
   finds `post-command-hook` targets. Core resolves its own bindings in
   process.
3. **Response fields per binding:** `binding_id`, kind, `app_id`,
   `installation_id`, generation, origin, resolved `method` and raw `path`,
   digest, `active_from`. For productions, it also returns the keys of that
   generation whose declared `purposes` include `hook-event` or
   `hook-delivery`, each with its `{kid, did_key, purposes}`. It never returns
   an emit-only or usage-only key. Each response carries `as_of` and
   `max_age_seconds`.
4. **Freshness.** `max_age_seconds` is at most 60 and is the same value that
   pads `active_from` (§A3). Callers fail closed when the cache expires and a
   refresh fails, mirroring certificate status
   (`docs/team-auth-envelope-v2.md:63`–`:69`). Uninstall, revocation and a new
   generation take effect within that bound.
5. **The core producer's key** must be discoverable from the team-server
   origin, with retired keys still listed with their validity windows so that
   old events verify. The key is operator configuration, never a team,
   controller or agent key. **Trust anchor:** one anchor for every consumer,
   the team's server origin from acgh.7's team-key-signed discovery record.
   A consumer resolves it through that chain and caches it per team. It never
   takes an origin from an event or from unsigned discovery, so forged "core"
   events cannot verify.
6. **Generic only:** no app names, and no catalog semantics beyond matching
   `(catalog id, version, hook)`.

### A5. The firing rule

A hook fires at the layer that **effects** an action, never at a layer that
merely requests it, and once per effect (hooks-spec §3–§4):

- Core fires `post-mutation-hook` for core effects. A naapp server fires its
  produced hooks for its own effects. `aw` does not fire for anything a server
  effected; it only dispatched it.
- `aw` fires `post-command-hook` only for **local effects** that reach no
  server: generating or rotating a key, storing a fetched certificate,
  recording a local app approval, minting a local grant snapshot. A command with
  both kinds produces one server event per server effect, from the server, and
  one client event for its local effects. They are distinct effects
  correlated by `trace_id`, not duplicates. The catalog vector lists the
  command classes with local effects. Reads fire nothing.
- The classes are disjoint per *effect*, not per command, so no effect is
  reported from two places.

**Trust consequence, stated plainly.** Client firing is bypassable. The agent
controls its own process: a patched `aw`, a direct HTTP call or an unmodified
`aw` with its outbox deleted all skip it. Client events are therefore recorded
and displayed as agent-reported, never as mediated fact. The audit guarantee
("recorded regardless of agent preference") comes only from **server-side
firing at a point the agent cannot route around**: core for core state, and
secrets for credential use when the agent holds no raw credential (secrets-spec
§8). It is also only as strong as the producer: a naapp that omits a firing
omits that record. Core cannot force a third-party app to fire, which is why a
production is an owner-visible commitment and not an assumption.

### A6. The canonical envelope

Signing bytes are the literal `aweb.hook-event/1`, a newline, then canonical
JSON (sorted keys, no insignificant whitespace, UTF-8, no floats, integers
within the JS safe range, duplicate keys rejected):

```json
{
  "v": 1,
  "type": "aweb.hook-event",
  "catalog": {"id": "aweb.hooks", "version": 1},
  "hook": "post-mutation-hook",
  "event_id": "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11",
  "trace": {"id": "4bf92f3577b34da6a3ce929d0e0e4736", "origin": "signed_request"},
  "team_id": "demo:example.com",
  "producer": {"kind": "core", "origin": "https://aweb.example", "kid": "hook-2026-10", "did_key": "did:key:z6Mk...", "seq": 812},
  "actor": {"did_key": "did:key:z6Mk...", "did_aw": "did:aw:...", "certificate_id": "uuid", "alias": "bond", "authority_mode": "team_cert", "grant_id": null, "attestations": []},
  "occurred_at": "2026-10-19T18:02:11.412Z",
  "fired_at": "2026-10-19T18:02:11.415Z",
  "result_status": "success",
  "payload": {"mutation_type": "task.updated", "target_ref": "task:uuid", "changes": ["status"], "old_status": "open", "new_status": "in_progress"}
}
```

These fields satisfy the brief (event_id, trace_id, team_id, actor, fired_at,
result_status, per-hook fields):

- **`event_id`** is a UUID fixed **once, inside the effecting transaction**,
  and stored with the outbox row. Retries re-deliver that row and never re-mint.
  It is minted once, with no derivation. A client's retried request either hits the producer's own idempotency (no new
  effect, no new event) or is a new effect with a new event. That is the
  "stable per effect" property of hooks-spec §4.
- **`producer.kind`** is `core`, `app` (with `app_id`, `installation_id`,
  `generation`) or `client` (the member's `did_key` and `certificate_id`).
  `producer.seq` is a gap-free counter per **(producer, team, hook)**,
  assigned in the effecting transaction, so a consumer can prove completeness
  per producer for each hook it is bound to. A per-producer counter would
  report legitimate gaps to consumers bound to a subset of hooks. It is
  required for server producers (recommendation; it costs one counter-row
  lock per producing transaction). `verify` judges gaps only inside the
  binding's active intervals.
- **Client events name their signer as actor.** For `producer.kind: client`,
  `actor.did_key` and `actor.certificate_id` must equal the producer's. Member
  A therefore cannot file agent-reported events attributed to member B.
- **`actor.authority_mode`** is how the actor's authority was proven to the
  producer: `team_cert`, `identity_grant` (with `grant_id`), `app_key`,
  `link_capability`, `owner_act` or `system`. Custody and principal facts
  appear only as verified `attestations` (§B4).
- **`result_status`** is `success`, `denied`, `failed` or `outcome_unknown`.
- **Signature.** The producer's key signs with detached Ed25519. Server
  producers use an `app_keys` entry that declares the `hook-event` purpose, or
  the core hook key. `aw` uses the
  member key, and its delivery carries the team certificate.

**Signing-family reuse.** The app-emit credential signs a *request descriptor*
and is useless once the HTTP exchange is over. Provenance must survive storage
and be re-verifiable by anyone holding the event. So the envelope reuses the
family's primitives (canonical JSON, Ed25519, `did:key`, `kid`, the
registered app key) under a new content-signing purpose with a
domain-separation prefix, as D1 does for `aweb.app-task-authorization/1`. A
request-bound credential carries it in transport (§A7). Neither purpose can be
replayed as the other.

### A7. Delivery

**Producer outbox.** Each producer owns two tables in its own database. They
come from one shared `aweb_naapp` module, shipped as a pgdbm migration set that
each producer applies to its own schema. Core uses the same module (§C). Its
drain follows migration 013's proven pattern.

- `hook_events`: `event_id`, team, hook, catalog version, `occurred_at`,
  `producer_seq`, exact signing bytes, signature, `audit_critical`.
- `hook_deliveries`: `event_id`, `binding_id`, state (`pending`, `delivered`,
  `duplicate`, `conflict`, `rejected`, `stalled`, `cancelled`), attempts,
  `next_attempt_at`, last status and error class, and the stored receipt.

The event row is written **in the same transaction as the effect**, which is
the fail-closed point. Deliveries are materialized at drain time from the
current registry: one per active registration with `active_from <=
occurred_at`. A revoked binding's backlog is handled by the revocation rule
of §A3. The event itself is target-independent, so every sink receives
byte-identical signed bytes. The shared kit takes the caller's transaction for
the enqueue, and exposes the age of the oldest undelivered event per binding.
Secrets uses that age for its backlog bound: it refuses new admissions once a
target is stalled beyond a threshold that Juan sets.

**Transport.** Each delivery is `POST` to the binding's origin and path with
`Authorization: AWEB-Hook DIDKey <did:key> <sig>`. The signed payload binds
`{v: 1, auth: "hook-delivery", aud, method, path, body_sha256, team_id,
binding_id, event_id, producer, kid, did_key, timestamp}`, and the body is
`{hook_event: <base64url signing bytes>, signature: <base64>}`. Egress
follows the secrets §14 network rules: HTTPS only, no redirects, no private or
internal addresses unless the operator allows them, and the destination taken
only from the owner-activated binding.

**Ack.** A 2xx response carries `{event_id, disposition: "appended" |
"duplicate", receipt?}`, and the producer keeps any receipt, such as logs'
signed receipt (§B3). A `409 event_conflict` (same id, different bytes) is
never retried and is surfaced as a fault. Schema and authorization
rejections retry with bounded backoff, in case a registry cache is stale, then
become `rejected` and are surfaced. Network errors and 5xx retry with capped
exponential backoff and are **never dropped**. After the operator-disclosed
delivery horizon, a delivery becomes `stalled` and is surfaced to the owner.
After drain the producer keeps a minimal tombstone of `event_id` and digest.
It also keeps at least the **highest receipt per (team, binding)**, because
that receipt's `event_hash` commits to the target's entire chain prefix. This
is what makes producers witnesses (§B3). The outbox is delivery
infrastructure, not an audit store (hooks-spec §7).

**Failure mode.**

- *Audit-critical* (`post-secret-use-hook`, and widening
  `post-governance-hook` acts): the producer refuses the effect (secrets'
  `audit_target_unavailable`, the real error logged) unless both hold:
  - a registry view no older than 60 s holds an active registration with
    `active_from <=` the event's `occurred_at`. A registration still inside
    its `active_from` pad does not count, so no effect can have zero
    deliveries owed;
  - the event row commits before the external dispatch.

  Secrets commits its `admitted` and `dispatching` events with its durable
  intent record, dispatches, then commits `completed`, `not_sent` or
  `outcome_unknown`; reconciliation emits `reconciled`. A crash after dispatch
  leaves a committed intent with no result, which is exactly what
  reconciliation finds (secrets-spec §14). Narrowing admin acts are enqueued
  in their own transaction and are never refused by this gate. The gate still
  leaves one window: the only registration can be revoked between commit and
  drain. So an audit-critical event whose deliveries all end `cancelled` or
  `rejected` becomes a **surfaced fault**, not just a count. The owner
  learns that an effect happened with no surviving audit record. Switching
  targets (for example, hosted to self-hosted) therefore follows a fixed
  order: activate the new target, wait for its `active_from`, then revoke the
  old one (§B7).
- *Core* (`post-mutation-hook`): the event row shares the mutation's
  transaction, so the two commit together or not at all. Core enqueues only
  when its fresh view shows an active registration. Requiring a target before
  every core mutation would make all coordination depend on logs being
  installed, so it is not required (recommendation).
- **Delivery is at least once. One logical firing is one `event_id`.** No
  exactly-once network claim is made. Consumers dedup on `(team_id, event_id)`.

### A8. Stream separation

Hooks record and govern. App events wake (hooks-spec §1). They share signing
primitives and nothing else:

- different credentials (`hook-delivery` vs `app-event`), endpoints, storage
  and guarantees;
- D1's post-commit observer (C6) stays a wake path for verified app events and
  **never** fires or delivers hooks, which the D1 lead has confirmed;
- the default `on_mutation` handler keeps translating to SSE wakes and is not
  a hook producer;
- a consumer subscribes to one stream only. logs takes hooks and never app
  events, which is the other route to double-logging (hooks-spec §4).

### A9. trace_id

- The format is 16 random bytes as 32 lowercase hex characters, not all zero.
  That is the W3C trace-context trace-id, so it can interoperate with
  OpenTelemetry.
- **`aw` mints one per user command invocation.** It places it in its own
  operation-specific `trace_id` member of the team-auth v2 signed payload (never
  inside the `operation` value) on every request the command makes: core and
  manifest tools. The member is signed and ignored by the auth layer
  (`docs/team-auth-envelope-v2.md:34`–`:38`), so no envelope version change is
  needed. Folio's verifier checks only named fields
  (`naapp/folio/src/folio/auth.py:264`–`:272`) and passes it. A positive
  vector case with `trace_id` is added deliberately to
  `team-auth-envelope-v2.json`.
- **The hosted MCP layer (L2) mints one per MCP tool call** and signs it the
  same way as the member. This is a requirement on the custodial deployment
  that runs L2, and D1 has accepted it.
- **Producers** take a valid signed `trace_id` as `trace.origin:
  "signed_request"`, mint their own when it is absent or invalid
  (`"producer"`), and propagate it in their own signed outbound calls. Unsigned
  header values are ignored.
- A trace is correlation only. It is never authority and never a dedup key,
  and consumers never merge events by trace.

### A10. post-mutation-hook and the on_mutation seam

The two are deliberately separate:

- `on_mutation` stays unchanged: an in-process, post-commit, best-effort
  embedding seam with experimental context keys that include content
  (`docs/aw-hooks-sot.md:113`–`:150`). It cannot carry an audit hook, because
  it is lossy by construction (§1).
- `post-mutation-hook` is enqueued by one helper **inside the effecting
  transaction, at the service layer**, so REST and MCP entry points are
  covered once. This structurally closes the MCP task gap (§1). Sites that are
  autocommit today (mail send without attachments, ack, comment, dependency,
  `connect`) must become transactional to carry it. That is implementation
  work, flagged here so it is not mistaken for a one-line hook call.
- **Vector.** A new `docs/vectors/post-mutation-hook-sites-v1.json` lists
  `{source, function, mutation_type}` for each enqueue call. The existing
  checker gains a second scan: literal `mutation_type`, the call lexically
  inside a transaction block, and counts matching in both directions. The
  vector also carries an explicit mapping from every `on_mutation` event in
  `mutation-hook-call-sites-v1.json` to a `mutation_type` or to `excluded`
  with a reason. A new `on_mutation` event therefore fails the build until
  someone decides its audit status. The pinned v1 inventory is not re-frozen.
- **v1 mutation types** (demo-critical, hooks-spec §9):
  - `task.created`, `task.updated` (with `changes`; one effect per update, not
    the several `on_mutation` calls a PATCH fires today), `task.deleted`,
    `task.comment_added`, `task.dependency_changed`, and `task.answered` once
    D1's C2 conditional answer lands. C2 is where approvals live in core.
  - `mail.sent`, `mail.acknowledged`, `chat.message_sent`.
  - `identity_grant.minted`, `identity_grant.revoked`.
  - `app.installed`, `app.updated`, `hook_binding.activated`,
    `hook_binding.revoked`.
  - `membership.connected` (the `connect` projection) and
    `membership.workspace_retired` (the lifecycle cascade).
  - Excluded, with reasons in the vector: reservations, which are operational
    locks, and `agent.status`, which is health reporting.
- **Certificate issuance and revocation.** Membership authority is effected at
  AWID by the controller's signature. AWID has no outbox, and core persists no
  membership effect (§1). Recommendation **M3**: core runs a registry observer
  for teams with an active `post-mutation-hook` registration. It reads the
  team's certificate history from its home AWID with the documented
  same-operator read credential (`docs/awid-sot.md:117`–`:131`). It enqueues
  `membership.certificate_issued`/`_revoked` events, marked as observed
  registry facts with AWID's timestamps and the certificate digest, in the
  same transaction that advances its cursor. Its limits are stated: it
  observes rather than effects, and a private team on a foreign registry is
  invisible to it. The alternative, **M1**, makes AWID a producer: AWID would
  store team hook targets and fire at register/revoke. That is an
  identity-path change and an inverted dependency, so it is Juan's decision.

### A11. Conformance vectors (deliverable)

Frozen only after review, positive and negative, each consumed by Go and
Python tests:

| Vector | Covers |
| --- | --- |
| `docs/vectors/hook-catalog-v1.json` | Hooks, class, producer kinds, audit-critical flag, precedence, the flat payload allowlists (including `post-secret-use-hook` and the `post-governance-hook` act/direction table), client command classes. |
| `hook-event-envelope-v1.json` | Seeds, canonical bytes, signatures. Negatives: wrong prefix, non-canonical bytes, float, duplicate key, unknown payload field, team mismatch, client-signed server hook, a client event whose actor is not its signer, unknown catalog version. Secret digests: `request_sha256` over the pre-injection request, with a negative where the digest covers injected credential bytes. |
| `hook-delivery-credential-v1.json` | `hook-delivery`. Negatives: an app-event or `hook-resolve` credential at a hook target, cross-audience, tampered body, wrong binding, stale timestamp. (`hook-resolve` vectors belong to acgh.7.) |
| `owner-act-v1.json` | Activate and revoke, plus each logs act. Negatives: admin signer, rotated-out team key, expired, nonce reuse, subject/generation mismatch, a valid act of the wrong type or audience, a team certificate presented as an owner act. |
| `hook-binding-cases-v1.json` | Semantic cases: admin install leaves bindings pending, a new generation supersedes, an unknown catalog is refused, the `active_from` pad, revocation cancels pending deliveries. |
| `post-mutation-hook-sites-v1.json` | Enqueue inventory, plus the `on_mutation` mapping (§A10). |
| `logs-chain-v1.json` | Genesis, append, receipt, checkpoint, a purged stub that still verifies. Negatives: reorder, gap, altered content, forged checkpoint. |
| `team-auth-envelope-v2.json` (added case) | A positive request carrying `trace_id`. |

## Part B — logs.aweb.ai

### B1. Shape

`logs` is an ordinary naapp in `naapp/logs` with its own database schema,
manifest v2 and registered key. Its tools and their contexts:

| Tool | Contexts | Authority |
| --- | --- | --- |
| `ingest` | `hook` only | Hook delivery (§B2) |
| `query`, `tail`, `verify`, `checkpoint`, `export` | `surface` on logs' own origin; CLI for owner acts | Owner or designated reader (§B5) |
| `readers`, `retention`, `erase` | owner acts | Owner only |

Its manifest registers `ingest` on all four v1 hooks. It never subscribes to
app events.

### B2. Ingest

Ingest admission is an ordered list, each step failing closed with a distinct
error:

1. **Transport.** Verify the `hook-delivery` credential: signature, `aud` equal
   to logs' configured origin, external raw path, body hash, timestamp skew.
2. **Binding.** `binding_id` must be logs' own active registration in
   `team_id` for the envelope's hook (acgh.7 resolution, ≤ 60 s cache). Logs
   returns 503 when authority is unavailable, so the producer retries and
   nothing is lost.
3. **Provenance.** Verify the envelope signature with the transport signer's
   key, and require the envelope `producer` to equal the transport signer:
   - `app` producers need an active production for the hook in that team, with
     a key active for that generation (acgh.7);
   - `core` producers need a key published by the team's discovered core
     server (acgh.7);
   - `client` producers need a valid member certificate, checked by B1, and a
     **client-class** hook only. A member-signed server hook is refused, and
     so is a client event whose actor is not its signer. Client ingest also has
     per-member rate and byte quotas, so one member cannot flood the team chain
     or push server records into retention pressure.
4. **Schema.** The catalog version must be known and the payload must match its
   strict allowlist. `occurred_at` must be no later than receipt plus skew.
5. **Dedup** on `(team_id, event_id)`. Identical bytes return `duplicate` with
   the original receipt. Different bytes return `409 event_conflict` and record
   a conflict fault that `verify` reports. Nothing is overwritten.
6. **Append** (§B3) in one transaction, then return a signed receipt. With
   the event, logs records the **key evidence** it verified against:
   `kid`, `did_key`, purposes, `installation_id`, generation and the
   `binding_id`s checked. Retained signatures therefore stay re-verifiable
   after an app update retires that key, and export bundles carry the
   evidence.

### B3. Chain and checkpoints

Per team and chain epoch, under a row lock on the team's chain head:

- `content_commitment = SHA-256("aweb.logs-commit/1\n" || salt || signing_bytes
  || signature)`, with a fresh 32-byte salt stored alongside the content.
- `event_hash = SHA-256("aweb.logs-chain/1\n" || canonical({chain_epoch,
  team_id, team_seq, prev_event_hash, received_at, hook, producer_origin,
  content_commitment}))`.
- `team_seq` is gap-free and monotonic, and `prev_event_hash` is the previous
  `event_hash`. Genesis uses the SHA-256 of a domain-separated canonical
  `{team_id, chain_epoch, logs_origin, created_at}`. A new epoch (for example,
  after moving to self-hosted) records the previous epoch's final checkpoint.
- **Receipt**, signed by logs: `aweb.logs-receipt/1`
  `{team_id, event_id, team_seq, event_hash, chain_epoch, received_at}`.
  Producers keep at least their highest receipt per (team, binding) (§A7).
  Each such receipt commits to the whole chain prefix, so every producer is an
  independent witness of the chain.
- **Checkpoint**, signed by logs: `aweb.logs-checkpoint/1`
  `{team_id, chain_epoch, team_seq, event_hash, issued_at, logs_origin, kid,
  did_key, previous_checkpoint_sha256}`. It is issued periodically while
  events arrive and on demand, and the owner can export it. External anchoring
  is future work (logs-spec §8).
- **`verify`** recomputes the chain over a range or from a checkpoint. It
  re-checks retained provenance signatures and commitments, and reports
  `intact`, `broken_at`, `missing` (gaps), purged ranges with their governing
  act, per-producer and per-hook `seq` gaps inside binding intervals, and
  conflicts. It also accepts **producer receipts and exported checkpoints as
  input**, and reports any receipt or checkpoint that the current chain
  contradicts. `aw logs verify --bundle` checks an export offline, with no
  server.

**What this does and does not protect against.** It detects in-transit loss
(the outbox), forgery by other apps (productions), agent deletion (there is no
API for it), and silent row edits, drops or reorders by anyone without logs'
key once a checkpoint or receipt has been witnessed. It cannot stop an operator
that controls logs' key from rewriting the whole chain *before* any witness
exists, or a compromised producer signing false events. Witnesses (producer
receipts, owner-exported checkpoints, self-hosting) and future anchoring are
the remedy. Copy must not claim more.

### B4. Event schema

Logs stores the verified signing bytes and signature as the authority, plus
the chain fields of §B3 and the key evidence of §B2. It also stores these
query projections, all derived from the envelope and never adding content it
did not carry:

- identifiers (`event_id`, `team_id`, `team_seq`, `trace_id`);
- `event_type` (`hook`, `mutation_type` or the secrets `event_type`);
- the actor's `did_key`, `did_aw`, `alias` and `certificate_id`;
- `app_id` and operation or tool, `target_type` and `target_ref`;
- `authority_mode` and its ids (`grant_id`, approval ref);
- request and payload digests, `signing_key_id`, `result_status` and
  `result_ref`.

Two fields carry the honesty of the record:

- **`mediation`** is derived from the producer kind, never claimed: `server`
  (core or an app at its point of effect), `registry_observed` (M3 membership)
  or `client` (`aw`, agent-reported).
- **Custody and principal provenance** (`custody_mode`, `human_principal_ref`,
  `custodial_grant_id`) are **null unless proven**. `grant_id` is proven when
  core admitted the request through an identity session grant. Custody mode and
  an OAuth human principal are not proven by team-auth v2 (§1), so they appear
  only through a verifiable **attestation** that the producer received with the
  request and embedded in `actor.attestations`. Logs re-verifies it. Such an
  attestation must be signed by an attester the owner bound to the team, bind
  the exact request digest, member key and certificate, custody mode, an
  opaque principal id and an expiry, and be verifiable without the hosted
  operator's private state. Producing it for custodial members is a
  requirement on the custodial deployment. The contract is shared with the
  secrets design, which proposes it so that policy can tell self-custodial
  from custodial actors and record the human principal. Until it exists, these
  fields are null, and policy that needs them refuses.

### B5. Owner-gated reads

Agents emit and cannot read. Signatures cannot tell a hosted human member from
an MCP agent: both are custodial members signed through the host (§1). So
"human-only" must rest on something other than a member signature:

- **Readers are designated humans with passkeys.** The controller key stays
  governance-only (§2): one `app-role.designate` owner act (role `reader`)
  designates a reader, including the owner. The reader enrols a passkey on **logs' own origin** using
  aweb-acgh.4's WebAuthn enrolment, recovery and audit, unchanged. This design
  adds only the reader designation that authorizes enrolment. `query`, `tail`,
  `verify` and `export` all run in a short-lived acgh.4 session on that
  origin, never with a per-request controller signature. There is no member
  signature and no hosted session.
- **CLI.** `aw logs query | tail | verify | export` completes a device-style
  authorization on logs' origin with the reader's passkey. That yields a
  short-lived read session bound to an ephemeral key the CLI generates.
  Anything that can read that session while it lives can read the log, and
  the doc says so.
- **Surfaces and MCP.** A D1 surface is rendered by the host as a member, so
  it shows no log content and links out to logs' origin. By default MCP has no
  read tools, and log content never enters a model provider's context.
  Recommendation: an owner may delegate a member, such as an MCP identity, to
  `verify` only. `verify` returns integrity results without content, and
  delegated `query` does not exist. The delegation is a governance event. Juan
  decides.
- **Self-administration is logged.** Reader changes, retention changes,
  erasures and purges are appended by logs to the same chain as `logs.*`
  governance entries signed by logs' key.

### B6. Append-only, retention and erasure

There is no edit or delete API. Logs' own closed owner-act list is
`logs.retention.set`, `logs.erase`, `logs.legal-hold.set` and
`logs.legal-hold.release`, on top of the generic app-governance acts.
Retention is owner-set per event class. Expiry and erasure **purge content but keep the skeleton**:

- They delete the signing bytes, signature and salt, **and every §B4
  projection, search index and derived cache for that event**.
- They keep `team_seq`, `prev_event_hash`, `event_hash`, `received_at`, hook,
  producer origin and `content_commitment`.

The chain still verifies, and `verify` reports the purged range and the act
that caused it. Deleting the salt makes the commitment unlinkable to guessed
content, so a hash of personal data does not survive erasure in confirmable
form. Backups expire content under a disclosed, evidenced deadline. Purge
tombstones are reapplied before any restored database is served, following
D1's backup rule.

This follows D1's rule: deletion overrides routine audit-content retention
unless a disclosed legal obligation requires retention, and minimal non-content
receipts remain (`agent-pages.md` §3, D1 8ef61170a70f). An owner-requested erasure of
an actor's content is a governance entry with counts, never silent. A legal
hold is an owner act and is disclosed in receipts. Uninstall and team deletion
use D1's lifecycle tools. Export produces a self-verifying bundle (envelopes,
chain, checkpoints, receipts). Deletion runs as D1's durable job and keeps the
final checkpoint and a deletion receipt. Logs needs its own hosted default
retention, separate from D1's 90-day page-audit baseline. That is an open
question for Juan.

### B7. Self-hosting

Core stores no audit, so self-hosting means **activating a different logs
installation's `ingest` registration** (logs-spec §5). The customer runs
`naapp/logs` at their own origin and installs its manifest. Because a registry
binds one app id to one origin (`docs/app-registry.md:79`), the self-hosted
install uses its own app id (for example `acme-logs`). Hooks bind by catalog
hook and not by app id, so nothing else changes. The switch order is fixed:
activate the new installation, wait for its `active_from`, then revoke the
hosted one, so audit-critical uses never lose a target (§A7). During the
overlap both receive every event and keep independent chains. The self-hosted
instance needs outbound HTTPS to the core server it pins (acgh.7, §A4) and to
AWID (owner acts), plus its own key. Producers reach it under the egress rules
of §A7.

### B8. Mediated facts versus agent-reported activity

Queries, the viewer and `verify` summaries separate `server`,
`registry_observed` and `client` records, and never upgrade a client record.
Free-text claims never enter the record, because payloads are allowlists. The
record makes no claim about raw shell, filesystem, browser or model activity
outside a mediated path (logs-spec §1).

## C. Component placement

The rule is Juan's: any runtime piece that more than one naapp could use lives
in `aweb_naapp` (`naapp-lib/`), and code moves there once a second user
exists, not before. Core is not a naapp, but it produces hooks too, so it must
not carry a second implementation of the producer kit. Recommendation: put
the hook kit (catalog, envelope, owner act, outbox, delivery credential) in a
dependency-light `aweb_naapp` module behind its own extra. Core and naapps
both install that extra, and core never pulls in the full runtime extra with
its WebAuthn and settings dependencies. Both already depend on `awid-service`
(`server/pyproject.toml:22` at A; `naapp-lib/pyproject.toml` on the B1 branch,
940edc420).

| Component | Placement | Justification for app-local or core |
| --- | --- | --- |
| Hook catalog loader and payload schemas | `aweb_naapp` | — |
| Envelope canonicalization, signing and verification (`aweb.hook-event/1`) | `aweb_naapp` | — |
| Producer outbox: tables, enqueue-in-transaction helper, drain, backoff, receipts | `aweb_naapp` | — |
| Hook-delivery credential: signer and verifier | `aweb_naapp` | — |
| Hook resolution client and cache | `aweb_naapp`, built by acgh.7 | — |
| Envelope and delivery-credential verification (§B2 steps 1 and 3) | `aweb_naapp` hook kit | — |
| Ingest admission order, dedup and quotas (§B2) | app-local (`naapp/logs`) | Logs is the only hook consumer. The pipeline moves to `aweb_naapp` when a second consumer exists, by the same rule as the chain. |
| Owner-act verifier (`aweb.owner-act/1`) | `aweb_naapp`; core uses the same | — |
| Team-auth verification | `aweb_naapp`, B1 (aweb-acgh.3) | Reused unchanged. |
| Passkey readers and approvals | `aweb_naapp`, aweb-acgh.4 | Reused unchanged. Logs adds only the reader-designation policy. |
| Binding registry (`app_hook_bindings`, activation, revocation, fence) | core server | It is a child of the team install record, which only core holds (§A3). |
| Resolution endpoint | core server, acgh.7 | It serves core's install records. |
| `post-mutation-hook` enqueue sites and the M3 registry observer | core server | Core is the effecting layer for core state. It calls the shared helper. |
| Client firing, local outbox, `trace_id` minting | `aw` (Go) | A different language and runtime. Byte parity with Python comes from the shared vectors (§A11), not shared code. |
| Chain append, checkpoints, receipts, retention and erasure jobs, the query/tail/verify viewer | app-local (`naapp/logs`) | These *are* the logs product. No other naapp keeps a tamper-evident chain. If one ever needs it, the chain primitives move to `aweb_naapp` at that point. |
| Firing `post-secret-use-hook` and `post-governance-hook` at each secrets decision point | app-local (`naapp/secrets`) | Only secrets knows its effects. Building and enqueueing the event uses the shared kit. |
| Firing `post-manifest-command-hook` | `aweb_naapp` request middleware, configured per app | Every producing app fires it the same way at tool admission. Apps declare only which reads fire it. It uses B1's declared-tool route mapping, so firing and admission resolve method and path to the same tool. |

## Dependencies on other lanes

- **D1 C3:** the `hooks` slot with registrations and productions, `app_keys`
  with purposes, and `invocation_contexts` (all accepted at D1 8ef61170a70f).
  **F6:** `installation_id` and generation, the fence, exact digests. **C2:**
  `task.answered`.
- **Custodial deployment** (stated generically, routed by the coordinator):
  owner-act signing behind a step-up owner gesture (§2), `trace_id` per MCP
  call in L2 (§A9), and the custody/principal attestation (§B4).
- **aweb-acgh.7:** discovery, `hook-resolve` and the resolution queries (§A4).
  **aweb-acgh.3 / .4:** verifier, passkeys and approvals.
- **Secrets design:** the post-secret-use action vocabulary, intent and
  dispatch states, and the attestation contract.
- **Juan and Athena:** the owner-act identity path needs Juan's approval and
  Athena's review. Juan also answers the open questions below.
- Order (recommended): the catalog, envelope and binding contracts land first
  with their vectors. Core firing and delivery, the shared hook kit, logs and
  secrets then build in parallel. Secrets does not launch until logs ingests
  real events end to end.

## Recommendations and open questions for Juan

1. **Owner proof.** A team-controller-signed `aweb.owner-act/1`: an
   identity-path change needing Juan's approval and Athena's review. For
   managed teams the custodial deployment signs owner acts only behind a
   step-up owner gesture. As stated in §2, the custodian can then mint any
   owner act, so the log does not protect against the hosted operator.
2. **Membership.** M3 (core observes the AWID certificate log, recommended,
   and Athena agrees) or M1 (AWID becomes a hook producer, an identity-path
   change)?
3. **Audit-critical requires a target.** Secrets refuses every use while no
   logs registration is past its `active_from` (recommended). It also refuses
   new admissions beyond a delivery-backlog age threshold, which Juan sets
   (the secrets design proposes 1 h).
4. **Reads in `post-manifest-command-hook`.** Opt-in per production
   (recommended) or every read?
5. **`producer.seq`.** Required per (producer, team, hook) for all server
   producers, including core, at the cost of a counter-row lock (recommended)?
6. **Retention.** The hosted default for logs content, the backup expiry
   deadline, and whether erasure requests may originate from data subjects or
   only from the owner.
7. **MCP read delegation.** Allow delegation of `verify` only, which returns
   no content (recommended), or nothing at all?
8. **Blocking `pre-*` hooks.** Deferred (recommended).
9. **`post-command-hook` scope.** Local identity, key, certificate,
   app-approval and grant effects only (recommended).
10. **Self-hosted app id.** A distinct app id per origin (recommended), rather
    than changing the registry's one-origin rule.
11. **What becomes shared.** This design adopts the reviewer's rule: a
    component moves to `aweb_naapp` once a second consumer exists, and not
    before (§C). The hook kit already has two users, core and every producing
    naapp, so it ships as a dependency-light `aweb_naapp` extra that both
    install (recommended). The alternatives are core importing the full
    runtime extra, or a duplicate implementation. The logs ingest pipeline and
    chain stay app-local until a second consumer exists. The contrary rule is
    to share anything that *could* be reused from the start. Juan decides.
