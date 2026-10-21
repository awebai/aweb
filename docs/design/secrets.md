# secrets: credential use without credential holding

Status: **design accepted, aweb-acgh.2 (epic aweb-acgh).** The D1 lead's fit
check, an independent review and Athena passed it. The secrets coordinator
decided the open questions under Juan's delegation (2026-10-19); §18 records
each decision. This is a design, not a claim that any interface here ships.
Nothing in it exists yet, history included. The build plan is
[secrets-build-plan.md](secrets-build-plan.md).

The app lives in `aweb/naapp/secrets` (aweb-aauv), and its source is public. It
builds on the generic naapp layer proposed by D1 without forking it. It also
builds on the shared `aweb_naapp` runtime: B1, the verifier (aweb-acgh.3), and
B2+B3, the approval primitive with WebAuthn (aweb-acgh.4). §3.1 marks every
component as shared or app-local, and §17 names the dependencies.

## Summary for Juan

secrets lets an agent **use** a credential without **holding** it. The agent asks
secrets to perform a bounded action: a named HTTPS operation, an open request
inside a host scope that policy permits, or a pinned job on a runner the user
operates. secrets checks the caller's verified team identity, its grant and the
policy, and gets a human passkey approval where the policy requires one. It then
injects or signs with the credential on its own side of the boundary, returns a
redacted and bounded result, and records each step through `post-secret-use-hook`.

Custody sits behind one backend interface with two implementations at launch: a
native store sealed with KMS envelope encryption, and 1Password through a service
account narrowly scoped to its vault. Values enter only on secrets' own human
console, which needs an owner passkey, or directly in the vault. No agent tool and
no MCP tool ever carries a value in or out. The only exception would be the
`--unsafe-inject` question, and that feature does not exist (§13.4).

Dispatch is a durable state machine. secrets records the intent and its audit
outbox rows in one transaction before any network send. If it cannot enqueue, it
refuses. An uncertain send becomes `outcome_unknown`, which blocks a retry of the
same operation until it is reconciled. Containment works from day one: revoke a
grant, revoke approvals, disable a secret or the whole installation, replace a
value, and deregister a runner.

The defensible claim is narrow, and §14 states it. Each brokered use was admitted
for one verified principal and one bounded action, and it leaves an auditable
record, within the trust boundaries listed there. The design does not promise
that nothing derived from a credential can ever end up with an agent.

§18 records the decisions taken on the open questions.

## 1. Sources, baseline and governing model

Source baseline **A = aweb origin/main b423415a92bf**. Every `A path:line` refers
to that commit.

D1 baseline **D1 = origin/agents/aweb-protocol-expert-pages-design 8ef61170a70f**
(the branch was rebuilt as one commit; earlier D1 SHAs are no longer on it).
It covers `docs/design/agent-pages.md` and `docs/design/agent-pages/contracts.md`.
It is a draft that Juan has not approved.

Juan's private specs are cited by name and section and never quoted: the secrets
SOT (with §14 read as amendments), the hooks SOT, the audit-logs SOT, and the
naapp-specs README for the self-contained naapp model. The working principle is
one generic architecture, built once in shared code. Anything this design needs
from a hosted operator is stated as a generic requirement on a custodial
deployment (§17).

| Fact at A | Evidence |
| --- | --- |
| Team-auth v2 binds one HTTP request (aud, method, raw path and query, body hash, team, timestamp) to a member certificate. The relying app applies its own policy. | `A docs/team-auth-envelope-v2.md:3`–`:6`, `:40`–`:61` |
| Team-auth v2 does not prevent replay: a byte-identical request replays within the 5-minute skew window. | `A docs/team-auth-envelope-v2.md:95`–`:105` |
| A relying app with no operator token checks certificate status anonymously at AWID. The cache lasts at most 60 s and fails closed. | `A docs/team-auth-envelope-v2.md:63`–`:71` |
| The certificate carries `member_did_key`, plus `member_did_aw` and `member_address` for global identities; `did:aw` is empty for local identities. | `A docs/awid-sot.md:545`–`:563`, `:658`–`:659`; `A naapp/folio/src/folio/auth.py:304`–`:367` |
| Team-auth proves neither custody mode nor an OAuth human principal. Custodial members act through the hosted operator's signing. | `A docs/product-authority-sot.md:114`–`:130` |
| Manifest v1 is frozen and strict; unknown fields and versions are rejected. | `A docs/app-manifest.md:46`–`:49`, `:281`–`:291`; `A cli/go/internal/appmanifest/interpret.go:39`, `:53`, `:196` |
| The registry records the app, its digest pin and per-team granted scopes. | `A docs/app-registry.md:1`–`:11`, `:95`–`:133` |
| App emit keys are app-owned Ed25519 `did:key`s declared in the manifest, and are the only shipped app credential. | `A docs/app-manifest.md:151`–`:177` |
| The only shipped hook seam is the in-process `on_mutation` callback. Named hooks, a registry and `trace_id` do not exist. | `A docs/aw-hooks-sot.md:9`–`:19`, `:42`–`:50` |
| Library's production operations are Make-only against a pinned topology allowlist, and health reports the full commit. | `A naapp/library/Makefile` (prod-* targets), `A naapp/library/docs/production-operations.md:1`–`:60`, `A naapp/library/ops/render-production.json`, `A naapp/library/src/library/build_identity.py:20`–`:95` |

**The authority model, stated before the mechanisms.**

- **Custody.** A credential value lives in a custody backend: the native
  KMS-sealed store, or the customer's 1Password vault. The secrets process is the
  only component that unseals a value, and only for one dispatch (§5). For runner
  jobs the value, or preferably a short-lived derivative, is sealed to one
  registered runner for one job (§9).
- **Who authorizes.** AWID establishes the current team authority and the member
  certificate. secrets' own tables decide everything else: app-local roles,
  grants, policy and approver designations, keyed to the member's stable
  identity. The team owner act (`aweb.owner-act/1`, team controller authority)
  designates the first owner, never install or admin authority (§10.2). Every later change that widens authority needs an enrolled owner
  passkey on secrets' own origin (§6.3). Narrowing changes never need a passkey
  (§12).
- **What a host or transport may do.** A hosted operator's MCP endpoint (D1 L2) signs team-auth
  as a custodial member. It can therefore exercise exactly that member's grants
  and nothing more. Listing a tool through L2 grants nothing (§4.5). No host or
  transport can approve, because approval is a passkey assertion made on
  secrets' origin. No host or transport ever receives a value.
- **Signed artifacts and who verifies each.**
  - secrets verifies the member's team-auth v2 envelope with the shared B1 verifier.
  - secrets verifies the approver's WebAuthn assertion over the frozen canonical
    request.
  - secrets verifies every runner message against that runner's registered key.
  - The runner verifies job assignments against secrets' pinned service key.
  - Hook targets (logs) verify secrets' provenance signature on each event.

Neither a domain string nor a working hosted-operator credential establishes membership or
any secrets role. secrets never creates, joins, recovers or reassigns an identity.

## 2. Positioning

The secrets SOT §14 recommends that secrets authorize and audit credential use
on top of the vaults teams already have, instead of replacing them. This design follows that
recommendation. It also keeps a native store, so both custody backends are
available at launch (Q1). The native store exists so that a team without a vault can start, and
so that secrets can seal its own operational credentials, including the
1Password service-account token (§5.3).

What aweb adds over a vault's own mediation is not mediation itself. It is three
things together:

- policy tied to a verified agent identity, team, operation and request;
- an approval made with an attributable passkey and bound to frozen intent;
- a signed, hash-chained record kept in the user's own logs app.

1Password's own credential mediation can be integrated as a further backend kind
(§5.5, open question Q3).

## 3. Components

```mermaid
flowchart LR
  subgraph Agent side (untrusted planner)
    A[aw CLI agent] -->|team-auth v2| API
    M[MCP agent] --> L2[Hosted MCP endpoint, D1 L2] -->|team-auth v2 as member| API
  end
  subgraph secrets (naapp/secrets)
    API[Agent API] --> ADM[Admission: verify, grant, policy, approval]
    ADM --> DB[(secrets DB: records, intents, outbox)]
    ADM --> DSP[Dispatcher + egress guard]
    DSP --> CUS[Custody backends]
    CON[Human console origin: passkeys, value ingress, approvals]
    CON --> DB
    OUT[Hook outbox drainer] --> DB
  end
  CUS --> KMS[(KMS)]
  CUS --> OP[(1Password vault)]
  DSP -->|HTTPS, pinned IP| UP[Upstream API]
  R[User-run runner] -->|outbound HTTPS, signed| API
  OUT -->|post-secret-use-hook| LOGS[logs.ingest and other targets]
  H[Approver / owner browser] -->|passkey| CON
```

- **Agent API.** This is the manifest-mapped tool surface, authenticated with
  team-auth v2. It never sets or reads cookies, so it has no ambient authority.
- **Human console.** This runs on a separate origin served by the same service
  (§15). It hosts passkey enrolment and login, value ingress and replacement,
  approval decisions, and the confirmation of policy changes. It never accepts
  team-auth and never exposes an agent tool.
- **Dispatcher.** It performs brokered HTTPS calls through the egress guard
  (§7.3) and assigns runner jobs (§9).
- **Outbox drainer.** It delivers hook events. The hooks design seat
  (`aweb-protocol-expert-hooks-design`) owns the envelope and delivery mechanics.
  secrets owns its payload fields and its enqueue rule (§11.5).

### 3.1 Placement: `aweb_naapp` or app-local

This follows Juan's direction: no runtime code is repeated across naapps. Shared
pieces live in the library `aweb_naapp` (`naapp-lib/`). The table applies Q16: a component becomes shared once a second consumer exists. Rows
marked "app-local, under Q16" move to `aweb_naapp` when a second consumer
appears. Q16 is decided this way (§18). Pieces marked
*proposed* are not yet in any `aweb_naapp` task. They go to the secrets coordinator for assignment, and their
runtime dependencies sit behind an extra, following B1's packaging seam.

| Component | Placement | Why |
| --- | --- | --- |
| Team-auth v2 verifier, scope enforcement, resource/action policy hook | `aweb_naapp`: B1, aweb-acgh.3 | Every naapp verifies members. |
| Server discovery, purpose-split app auth, grant status, hook-target resolution | `aweb_naapp` client of aweb-acgh.7 | It is the generic app-to-team-server API. |
| Approval primitive; WebAuthn verifier, designation, enrolment, recovery | `aweb_naapp`: B2+B3, aweb-acgh.4 | Pages and secrets both approve. |
| App-emit and hook-event signing; producer outbox with same-transaction enqueue; delivery client | `aweb_naapp`: B4, aweb-acgh.6, and the hooks design | Every hook producer needs them. secrets supplies only its payload and its enqueue points. |
| DB bootstrap, settings, health with build identity, manifest serving, docs surface, usage reporting client | `aweb_naapp`: B4, aweb-acgh.6; D1 C5 | These are the common runtime of every naapp. |
| Canonical JSON and domain-separated Ed25519 signing helpers | `aweb_naapp` | B2, the hooks design and secrets' runner protocol all sign typed payloads. |
| Console session for an app-origin human page: passkey login, short `__Host-` cookie, CSRF | `aweb_naapp`, *proposed* | Any naapp with human pages on its own origin needs it, pages' approval page included. B3 verifies assertions but does not hold a session. |
| Idempotency-key store: request hash, `409` on conflict, `410` on expiry | `aweb_naapp`, *proposed* | D1 §3 states the same rule for pages. |
| External-effect dispatch state machine: intent, fence, `dispatching`, `completed`, `not_sent`, `outcome_unknown`, reconcile before retry | `aweb_naapp`, *proposed* | D1's A2 enforcing adapter needs identical semantics (D1 §4). |
| Egress guard: canonical URL, destination matching, DNS and address policy, pinned connection, redirects off, header policy, bounds | `aweb_naapp`, *proposed* | Any naapp calling an external API with its own credential needs it: pages' A2 adapter, and a Linear naapp. |
| Auth-scheme injectors: bearer, basic, header, query, OAuth2 client credentials with a token cache, SigV4 | app-local, under Q16 | No second consumer exists yet, and secrets' custody argument (below) says another naapp needing a customer credential should use secrets. They move to `aweb_naapp` when a second consumer appears. |
| Response handling: header filter, JSON-pointer projection, known-value redaction, credential-shape detector, log redactor | app-local, under Q16 | Only secrets returns upstream responses to agents. Hook payload redaction is structural, through the strict allowlists, so it does not need this. They move to `aweb_naapp` when a second consumer appears. |
| KMS envelope sealing with bound context | app-local, under Q16 | No second consumer is committed yet. Other naapps could seal their own operational credentials this way, and it moves to `aweb_naapp` when one does. |
| Rate-limit buckets and time windows | app-local, under Q16 | D1's safety throttles are a candidate second consumer but are not yet committed to this component. They move to `aweb_naapp` when that consumer is confirmed. |
| Role assignments keyed by stable principal | `aweb_naapp`, *proposed* | Pages resolves role targets the same way (D1 §4). secrets only names its roles. |
| Principal-attestation verifier (§4.6) | `aweb_naapp`, when the contract exists | Any relying app could require it. |
| Secret, version, destination, operation, grant and policy records and their evaluation | app-local | They are secrets' domain model. They call the shared pieces above and contain no generic mechanism. |
| Custody backend interface and the 1Password adapter | app-local | Concentrating customer-credential custody in one app is itself the security property. Another naapp that needs a customer credential should use secrets, not open a vault itself. The KMS sealing underneath is shared. |
| Token-issuing result handling and derived secrets (§8.3) | app-local | They depend on secrets' custody and grants. |
| Runner protocol, runner binary, HPKE credential delivery, job definitions | app-local | Only secrets releases credentials to user-run executors, and no second consumer is in view. They are built on the shared signing helpers, and would be extracted when a second naapp needs remote execution. |
| Console page content: value ingress, change confirmation, rendering of secrets' approval payloads | app-local, on the shared console session and chrome | The content is secrets-specific; the mechanism is shared. |
| `post-secret-use-hook` payload fields and enqueue points; the `aweb.secrets.use-approval/1` and `aweb.secrets.change/1` payload types | app-local | These are secrets' contracts carried by shared mechanisms. |

## 4. Identity, roles, grants and policy

### 4.1 Admission of a member request

Every agent-API request is verified in this order, and every step fails closed.

1. **Team-auth v2** through the shared `aweb_naapp` verifier (B1,
   aweb-acgh.3). It checks the signature, the canonical payload, `aud`, method,
   raw external target, body hash, timestamp skew, the certificate against the
   current team key, and revocation status from a cache that fails closed when
   it expires. secrets uses B1 as it is and does not re-specify it.
2. **Installation status and scope.** B1's scope enforcement checks the tool's
   declared scope against the installed grant. Grant status comes from the
   generic app-to-team-server API (aweb-acgh.7) and D1's admission fence. The
   admitted generation is recorded on the intent. A request made under a grant
   from an installation generation that a later one has superseded is refused
   with `generation_superseded`, here and again at the fence (§11.3). B1's resource/action policy hook is where
   secrets plugs in steps 3–5.
3. **Principal.** The principal is keyed `(team_id, member_did_aw)` when the
   certificate carries `member_did_aw`, and never by `did:aw` alone across
   teams. Otherwise it is `(team_id, member_did_key)`, which covers local
   identities.
   - **What the key rests on.** `member_did_aw` is a binding asserted by the team
     controller. The team signature covers the whole certificate, and the
     controller is the membership authority. That is sound for grants inside
     that team (A `docs/awid-sot.md:97`–`:100`, `:650`–`:672`). B1 surfaces it
     from the verified certificate.
   - **What it does not prove.** It does not prove that the `did:key` is the
     did:aw's current registry key. That check is D1's proposed current-key
     profile (B1b), which is out of B1's scope. Nothing here calls the principal
     registry-verified, and a policy that requires that assurance refuses until
     B1b lands.
   - **Rotation.** A key rotation keeps the principal's grants only through a
     reissued certificate under the same `member_did_aw`. Until the old
     certificate is revoked, both keys act as the same principal. A new local
     key is a new principal.
4. **Replay.** Every mutating body carries a client `request_id`, covered by
   `body_sha256`. secrets deduplicates `(installation_id, principal, request_id)`
   (§11.2). A replayed envelope inside the skew window therefore returns the
   first receipt and never dispatches twice. This closes, for secrets, the replay
   gap that team-auth v2 leaves open, without a protocol change.
5. **Role, grant and policy**, as set out in §4.2–§4.4.

### 4.2 App-local roles

Roles are secrets' own data. They are not the core role system and not data on
the page (secrets SOT §12). The roles are:

- **owner.** Owners manage secrets, destinations, operations, jobs, runners,
  grants, roles and approvers. Every widening change by an owner needs that
  owner's passkey (§6.3).
- **user roles.** These are owner-defined names, such as `deployers`, that grants
  can target.

Approvers are not a DID role. An approver is an app-local person record with a
registered contact and enrolled passkeys, optionally linked to a member principal
(§10.2).

### 4.3 Grants

A grant is:

```
(secret_id, subject: principal | user_role, capability: use | run,
 allowed operations: [operation_id@digest] | open_request,
 policy_id)
```

The rules:

- **No grant, no use.** This holds whatever the scope, the host, or the L2
  listing says.
- **Open requests inside the host scope** are possible only when the secret's
  sensitivity is `standard` and the grant explicitly allows `open_request`.
- **A `sensitive` secret** admits only named operations (§8).
- **Grants bind operation digests.** Editing an operation produces a new digest,
  so existing grants do not silently widen. The owner re-grants with a passkey.

### 4.4 Policy

A policy is an immutable, digest-addressed record. Grants reference it, and every
audit event carries its digest. It holds the following fields:

| Field | Meaning |
| --- | --- |
| `approval` | `none` or `per_use`. The secret's `approve_only` flag forces `per_use`, whatever the grant says. |
| `approvers` | entries are a plain `approver_ref` (slug grammar) or the explicitly tagged `owner:<principal_did>`; validation refuses every other form. Quorum 1 at launch (§10). |
| `approval_ttl_s` | the approval's `expires_at` in B2: the request must be decided and consumed before it. Recommended 900 s. |
| `rate` | token buckets per (principal, secret) and per secret, e.g. 30/hour. Counters update atomically in the admission transaction. |
| `windows` | allowed weekday and hour ranges in an owner-set IANA time zone. |
| `operations` | the operation allow-list (named operation IDs with digests). |
| `open_request` | boolean. Never true for `sensitive` secrets. |
| `result` | the result-handling defaults and bounds (§7.6). |
| `requires_attestation` | optional custody or principal predicates (§4.6). |
| `distinct_approver` | `required` or `not_required`. When required, the approver's linked principal must differ from the requesting principal: a four-eyes rule between humans (§10.2, Q7). |

Policy is evaluated at admission and again at the dispatch fence (§11.3). Rate
and window denials are security outcomes. They are recorded and never metered as
economic limits.

Use-approval candidates are the intersection of approver records covering the
secret and entries listed in `policy.approvers`. An owner is eligible only when
explicitly listed; a listed owner covers every secret under that policy because
owners have no `covers` field. For a derived secret, an approver covering an
ancestor also covers its descendants (§8.4); the child policy must still list
that approver. An empty intersection refuses the request with
`no_eligible_approver` before creating a pending approval (decision 63).

### 4.5 L2 exposure grants nothing

Hosted MCP users never run `aw`. They reach secrets only through a hosted operator's MCP endpoint (D1 L2), which
signs as the member (D1 L2, aweb-abzo). secrets cannot see that a request came
through L2, because what it verifies is the member's own signature. Exposure through L2 is
therefore a host listing, not an authorization. secrets applies its grant table to
every call exactly as it does for a CLI call. An owner who wants MCP agents to
have less authority grants their principals less. An owner who wants the
distinction enforced needs the attestation of §4.6.

### 4.6 Custody and principal attestation contract

Team-auth v2 tells secrets *which member signed*. It does not tell secrets who
holds that key, or which human, if any, initiated the call (A
`docs/product-authority-sot.md:114`–`:130`). This design proposes a generic,
optional companion artifact, `aweb.principal-attestation/1`:

- **Issuer.** The custodian that signed the request: the custodial deployment,
  for its custodial members and for its L2 endpoint.
- **Issuer key.** It is registered as a custodian of that member in AWID, by a
  controller-signed record. A custodian's say-so alone is not enough.
- **Claims.**
  - `member_did_key`, `certificate_id`, and `team_id`.
  - `custody: custodial`, with the custodian ID.
  - `channel`: `mcp_l2`, `dashboard` or `api`.
  - An optional `human_principal`: an opaque, issuer-scoped OAuth subject handle.
    It is never an email address.
  - A session ID, `iat` and `exp`.
  - `request_binding`: the SHA-256 of the exact team-auth signed-payload bytes
    that it accompanies.
- **Transport.** A header `X-AWEB-Principal-Attestation`, carrying canonical JSON
  with the domain prefix `aweb.principal-attestation/1\n` and an Ed25519
  signature.

What this artifact can and cannot prove:

- It proves positive custodial facts that the registered custodian asserts.
- It can never prove self-custody. A member's key can be copied, and the absence
  of an attestation is not proof. Policy therefore expresses predicates such as
  `custodial_via: X`, `channel != mcp_l2` or `human_principal present`, never
  "is self-custodial".
- An unknown issuer, an expired artifact or a binding mismatch makes a policy
  that requires the attestation refuse.

**Requirement on a custodial deployment.** The deployment issues this
attestation for every request it signs as a custodial member, covering both L2
MCP calls (`channel: mcp_l2`, with the OAuth human handle) and dashboard calls.
It registers its issuer key as custodian through the AWID record above. The
artifact format, the AWID custodian record and the verifier are generic AWID, OSS
and `aweb_naapp` work. Issuing the artifact is the custodial deployment's work.
secrets only consumes it.

The frozen contract is [principal-attestation.md](../principal-attestation.md),
which adds the controller-signed custody and custodian records this section
describes, and the verifier is `aweb_naapp.runtime.attestation`.

**Until custodial deployments issue the artifact, any policy with
`requires_attestation` refuses every request without one.** Owners can configure the field now, and
it is honestly inert. The artifact is a launch requirement (Q5, decided).

## 5. Custody backends

### 5.1 Interface

```text
CustodyBackend
  kind                                  "native" | "onepassword"
  bind(secret_id, config)  -> backend_ref     # native: allocate; 1P: validate vault/item/field reference
  ingest(backend_ref, value) -> version_ref   # native only; console-only caller (§6)
  open(version_ref) -> Plaintext              # one dispatch, under the version's bound context
  describe(backend_ref) -> {version_ref, updated_at, state}   # never the value
  disable(backend_ref)                        # refuse open() from now on
  destroy(version_ref)                        # native: delete from the live store; 1P: forget reference only
  health() -> ok | degraded(reason)
```

The backend wire values are exactly `native` and `onepassword`, matching the
frozen use-approval vectors.

How a value is handled once opened:

- **Lifetime.** A `Plaintext` value lives in process memory for one dispatch
  only. It is never logged, persisted, put in an exception message or returned
  through any API.
- **Wiping.** Python cannot guarantee that memory is wiped. The implementation
  uses bytes-like buffers, avoids string interning and drops references
  promptly. It does not claim zeroization.
- **Crash dumps.** Core dumps are disabled in the deploy (§15).
- **Errors.** Backend errors map to `custody_unavailable`, and the request is
  refused. There is no fallback to any other backend.

### 5.2 Native KMS-sealed store

- **Envelope encryption.** Each secret version gets a fresh data key from KMS
  (`GenerateDataKey`) under a single key-encryption key. The value is encrypted
  with AES-256-GCM. The DB stores the ciphertext, nonce and wrapped data key.
- **Bound encryption context.** The KMS encryption context and the GCM AAD bind
  `{app:"secrets", installation_id, team_id, secret_id, version}`. A blob copied
  to another secret or version fails to decrypt.
- **Decryption.** Every dispatch calls KMS `Decrypt` with that context. There is
  no long-lived cache of plaintext data keys. KMS's own audit trail is a second,
  independent record of every unseal. Decrypt needs exactly the context given
  when the data key was generated, so the context cannot carry a per-dispatch
  `dispatch_id`. A KMS record is correlated with a dispatch through the
  dispatch's audit row instead: its timestamp and the secret version it names.
- **Key policy.** Only the secrets service role can decrypt or generate keys. No
  human operator role has decrypt rights in production. Break-glass access is an
  explicit, audited KMS policy change outside the app.
- **Destroy.** Destroying a version deletes its wrapped data key and
  ciphertext from the live database. Copies in backups and the write-ahead log
  stay decryptable until they expire or the key-encryption key is retired
  (§15, item 5), so destroy is not an irreversible erasure.

### 5.3 1Password backend

- **Reference.** A secret's `backend_ref` names the vault, item and field. secrets
  stores no copy of the value.
- **Credential.** secrets holds one 1Password **service account token** per
  installation. Its access is read-only to a dedicated vault that holds only the
  credentials agents may use. That token is itself a credential, so the owner
  enters it through the console (§6), and it is sealed in the native store. The
  1Password backend therefore depends on KMS.
- **Reads.** secrets reads the field at dispatch through the 1Password SDK. At
  launch it does not cache values across dispatches. There is no read cache
  at launch (Q4, decided). 1Password's own activity
  log is a second, independent record of every read.
- **Ingress and replacement.** Both happen in the vault. `open()` returns the
  item version it read. secrets compares it at the dispatch fence (§11.3) with
  the version bound to the intent, and with the approved version when there is
  an approval. On a mismatch secrets refuses (`secret_version_changed`), voids
  the approval and records a `secret.version_observed` event. An approval given
  for one value therefore never dispatches with another. Disable and destroy act on secrets' reference only. Revoking the service
  account is the owner's action in 1Password, and the console links to it.

### 5.4 What the broker sees, when, and for how long

| Backend | What secrets holds at rest | When plaintext exists in secrets | Who else can read |
| --- | --- | --- | --- |
| native | ciphertext and wrapped data key; metadata | during one `open()` for one dispatch: the brokered call, OAuth token exchange, SigV4 signing, or HPKE sealing to a runner | KMS custodian with decrypt rights; a production operator able to run code as the service (trust boundary T4) |
| onepassword | vault, item and field reference; the sealed service-account token | the same window, after an SDK read | the 1Password account's members and admins; the vault provider; holders of the service-account token |
| derived (OAuth access token, STS session) | sealed in the native store with its TTL, or in memory until expiry | per dispatch | as native |

### 5.5 Delegated vault mediation (option)

Some vaults can mediate a call themselves. A third backend kind, `delegated`,
could hand the frozen, policy-approved request to that mediator instead of
opening a value. secrets would then never see plaintext. That is stronger custody,
but secrets can enforce the egress guard (§7.3) and response handling (§7.6) only
as far as the mediator exposes them. It is not at launch (Q3, decided). The interface already admits it,
because `open()` is the only plaintext path.

## 6. Value ingress, replacement and the owner console

### 6.1 The rule

A value enters only in one of two ways:

- through the human console on secrets' own origin, under an owner passkey;
- directly in the customer's vault (1Password).

No manifest tool carries a value in any context, including `surface`. There is a
reason ingress is not a surface tool rendered by a host: a D1 surface renders on
the host and calls tools through the host as the member, so the host would see the
plaintext in transit. The manifest surface therefore offers a **link-out** to the
console (§13.2). Typing, pasting or uploading the value happens browser-to-secrets
over TLS. The requirement is that values enter only through a human surface or
the vault. This design meets it with secrets' own console rather than with a
host-rendered `surface` tool. That changes the secrets SOT §6, where creating a
secret was a manifest tool.

### 6.2 The owner's flow

1. **Sign in to the console.** The owner uses a passkey (WebAuthn `get`, with
   `userVerification: required`). The console session lasts 15 minutes at most,
   in a `SameSite=Strict`, `HttpOnly`, `__Host-` cookie scoped to the console
   origin. A CSRF token is required on every POST.
2. **Create the secret.** The owner sets the ref, description, kind and its
   non-secret parameters (header name, query parameter name, OAuth token
   endpoint, client authentication method, scope string, SigV4 region and
   service), plus the sensitivity, `approve_only`, the backend, and the
   destinations (§7.2).
3. **Enter the value.** It goes in a form field that never echoes it back. For
   multi-part kinds the value is structured: basic is username and password;
   OAuth2 client credentials is client ID and client secret; SigV4 is access key
   ID, secret key and an optional session token. secrets validates the shape,
   never the content, then calls `ingest()`. The response shows the version and
   a timestamp only. It never shows a fingerprint, because a hash of a
   low-entropy secret is a guessing oracle.
4. **Confirm the change.** Steps 2 and 3 form one change set. The owner confirms
   it with a second passkey assertion over the canonical change (§6.3) before it
   becomes active.
5. **Record it.** secrets records a `secret.created` or `secret.version_added`
   event through the hook (§11.5).

**Replacement** follows the same steps on an existing secret. The new version
activates atomically, and the previous version is destroyed in the same
transaction (§12).

### 6.3 Widening changes need owner passkey confirmation

The following are *widening* changes:

- creating a secret, or adding a value;
- adding or broadening a destination;
- defining or editing an operation, job or runner;
- granting, or assigning a role;
- designating an approver or changing an approver's contact;
- re-enabling anything that was disabled;
- changing a policy towards less restriction.

A widening change is a frozen canonical change set (`aweb.secrets.change/1`). It
is approved through B2/B3 with minimum assurance `passkey`, and an owner is the
designated approver (§10). An owner who is also a team member may draft the
change through a surface tool or `aw` (§13). The draft is inert until a passkey
confirms it on the console.

Anything that can sign as an owner can draft a change, an agent included. The
console therefore renders each change set by the same rules as an approval
(§10.4):

- it renders from the frozen bytes;
- hosts are emphasized, and each IDNA host is shown both as Unicode and as its
  punycode A-label;
- every widening element is highlighted against the current state;
- drafter-supplied text is labelled untrusted and escaped.

Because the confirmation is a passkey assertion on secrets' origin, holding the
owner principal's team-auth key is not enough to widen anything. That includes
a hosted operator's custody of an owner member.

## 7. The brokered URI path

### 7.1 Request

```json
{
  "request_id": "01JB…",
  "secret_ref": "stripe-test",
  "operation": {"id": "create-refund", "params": {"charge": "ch_123", "amount_minor": 500}},
  "reason": "untrusted free text shown to an approver",
  "trace_id": "optional, per the hooks contract"
}
```

An open request replaces `operation` with
`{"method","url","headers":{…},"body_b64"|"body_json"}`. That is permitted only
under §4.3.

### 7.2 Canonical destinations and matching

A destination entry is
`{scheme:"https", host, port, path, methods, query_rules, header_allow, network}`.
Matching is exact on a canonical form. secrets canonicalizes the request URL
itself and refuses anything ambiguous instead of guessing.

- **Scheme.** `https` only. `http`, other schemes, userinfo (`user@`) and
  fragments are refused.
- **Host.** IDNA2008 is mapped to lowercase A-labels, and a trailing dot is
  refused. An IP literal is refused unless the destination entry is that exact
  IP and has `network: internal` (§7.3). A wildcard is allowed only as a single
  leftmost label over a domain the owner controls (`*.api.example.com`). It
  never matches the bare parent domain and never matches more than one label.
  It is never allowed on a public suffix, as listed by the full Public Suffix
  List, private section included. Shared-hosting suffixes such as
  `s3.eu-west-1.amazonaws.com` are in that section, so owners list exact hosts
  there (`mybucket.s3.eu-west-1.amazonaws.com`).
- **Port.** It defaults to 443. An explicit port must equal the entry's port.
- **Path.** Path matching works as follows:
  - **Decoding.** Percent-encodings of unreserved characters are decoded, and the
    hex digits of the remaining encodings are uppercased.
  - **Refused forms.** secrets refuses `%2F`, `%5C`, `%00`, backslash, empty
    segments (`//`), and `.` or `..` segments, whether raw or encoded.
  - **Segment matching.** Paths are compared segment by segment. A pattern is
    either an exact path, an exact path ending in `/**` (meaning that segment and
    anything below it), or a path with typed `{param}` segments (§8).
    `/v1/charges/**` matches `/v1/charges/x`. It does not match `/v1/chargesX`.
- **Method.** The method must be in the entry's set. `CONNECT`, `TRACE` and
  unknown methods are always refused.
- **Query.** It is re-encoded in canonical form. `query_rules` can require,
  forbid or constrain named parameters. Duplicate keys are refused unless
  declared.

The canonical URL is what is matched, dispatched, approved and recorded, so all
four always agree.

### 7.3 Network boundary (egress guard)

These checks complement the scope checks. They follow the secrets SOT §14 network
requirement.

1. **Own resolver.** secrets resolves the host with its own resolver and collects
   all A and AAAA records.
2. **Denied addresses.** If any resolved address falls in a denied range, the
   request is refused (`destination_address_denied`). The only exception is a
   destination with `network: internal` and an exact allowed CIDR. That needs
   both an owner's passkey confirmation **and** the deploy-level switch
   described below. The denied ranges are:
   - loopback, `0.0.0.0/8` and unspecified;
   - RFC 1918 private and CGNAT `100.64/10`;
   - link-local, including `169.254.169.254` and IPv6 `fe80::/10`;
   - ULA `fc00::/7`, multicast, and broadcast;
   - documentation and benchmarking ranges (`198.18/15`), and `240/4`;
   - IPv4-mapped or IPv4-compatible IPv6, NAT64 `64:ff9b::/96`, 6to4 and Teredo
     forms that embed a denied IPv4 address;
   - the deployment's own egress and metadata addresses.
3. **Pinned connection.** secrets connects to one validated address that it
   chose, and sends SNI and `Host` as the canonical hostname. It verifies the TLS
   certificate against the hostname with the system trust store; there is no
   option to skip verification. Re-resolving between the check and the connect
   is impossible by construction, so DNS rebinding cannot swap the target.
4. **Redirects.** Redirects are **disabled**. A 3xx response is returned through
   response handling (§7.6) as a response. `Location` is treated as untrusted
   output and redacted like any body. Following redirects with revalidation at
   each hop is not offered at launch: it adds attack surface and no use case
   needs it.
5. **Proxies.** There are no proxy settings from the environment. Any egress
   proxy is a deploy-level allowlist (§15), never a request option.
6. **Bounds.** Connect timeout 5 s, total 30 s (per operation, overridable
   downwards), request body at most 1 MiB, response at most 4 MiB. Both bounds are
   reduced by policy.

"Internal" means internal to the secrets deployment's network. Whether such a
destination is possible at all is an **operator deploy setting**,
`internal_destinations: disabled | allowed`, which defaults to `disabled`.

- **`disabled`.** Any `network: internal` entry, and any IP-literal destination,
  is refused at definition time and again at dispatch, whatever an owner
  confirms. Owner passkeys cannot change this, because the setting is not in any
  installation's policy.
- **Hosted deployments** run with `disabled`, because one deployment serves many
  customers and its network is the operator's own.
- **A self-hosted operator** may set `allowed` for their own network.

A customer's private services belong behind a runner (§9).

### 7.4 Headers

- **Allow-listed.** Agent-supplied request headers pass only if they are allowed.
  The default allow-list is `Accept`, `Accept-Language`, `Content-Type`,
  `If-Match`, `If-None-Match` and `X-Request-Id`, plus each destination's
  `header_allow`.
- **Always rejected,** even if a destination allows them:
  - `Authorization`, `Proxy-Authorization`, `Cookie`;
  - `X-Api-Key`, `X-Amz-Security-Token`;
  - any `X-Amz-*` header except those the operation declares;
  - any header name the secret's kind injects;
  - `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `TE`,
    `Upgrade`, `Forwarded` and `X-Forwarded-*`.
- **Credential-shaped values.** A header value that looks like a credential is
  rejected (`header_not_allowed`) using the same detectors as §7.6. This stops an
  agent from smuggling its own credential through a scope that injects a
  different one.
- **Header set by the broker.** The broker sets `User-Agent: aweb-secrets/<version>`.

### 7.5 Auth schemes

The scheme is executed server-side, so the raw value never leaves secrets
(secrets SOT §3, spine item 2).

| Kind | Injection | Notes |
| --- | --- | --- |
| `bearer` | `Authorization: Bearer <v>` | |
| `basic` | `Authorization: Basic base64(user:pass)` | The composite and its base64 are both added to the redaction set. |
| `header` | `<owner-set name>: <owner-set prefix><v>` | The name is fixed in secret metadata, never chosen by the agent. |
| `query` | `<owner-set param>=<v>` | Recorded URLs replace the value with `[REDACTED]`. Upstream logs will hold it; the console warns. |
| `oauth2-client-credentials` | The broker exchanges client credentials at the owner-set token endpoint, then injects `Bearer <access_token>`. | The token endpoint passes the same egress guard and is an internal step of the dispatch. The access token is cached sealed with its TTL minus 60 s, never returned, and added to the redaction set. The scope string is owner-set. |
| `aws-sigv4` | The broker signs the final canonical request (after header filtering) with SigV4, including `x-amz-date` and `x-amz-content-sha256`. | Region and service are owner-set per secret and never agent-chosen. `X-Amz-Target`, which selects the operation for AWS JSON APIs, is allowed only when a named operation fixes it. STS is token-issuing (§8.3). |

`oauth2-refresh` and `mtls-client-cert` are in the secrets SOT §3. The
recommended launch set is the six kinds above. mTLS is proposed for later, and
refresh tokens are not in the launch set. This design
keeps the interface able to carry both, and lists their timing as Q9.

### 7.6 Response handling and default deny on credential-shaped results

Responses reach the agent, and through L2 the model provider's context. The order
of operations is:

1. **Bound.** The response is cut at its size and time limits. Truncation is
   reported, never silent.
2. **Filter headers.** Only `Content-Type`, `Content-Length`, `ETag`,
   `Last-Modified`, `Retry-After`, `X-RateLimit-*`, request-ID headers and
   `Location` pass. `Location` is then redacted as in step 4. `Set-Cookie` and
   every other header are dropped.
3. **Project.** A named operation may declare a response projection, which is a
   list of JSON pointers to return; everything else is dropped. Projection is
   **required** for `sensitive` secrets and is the strong control. Open requests
   return the whole body, subject to steps 4 and 5.
4. **Known-value redaction.** Every value opened or derived in this dispatch is
   replaced with `[REDACTED:<secret_ref>]`. That covers the raw value; its
   base64, base64url, hex and percent-encoded forms; the Basic composite; and
   the OAuth access token. Matches are counted.
5. **Credential-shape detection, default deny.** The detector looks for JSON keys
   such as `access_token`, `refresh_token`, `id_token`, `client_secret`,
   `password`, `private_key`, `secret`, `SecretAccessKey`, `SessionToken` and
   `api_key` that carry non-empty string values. It also looks for high-confidence
   token patterns: AWS `AKIA`/`ASIA` key IDs paired with secret keys, PEM private
   key blocks, JWTs, and well-known vendor token prefixes. If either is present,
   the default disposition is **`withheld`**. The agent receives status, filtered
   headers, `result_withheld: credential_shaped` and the redaction count, but no
   body.
6. **Record.** secrets records the disposition, the response hash and the counts,
   never the body.

`withheld` means the upstream effect already happened. The audit event says so,
and the owner sees it in the console.

Known-value redaction and pattern detection do **not** prove confidentiality
(secrets SOT §14). Only projection and the token-issuing policy (§8.3) bound what
leaves.

## 8. Operation bounding

### 8.1 Named operations

An `operation_template` is owner-defined and passkey-confirmed. It is immutable
once confirmed, and it is addressed by `operation_id@sha256(canonical template)`.
It holds:

```text
operation_id, secret_id, method,
url: fixed host/port, path template with typed {params},
params: typed schema per param (D1's bounded JSON Schema subset: enum, integer ranges,
        bounded strings with fixed character classes, no free regex), placement path|query|body,
body: fixed JSON template with param slots | schema-validated body subset,
headers: fixed values and allowed agent headers,
response: projection (JSON pointers), max bytes, content types,
side_effect: none | reversible | irreversible,
token_issuing: bool, result_handling (§8.3),
idempotency: {header: "Idempotency-Key"} | none,
reconcile: optional status-lookup operation_id keyed by the idempotency key or the response id
```

Parameters fill only typed slots. A value never becomes a path separator, header
name, host or method. An amount ceiling ("refund at most 50.00 EUR") is an integer
range on a minor-units parameter. An operation limits what can be done with the
credential, as well as where it can be sent.

### 8.2 Where named operations are required

- **`sensitive` secrets** admit named operations only.
- **`approve_only`** implies `sensitive`. Informed consent needs a bounded,
  renderable action (§10.4).
- **Open requests** are allowed only for `standard` secrets whose grant allows
  them. They are always recorded with their canonical method, URL and body hash.
- The console tells owners that host scope alone does not stop destructive calls
  or credential creation. That is the secrets SOT §14 point, and the reason
  sensitive secrets require named operations.

Narrow upstream permissions are the owner's responsibility. secrets cannot verify
them. The console asks for them, and the defensible claim does not depend on them.

### 8.3 Token-issuing operations

An operation whose result can contain a credential, such as an STS `AssumeRole` or
`GetSessionToken`, an OAuth token endpoint or an API-key creation endpoint, must
declare `token_issuing: true` and one `result_handling`:

| Handling | Behavior |
| --- | --- |
| `deny` (default) | The operation is refused before dispatch. |
| `withhold` | The operation must declare a nonempty response projection; validation refuses its absence (`operation_invalid`, decision 64). secrets dispatches, then applies projection, redaction and credential-shape checks (§7.6). |
| `store_as_secret` | One issuance creates one native-custody child secret, with fixed child destinations, kind parameters, a grant from pinned template terms and a bounded expiry (§8.4). The agent receives `{derived_ref, expires_at}`, never the value. |
| `return` | **Does not exist (Q8, decided).** Returning the credential is a value release, like `--unsafe-inject`, and `store_as_secret` plus runner `short_lived` delivery covers the use cases. |

When detection (§7.6) finds credential-shaped content in an operation that did not
declare `token_issuing`, the result is withheld. The `completed` event then
carries `undeclared_credential: true` with disposition `withheld`, and no
separate event is raised (one effect, one event, §11.5). The console reads that
flag to tell the owner to fix the template.

### 8.4 Derived-secret creation and use

This is the `store_as_secret` contract (decision 71), implementing the controlled
result handling required by secrets SOT §14. It adds no value-ingress tool.

**Issuer definition.** `operation/1.store_as_secret` has exactly
`derived_kind`, `kind_params`, `capture`, `destinations`, `grant_template`,
`grant_template_digest`, and exactly one of `expires_at` or `expires_in`.
The issuer operation's digest covers every field. Its owner passkey confirmation
shows the child authority as well as the issuance request. The existing
`store_as_secret_unavailable` guard is lifted only when the record, resolver and
expiry paths implement this contract; other operation/1 forms keep their
existing shape. The operation/1 and change/1 vectors are regenerated together
under deliberate review, not hand-merged.

- `derived_kind` and `kind_params` follow secret/1's auth-scheme validation.
  OAuth access tokens become `bearer` children; they do not become OAuth client
  secrets. STS children use `aws-sigv4` with explicitly fixed region and service
  and must capture the session token as well as the access-key pair.
- `capture` maps the selected kind's value fields to response JSON pointers.
  These pointers extract credential material only into custody, before response
  projection. Values use the same custody-owned structured-value codec as the
  broker's opener; there is no second encoding or opaque string conversion.
- `destinations` is a nonempty list of destination/1 bodies without
  `destination_id` or `secret_id`; each retains its `v` and all canonical egress
  constraints (§7.2–§7.3). Child destinations are **not** a union with the
  parent's destinations. They are an explicit, owner-confirmed issuance scope,
  and the child's usable scope is at most that list, further narrowed by its
  grant, policy, selected operation and current deployment network policy.
  An STS-only parent may therefore issue an S3-only child without ever allowing
  the parent credential to be sent to S3. Request parameters and upstream
  responses cannot supply child hosts, paths, methods or kind parameters.
- `grant_template` is an existing template ID in the same installation.
  `grant_template_digest` is the lowercase SHA-256 of
  `"aweb.secrets.grant-template/1\n" || canonical_json(template.after)`, including
  all fields, `v` and the template ID. At issuance admission, secrets snapshots
  the complete terms and verifies that hash against the issuer operation's pin.
  The approval thus covers the terms through `operation_digest` (§10.4), without
  changing use-approval/1's field set. The dispatch fence re-reads and locks the
  template, rejects a mismatch (`operation_not_allowed`), and uses only the
  persisted snapshot to construct the child grant. Editing template terms
  requires a newly confirmed issuer-operation digest before issuance can resume.

There is no implicit child permission. A child inherits the parent's
`sensitivity` and `approve_only` flags, but **no ancestor grant or policy grants
permission** to the child. The ancestor rate constraints below are additional
limits. Its new grant copies the one named template's subject, capability,
policy digest, pinned operations/jobs and open-request setting; only its grant
ID and secret ID are minted. Definition and issuance refuse an incompatible
combination, such as an open-request grant on a sensitive child or missing
policy/operation pins. The template's policy must permit the intended child
uses. Child operation lookup follows the explicit rule below.
For an internal runner mint, §9.5 adds an immutable run binding that further
restricts this copied grant; it does not change the grant record's shape.

**One atomic child per issuance.** Add an ordered migration for server-managed
lineage and expiry metadata: parent secret ID and parent value version, source
issuance dispatch ID and issuing grant ID, issuing principal and policy digest,
upstream expiry and effective expiry, with a same-team, same-installation
parent reference and a uniqueness constraint on the source
dispatch. These are not agent-editable secret/1 fields. A successful capture
creates the child metadata, a new secret ref, sealed native version 1,
child-bound destination rows, its fresh grant, the dispatch result and the
operational/hook outbox record in **one transaction**. Parent version, state,
ancestor expiry and issuing-grant liveness are rechecked under the recording
fence; if containment won the race, no usable child is committed. The minted ref obeys secret/1's existing
slug grammar and length, with a collision-checked random suffix; no upstream
field chooses it. The source dispatch's uniqueness makes replay return the
same child, without minting another or calling the issuer again.

**The issuing grant remains a containment boundary.** Revoking a grant disables
all child secrets whose issuing dispatch used that exact grant, and all of those
children's descendants, in the **same transaction** as the revocation. Their
pending and approved-but-unconsumed approvals are voided in that transaction.
This does not disable the parent or siblings issued under other grants. The
lineage's issuing grant ID makes this precise even when a template designates a
different principal. Admission, dispatch, capture and runner release recheck all
issuing-grant links in the ancestry; a revoked link refuses with `grant_revoked`.
Regranting or re-enabling a parent never resurrects disabled descendants. The
local cascade does not claim to revoke a credential already held upstream or on
a runner; §12's remote-containment limits still apply.

**Approver coverage follows the lineage.** An active approver record covering a
secret ID also covers every descendant of that secret in the same installation
and team, including descendants minted later. The designation surface and the
issuer-operation confirmation disclose that meaning. For a child request,
coverage is a match on the child **or any recorded ancestor**, intersected with
that child's `policy.approvers`. An unlisted ancestor approver gains nothing;
owner eligibility, passkey assurance and `distinct_approver` remain unchanged.
No approver record is copied or minted at issuance. Coverage and policy listing
are rechecked at approval admission as well as request time; withdrawing
coverage or revoking the approver voids affected unconsumed child approvals.
An empty eligible set still refuses immediately with `no_eligible_approver`.

**One lock order for capture and containment.** After the existing installation
fence, creation, use and every cascade lock the stored secret ancestry from root
to leaf; multiple sibling paths use ascending `secret_id`. They then lock the
relevant grants in ascending `grant_id`, including the issuing grant. Re-read
liveness, parent version and expiry only after those locks. Insertion takes the
same locks on the prospective parent's complete ancestry before creating its
child. A cascade therefore cannot miss an insertion: either capture commits
first and the cascade disables it, or capture sees the revoked/disabled ancestor
and commits no usable child. Re-enable cannot undo the descendant's own disabled
state. Existing configuration-revision and approval locks keep their relative
order; S11 and S8 use this same lineage order at both recording and revocation.

**Rate limits do not reset at derivation.** Child admission charges its own
policy's buckets **and** the rate buckets pinned by every ancestor issuance's
recorded policy digest. An inherited secret-wide bucket remains keyed to the
ancestor secret; an inherited principal/secret bucket remains keyed to that
secret and its recorded issuing principal. Thus fan-out into many child IDs or
template subjects does not multiply an issuer's budget. This inherits limits,
not authorization. Deduplicate identical bucket keys, lock all applicable keys
in one deterministic order, and charge them atomically only for an admitted
request. Refusal charges none, and an idempotent replay never charges twice.
Missing ancestor rate policy refuses; a new child never starts fresh copies of
those buckets. The child policy may impose additional, tighter limits.

**Expiry.** `expires_at` and `expires_in` are mutually exclusive JSON pointers,
not expiry values supplied by the requester:

- `expires_at` points to an absolute RFC3339 timestamp with a timezone; normalize
  it to UTC. A missing timezone or invalid timestamp is refused.
- `expires_in` points to an integer number of seconds from 1 through
  `2**53 - 1`, never a boolean, string or float. Compute upstream expiry from the issuance dispatch's
  **persisted start time**, not response receipt, replay or reconciliation time.
  Neither a retry nor a status request restarts the lifetime.
- The deployment's `derived_secret_max_ttl_s` is a positive finite integer,
  **3600 s by default** (decision 71). Effective expiry is the earliest of
  upstream expiry, persisted dispatch start plus this cap, and every ancestor's
  expiry. Store that deadline once; later cap increases cannot extend it. Any
  tighter current cap or ancestor deadline still applies at use. Missing,
  malformed, overflowing or already-past expiry refuses child creation; so does
  an effective deadline that is no longer in the future when recording commits.

The one-hour default matches [STS AssumeRole's default session duration and its
role-chaining bound](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
It is a local use limit, not a claim that all STS sessions last one hour. For
OAuth, [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
defines `expires_in` in seconds without a universal lifetime; a shorter upstream
lifetime always wins, and an omitted lifetime has no guessed default here.
A deployment can support longer intended sessions by raising its cap; the
upstream and ancestor deadlines still win. Local expiry does not revoke a
credential already accepted by an upstream or delivered to a runner.

**Child operation resolution.** For a child use, resolve `operation_id` only
within its stored ancestry, in this fixed order: the child first, then its
immediate parent, then each ancestor toward the root. Choose the **first current
definition** with that ID, even if a more distant definition would match a pin.
Its original source `secret_id` remains part of its original digest. Require
that current digest to match both the child's grant and policy pins. On a
mismatch refuse `operation_not_allowed`; never fall back to a historical digest
or a farther ancestor. The child's approved use names the exact selected
operation digest. Editing a source operation therefore invalidates an old child
grant until regrant, and a nearer definition cannot silently replace it. No
installation-wide or cross-team search is allowed. The effective credential,
grant, policy, destination checks, approvals and dispatch fence always belong to
the **child**, with its recorded ancestor liveness/version checks in addition.

**Failure, containment and cleanup.** After a definite upstream response, invalid
capture or expiry, a stale template snapshot or lost parent authority yields a
`completed` event with disposition `withheld` and `undeclared_credential: false`;
no child or value is returned. The owner's operational record has the distinct
capture/expiry/authority failure reason. This is a known issuance outcome with a
withheld result, not permission to retry issuance. A recording transaction that
cannot enqueue rolls back; the dispatch remains for reconciliation (§11.4).
Reconciliation reuses the same dispatch and recorded start time; if it cannot
recover the issued credential safely, it withholds rather than dispatching again.

Admission, the dispatch fence, `SecretOpener` and runner credential release all
refuse an expired child or an inactive/replaced ancestor. Disable or value
replacement on any ancestor disables every descendant and voids its pending
approvals; re-enabling the parent does not resurrect descendants. Expired use is
`secret_disabled` with the distinct message that the derived secret expired.
The sweeper destroys expired sealed live values and cached copies; the expiry
checks apply even if that sweep is delayed. Metadata and signed receipts remain
under their retention policy. Upstream revocation is attempted where supported,
without treating local disable as proof of remote revocation (§12).

## 9. The runner

### 9.1 Role

The runner reaches what secrets cannot: database wire protocols, shell tools and
infrastructure-as-code on the user's own network. It runs only **pinned job
definitions** with validated parameters. It never runs a command an agent supplies
(secrets SOT §4).

### 9.2 Registration and authentication

1. **Create the runner.** In the console, the owner creates a runner record
   (label and allowed jobs) and confirms it with a passkey. The console shows a
   one-time registration code. It is valid for 10 minutes, single use, and stored
   only as a hash. It is shown only on the console, never through any agent tool.
2. **Register.** On the host, the user runs
   `aweb-secrets-runner register --origin <secrets origin> --code <code>`. The
   runner generates an Ed25519 signing key and an X25519 encryption key locally.
   It sends both public keys (as `did:key` and a raw X25519 key) with the code.
   It receives `runner_id` and pins secrets' service signing key.
3. **No identity of its own.** The runner is an app-local principal, not an AWID
   identity. It needs no team membership and holds no team certificate.
4. **Rotation.** The runner re-registers with a new code. Deregistration (§12) is
   immediate.

### 9.3 Transport

The runner connects outbound only. It opens no listening port.

- **Long-poll.** `POST /runner/v1/claim` waits up to 30 s and returns zero or one
  assignment. `POST /runner/v1/dispatches/{id}/started|result` reports progress.
  It is plain HTTPS through ordinary proxies.
- **Runner to secrets.** Every runner request is signed with the domain prefix
  `aweb.secrets.runner-request/1\n` over canonical JSON. The signature binds
  `runner_id`, `kid`, method, raw path, body SHA-256, timestamp and nonce. The
  skew window is 120 s, and nonces are deduplicated in the DB until they expire.
- **Secrets to runner.** Every assignment is signed by secrets' service key with
  the prefix `aweb.secrets.runner-assignment/1\n`. The signature binds
  `runner_id`, `dispatch_id`, `job_id@digest`, the parameters' SHA-256, the
  sealed-credential digest and `expires_at`. The runner refuses an assignment
  that is unsigned, expired, for another runner, or a replay; it keeps a local
  journal of executed dispatch IDs.
- **Credential delivery.** The credential travels sealed with HPKE (RFC 9180,
  X25519 / HKDF-SHA256 / ChaCha20-Poly1305) to the runner's encryption key, with
  `dispatch_id` as `info`. It exists in plaintext only on the runner host, for
  that job.

### 9.4 Job definitions

A job definition is owner-defined, passkey-confirmed, immutable and addressed by
digest. It holds:

```text
job_id, runner_ids, kind: exec | oci,
exec: absolute executable path + sha256; declared file set (scripts, config, lockfiles) each with sha256,
oci:  image reference by digest (never a tag); no host mounts except declared read-only paths,
argv template: array; params substitute only as whole elements, never through a shell;
               each slot is `positional` (placed after a literal `--`) or `option_value`
               (the element after a fixed option name),
env template: names that receive credential material or params, never a code-loading name,
cwd, timeout, max output bytes, output projection,
params: typed schema as in §8.1,
credentials: [{secret_ref, delivery: short_lived | durable, mint}]
```

**Credential slots and mint recipes.** Each `secret_ref` is unique in the job's
ordered credential list and names a fixed secret in the same installation and
team. It is also the stable slot label used by `env` entries of the form
`{"$credential": "<secret_ref>"}`. An environment reference must name a declared
slot. It never names a future random child ref.

- For `short_lived`, `secret_ref` names the **parent** and `mint` is exactly
  `{operation_id, digest, params}`. The operation must resolve for that parent
  under §8.4's CURRENT operation rule and be token-issuing with
  `result_handling: store_as_secret`; `digest` is its exact approved operation/1
  digest. Each `params` entry is exactly one of
  `{"value": <typed literal>}` or `{"$param": "<job parameter name>"}`.
- For `durable`, `mint` is `null`; there is no implicit mint operation. The job
  also needs its explicit passkey-confirmed `allow_durable: true` flag (§9.5).
- The recipe supplies every declared issuer parameter exactly once, with no
  unknown names. A literal must satisfy that parameter's type and bounds at job
  definition. A job-parameter reference must name a declared job parameter of
  the same type. At admission, validate the job parameters, expand the recipe
  without coercion, then validate every resulting value against the issuer's
  constraints. Invalid mappings refuse with `params_invalid`; a schema match
  never dispenses with validating the actual value.
- Mappings fill only the issuer's declared parameter slots (§8.1). They cannot
  replace fixed request fields, fixed role/session-policy terms, destinations,
  kind parameters, capture/expiry pointers or the grant-template pin. Neither
  the agent's run request nor an upstream response supplies a recipe or an
  override. The owner confirmation shows each literal and each job-to-issuer
  mapping, together with the resulting child authority.

The job/1 digest is SHA-256 of
`"aweb.secrets.job/1\n" || canonical_json(after without v)`, using the shared
integer-only canonical JSON rules. It covers the ordered slots, complete mint
recipes, parameter schemas, delivery modes and `allow_durable`, as well as the
executable and other job fields. Changes require a new owner confirmation, job
digest, run grant and runner-local pin. Jobs resolve through the installation's
single CURRENT `job_id` definition, then compare its digest with the approved
pin; mismatch refuses with `job_not_allowed`. There is no secret-scoped or
ancestor job namespace and no fallback to a historical job definition. Each
mint operation likewise resolves the parent's CURRENT operation under §8.4 and
requires the recipe's exact digest at admission and the dispatch/release fences; an
edit refuses with `operation_not_allowed`, without substituting another mint
operation or a newer digest.

**Argument and environment safety.** These rules are checked when a job is
defined and checked again by the runner before each run.

- **Option injection.** A typed string parameter that starts with `-` is refused
  unless its slot is declared `option_value`. Positional slots come after a
  literal `--` in the template. A value like `--upload-pack=…` or
  `-oProxyCommand=…` therefore can never become a flag.
- **Environment names.** Names that load code or change resolution are refused
  as targets for a parameter or a credential. They include `LD_*`, `DYLD_*`,
  `PATH`, `*_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `GIT_*`, `SSH_ASKPASS` and `IFS`.
- **Starting environment.** The runner starts each job from an empty
  environment plus the declared names. It does not inherit the runner's own
  environment.

**Two-key pinning.** secrets checks the parameters and the digest. The runner's
own local config independently lists the job digests it will execute. A job runs
only if both agree.

The local config is owned by the runner's OS user and kept outside the agents'
write authority. That is the secrets SOT §14 requirement: if an agent can
edit what the job runs, the job runs whatever the agent wants. Before every run, the runner re-hashes the
executable and the declared files, or pins the image digest. It refuses on any
mismatch.

`aweb-secrets-runner doctor` refuses to start when:

- the config, the executables or the declared files are writable by any user
  other than the runner's own user;
- the runner runs as the same OS user as a configured agent.

The documented requirement is a dedicated OS user or container per runner. Agents
running as the same user can defeat any runner. That is boundary T8, stated
honestly rather than detected.

### 9.5 Short-lived scoped credentials are preferred

`delivery: short_lived` is the default where a minting recipe exists for the kind:

- **AWS.** STS `AssumeRole`, with an owner-set role, a session policy and a
  duration of 15 minutes or less. The runner receives a session triple.
- **OAuth2 client credentials.** The runner receives an access token.

**One authorized run, with internal mints.** A `short_lived` slot is authorized
by the parent's `run` grant for this exact installation CURRENT `job_id@digest`,
not by a child grant that must itself pin the invoking job. The owner-confirmed
job's recipe authorizes the named mint as an internal step of that run; it
does not grant the caller independent broker access to the parent operation.
Every credential slot needs its own matching authorization for the same verified
requester, job, runner and frozen parameters. A grant for one parent grants
nothing for another slot. Resolve and freeze the complete slot plan before
approval or minting: source secret/version, authorizing grant/policy, recipe
operation/digest and expanded parameters, and the complete pinned template
snapshot. Approval rendering shows the job and its credential/mint plan. Every
required parent approval binds the same job digest and job parameters through
§10.4; all must be admitted for this one run. There is no second agent-visible
request in which the caller chooses the mint's parameters.

For each slot requiring approval, use §10.4's existing `run_job` request with
that slot's source secret/version, parent run grant/policy and delivery mode;
the shared job digest and typed job parameters bind its complete recipe.
Persist its association with this run and slot. Admit all required approvals
atomically with the run intent; internal mints reference that admission rather
than consuming an approval again under a different dispatch ID. The plan and
template snapshots are retained with the frozen request for rendering; neither
a live job edit nor a live template lookup can change what the approver sees.

secrets dispatches each mint through the broker's existing admission, network,
custody and recording path, applying the selected operation and §8.4's template
snapshot/hash, recording fence, expiry, lineage, containment, approver coverage
and inherited rate limits. Internal mint authority is the recorded parent run
grant. The template must match the same requester, and its policy is an
additional restriction, including its time/rate constraints and listed
approvers. If the parent secret or either policy requires approval, this slot
requires approval before minting. Choose an approver eligible under both
the parent's run policy and that template policy before minting; an empty
intersection refuses with `no_eligible_approver`. A template never supplies a
different principal's authority to release this run's credential.

**Run-bound children.** The ordinary atomic capture still creates the child,
sealed value, copied template grant, result and paired child/grant receipt
(§8.4, §11.5). In that same transaction, add an immutable server-managed binding
to the run dispatch ID, credential-slot ordinal, mint dispatch ID and issuing
parent run grant ID. These fields are not job/1, secret/1 or agent inputs.
The copied grant and its template pin remain intact; the binding restricts
their use further. In particular:

- The child can be released only to the originally selected runner through
  that original run's parent-grant fence. It cannot be independently admitted
  for a broker request or another run, regranted, or used as an issuer for
  another derivation. Broker/derivation attempts refuse with
  `operation_not_allowed`, independent runs with `job_not_allowed`, and regrant
  changes with `change_kind_not_applicable`, even if a copied template allowance
  would otherwise match. No new grant shape is added.
- The template need not pin the invoking job: its copied allowances confer no
  independent use of this run-bound child. The parent run grant supplies the
  exact job pin, and the job supplies the mint operation pin, so these digest
  dependencies have no cycle.
- The run binding survives containment and re-enable, and cannot be cleared or
  retargeted. Re-enabling never makes a run-bound child independently usable.
  Revoking the recorded issuing run grant disables its children in the same
  transaction, exactly as §8.4 requires.
- Persist a unique mapping from `(run dispatch, slot ordinal)` to its mint
  dispatch and resulting child/grant. Replay returns that same child. An
  outcome-unknown mint goes through reconciliation before any new mint; a
  later claim, retry or expired child does not silently mint a replacement.
  A new run needs new admission and any required approvals.

Missing, invalid or past upstream expiry refuses child creation. The child's
deadline is recorded once using §8.4's immutable dispatch-start anchor, default
3600-second deployment cap, upstream expiry and every ancestor expiry. The job
cannot extend it. Recheck the full lineage, all issuing grants, parent versions,
policies, approvals and CURRENT operation/job pins before releasing any slot,
using §8.4's lock order. An expired or contained child prevents release; there
is no fallback to a durable value. Assignment expiry is no later than any
delivered child's effective expiry and the runner protocol's existing bound.
If another slot fails after a mint, the already-created child stays run-bound
and expires normally; it grants no partial runner release.

**Slot substitution on the wire.** The signed assignment's `credentials` array
has exactly the job's slot count and order. At index `i`, `secret_ref` is the
actual delivered ref: the recorded run-bound child for a `short_lived` slot,
or the selected secret for a `durable` slot. The runner maps this element to
`job.credentials[i].secret_ref`, the stable environment label. It must not
compare a fresh child ref for equality with the parent's label, search by an
untrusted ref, or accept missing/extra slots. The existing assignment
signature binds `job_digest`, `dispatch_id` and the hash of the complete
ordered sealed-credential array; its per-item `{secret_ref, sealed}` shape is
unchanged; reordering without a new signature fails that commitment. secrets
validates the recorded substitution and lineage before signing; the runner
trusts that signed assignment for the substitution, while
independently enforcing its local job pin. Values are HPKE-sealed only to the
selected runner. Both the internal mint and the run have their own operational
and hook records; the mint's receipt retains the real `derived_grant_id`.

**Ordinary derived children outside a run.** These remain supported (decision
80): a child issued through an ordinary broker request has no run binding and
needs its **own** explicit `run` grant/template pin for any job. Such a grant
does not inherit the parent's permission. A durable-delivery job slot may name
that child directly, or its fixed ancestor when the requested child's recorded
lineage proves the relationship. Only the slot matching the run request's
selected secret accepts this descendant substitution; other slots retain their
fixed selectors. The same actual-ref/ordinal assignment rule applies. The job
is still the installation CURRENT definition, its digest must match the child's
grant and the runner's local pin, and its durable-delivery confirmation is
required. A pre-existing job with no internal mint recipe can therefore be
pinned by an ordinary issuer's template without a digest cycle. This path
never accepts a run-bound child or borrows an ancestor grant.

`delivery: durable` sends the durable value. It needs a passkey-confirmed
per-job flag, and the console and events label it as reduced protection.

Either way the claim is the same: a smaller blast radius, not confidentiality. The
job's process has the credential (secrets SOT §4).

### 9.6 Output

The runner returns the exit code and bounded stdout and stderr. It applies
known-value redaction locally (it knows what it was given) and credential-shape
detection. secrets applies both again, then the job's output projection. Withheld
output follows §7.6.

## 10. approve_only on the joint approval primitive

### 10.1 The primitive

secrets builds on the shared approval primitive (B2) and WebAuthn verifier (B3)
in `aweb_naapp`, under construction as aweb-acgh.4 against the record the D1 lead
merged into D1 C2/C4. This design does not re-specify them. B2 and B3 already
provide the following:

- the frozen canonical request and its `request_sha256`;
- single-use admission by atomic compare-and-set;
- hashed, expiring, revocable link tokens bound to the request digest;
- the per-policy minimum assurance;
- the rule that the requester never receives a token and never controls the
  approver or the delivery;
- reconciliation before re-dispatch, with a fresh approval for a new dispatch;
- the passkey ceremony on the app's own origin;
- owner designation, enrolment to the registered contact, and recovery by
  re-designation;
- an audit-event interface.

secrets supplies these:

| B2 record field | secrets' value |
| --- | --- |
| immutable request ref | the stored frozen `aweb.secrets.use-approval/1` bytes (§10.4), or `aweb.secrets.change/1` for a widening change (§6.3) |
| `policy_ref`/version | for a use, `secrets.use\|<installation_id>\|<team_id>\|<grant_id>\|<policy_digest>`, version 1 (§4.4; decision 63) |
| `requested_by` | the verified principal (§4.1) |
| `approver_subject`/type | the approver ID; the approver type is passkey, which every secrets action policy declares as its minimum assurance |
| presentation kind/ref | the secrets console approval page; `task_answer_ref` is unused unless Q13 adds a task presentation |
| `expires_at` | `approval_ttl_s` from the policy |
| `consumed_operation_id` | the `dispatch_id` (§11) |
| audit-event interface | the producer outbox (§11.5), so that every designation, enrolment, recovery and decision is a hook event |

For a use approval, `PolicySource.current(ref)` returns the policy only while
that grant is active and still references that digest. Otherwise it returns
`None`, and B2 voids the approval. The dispatch fence still re-reads the grant
and policy digest under a row lock (§11.3).

The secrets SOT §13 described the approval link as the authority. Under §14 and
the joint recommendation, **the link is only a locator**. The authority is a B3
passkey assertion bound to the request hash. That replaces the bearer-link model,
which proves only possession.

**Two requirements for B2 from secrets**, sent to aweb-acgh.4:

- **(a)** Admission must run inside the caller's database transaction, so that
  the compare-and-set, secrets' intent row and its outbox rows commit or fail
  together (§10.5).
- **(b)** It must offer `revoke_many(connection, approval_ids, reason)` for
  containment (§12). secrets selects the IDs with its own predicate (a grant, a
  secret or a version) in the same transaction, and B2 never interprets app
  predicates. Only `pending` and `approved` approvals move to `revoked`;
  `consumed` ones are never touched. Each revocation is audited, and the dispatch
  fence (§11.3) still re-checks.

Under the primitive's states, an approved approval goes to `consumed`, `expired`
or `revoked`, and a revocation before dispatch wins. A `not_sent` transport
retry under the same `dispatch_id` (§11.1) is a retry of the one admitted
operation. It does not consume again, and it needs no new approval. D1 has
adopted this outcome vocabulary.

### 10.2 What secrets adds to designation, enrolment and recovery

- **Who designates.** An owner, through a widening change confirmed by passkey
  (§6.3). An approver record covers chosen secrets or groups, and may link to a
  member principal.
- **Bootstrap and re-designation need the team owner act, not install
  authority.** Install authority can belong to any certified member today, and
  so possibly to an agent. Designating the first owner-approver, and
  re-designating owners after a lockout, therefore take the team owner act
  `aweb.owner-act/1` defined by the hooks design (aweb-acgh.1, audit-substrate
  §A3): a statement signed by the current AWID team key, single-use and
  short-lived. Bootstrap uses its `app-role.designate` act with the
  owner-approver role. Recovery after a lockout uses `app-credential.recover`,
  and `app-role.revoke` removes an owner. The subject commits to the contact by
  hash, without carrying it.
  - For BYOT the owner signs it locally with `aw`.
  - Where a custodial deployment holds the controller key, it signs only after a
    fresh, interactive step-up by the human owner. That requirement on custodial
    deployments is stated in §17.
  - A member or admin signature is refused with `owner_required`.

  This act is the installation's root of trust (boundary T11). Enrolment then
  follows B3, with trust on first use stated honestly.
- **Owner lockout is protected (mandatory).** Revoking an owner's passkey or
  contact through team-auth alone, the narrowing path in §12, is refused if it
  would leave no owner with an enrolled passkey and a verified contact
  (`last_owner_protected`). The last owner's passkey or contact can be changed
  only on the console with that owner's own passkey, or by re-designation.
  Re-designation after a lockout has a mandatory 72 h cooling-off period.
  During it, `approve_only` uses and widening changes are frozen, and every
  owner and approver contact recorded before the lockout is notified. A contact
  change takes effect after 24 h and is notified to both the old and the new
  contact. These rules are generic and proposed for B3 (aweb-acgh.4), because
  pages' passkey approvals face the same takeover path.
- **Self-approval** follows the policy in §4.4 (Q7). Here is what the rule can
  and cannot protect. A passkey assertion already proves that a human with an
  enrolled authenticator decided, not the agent. A distinct-approver rule adds
  separation between the *requesting human* and the *approving human*. It
  cannot separate a human from their own agent: a hosted human's MCP agent signs
  as that human's custodial member, so the request and the approval come from
  the same principal. Secrets compares the approver's linked principal with the
  requesting principal. Under L2 that comparison therefore tests the human, not
  the agent.

### 10.3 Flow

```mermaid
sequenceDiagram
  participant Ag as Agent (aw or L2)
  participant S as secrets API
  participant C as secrets console
  participant H as Approver
  participant U as Upstream
  Ag->>S: request (request_id, secret_ref, operation, params)
  S->>S: verify, grant, policy; freeze canonical request; approval=pending; outbox(approval.requested)
  S-->>Ag: 202 {state: awaiting_approval, approval_ref}
  S->>H: notification to registered contact (locator link, no request details)
  H->>C: open link, passkey login
  C->>C: render frozen request from frozen bytes
  H->>C: approve: B3 passkey assertion bound to request_sha256
  C->>S: B3 verifies; B2 records the decision; outbox(approval.decided)
  Ag->>S: status(approval_ref)
  S-->>Ag: {state: approved, next: re-submit request_id}
  Ag->>S: re-submit same request_id
  S->>S: B2 admission CAS + intent row + outbox, in one transaction
  S->>U: dispatch (§11)
  S-->>Ag: result (§7.6)
```

`secrets.status` only reports the decision; it never admits or dispatches. An
approved status is `{state: "approved", next: "re-submit request_id"}`. Only
re-submitting `secrets.request` or `secrets.run` with the same `request_id` can
admit the frozen request and dispatch it. Re-submission is idempotent. A consumed
approval cannot authorize another dispatch. A denial or expiry is final for that
`request_id`.

### 10.4 The frozen canonical request

`aweb.secrets.use-approval/1` is the typed request object secrets hands B2 to
freeze. It carries `type` (`aweb.secrets.use-approval`) and `v` (1) inside. B2
covers it under its single prefix: the approval binds
`"aweb.approval-request/1\n" || canonical_json({policy, request})`, with B2's
canonical-bytes rules (integers only, so amounts are integer minor units). It
contains:

```text
v, type, installation_id, install_generation, team_id,
requester: {principal, member_did_key, certificate_id, did_aw?, alias},
secret: {secret_id, secret_ref, version, kind, backend},
action: broker | run_job,
broker: {operation_id, operation_digest, params}  |  {method, canonical_url, header_names, body_sha256, body_preview}
run_job: {runner_id, job_id, job_digest, params, credential_delivery},
policy_digest, grant_id, request_id, reason (untrusted, bounded),
issued_at, expires_at
```

- **No approval id inside.** B2 mints the approval id after it freezes and hashes
  the request, so the request cannot carry it. B2's record binds the two
  (`request_sha256` with `approval_id`), admission compares the hash, and the
  hook event takes `approval_id` from that record. `request_id` is secrets'
  re-submission key.
- **Shape.** `requester.principal` is `did_aw` when the certificate carries
  `member_did_aw`, otherwise `member_did_key` (§4.1); `did_aw` is omitted, never
  null, when absent. Exactly one of `broker` and `run_job` is present, named by
  `action`. `naapp/secrets/vectors/use-approval-v1.json` freezes the fields and
  bytes, and its test checks them against B2's real mint.

- **Evidence.** B3 binds the assertion to the request hash. secrets keeps B2's
  `auth_evidence_ref` and puts the hash of the evidence in the hook event
  (§11.5). That lets a reviewer holding the approver's public key check the
  approval later.
- **What the console renders.** The console renders from the frozen bytes, not
  from live records. It shows:
  - the secret ref and kind, never the value;
  - the method and the full canonical URL with the host emphasized, or the
    operation and its typed parameters, or the job and its parameters;
  - the requester's alias and DID;
  - the policy, and the times.
- **The requester's reason.** It is shown in a box labelled as unverified text
  from the requesting agent. It is escaped and cannot be styled. Its maximum
  is 1024 Unicode code points; a longer reason is refused with `params_invalid`,
  never truncated.
- **Open requests.** They are approvable only when the body is UTF-8 JSON or text
  of 64 KiB or less, rendered in full. Anything else is refused with
  `approval_unrenderable`, because consent to unseen bytes is not informed.
- **Version binding.** The approval binds the secret **version**. Replacing the
  value voids pending and approved-but-unconsumed approvals.

### 10.5 Single-use admission

secrets calls B2's admission with the approval ID, the frozen `request_sha256`
and `consumed_operation_id = dispatch_id`. It makes that call inside its own
transaction, which also inserts the intent row and the outbox rows; this is
requirement (a) in §10.1. A refused compare-and-set rolls the whole transaction
back. B2's concurrency guarantee then yields exactly one dispatch per approval.

## 11. Dispatch state machine

### 11.1 States

```text
received ─┬─> refused (terminal)
          ├─> awaiting_approval ─┬─> approval_denied | approval_expired | cancelled (terminal)
          │                      └─> admitted
          └─> admitted ──> dispatching ─┬─> completed            (definite upstream response or job exit)
                                        ├─> not_sent             (definite: failed before any request byte left)
                                        └─> outcome_unknown ──> reconciled_completed | reconciled_failed
                                                               | reconciled_unknown (owner-closed)
```

- **`admitted`.** The approval is consumed (if any), the rate counters are
  charged, and the intent row and outbox rows are committed together. This is the
  durable intent.
- **`dispatching`.** It is committed **before** the first byte is sent, or before
  the job assignment is released to the runner.
- **`completed`.** It records the upstream status (2xx through 5xx), the
  disposition (§7.6), the response hash and the counts. For an HTTP request
  `completed` means "a response was received", not that the operation succeeded.
- **`not_sent`.** This is for a DNS or egress-guard refusal, a connection refused,
  or a TLS handshake failure before the request was written. Under the same
  intent it may be retried automatically while the approval's `expires_at` holds,
  or, without an approval, within the request's total time bound (§7.3). Nothing
  reached the upstream.
- **`outcome_unknown`.** This covers a timeout after bytes were written, a reset
  mid-exchange, a lost runner after `started`, or a process crash, which the
  sweeper detects as a stale `dispatching` row.
  - **Sweeper threshold.** The sweeper's threshold exceeds the maximum total
    dispatch time (§7.3; the job timeout for runners) plus a margin, so a
    dispatch that is still running is never swept.
  - **Late results.** `completed` and `not_sent` are compare-and-set transitions
    from `dispatching` only. A response or job result that arrives after the
    sweeper has written `outcome_unknown` does not overwrite it. It is kept as
    reconciliation evidence and resolves the state through §11.4.

### 11.2 Idempotency

- **Client key.** The key is `(installation_id, principal, request_id)` with the
  canonical request hash. The same bytes return the existing receipt at its
  current state, after rechecking current read permission. Different bytes
  return `409 idempotency_conflict`. The key store is the shared one (§3.1), with
  D1's semantics and a retention period set per app. secrets keeps keys for 30
  days. After that they return
  `410 idempotency_expired`; they never re-execute.
- **Upstream key.** Where the operation declares one, secrets sends
  `Idempotency-Key: secrets-<dispatch_id>` (the header name comes from the operation).
  A transport retry of a `not_sent` dispatch reuses it, so the upstream can
  deduplicate.

### 11.3 The dispatch fence

The transition to `dispatching` re-reads the following under a row lock in the
same transaction:

- the grant, the policy digest, the secret state and version;
- installation status and generation;
- runner registration;
- whether the approval has been revoked.

An installation generation that has changed since admission means the request
was admitted under a superseded generation, so the fence refuses it with
`generation_superseded`, as admission does (§4.1). `installation_disabled` is
for an installation that is inactive or uninstalled.

A revocation that commits before this point stops the dispatch (§12). After this
point it cannot recall bytes already sent, and the record says so.

### 11.4 Reconciliation before retry

- If the operation declares a `reconcile` lookup, secrets runs it as a brokered
  dispatch of its own, recorded and linked, and resolves to
  `reconciled_completed` or `reconciled_failed`.
- Otherwise the console asks an owner or approver to resolve it, and the agent
  sees `outcome_unknown` together with an opaque `reconcile_ref`.
- **Retry block.** While a principal has an unreconciled `outcome_unknown` on
  `(secret, operation)` (or the canonical method and URL for open requests), new
  requests from that principal for the same pair are refused with
  `reconciliation_pending`. The exception is operations declared
  `side_effect: none`. This is how "reconcile before retry" is enforced. secrets
  cannot tell a retry from a new request, so it blocks the pair.
- **In flight.** While a principal has a dispatch of the same pair in
  `dispatching`, a new request for that pair is refused at admission and at the
  fence with `dispatch_in_flight`, under the same `side_effect: none`
  exception. Unlike `reconciliation_pending`, it clears by itself when that
  dispatch reaches `completed` or `not_sent`. If it becomes `outcome_unknown`
  instead, the retry block above applies.
- A new dispatch after reconciliation is a new intent. Under `approve_only` it
  needs a **fresh approval**, per the joint recommendation.

### 11.5 Operational record and the post-secret-use-hook outbox

secrets' DB is its own operational record of every request, approval, intent,
dispatch and result (secrets SOT §12). The audit record lives in logs (audit-logs
SOT §2), reached through the hook.

**The enqueue rule. This is secrets' contract, and it fails closed.**

- Each state transition that must be audited writes its hook event row into
  secrets' outbox **in the same DB transaction as the transition**.
- If the outbox insert fails, the transition does not commit. The request is
  refused or stays in its previous state, and nothing is dispatched.
- A dispatch therefore never happens without durably enqueued `admitted` and
  `dispatching` events.
- **No active target.** secrets resolves targets through aweb-acgh.7, using the
  hooks design's freshness bound of 60 s at most. The rule counts only a
  registration whose `active_from` is at or before the event's `occurred_at`.
  If no registration for `post-secret-use-hook` is active for the team in that
  sense, secrets refuses every use with `audit_target_unavailable`. A
  registration still inside its activation pad therefore does not let a use
  through with zero deliveries. The recommended default is that owners cannot
  turn this off (Q11, decided).
- **Backlog bound.** secrets refuses new admissions with
  `audit_delivery_stalled` when **no** active `post-secret-use-hook`
  registration is current, meaning its oldest undelivered event is older than
  a threshold (recommended 1 h, Q11). A stalled secondary target, such as a
  self-hosted copy during a migration, does not block use while another active
  registration is current. It is surfaced to owners on the console. This keeps
  "every use is recorded" true in practice, not only eventually.
- **Cancelled or rejected deliveries are a fault.** An audit-critical event can
  end with every delivery cancelled (for example, its target was revoked between
  commit and drain) or rejected. secrets records that as a fault in its
  operational record and surfaces it to owners. It is never treated as
  delivered.

The drainer delivers at least once. As the hooks design specifies, `event_id` is
minted once inside the effecting transaction and stored with the outbox row, and
retries never re-mint it. The hooks seat owns delivery, retry, the signature
envelope and target registration.

**Schema.** The hooks design owns the `post-secret-use-hook` schema: one action
enum, one flat allowlisted payload and the `refusal_code` enum. They are defined
in aweb-acgh.1, `docs/design/audit-substrate.md` §A2 (at hooks head 1b40a1d44, or
as merged), and recorded in the hook catalog vector that H1 freezes.
This design cites that schema and does not define its own. The actor comes from
the common envelope. secrets' part is deciding which transition emits which
action:

| secrets transition (§11.1) | hook `action` |
| --- | --- |
| refusal at admission or at the fence | `refused`, with `refusal_code` |
| `awaiting_approval` | `approval_requested` |
| approval decided (approve, deny, expire, revoke) | `approval_decided`, with `approval_evidence_sha256` when a passkey decided |
| `cancelled`: the requester withdraws, or containment revokes the pending approval through B2 | `approval_decided`, with `approval_decision: revoked` |
| `admitted` | `admitted` |
| `dispatching`, enqueued in the fence transaction before any byte is sent | `dispatching` |
| `completed`, including a withheld result or an undeclared credential | `completed`, with `disposition`, `returned_hmac`, and `undeclared_credential: true` (with disposition `withheld`) when §8.3 detects an undeclared credential |
| `not_sent` | `not_sent` |
| `outcome_unknown` | `outcome_unknown` |
| `reconciled_*` | `reconciled` |

`naapp/secrets/vectors/hook-actions-v1.json` freezes this table and the
governance table below as data, with an example event per row that the catalog
validates. S13's tests read it.

secrets fills every field of the §A2 allowlist that applies to the event. The
list below highlights fields with secrets-specific rules and is not exhaustive:
the `secret_*`, `request_sha256`/`params_sha256`, `approval_*`, `dispatch_*` and
`upstream_*` fields are filled as §A2 defines them.

- **Broker target.** `target_method`, `target_host`, `target_port` and
  `target_path_template`, plus `operation_id` and `operation_digest` for a named
  operation. Concrete paths and query values are never sent. A runner job sends
  `runner_id`, `job_id` and `job_digest` instead.
- **Child creation.** The issuance's `completed` event with disposition
  `stored_as_secret` is the signed creation receipt. `grant_id` remains the
  issuing grant; `derived_secret_id` names the new child and `derived_grant_id`
  names its fresh grant. It shares the recording transaction with those rows
  (§8.4), so no child is exposed without its enqueued creation receipt. The
  hook-contract owner puts `derived_grant_id` in the re-frozen post-secret-use
  shape (decision 73 delta): both derived refs are required together for this
  disposition and forbidden elsewhere. This is an in-place schema/vector
  re-freeze: no deployed producer or consumer uses this hook, so there is no
  parallel catalog version. Until that shape is accepted, the kit, ingest and
  resolution support it, and an owner activates the production,
  `store_as_secret` cannot emit or activate; secrets does not add private fields
  to an existing envelope.
- **`returned_hmac`.** This is an HMAC, keyed by secrets, over the bytes returned
  to the agent. It is absent when the result is withheld. secrets' keyed HMAC of
  the raw response fills `upstream_response_hmac`.
- **`refusal_code`.** It takes values from the §A2 enum. secrets proposed every
  code there, and each one is a refusal this design defines.
  `no_eligible_approver` means no covering, policy-listed approver exists at
  request time (§4.4). `approval_consumed` means the approval was already
  consumed under another dispatch; an idempotent replay of the same dispatch
  returns its existing state. Both codes are in the v1 catalog and secrets
  hook-actions table before any producer emits them.
- **`disposition`.** It takes `returned`, `withheld` or `stored_as_secret`
  (§A2 at hooks head 31206a4d). There is no value for a returned credential,
  because `return` does not exist (Q8).

**Governance acts** go on the generic `post-governance-hook` (audit-substrate §A2).
The catalog fixes its act enum and fixes each act's direction:

| secrets act | hook `act` |
| --- | --- |
| owner and approver designation and revocation (B3's audit interface) | `role.designated`, `role.revoked` |
| passkey and contact enrolment, recovery and revocation | `credential.enrolled`, `credential.recovered`, `credential.revoked` |
| grant lifecycle | `grant.created`, `grant.changed`, `grant.revoked` |
| secret, destination, operation and job lifecycle | `resource.created`, `resource.version_added`, `resource.replaced`, `resource.disabled`, `resource.enabled` |
| policy changes | `policy.changed` |
| runners | `runner.registered`, `runner.deregistered` |
| kill switch | `installation.disabled`, `installation.enabled` |

How audit availability applies to governance acts:

- **Widening acts are audit-critical.** One that cannot enqueue does not commit,
  and it is refused, like a use, when no audit target is active.
- **Narrowing acts are never gated.** That covers every containment act in §12.
  Each is enqueued in its own transaction. A containment act is **never**
  refused for `audit_target_unavailable` or `audit_delivery_stalled`; it fails
  only if its own local commit fails. Containment does not wait on logs.

secrets fills `authority` with one of:

- `owner_act`, with `owner_act_sha256`;
- `passkey_session`, with `approval_evidence_sha256`;
- `team_cert`, for narrowing acts through the agent API.

**One effect, one hook.** A secrets tool call fires only its specific hook:
`post-secret-use-hook` for a use, `post-governance-hook` for a governance act. It
never also fires `post-manifest-command-hook`.

**Provenance and production.** secrets declares `post-secret-use-hook`, and the
governance hook, in its manifest v2 `hooks.productions`. An owner must activate
each production; until then, ingest refuses secrets' events. The signing key is
declared in v2 `app_keys`, with explicit purposes for the hook events the hooks
seat defines. A v1 emitter key stays emit-only.

## 12. Containment from day one

Every containment action **narrows** authority. It can therefore be done:

- by any owner through the agent API or `aw`, with team-auth and no passkey;
- by an owner or approver through the console;
- for an approval request, by its approver.

Narrowing must never wait on a ceremony, and never on logs. Each action is
recorded as a `post-governance-hook` event. It is never refused for audit
availability, only for a failed local commit (§11.5).

| Action | Effect |
| --- | --- |
| **Revoke a grant** | Admission refuses at once. The dispatch fence (§11.3) stops admitted, not-yet-sent intents (`refused: grant_revoked`). The same transaction disables children issued under that grant and their descendants, and voids affected unconsumed approvals (§8.4); the parent and children issued under other grants stay usable. |
| **Revoke approvals** | A pending or approved-but-unconsumed approval moves to `revoked`. The consume CAS fails. There is no bearer token to chase, because the link was never authority. |
| **Disable a secret** | New admissions, the fence and runner credential release all refuse. Pending approvals are voided, and the cached OAuth tokens and derived secrets are disabled. For 1Password, the console also links to revoking the service account. Re-enabling is widening, so it needs a passkey. |
| **Disable the installation** (kill switch) | Every secret is disabled at once, through one flag checked at admission and at the fence. |
| **Replace a value** (§6.2) | The new version activates. The old version is destroyed in the live database in the same transaction (backups per §15, item 5). Version-bound approvals are voided. All descendants are disabled locally and their pending approvals voided (§8.4); derived and cached credentials are also revoked where the upstream allows it. STS sessions cannot be revoked one by one, so the console guides the owner to the IAM "revoke older sessions" action. Upstream rotation remains the owner's act. |
| **Deregister a runner** | The key is invalidated, unclaimed assignments are cancelled, and claimed ones go to `outcome_unknown`. |
| **Revoke an approver passkey or contact** | That approver's pending decisions are voided. If no approver can decide anymore, `approve_only` uses refuse. Through team-auth, revoking the last owner's passkey or contact is refused (`last_owner_protected`, §10.2). |

Installation uninstall (D1 §5) fences all normal calls. Deletion of secrets data
follows D1's lifecycle jobs, with every native version destroyed as §5.2 describes.

## 13. Manifest v2 tool surface

### 13.1 Tools

The manifest is v2 (D1 C3). Every tool is signed with team-auth. Nothing is
`auth: none`. `invocation_contexts` uses D1's values `agent`, `surface` and
`hook`. secrets registers on no hook. It is a hook producer, not a target.

| Tool | Contexts | Scope | Role | Purpose |
| --- | --- | --- | --- | --- |
| `secrets.list` | agent, surface | `secrets:read` | any member with a grant; owners see all | refs, kinds, sensitivity, destination summary, approval requirement; **never values** |
| `secrets.describe` | agent, surface | `secrets:read` | as above | one ref's operations (with parameter schemas) and jobs available to the caller |
| `secrets.request` | agent, surface | `secrets:use` | a grant | a brokered named operation or open request (§7). Returns the result, or `awaiting_approval` with an `approval_ref` |
| `secrets.run` | agent, surface | `secrets:run` | a grant | a runner job (§9) |
| `secrets.status` | agent, surface | `secrets:read` | the requester; owners | state of a `request_id`, `approval_ref` or `reconcile_ref`; never a link, admission or dispatch. Approved: re-submit the same `request_id` (§10.3) |
| `secrets.cancel` | agent, surface | `secrets:use` | the requester | cancel the caller's own request while it is still before `admitted` |
| `secrets.contain` | agent, surface | `secrets:admin` | owner (approver for its own approvals) | revoke a grant, revoke approvals, disable a secret or the installation, deregister a runner (§12) |
| `secrets.propose-change` | surface | `secrets:admin` | owner | draft a widening change: secret metadata, destination, operation, job, grant, role or approver. It is inert until passkey confirmation on the console (§6.3) |
| `secrets.activity` | surface | `secrets:read` | owner | operational record view: requests, approvals, dispatch states, `outcome_unknown` queue |

There is **no** value tool in any context: no `get-value`, no `set-value`, no
`export` (secrets SOT §6, §8 item 4). Value ingress and every confirmation happen
on the console (§6).

`invocation_contexts` decides where a host *exposes* a tool. It does not
authorize. A member who signs a request directly reaches the endpoint anyway.
Authority always comes from secrets' role, grant and passkey checks. That is why
`propose-change` stays inert without a passkey.

### 13.2 How it looks to users

- **aw users.** The generic dispatcher renders the tools as `aw secrets list`,
  `aw secrets describe stripe-test`, and
  `aw secrets request stripe-test --op create-refund --param charge=ch_123 --param amount_minor=500`.
  For an open request it renders the typed body parameters as flags, for example
  `aw secrets request github-ci --method POST --url https://api.github.com/repos/o/r/dispatches --data '{…}'`.
  A curl-like positional form would be a generic CLI feature; it is not part of
  the manifest contract.
  It also renders `aw secrets run deploy-staging --runner home-1 --param env=staging`,
  `aw secrets status <request_id>` and `aw secrets contain revoke-grant <grant_id>`.
  The CLI generates `request_id` once per invocation and reuses it on transport
  retries. After polling approval status, it re-submits the original request
  with that same `request_id` to dispatch. Exit codes distinguish
  `awaiting_approval`, `refused`,
  `outcome_unknown` and `result_withheld`. `--param` binding follows the manifest
  `params` mapping. Open requests need no manifest change. `method` (a string
  enum), `url`, `headers` (an array) and `data` (a string or an object) are
  `in: body` parameters with typed coercion (A `docs/app-manifest.md:121`–`:150`,
  `:189`–`:205`). Binary data uses base64. The manifest's relative-path rule
  protects secrets' own endpoint, not the URL argument. SSRF control for the URL
  stays at the egress guard (§7.3).
- **MCP users (L2).** The same tools appear as `secrets_list`,
  `secrets_request`, and so on, with the same parameter schemas. A pending
  approval returns `approval_ref` and a message that a designated human has been
  notified. The model polls `secrets_status`, then re-submits `secrets_request`
  (or `secrets_run`) with the same `request_id` after approval. It cannot see or
  act on the approval. Responses are already projected and redacted for the model
  provider's context.
- **Dashboard surface.** This is an `aweb.page/1` surface with read-only views
  (`list`, `activity`), containment buttons, `propose-change` forms, and a
  link-out to the console for confirmation and value ingress. The link-out widget
  is a D1 dependency (§17).

### 13.3 `aw do` and a generic alias

There is no built-in `aw do`. Every capability is a manifest verb
(`aw secrets …`, and the same tools through MCP). If short spelling
matters, one option is a **generic** v2 manifest field `cli_aliases`, for example
`{"do": "secrets request"}`, offered by any app. It would be activated only by a
local user opt-in recorded in the identity's app approvals, and refused if it
collides with a built-in or another alias. This is generic aw-core work. The
recommendation is to **not** add it at launch (YAGNI; `aw secrets request` is
clear) and to revisit it if users ask (Q12).

### 13.4 `--unsafe-inject` does not exist

Injecting a value into a process the agent chooses is a value read under another
name (secrets SOT §1). Offering it through an agent-context tool would contradict
"no get-value, ever". Offering it to MCP agents would put the value into the
model provider's context and into the hosting operator in transit. Legacy local tools have two
better paths:

- a pinned runner job with `delivery: short_lived` (§9.5);
- a `store_as_secret` derived credential used through the broker.

Q8 decided that neither `--unsafe-inject` nor `result_handling: return` exists.

## 14. Threat model and the defensible claim

### 14.1 Trust boundaries

| ID | Party | Trusted for | Not trusted for, and what it means |
| --- | --- | --- | --- |
| T1 | Requesting agent, including a prompt-injected one | nothing beyond its grants | It may use every grant it holds, within policy. secrets limits *what* it can do, not *why*. |
| T2 | Model provider (MCP) | nothing | Responses enter its context. Hence projection, redaction and default-deny (§7.6). |
| T3 | Custodial deployment and its L2 endpoint | custody of its custodial members' keys | It can sign as those members and so exercise their grants. It sees their parameters and responses in transit. It cannot read values, approve, widen policy or reach the console. **Consequence: an MCP agent's grants are only as strong as the operator's custody.** Grant MCP-used principals narrowly. Until §4.6 exists, secrets cannot require "not via the custodial host". |
| T4 | secrets service and its production operators | executing policy; transient plaintext | An operator able to run code as the service, with KMS decrypt or the 1Password token, can read values. Mitigations: KMS policy, KMS and 1Password independent logs, Make-only operations (§15). Not zero-knowledge. |
| T5 | KMS provider | key custody | as for any KMS user |
| T6 | 1Password | custody for that backend | the vault's own model |
| T7 | Upstream API | receiving the credential it issued | obviously |
| T8 | Runner host and its OS user | running pinned jobs; holding job credentials | Same-user agents or a writable config defeat it. Documented, partly detected by `doctor`. |
| T9 | Approver, authenticator and contact channel | decisions; enrolment and recovery delivery | A passkey proves an enrolled authenticator, not a named human or humanity. A compromised contact mailbox plus an owner-initiated enrolment can add an authenticator, hence notifications and delays. |
| T10 | AWID and team controller | membership and keys | A controller can certify new keys. New principals get nothing without grants, but a controller who re-certifies an existing `did:aw` inherits its grants. |
| T11 | Team controller (owner act) | designating the first owner and re-designating after a lockout (§10.2) | It is the root of trust for the installation's policy. Install or admin authority alone cannot bootstrap or recover secrets. A custodial deployment holding the controller key signs owner acts only after fresh interactive step-up. |
| T12 | Hook targets (logs) | storing redacted events | They receive metadata, hashes and identifiers, never values. |
| T13 | Network path and DNS | nothing | TLS verification, address checks and connection pinning (§7.3) |

### 14.2 The defensible claim

This follows the secrets SOT §14, final paragraph. Each brokered use or runner job
is:

- admitted only for a verified member principal holding a matching grant, under
  a recorded policy;
- for `approve_only`, decided by an enrolled approver's passkey over the frozen
  request it then dispatched, consumed at most once;
- recorded as durable intent and outcome in secrets' own store, with a signed
  hook event durably enqueued before any dispatch;

all under T1–T13.

**This design does not claim:**

- that nothing derived from a credential can ever end up with an agent;
- that redaction proves confidentiality;
- that a passkey identifies a natural person;
- that an MCP agent's use is distinguishable from the custodial host acting as that member;
- that an upstream side effect is exactly-once;
- that runner jobs are confidential from the runner host;
- replay protection beyond `request_id` deduplication.

It also does not claim audit completeness for credentials the agent can reach by
other means. The guarantee holds only where secrets is the sole path to the
credential (secrets SOT §8, item 5).

## 15. Deploy

secrets follows Library's pattern (A `naapp/library`):

- **Service layout.** Its own service, database (pgdbm, its own schema, ordered
  migrations only) and Dockerfile.
- **Health.** The health endpoint reports build identity, including the full
  40-character commit, as Library's `build_identity.py` does. It also reports
  dependency status: DB, KMS (a cached result of an encrypt/decrypt canary under
  a dedicated non-secret context), and the oldest undelivered outbox age.
- **Ops manifest.** `ops/render-production.json`, or the hosting provider's
  equivalent, pins the topology fail-closed.
- **Production operations** are Make-only (`prod-status`, `prod-deploy`,
  `prod-wait`, `prod-verify`, `prod-rollback`, `prod-public-identity`), backed by
  checked-in scripts with tests. The app's production-operations document
  describes them, along with the release record Library requires.

Requirements specific to secrets:

1. **KMS is a dependency.** The service fails readiness and refuses all
   admissions when KMS is unavailable. The KMS provider and key are deployment
   facts recorded with the operator (Q2). The service authenticates to KMS
   through workload identity where the platform supports it. Otherwise it uses a
   narrowly scoped static credential held only in the platform's secret store,
   which is a T4 element.
2. **Service signing key.** The key that signs hook provenance and runner
   assignments is a KMS asymmetric key if the provider supports Ed25519 signing.
   Otherwise it is generated at deploy, sealed under KMS and unsealed at start.
   The public key is published in the manifest's registered app keys.
3. **Two origins.** The agent API origin accepts only team-auth and the runner
   protocol, and serves no cookies.
   - **RP ID.** The WebAuthn RP ID is the **exact console host**. It is never a
     registrable parent domain shared with origins that serve agent-authored
     content, such as pages, so a sibling origin cannot request assertions for
     the console's RP.
   - **Cookies.** The console cookie is host-only (`__Host-`), with no `Domain`
     attribute.
   - **Headers.** The console serves strict CSP, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`
   and `Cache-Control: no-store`, and accepts no team-auth.
4. **Hardening.** Core dumps off. Request and response bodies are never logged.
   The log redactor is shared with §7.6. An egress allowlist proxy is used where
   the platform allows one, as defence in depth (Q2).
5. **Backups.** Backups hold ciphertext and wrapped data keys only. The
   key-encryption key still decrypts a wrapped data key restored from a backup,
   so a destroyed version stays recoverable from backups until they expire. The
   design states that honestly instead of claiming immediate shredding. Two
   controls apply. secrets keeps a tombstone list of destroyed versions outside
   restorable content and reapplies it before a restored database serves, as D1
   §3 does for deletions. Backup expiry is bounded by the operator policy that
   D1 §3 proposes. Destruction is complete when the last backup holding the
   version expires, and the replacement receipt says when that will be.
6. **Email.** Approver notifications and enrolment need a transactional email
   provider. It is a dependency, and its credential is sealed like any other.

## 16. Tests

**E2E exercises real user paths with no mocks.** That means:

- real team certificates and team-auth signatures from real `aw` and from an L2
  signing path;
- real KMS and a real 1Password test vault, with credentials referenced only by
  name in the operator secret store;
- a real browser WebAuthn ceremony. It uses a browser's built-in virtual
  authenticator, which is a real ceremony with a software authenticator, stated
  as such;
- a real runner process under a separate OS user;
- a real logs ingest, or at least a real hook target, receiving signed events.

**The test upstream** is a service we control, deployed for E2E only. It verifies
each auth scheme for real:

- it compares the received bearer, basic, header or query credential against its
  own copy, by name;
- it implements an OAuth2 client-credentials token endpoint;
- it verifies SigV4 signatures with the real algorithm.

It also provides endpoints for redirects, credential-shaped responses, slow and
reset responses (for `outcome_unknown`), idempotency-key echo and status lookup,
plus a host whose DNS answers with a private address. One additional case runs
SigV4 against real AWS STS in a dedicated test account. Credentials appear only as
names, never values, in fixtures, logs or evidence.

**Required cases, each in both directions** (a valid neighbour versus the
boundary):

| Area | Accepted neighbour | Refused boundary |
| --- | --- | --- |
| Grant | granted principal, named operation | other member; same `did:aw` on another team; revoked certificate; uninstalled installation |
| Scope | `/v1/charges/x` under `/v1/charges/**` | `/v1/chargesX`; `%2F`; `..`; uppercase-host variant canonicalized and matched; userinfo; IP literal |
| Network | public host | private, link-local, metadata, IPv4-mapped and NAT64 addresses; DNS answering private; redirect to another host returned, not followed; with `internal_destinations: disabled`, an owner-confirmed `network: internal` entry is refused at definition and at dispatch |
| Headers | `Accept` | agent `Authorization`, `Cookie`, `X-Amz-Security-Token`, a credential-shaped value |
| Schemes | each of the six injects or signs correctly upstream | wrong host gets no injection; SigV4 with an agent-chosen region or service |
| Results | projected body | credential-shaped body withheld; undeclared token issuance flagged; STS `store_as_secret` yields a derived ref and no value |
| Approval | eligible listed approver, passkey approve, status reports approval, then re-submit for one dispatch | no covering listed approver refuses immediately with `no_eligible_approver`; status never dispatches; requester sees no link; reuse after consume; changed parameters after approval; expired; revoked; `distinct_approver: required` with the same principal; native value replaced before consume; 1Password item changed between approval and dispatch (refused, approval voided) |
| Derived secrets | STS-to-S3 child with fixed destinations; absolute STS expiry or OAuth `expires_in`; child grant with a matching current lineage operation | response-selected destination/kind parameters; inherited ancestor grant; missing, malformed or past expiry; a non-integer relative lifetime; replay extending expiry; a source operation edited after granting; a nearer definition with a different pin; parent disable/replace or issuing-grant revocation racing capture; grant revocation leaving one of its descendants usable; listed ancestor approver withdrawn before admission; unlisted ancestor approver accepted; child fan-out resetting ancestor rate budgets; duplicate child for one dispatch; missing signed child/grant linkage; a delayed sweep allowing expired use |
| State machine | `not_sent` retry under the same intent | crash after send leads to `outcome_unknown`, which blocks a retry of the same operation until reconciled; reconciled-then-new needs a fresh approval |
| Idempotency | same `request_id`, same bytes returns the same receipt | same `request_id`, different bytes is `409`; a replayed envelope inside the skew window does not dispatch again |
| Outbox | event enqueued with every transition | outbox insert failure refuses dispatch; no hook target refuses; a registration inside its `active_from` pad refuses; no current registration refuses, while a stalled secondary target alone does not; all deliveries cancelled is surfaced as a fault; a governance act that cannot enqueue does not commit |
| Runner | pinned job with valid parameters; a declared `option_value` slot taking `-x` | job digest not in the local config; executable hash changed; writable config; parameter outside the schema; a leading `-` in a positional slot; a job definition targeting `LD_PRELOAD`, `PATH`, `GIT_SSH_COMMAND` or `NODE_OPTIONS`; an inherited runner environment variable visible to the job; assignment for another runner; replayed assignment |
| Containment | each action takes effect at admission and at the fence | revocation racing dispatch: committed revocation before the fence stops it; team-auth revoking the last owner's passkey or contact refused; bootstrap or re-designation by admin or member signature refused (`owner_required`); a valid owner act starts the cooling-off |
| Ingress | value set on the console with a passkey | no tool in any context accepts a value; `propose-change` without a passkey stays inert |
| L2 | MCP member with a grant succeeds | MCP member without a grant is refused although the tool is listed; `requires_attestation` refuses |

Each harness states whether it was shown to fail for the fault it targets.

## 17. Dependencies on the generic layer

The design is one generic naapp architecture serving pages and secrets. §3.1
places every component. This table lists what secrets needs from contracts that
others own. The D1 lead's fit review (against D1 8ef61170) confirmed the D1
rows.

| Need | Owner | Notes |
| --- | --- | --- |
| Team-auth v2 verifier with scope enforcement and a resource/action policy hook | B1, aweb-acgh.3 | §4.1. secrets uses B1 as specified. It needs the certificate's `member_did_aw` field in the principal output, so that grants follow the stable identity. It does not need the did:aw current-key profile. |
| Grant status, admission fence, hook-target resolution | aweb-acgh.7; D1 F5/F6 | §4.1 step 2; §11.5 "no registered target". |
| Approval primitive and WebAuthn | B2+B3, aweb-acgh.4 | §10. Requirements (a) and (b) in §10.1, plus the owner-lockout protection in §10.2, proposed as generic B3 behaviour. |
| Team owner act `aweb.owner-act/1` and its verifier | hooks design (aweb-acgh.1); `aweb_naapp` | §10.2: bootstrap and re-designation. |
| `post-governance-hook`; `post-secret-use-hook` schema, action enum and `refusal_code` enum | hooks design (aweb-acgh.1, §A2) | §11.5. secrets cites the schema. The hooks seat has taken secrets' additions; the `refusal_code` list in §11.5 goes into its catalog vector. |
| Manifest v2 with `invocation_contexts`, the `hooks` slot (`productions`) and `app_keys` with purposes | D1 C3 (in D1 §5) | §13 and §11.5. Open requests already fit as typed body parameters. |
| `link_out` widget restricted to the installed app's pinned origin | D1 C1/R1, a *proposed* vocabulary addition that needs Juan's acceptance | §6.1. It shows the normalized domain, opens a new top-level context with no opener or referrer, and carries no token in the URL. |
| Hook envelope, catalog, provenance purpose, producer outbox, delivery | hooks seat; B4 for the shared code | §11.5. secrets owns its payload fields and its enqueue points. |
| Usage reporting `aweb.usage/1` | D1 C5 | secrets reports `uses_admitted`, `dispatches`, `approvals_requested` and `job_runs` under the same rules. |
| The *proposed* `aweb_naapp` components in §3.1 | secrets coordinator to assign | Under Q16 (decided): the egress guard, dispatch state machine, idempotency store, console session and role assignments keyed by stable principal, each with pages as its second consumer (D1's A2 adapter, approval pages, and role-target resolution in D1 §4). |
| Principal attestation (§4.6) | generic AWID/OSS work, with the custodial deployment as issuer | Q5. Policy that requires it refuses until it exists. |

**Requirements on a hosted operator or custodial deployment.** These are stated
generically. Any deployment that hosts custodial members, an L2 endpoint or a
surface host must meet them:

1. **Issue principal attestations** (§4.6) for L2 and dashboard calls signed under
   its custody, and register its custodian key.
2. **Make L2 exposure follow manifest v2 `invocation_contexts`.** Expose only
   `agent` tools, never list `surface`-only tools to MCP clients, and attach the
   attestation from item 1. Exposure still grants nothing (§4.5).
3. **Render the secrets surface through D1's generic surface host.** That covers
   the read-only views, containment and `propose-change` forms, and the link-out
   to the console (§6.1, §13.2).
4. **Sign the team owner act only after fresh interactive step-up.** Where a
   custodial deployment holds a team's controller key, it signs
   `aweb.owner-act/1`, which secrets needs for bootstrap and re-designation
   (§10.2), only for an organization owner and only after a fresh, interactive
   step-up by that owner. A session or a stored credential alone is never
   enough.

No secrets-specific branch in aw-core is needed. Everything else is either
secrets-local or generic.

## 18. Decisions

The secrets coordinator decided these on 2026-10-19 under Juan's delegation.
Each follows the recommendation the authors and reviewers agreed, except where
it says otherwise. Juan can revisit any of them.

1. **Q1. Positioning and custody.** Both backends at launch: the native
   KMS-sealed store and 1Password. The native store also seals the 1Password
   token.
2. **Q2. KMS provider, hosting and egress controls.** Not decided. These are
   deployment facts for the operator, and the build plan treats them as an
   input to the deploy and native-custody tasks.
3. **Q3. Delegated vault mediation.** Not at launch. The interface keeps room
   for it (§5.5).
4. **Q4. 1Password read caching.** None at launch, as recommended.
5. **Q5. Principal attestation.** A launch requirement. Policy that requires it
   refuses until it ships (§4.6).
6. **Q6. Launch auth schemes.** bearer, basic, header, query, OAuth2 client
   credentials and SigV4. Named operations are required for `sensitive` and
   `approve_only` secrets.
7. **Q7. Distinct approver.** `not_required` by default. Owners may require
   four eyes per policy.
8. **Q8. `--unsafe-inject` and `result_handling: return`.** Neither exists.
9. **Q9. `oauth2-refresh` and mTLS.** Later, through the existing interface.
10. **Q10. Passkey authenticator policy.** Any authenticator with user
    verification.
11. **Q11. Audit fail-closed rules.** As recommended: refuse unless a registry
    view no older than 60 s holds an active registration with `active_from` at
    or before the event, and refuse when no active registration is current
    (1 h threshold). Owners cannot turn this off.
12. **Q12. Generic `cli_aliases`.** Not at launch, as recommended.
13. **Q13. Approval notification channel.** Email at launch. Approvals as tasks
    may come later through the existing seam.
14. **Q14. Approval TTL and lockout timings.** The approval TTL is a policy
    parameter, 15 min by default. The 24 h contact-change delay and the 72 h
    re-designation cooling-off are floors: app or owner policy may lengthen
    them, never shorten them, and only deploy configuration sets the floor.
15. **Q15. Launch order.** The hook contract lands first. aw-hooks, logs and
    secrets then build in parallel. secrets does not launch until logs ingests
    real events end to end. One runner job end to end is part of launch.
16. **Q16. Shared components.** A component becomes shared once a second
    consumer uses it. Shared now: the egress guard, the dispatch state machine,
    the idempotency store, the console session and role assignments.
    App-local for now: the auth-scheme injectors, KMS sealing, rate buckets and
    the credential-shape detector.

The `link_out` widget (§17) is supported from the secrets side. Accepting it
into the page vocabulary is D1's decision.

Later, through the existing interfaces: HSM custody, multi-party approval
(quorum above 1), automated rotation, a runner fleet, mTLS and `oauth2-refresh`.
