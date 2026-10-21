# Audit substrate build plan: aw-hooks and logs.aweb.ai

Status: **build plan for aweb-acgh.1**, for review by an independent reviewer
and Athena. Once reviewed, the coordinator creates the board tasks and staffs
them. This is a plan, not an implementation. It contains no estimates.

The plan builds the accepted design, `docs/design/audit-substrate.md` at
`98c1aa21`, under the coordinator's decision record of 2026-10-19 (Juan
delegated it). It reuses three sibling lanes rather than re-specifying them:
aweb-acgh.7 (docs/design/app-team-server-api.md at `2ee4615a`), the secrets
design (docs/design/secrets.md at `a01085c0`), and D1
(`docs/design/agent-pages.md` on main, §11 task graph).

## Rules every task follows

- **TDD, both directions.** Every behaviour change starts with a failing test.
  Tests cover the claimed boundary and the valid neighbouring case beside it.
  Server and naapp tests run on real Postgres through pgdbm fixtures.
  Signatures are real, and no internal boundary is mocked.
- **Every schema change is a new ordered migration.** No existing migration is
  edited.
- **A vector is frozen once.** A conformance vector is frozen only by a
  reviewed decision. A deliberate re-freeze of an existing vector is named in
  the task and reviewed as such.
- **Public vectors live in `docs/vectors`**, the only public vector authority
  (`scripts/check_vector_provenance.py`). Go and Python read them there and
  never keep a copy.
- **One implementation.** Generic pieces live in `aweb_naapp` (`naapp-lib/`)
  and are never copied into an app or into core. "App-local" means the design's
  §C names a reason.
- **Test credentials are named, never written.** Fixtures reference keys and
  passwords by their secret-store path or environment variable name. No value
  appears in a vector, fixture, log, task comment or mail.
- **Review classes.**
  - **R:** independent reviewer only.
  - **R+A:** independent reviewer plus Athena. This applies to anything that
    signs, verifies, gates on authority, touches an identity path, or decides
    what leaves a team.
- **Seats.** Every task runs on Claude Opus 5.5.
  - **aweb-protocol-expert** owns public contracts, signing families, identity
    paths and `aw` (Go).
  - **aweb-expert** owns server and naapp implementation on top of a frozen
    contract.
- **The done-signal** for every task is a reviewer ACK on an exact SHA, merged
  to main by the task's seat (or by the coordinator, where the task says so),
  with the evidence its acceptance names.

## Order of work

1. **The hook contract lands first (phase 1).** It contains the catalog,
   envelope, delivery credential, owner act and binding cases, together with
   their vectors and a Go authority. Nothing downstream freezes a byte without
   it.
2. **The shared kit (phase 2)** goes into `aweb_naapp` behind a new
   dependency-light `hooks` extra. Core and every producing naapp install that
   extra; nothing is copied.
3. **Core (phase 3), `aw` (phase 4) and logs (phase 5)** then build in
   parallel, each on the frozen contract and the kit. Secrets (aweb-acgh.2)
   builds its firing on the same kit in its own lane.
4. **End-to-end and launch gates (phase 6).** Secrets does not launch until
   logs ingests real events end to end (decision 11).

```
H1 ─┬─ H2 ─┬─ K1 ─┬─ K3a ┬─ S2 ─┬─ S3a ─ S3b, S3c
    │      │      │      │      └─ S4
    └─ H3 ─┴─ K2 ─┴─ S1 ─┘ (S2 also needs K0, P1)
K0 (signing_key, acgh.6) ─ S2, L1
S1 ─ acgh.7 G1-d ─ K3b (app-producer resolver) ─ K4 ; secrets firing
H2 ─ C1 ;  H3+S1 ─ C3 ;  H1+H2+G1-d ─ C2
K1+K2+K3b+G1-c/d ─ L1..L5 ─ L6 ;  all ─ E1, E2
```

## Phase 1: the hook contract (aweb-protocol-expert)

| Id | Task | Repo and paths | Acceptance criteria | Depends | Review |
| --- | --- | --- | --- | --- | --- |
| H1 | Catalog, binding and delivery contract | docs/hook-events.md (new public source of truth); docs/vectors/hook-catalog-v1.json; docs/vectors/hook-binding-cases-v1.json; a pointer from `docs/aw-hooks-sot.md` stating that `on_mutation` is unchanged and is not an audit hook | - **Catalog** `aweb.hooks` v1 has the five hooks with class, producer kinds, audit-critical flag and precedence (design §A2).<br>- **Payloads** are strict flat allowlists, including the `post-secret-use-hook` fields with the 28 `refusal_code` values from secrets §11.5, the governance act/direction table, and every §A10 mutation type with its per-type fields (`app_key.revoked` included).<br>- **Client** command classes with local effects (design §A5) are listed.<br>- **Binding states and `active_from`** are specified, along with the ack dispositions, `409 event_conflict` and the audit-critical gate (§A3, §A7).<br>- **Binding cases** cover admin install leaving bindings pending, supersession by a new generation, an unknown catalog, the pad, and revocation's final entry and cancellation.<br>- **Python** loads the catalog with a strict reader in a test, and a schema with an extra field is refused. | design accepted (done) | R+A |
| H2 | Envelope and delivery-credential signing family, Go authority | cli/go/hookevent/ (sign, verify, canonical bytes); `docs/vectors/hook-event-envelope-v1.json`, `hook-delivery-credential-v1.json`; a deliberate added `trace_id` positive case in `team-auth-envelope-v2.json`; vector README and consumer classification updated | - **Envelope** `aweb.hook-event/1`: the prefix, canonical JSON and detached Ed25519 (§A6).<br>- **Delivery credential** `AWEB-Hook DIDKey` binds the fields in §A7.<br>- **Envelope negatives** listed in §A11: wrong prefix, non-canonical bytes, float, duplicate key, unknown payload field, team mismatch, client-signed server hook, client actor not equal to signer, unknown catalog version; decision 73 removes the obsolete plain-SHA digest demonstration, leaving producer commitments to K4/S13 proofs.<br>- **Delivery-credential negatives:** an app-event or `hook-resolve` credential at a hook target, cross-audience, tampered body, wrong binding, stale timestamp.<br>- **Freeze:** the Go conformance test regenerates byte for byte. The `team-auth-envelope-v2.json` change is named as a deliberate re-freeze with an additive case only, and existing cases are byte-identical. | H1 | R+A |
| H3 | Owner act `aweb.owner-act/1` | docs/owner-act.md (new public source of truth); cli/go/awid/owneract.go (sign, verify); docs/vectors/owner-act-v1.json | - **Signing bytes and subject** per act (§A3): `hook-binding.activate` and `.revoke`; the generic `app-role.designate`, `app-role.revoke` and `app-credential.recover`; logs' `logs.retention.set`, `logs.erase`, `logs.legal-hold.set` and `.release`.<br>- **Rules:** a closed vocabulary per audience, a lifetime of at most ten minutes, single-use nonce semantics, and the current team key.<br>- **Disclosure:** the doc states that a custodian of the controller key can mint any owner act (§2).<br>- **Negatives:** admin signer, rotated-out key, expired, nonce reuse, subject or generation mismatch, wrong type or audience, and a team certificate presented as an owner act.<br>- **Approval of record:** the commit records Juan's approval of `aweb.owner-act/1` as an identity-path change (given explicitly with the D1 decision package, coordination message 811c3b3e), and docs/owner-act.md states the constraint: an owner act is valid only from team controller authority exercised by the organization owner (for BYOT, the controller key holder), and a custodial deployment signs one only after the owner's fresh interactive step-up. | H1 | R+A |

## Phase 2: the shared kit in `aweb_naapp`

A new `hooks` extra in `naapp-lib/pyproject.toml` depends on `pgdbm`,
`pynacl`, `httpx` and `awid-service` only. It never depends on `webauthn`,
`fastapi` or `pydantic-settings`, so core can install it (decision 12). It
builds on the shipped `aweb_naapp.outbox` (Target meta, `Cancelled`,
`latest_receipt`, status). It needs the approved `channel` addition, under
which hooks use channel `hooks`.

| Id | Task | Repo and paths | Acceptance criteria | Depends | Seat | Review |
| --- | --- | --- | --- | --- | --- | --- |
| K0 | Core-importable signing-key loader | `naapp-lib/src/aweb_naapp/signing_key.py` behind a `signing-key` extra (stdlib plus `pynacl` only), built in aweb-acgh.6 | - **Decision 10:** `read_signing_key_file` and `parse_signing_key_hex` provide one loader for every app key and purpose. It fails closed, refuses writable or non-regular files, uses one 64-hex format, and puts no key material in errors.<br>- **Importable by core:** core loads its hook key with `read_signing_key_file`, with no runtime extra installed.<br>- **One copy:** the runtime's key loading calls this module. | decision 10 | aweb-expert (aweb-acgh.6) | R+A |
| K1 | Catalog loader, envelope, delivery credential (Python) | `naapp-lib/src/aweb_naapp/hooks/` (`catalog.py`, `envelope.py`, `delivery.py`) | - The H1 and H2 vectors pass from the files themselves; no copy is made.<br>- The Python consumer is registered in the vector consumer classification.<br>- An import test proves that the `hooks` extra pulls in no runtime-only dependency. | H1, H2 | aweb-protocol-expert | R+A |
| K2 | Owner-act verifier | `naapp-lib/src/aweb_naapp/hooks/owner_act.py` plus an ordered migration for the nonce table | - **Order of checks:** exactly as `docs/owner-act.md` states them, the single source, with every verifier option required. The current AWID team key is read fresh (≤ 60 s cache). Each check has a distinct error, and any key but the current team key fails with `owner_required`.<br>- **Single use:** the nonce table's migration has a unique constraint on (verifier scope, team, nonce). The insert happens in the act's effect transaction, a conflict rolls the effect back with `nonce_reused`, and rows are kept at least until `expires_at` plus 60 s. A test runs two concurrent uses of one act and shows exactly one commits.<br>- **Vector:** the `owner-act-v1.json` vector passes.<br>- **Rotation:** a real AWID test rotates the team key and shows the old key refused within the bound. | H3, K1 | aweb-protocol-expert | R+A |
| K3a | Producer: enqueue, gate, transport, core resolver interface | `naapp-lib/src/aweb_naapp/hooks/producer.py`, `transport.py` | - **Enqueue** builds and signs the envelope inside the caller's transaction. It mints `event_id` once and assigns `producer.seq` through `next_sequence` scoped `(producer, team, hook)`.<br>- **Audit-critical gate:** an audit-critical enqueue refuses with `audit_target_unavailable` unless a view no older than 60 s holds a registration with `active_from <= occurred_at`. A narrowing governance act is never refused.<br>- **Resolver interface:** the drain takes a resolver that materializes one delivery per eligible registration and leaves the event pending when its view is stale. Core supplies its in-process resolver (S2); K3b supplies the app producers' one.<br>- **Transport** signs `hook-delivery` per request and sends to the stored endpoint (Target meta) after re-checking the binding (`Cancelled` if revoked).<br>- **Egress** follows the shared egress guard: HTTPS only and no redirects. A hosted deployment disables private and internal destinations at deploy level, whatever an owner configures (the same rule as secrets); allowing them is only a self-hosted operator's configuration.<br>- **Outcomes:** 2xx maps to delivered or duplicate with the receipt kept; 409 maps to conflict; authorization or schema rejection retries in bounded fashion and then ends rejected; network errors and 5xx are never dropped.<br>- **Faults:** an audit-critical event whose deliveries all end cancelled or rejected is reported as a fault.<br>- **Tests:** a drain crash on real Postgres, revocation between materialization and send, and a stale view keeping the event pending. | K1; aweb-acgh.6 `channel` addition; the shared egress guard (secrets lane, decision 12), which must also be importable without the runtime extra | aweb-expert | R+A |
| K3b | App-producer resolver | `naapp-lib/src/aweb_naapp/hooks/resolver.py` | - **Resolution:** registrations come from acgh.7's `HookResolver`, with the ≤ 60 s fail-closed cache.<br>- **Gate input:** the audit-critical gate reads this resolver's view.<br>- **Test:** against a real core server with an activated registration, an expired view refuses and a revoked binding drops out within the bound. | K3a; acgh.7 G1-d (which depends on S1) | aweb-expert | R+A |
| K5 | Owner-act evidence in the approval primitive | aweb-acgh.10 (already on the board) | - The `OwnerActEvidence` placeholder is replaced with K2's `VerifiedOwnerAct`, and secrets bootstrap uses it.<br>- **Call sites:** the designation calls `OwnerActVerifier.prepare` before its transaction and `consume_in` inside the transaction that records the designation, so the act is single-use and no registry read holds that transaction's locks. `role` is the approver scope, and `contact_sha256` is the enrolment contact's hash. | K2; aweb-acgh.4 | aweb-expert | R+A |
| K4 | `post-manifest-command-hook` firing | `naapp-lib/src/aweb_naapp/runtime/` admission middleware, configured per app | - **What fires:** every admitted mutation tool call and every attributable refusal. Reads fire only for the production's `reads`.<br>- **Precedence:** a tool whose effect a specific hook covers (declared per tool) fires nothing here, so one effect never produces two events.<br>- **Payload (decision 70):** `request_sha256` is the producer-keyed HMAC-SHA-256 specified in docs/hook-events.md, with no parameter values or concrete path/query in event fields. Tests distinguish it from plain SHA-256, cover key and installation-context separation, missing/malformed key refusal, rotation with byte-identical outbox retry, and a credential-shaped parameter or path. The length-framed request binds method, external raw path+query, received content-type values and exact pre-injection body bytes; changing any component changes the MAC, including raw-body mode. An attributable refusal requires the complete bounded body; early/oversize refusals without it emit no manifest-command hook, with tests for both cases.<br>- **Runtime producer (decision 70):** K4 owns the hook-event key, `ServerProducer.app` per installation and the hooks drain with `HookTransport`, consuming `runtime.hook_resolver()` from decision 69.<br>- **Routing** uses B1's declared-tool route mapping, so firing and admission resolve the same tool.<br>- **Sequence:** decision 76 splits the independent framing/HMAC/key-loader helper into aweb-acgh.16.8.1, built now. Runtime attachment waits for aweb-acgh.23, D1 C3 and the decision-69 resolver on main. | K3b; aweb-acgh.3 (B1); aweb-acgh.23; D1 C3 (aweb-acgg.9); decision-69 runtime resolver | aweb-expert | R+A |
| P1 | Publish `aweb-naapp` as a release artifact | `naapp-lib/pyproject.toml` version policy; the release skill's artifact list | - `aweb-naapp` ships as a versioned package, so the core server can declare `aweb-naapp[hooks]>=<floor>` the way it declares `awid-service`.<br>- The release dry run builds and installs the server with that dependency from the published artifacts.<br>- **Who tags:** the coordinator sends the reviewed SHA to the release owner, who tags and publishes `aweb-naapp` through the build-once release lane. No implementation seat cuts the tag. | K0, K1, K3a | aweb-protocol-expert (package and release-list change) | R |

### Decision 73: secret-use contract re-freeze and S13 dependency

The `post-secret-use-hook` shape is re-frozen in catalog v1 in place because
no deployed producer/consumer or pending use exists. This contract delta
updates the public catalog, its managed package copy, secret-use transition
examples and their consumers together. It adds the paired child secret/grant
creation linkage and specifies separately keyed request/parameter MACs in
`docs/hook-events.md`. The envelope vector's obsolete plain-SHA demonstration
is removed; its signing cases remain unchanged. Review is R+A.

S13 (aweb-acgh.18.14) consumes the re-frozen shape. Its proofs must cover the
initial authenticated inbound request (including raw path/query, content type
and exact body), typed integer-only operation/job params, absent params for
open requests, startup refusal for missing keys, and producer/key/domain
separation. Persisted MACs/context survive approval, re-submission and key
rotation without recomputation. Local idempotency and B2 approval hashes stay
separate; a conflicting request is recorded under its attempted bytes, without
replacing the accepted use's commitments. Refusals enqueue without an intent
row after admission-savepoint rollback, with missing optional MACs allowed
when the corresponding bytes are unavailable. Child/value/grant/result/outbox
commit together; rollback and a lost recording fence emit no child pair.
K4 supplies the generic framing/key helper once; S13 consumes it. No live
producer is enabled before kit, ingest, resolution and owner activation.

### Passkey evidence convention (aweb-acgh.39)

The public hook contract proposes one privacy projection and HMAC input for
`approval_evidence_sha256` in governance and secret-use events. Its byte vector
is `docs/vectors/passkey-evidence-v1.json`. It is on hold for Juan's ruling on
the accepted secrets §10.4 later-verification promise: B3's current summary
cannot fulfill it. No producer activation is authorized by this draft. Once
the evidence claim/storage is settled, review is R+A. No actor field/mode
or catalog wire shape is added. B3 supplies one shared canonical projection
helper after this contract is ACKed, with the hook commitment/key helper
reused for purpose-separated MAC/key loading rather than a producer-local
codec. Assignment of that implementation follows the contract review.

B3/S13/S14 implementation proofs must cover real restricted evidence lookup,
session/candidate subject and purpose matching, authoritative scope and approval
bindings, nullable-field omission, UTC microsecond preservation, exclusion of
credential IDs/counters, each included field changing the MAC, separate keys,
installation context, startup refusal and persist-once reuse across rotation.
Any new stored association is an ordered migration. An unavailable audit target
never blocks containment. Console governance uses the identity-free system
actor; a different affected subject remains in payload subject_ref. The vector
checks bytes and contract shape, not these runtime/lifecycle obligations.

### Decision 76: independent K4 helper (aweb-acgh.16.8.1)

The generic helper is `aweb_naapp.hooks.commitment`, shared by K4 and S13.
It provides `CommitmentContext`, complete inbound `RequestBytes`, purpose-tagged
`CommitmentKey.request`/`.params`, and `load_commitment_key` through the common
key-file reader. It imports no runtime, reads no HTTP stream and performs no
upstream rendering. The caller supplies authoritative context and complete
bounded bytes. Parameter bytes come from the caller's existing validated typed
canonical-JSON path under B2's value rules, with no B2 prefix/wrapper; the
helper does not introduce a second parameter codec.

This helper is built and reviewed independently (R+A) and can land through the
naapp train without waiting for runtime attachment. Runtime key configuration,
MAC/context persistence, rotation/destruction and authorization-path wiring
remain K4/S13 obligations. K4's attachment still waits for acgh.23, C3 and the
runtime resolver. The helper's exact ACKed SHA is handed to S13 for reuse.

## Phase 3: core server

| Id | Task | Repo and paths | Acceptance criteria | Depends | Seat | Review |
| --- | --- | --- | --- | --- | --- | --- |
| S1 | `app_hook_bindings` and owner activation | `server/src/aweb/migrations/aweb/<next>_app_hook_bindings.sql`; server/src/aweb/hook_bindings.py; activation and revocation routes | - **Rows:** install or update creates pending rows from the digest-pinned manifest bytes, read through `manifest_registration()` for the v2 `hooks` slot. A new generation supersedes, and uninstall revokes.<br>- **Owner acts:** activation and revocation require an owner act verified by K2 with core's closed vocabulary. The subject must equal the stored pending row. Core calls `OwnerActVerifier.prepare` before the activation transaction and `consume_in` inside it, so the nonce is consumed with the binding's state change and no registry read holds that transaction's locks.<br>- **Pad and refusals:** `active_from = activated_at + 60 s`. Activation refuses until F6 supplies `installation_id` and generation. Production activation refuses until keys come from pinned bytes (acgh.7 G1-b).<br>- **Tests:** an admin or member signature is refused, a stale subject is refused, and so is a replayed nonce. | H3, K2; D1 F6 (aweb-acgg.5), C3 (aweb-acgg.9); aweb-acgh.8 step 1; acgh.7 G1-b | aweb-protocol-expert | R+A |
| S2 | Core producer | `server/pyproject.toml` (`aweb-naapp[hooks]`); kit migrations applied to core's schema as new ordered migrations; server/src/aweb/hook_producer.py (service-layer `enqueue_mutation_hook(tx, …)`, an in-process resolver over S1, drain in the server lifespan); configuration for the core hook key (`kid`, key file path, validity window) | - **Key:** the core key is operator configuration, loaded by the one key loader of decision 10 (key file by `kid`, refusing writable or non-regular files). It is never a team, controller or agent key.<br>- **Gating:** enqueue happens only when the fresh view shows an active registration, and never gates a mutation otherwise.<br>- **`trace_id`:** a signed `trace_id` member is taken as `signed_request`; otherwise one is minted and marked `producer`.<br>- **Same transaction:** `hook_binding.activated` and `.revoked`, and `app.installed` and `.updated`, are enqueued in the same transaction as the act.<br>- **Revocation:** the revoked target's final entry, cancellation of its backlog, and the gap-explaining governance event to the remaining registrations (§A3).<br>- **Server-lane task:** the `on_mutation` seam is unchanged. | S1, K3a, K0, P1 | aweb-expert | R+A |
| S3a | Sites vector, checker and task mutations | docs/vectors/post-mutation-hook-sites-v1.json; second scan in `scripts/check-extension-docs.py`; task service enqueue sites | - **Checker:** the scan requires a literal `mutation_type`, the call lexically inside a transaction block, and counts that match in both directions. The `on_mutation` mapping covers all 23 pinned rows (each mapped or excluded with a reason). A new `on_mutation` event fails the build.<br>- **Task mutations:** `task.created`, `.updated` (one event per update, with `changes`), `.deleted`, `.comment_added` and `.dependency_changed`. Comment and dependency become transactional.<br>- **MCP:** MCP task tools are covered through the service layer, and a test drives them. | S2 | aweb-expert | R |
| S3b | Messaging mutations | `server/src/aweb/messaging/` | - **Transactional sends:** mail send without attachments and ack become transactional.<br>- **Events:** `mail.sent`, `mail.acknowledged` and `chat.message_sent` are enqueued in the effect's transaction from REST and MCP.<br>- **Payloads:** no bodies, subjects or previews.<br>- **Rollback:** a failure injected after the insert rolls both back. | S2, S3a | aweb-expert | R |
| S3c | Identity, app, key and membership mutations | `routes/identity_grants.py`, `routes/connect.py`, `lifecycle.py`, the acgh.7 key-revoke route | - **Events:** `identity_grant.minted` and `.revoked`; `app_key.revoked` (in the transaction that sets `revoked_at`); `membership.connected` (`connect` becomes transactional); `membership.workspace_retired` (in the lifecycle cascade).<br>- **Later:** `task.answered` is added once D1 C2 (aweb-acgg.8) lands, as its own follow-up row in the vector. | S2, S3a; acgh.7 G1-b (key revoke route) | aweb-expert | R |
| S4 | Membership observer (M3) | server/src/aweb/membership_observer.py; an ordered cursor migration | - **Scope:** it runs only for teams with an active `post-mutation-hook` registration.<br>- **Reading:** it reads the certificate history from the team's home AWID with the documented same-operator read credential (`docs/awid-sot.md:117`–`:131`). It moves to a narrow per-capability read grant once the service-token split lands, so it never needs provisioning authority.<br>- **Enqueue:** `membership.certificate_issued` and `_revoked`, marked observed with AWID's timestamps and certificate digest, in the transaction that advances the cursor.<br>- **Failure:** a restart resumes without loss or duplicate events.<br>- **Limits:** the documented limit is that a private team on a foreign registry is not observed. | S2 | aweb-protocol-expert | R+A |

## Phase 4: `aw` client (aweb-protocol-expert)

| Id | Task | Repo and paths | Acceptance criteria | Depends | Review |
| --- | --- | --- | --- | --- | --- |
| C1 | `trace_id` minting and propagation | `cli/go` team-auth request builder | - **Minting:** one W3C trace id per command invocation, placed in the signed `trace_id` member of every request the command makes (core and manifest tools), never inside `operation`.<br>- **Vectors:** the H2 `trace_id` case passes.<br>- **Compatibility:** a server at an older version accepts the request unchanged (a test against the released verifier behaviour). | H2 | R+A |
| C2 | `post-command-hook` | `cli/go` local outbox, resolver and delivery | - **Scope:** it fires only for the catalog's command classes with local effects. Reads fire nothing.<br>- **Signing:** events are signed by the member key with actor equal to signer, and delivered with the team certificate to client-class registrations listed through acgh.7.<br>- **Outbox:** the local outbox survives a crash. A deleted outbox loses events by design, and the docs state that client events are agent-reported. | H1, H2; acgh.7 G1-d (client-class listing) | R+A |
| C3 | Owner-act commands | `cli/go/cmd/aw` (`aw hooks bindings`, `aw hooks activate`, `aw hooks revoke`, `aw app role designate`, `aw app role revoke`, `aw app credential recover`) | - **Before signing:** the client fetches the manifest bytes from the origin, checks the pinned digest, resolves the tool, and shows the owner the hook, tool, scopes, `reads` and target before it signs.<br>- **Signing:** acts are signed under the existing controller custody (BYOT or local).<br>- **Refusal:** a member without the controller key gets a distinct refusal.<br>- **Test:** the real path against a local AWID and server, through activation. | H3, S1 | R+A |

## Phase 5: logs (`naapp/logs`)

Logs is app-local (design §C). It uses the B1 verifier, acgh.4 passkeys and
approvals, the K kit and acgh.7's client unchanged.

| Id | Task | Repo and paths | Acceptance criteria | Depends | Seat | Review |
| --- | --- | --- | --- | --- | --- | --- |
| L1 | App skeleton | `naapp/logs/` package, manifest v2, migrations, health, generic deploy configuration | - **Manifest:** `ingest` is declared with `invocation_contexts: ["hook"]` and registered on all five v1 hooks. There are no app-event subscriptions.<br>- **Keys:** logs' own key (receipts and checkpoints) is loaded by the decision-10 loader.<br>- **Runtime:** it runs on the shared runtime with no copied auth code. | K0; D1 C3 (aweb-acgg.9); F0 (aweb-abre); aweb-acgh.3 (B1) | aweb-expert | R |
| L2 | Ingest admission | `naapp/logs/src/logs/ingest.py` | - **Admission order** (design §B2), each step with a distinct error: transport, own binding (acgh.7 own-bindings read; 503 when authority is unavailable), provenance (app production key; core key anchored per team through `TeamServerDirectory`; client certificate through B1 with client-class only), schema, dedup (duplicate returns the original receipt; conflict returns 409 and records a fault), then append.<br>- **Key evidence** is recorded with each event.<br>- **Client quotas:** per-member rate and byte limits for client events.<br>- **Forgery:** a forged core event from an origin not anchored through acgh.7 is refused. | K1; acgh.7 G1-c, G1-d; L1 | aweb-expert | R+A |
| L3 | Chain, receipts, checkpoints, verify | `naapp/logs/src/logs/chain.py`, `verify.py`; docs/vectors/logs-chain-v1.json | - **Chain:** commitments, `event_hash`, gap-free `team_seq` under a head-row lock, genesis and epochs (§B3).<br>- **Signed artefacts:** `aweb.logs-receipt/1` and `aweb.logs-checkpoint/1`.<br>- **`verify`** reports intact, broken, missing, purged with its act, per-producer and per-hook seq gaps inside binding intervals, and conflicts. It also accepts receipts and checkpoints as input.<br>- **Vector negatives:** reorder, gap, altered content, forged checkpoint, and a purged stub that still verifies. | L2 | aweb-expert | R+A |
| L4 | Owner-gated reads | `naapp/logs/src/logs/readers.py`, viewer on logs' origin | - **Designation:** readers are designated by `app-role.designate` (role `reader`) through K2. Removing the last reader with team-auth alone is refused.<br>- **Passkeys:** enrolment and sessions come from acgh.4 on logs' origin.<br>- **Viewer:** `query`, `tail`, `verify` and `export` run only in such a session. A member signature, a hosted session or an MCP identity is refused.<br>- **Delegation:** delegated `verify` returns no content, and delegated `query` does not exist (decision 5).<br>- **Self-administration:** reader, retention and erasure changes become `logs.*` chain entries signed by logs.<br>- **Surface:** a D1 surface shows no content and only a `link_out` to logs' own origin.<br>- **Copy:** the viewer marks client events as agent-reported, never as mediated fact, and states that a revoked target may see up to 60 s of further redacted activity. | L3; aweb-acgh.4; K2 | aweb-expert | R+A |
| L5 | Retention, erasure, legal hold, export and deletion | `naapp/logs/src/logs/retention.py`, jobs | - **Acts:** `logs.retention.set`, `logs.erase` and `logs.legal-hold.*` require owner acts.<br>- **Purge:** content, salt, projections, indexes and caches are purged, the skeleton is kept, and `verify` reports the range and its act.<br>- **Default:** the hosted default is to keep with no automatic expiry (decision 16).<br>- **Restore:** a restored database reapplies purge tombstones before it serves.<br>- **Export** produces a self-verifying bundle.<br>- **Deletion** runs as D1's durable job and keeps the final checkpoint and a receipt. | L3, L4; D1 N1 (aweb-acgg.13) backup-tombstone rule | aweb-expert | R+A |
| L6 | `aw logs` | `cli/go/cmd/aw` (`aw logs query`, `tail`, `verify`, `export`) | - **Authorization:** a device-style flow on logs' origin with the reader's passkey yields a short-lived session bound to an ephemeral CLI key.<br>- **Offline:** `aw logs verify --bundle` works offline, and the `logs-chain-v1.json` vector passes in Go. | L3, L4 | aweb-protocol-expert | R+A |

## Phase 6: end-to-end and security pass

| Id | Task | Acceptance criteria | Depends | Seat | Review |
| --- | --- | --- | --- | --- | --- |
| E1 | Real-path end-to-end | - **Harness:** the Docker e2e harness runs real AWID, aweb, logs, one fixture producer naapp, and `aw`, on a disposable BYOT fixture team whose credentials are referenced by name.<br>- **Activation:** the owner activates the logs registration and the fixture production with real owner acts.<br>- **Ingest:** a core mutation from REST and from MCP appears in the chain, and `verify` reports intact.<br>- **Gating:** an audit-critical event with no eligible target is refused (also inside the pad). A narrowing act passes with no target.<br>- **Revocation:** revoking a target produces its final entry and an explained gap elsewhere.<br>- **Switch:** the target-switch order between two logs installs with distinct app ids loses nothing.<br>- **Client and forgery:** a client event is shown as agent-reported, and forged core and app events are refused.<br>- **Faults:** conflicting bytes are recorded as a fault, a drain crash causes no loss and no duplicate effect, and a purged range still verifies.<br>- **Heavy-run hold:** this runs only after the coordinator lifts the hold. | all of phases 1–5 | aweb-expert | R+A |
| E2 | Athena security pass | - Findings on owner-act custody, provenance at ingest, egress, redaction and erasure are resolved on the implementation deltas. | E1 | (Athena) | A |

## Hosted-side items (custodial deployment)

Each item is stated generically here. Where a board task already carries an
item, that task is cited. X4 and X5 are operations tasks.

| Id | Requirement | Carried by | Depends |
| --- | --- | --- | --- |
| X1 | Sign `aweb.owner-act/1` for a managed team only for the organization owner (never an organization admin), after a fresh interactive step-up (passkey or re-authentication). It is never signed with a stored credential, an API key or an MCP token. The signer is a narrow provisioning signer, not controller-key material loaded into every web or worker request process. The owner copy discloses that the custodian can mint owner acts (decision 1; Juan's ruling: organization owners only). **Acceptance:** for a managed team, an organization admin's gesture, a stale session without step-up, and an API or MCP credential are each refused, and no owner act is signed. | D1 L1, aweb-acgg.21, and L3, aweb-acgg.22 | H3, K2 |
| X2 | Hosted MCP mints one `trace_id` per tool call and signs it in the team-auth payload. It never lists or calls `hook`-context tools and logs no parameters or results. | D1 L2, aweb-abzo | H2, C1 |
| X3 | The `aweb.principal-attestation/1` custody and principal attestation (secrets design contract). It is a launch requirement, and policy that needs it refuses until it ships (decision 2). | carried by D1 L1 (aweb-acgg.21), attached by D1 L2 (aweb-abzo) | secrets-lane contract |
| X4 | Run the hosted logs installation: its own origin and key custody, the decision-16 retention default, an evidenced backup-expiry deadline with tombstone reapplication on restore, and inbound reachability for producers. | aweb-acgh.12 | L1–L5 |
| X5 | Core hook producer key configuration and rotation, with retired keys kept listed. Also the same-operator AWID read credential for the M3 observer, the drain worker in the deployed server, and the operator-disclosed delivery horizon. | aweb-acgh.13 | S2, S4, P1 |
| X6 | Publish and backfill `aweb.team-server/1` records for every team whose controller key the deployment holds, before any naapp depends on discovery (decision 3). | D1 L6, aweb-acgg.31 | acgh.7 G1-a |

## Cross-lane dependencies

- **aweb-acgh.6:** the outbox `channel` addition (approved, not yet on main)
  and the shared egress guard.
- **aweb-acgh.7:**
  - G1-b (keys from pinned bytes, the per-team key revoke);
  - G1-c (`TeamServerDirectory`);
  - G1-d (resolution endpoints, own bindings, producer keys, client-class
    listing).

  G1-d itself depends on S1.
- **The decision-10 app-key loader** (agreed between acgh.7 and the shared
  runtime seat) must sit in a module that core can import without the runtime
  extra, because S2 loads the core hook key with it.
- **aweb-acgh.8:** step 1 (team-scoped registrations, `manifest_registration()`).
- **aweb-acgh.3 (B1)** and **aweb-acgh.4 (approvals and WebAuthn).**
- **D1:**
  - C3, aweb-acgg.9 (manifest v2 `hooks` slot, `app_keys`, invocation
    contexts);
  - F6, aweb-acgg.5 (installation identity, generation, admin install);
  - C2, aweb-acgg.8 (`task.answered`);
  - L1, aweb-acgg.21 (X1, X3);
  - L2, aweb-abzo (X2, X3);
  - L3, aweb-acgg.22 (the member surface; owner acts need fresh step-up);
  - L6, aweb-acgg.31 (X6);
  - N1, aweb-acgg.13 (the backup-tombstone rule).
- **The secrets lane (aweb-acgh.2)** fires `post-secret-use-hook` and
  `post-governance-hook` with K3a and K3b, and its launch waits on E1.
