# Audit substrate build plan: aw-hooks and logs.aweb.ai

Status: **the build plan for aweb-acgh.1 (epic aweb-acgh.16), with the status
of every task on main.** Each task names its board task and is **Built** (on
main, with the code and its first-parent merge commit), **In flight** (what is
on main and what remains), **Open** (decided and planned, not on main) or
**After the first release** (decided and deliberately parked). It contains no
estimates.

The plan builds the accepted design, [`audit-substrate.md`](audit-substrate.md),
under the decision record, whose decisions it cites by number. It reuses three
sibling lanes rather than re-specifying them: aweb-acgh.7
([app-team-server-api.md](app-team-server-api.md)), the secrets design
([secrets.md](secrets.md)), and D1 ([agent-pages.md](agent-pages.md), §11 task
graph).

## Status by task

| Id | Board task | Task | Status | On main |
| --- | --- | --- | --- | --- |
| — | aweb-acgh.1 | Design | Built | `docs/design/audit-substrate.md` (e78d12ac3) |
| H1 | aweb-acgh.16.1 | Catalog, binding and delivery contract | Built; activation refusal of unknown catalogs Open (aweb-acgh.16.35) | `docs/hook-events.md`, `docs/vectors/hook-catalog-v1.json`, `docs/vectors/hook-binding-cases-v1.json`, pointer in `docs/aw-hooks-sot.md` (f064438b4) |
| H2 | aweb-acgh.16.2 | Envelope and delivery credential, Go authority | Built | `cli/go/hookevent/envelope.go`, `delivery.go`; `docs/vectors/hook-event-envelope-v1.json`, `hook-delivery-credential-v1.json`; case `oss_task_create_with_trace_id` in `team-auth-envelope-v2.json` (3c3195e74) |
| H3 | aweb-acgh.16.3 | Owner act `aweb.owner-act/1` | Built | `docs/owner-act.md`, `cli/go/awid/owneract.go`, `docs/vectors/owner-act-v1.json` (7426a016e; subject canonicalization d76a7d253) |
| — | aweb-acgh.16.34 | Owner act `logs.verify.delegate` | Open | — |
| K0 | aweb-acgh.6 | Core-importable signing-key loader | Built | `naapp-lib/src/aweb_naapp/signing_key.py`, `signing-key` extra (fd806b7db) |
| K1 | aweb-acgh.16.4 | Catalog loader, envelope, delivery credential (Python) | Built | `naapp-lib/src/aweb_naapp/hooks/catalog.py`, `envelope.py`, `delivery.py`, packaged `catalog-v1.json` (f064438b4) |
| K2 | aweb-acgh.16.5 | Owner-act verifier | Built | `hooks/owner_act.py`, `hooks/owner_act_nonces.py`, `hooks/migrations/001_owner_act_nonces.sql` (f064438b4) |
| — | aweb-acgh.16.28 | Move K2 nonces onto the shared nonce store | Open | `aweb_naapp.nonces` exists; owner-act nonces keep their own table |
| K3a | aweb-acgh.16.6 | Producer: enqueue, gate, transport, resolver interface | Built | `hooks/producer.py`, `hooks/transport.py`, outbox channels `outbox/migrations/002_outbox_channels.sql` (7bd1acce6) |
| K3b | aweb-acgh.16.7 | App-producer resolver | Built | `hooks/resolver.py`, `runtime/hook_resolver.py` (d66fe3e1c, 0131348ff) |
| K4 | aweb-acgh.16.8 | `post-manifest-command-hook` firing | Built | `runtime/hooks.py`, `runtime/manifest_hooks.py`; `HookProducer.enqueue_refusal` and `require_admission`; `outbox/migrations/003_admission_backlog.sql` (5265fa2fb, 134bd3773) |
| K4 helper | aweb-acgh.16.8.1 | Independent commitment helper (decision 76) | Built | `naapp-lib/src/aweb_naapp/hooks/commitment.py` (924bd0ff4) |
| K5 | aweb-acgh.10 | Owner-act evidence in the approval primitive | Built | `runtime/passkeys/service.py` takes `VerifiedOwnerAct` (f064438b4) |
| P1 | aweb-acgh.16.9 | Publish `aweb-naapp` | Built | `aweb-naapp` 0.5.1 (`naapp-lib/pyproject.toml`); the server declares `aweb-naapp[egress,hooks]>=0.5.1` (`server/pyproject.toml`) |
| S1 | aweb-acgh.16.10 | `app_hook_bindings` and owner activation | Built; signer-readiness refusal Open (aweb-acgh.16.36) | `server/src/aweb/migrations/aweb/032_app_hook_bindings.sql`, `server/src/aweb/hook_bindings.py`, `server/src/aweb/routes/hook_bindings.py` (e6b14c292, 2ab7556f5) |
| S2 | aweb-acgh.16.11 | Core producer | In flight | Public half only: `AWEB_HOOK_PRODUCER_KEYS` (`server/src/aweb/config.py`) and `GET /v1/hooks/producer-keys` (`server/src/aweb/routes/app_hooks.py`) (f562e8d33) |
| — | aweb-acgh.16.31 | Core signer-unavailable reservations | Built (contract); implementation in S2 | `docs/hook-signer-unavailable.md` (2fcb7f481) |
| — | aweb-acgh.16.29 | Terminal delivery authority and cancellation evidence | Built (contract) | `docs/hook-terminal-delivery.md` (2fcb7f481) |
| — | aweb-acgh.16.30 | Shared outbox nonblocking end fence and attempt CAS | After the first release | — |
| — | aweb-acgh.16.32 | Terminal helpers (capsule, credential, seal) and vectors | After the first release | — |
| — | aweb-acgh.16.27 | `dispatch_in_flight` and `generation_superseded` refusal codes | Built | both in the catalog's `refusal_code` enum (decisions 29, 35) |
| — | aweb-acgh.16.33 | Catalog v1 `use_ref` | Built | `use_ref` in `docs/vectors/hook-catalog-v1.json` and `docs/hook-events.md` (22f3cc779) |
| S3a | aweb-acgh.16.12 | Sites vector, checker and task mutations | Open | — |
| S3b | aweb-acgh.16.13 | Messaging mutations | Open | — |
| S3c | aweb-acgh.16.14 | Identity, app, key and membership mutations | Open | — |
| S4 | aweb-acgh.16.15 | Membership observer (M3) | Open | — |
| C1 | aweb-acgh.16.16 | `trace_id` minting | Open | the H2 vector case only |
| C2 | aweb-acgh.16.17 | `post-command-hook` | Open | the catalog's command classes only |
| C3 | aweb-acgh.16.18 | Owner-act commands | Open | the Go library only (`cli/go/awid/owneract.go`) |
| L1 | aweb-acgh.16.19 | Logs app skeleton | Built | `naapp/logs` (package `aweb_logs`), `aweb-app.json`, `naapp/logs/Dockerfile` (af1457baf, 74115acfd) |
| L2 | aweb-acgh.16.20 | Ingest admission | Built (active registrations only) | `naapp/logs/src/aweb_logs/ingest.py`, `migrations/001_chain.sql`, `migrations/002_client_quotas.sql` (bf3c36d6c) |
| L3 | aweb-acgh.16.21 | Chain, receipts, checkpoints, verify | Built | `aweb_logs/chain.py`, `ledger.py`, `verify.py`; `docs/logs-chain.md`, `docs/vectors/logs-chain-v1.json` (af1457baf, bf3c36d6c) |
| L4 | aweb-acgh.16.22 | Owner-gated reads | Open | `ledger.append_on`, the caller-transaction append it needs, ships with L2 |
| L5 | aweb-acgh.16.23 | Retention, erasure, legal hold, export, deletion | Open | the owner-act verifier knows the four logs acts; `verify` reports purged ranges |
| L6 | aweb-acgh.16.24 | `aw logs` | In flight | `cli/go/logschain`, which passes `logs-chain-v1.json` (9ad392cc5) |
| E1 | aweb-acgh.16.25 | Real-path end-to-end | Open | — |
| E2 | aweb-acgh.16.26 | Athena security pass | Open | — |
| X4 | aweb-acgh.12 | Operate hosted logs | Open | — |
| X5 | aweb-acgh.13 | Hosted core hook producer operations | Open | — |

X1, X2, X3 and X6 are carried by hosted-product tasks; this OSS plan does not
record their status (see "Hosted-side items").

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
- **The done-signal** for every task is a reviewer ACK on an exact SHA, landed
  on main through the coordinator's train, with the evidence its acceptance
  names.

## Order of work

1. **The hook contract lands first (phase 1).** It contains the catalog,
   envelope, delivery credential, owner act and binding cases, together with
   their vectors and a Go authority. Nothing downstream freezes a byte without
   it.
2. **The shared kit (phase 2)** goes into `aweb_naapp` behind the
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

## Phase 1: the hook contract

| Id | Task | Status and scope | Review |
| --- | --- | --- | --- |
| H1 | Catalog, binding and delivery contract | **Built (aweb-acgh.16.1).** The catalog `aweb.hooks` v1 with the five hooks, strict flat payload allowlists (the `post-secret-use-hook` fields with the 33 `refusal_code` values, the governance act/direction table, every §A10 mutation type, the client command classes), binding states, `active_from`, ack dispositions, `409 event_conflict` and the audit-critical gate. `docs/aw-hooks-sot.md` states that `on_mutation` is unchanged and is not an audit hook. The catalog is re-frozen in place by decisions 73, 92 and 93 and by `use_ref` (aweb-acgh.16.33). **Open (aweb-acgh.16.35):** core activation refusing an unknown catalog id, version or hook (`hook-binding-cases-v1.json` case `unknown_catalog_cannot_activate`, replayed only by `naapp-lib/tests/hooks/test_binding_cases.py`). | R+A |
| H2 | Envelope and delivery-credential signing family, Go authority | **Built (aweb-acgh.16.2).** `aweb.hook-event/1` and `AWEB-Hook DIDKey` in `cli/go/hookevent`, with their vectors and negatives (§A11). The `team-auth-envelope-v2.json` change is an additive `trace_id` case. Decision 73 removed the obsolete plain-SHA digest demonstration, leaving producer commitments to K4/S13 proofs. | R+A |
| H3 | Owner act `aweb.owner-act/1` | **Built (aweb-acgh.16.3).** `docs/owner-act.md` and `cli/go/awid/owneract.go`: the core acts `hook-binding.activate` and `.revoke`; the generic `app-role.designate`, `app-role.revoke` and `app-credential.recover`; logs' `logs.retention.set`, `logs.erase`, `logs.legal-hold.set` and `.release`. The commit records Juan's approval of `aweb.owner-act/1` as an identity-path change, and `docs/owner-act.md` states the constraint: an owner act is valid only from team controller authority exercised by the organization owner (for BYOT, the controller key holder), and a custodial deployment signs one only after the owner's fresh interactive step-up (decision 1). Adding an act is additive; changing an act's subject requires `aweb.owner-act/2` (decision 28). | R+A |
| — | Owner act `logs.verify.delegate` | **Open (aweb-acgh.16.34).** Juan's ruling on verify delegation: the logs act `logs.verify.delegate` lets an owner delegate `verify` only (decision 5). Deliverables: the `docs/owner-act.md` delta, Go and Python verifiers, `owner-act-v1.json` cases, and the nonce, rollback and substitution proofs on real Postgres. It is additive under decision 28. | R+A |

## Phase 2: the shared kit in `aweb_naapp`

The `hooks` extra in `naapp-lib/pyproject.toml` depends on `awid-service`,
`pgdbm` and `pynacl` only. It never depends on `webauthn`, `fastapi` or
`pydantic-settings`, so core installs it (decision 12). It builds on the
shared `aweb_naapp.outbox`, whose channels let hooks drain on channel `hooks`
(`outbox/migrations/002_outbox_channels.sql`).

| Id | Task | Status and scope | Review |
| --- | --- | --- | --- |
| K0 | Core-importable signing-key loader | **Built (aweb-acgh.6).** Decision 10: `read_signing_key_file` and `parse_signing_key_hex` in `naapp-lib/src/aweb_naapp/signing_key.py`, behind the `signing-key` extra (stdlib plus `pynacl`). One loader for every app key and purpose; fails closed, refuses writable or non-regular files, one 64-hex format, no key material in errors. Core loading its hook key with it is S2's. | R+A |
| K1 | Catalog loader, envelope, delivery credential (Python) | **Built (aweb-acgh.16.4).** `aweb_naapp.hooks` `catalog`, `envelope` and `delivery` pass the H1 and H2 vectors from `docs/vectors`; the packaged catalog is byte-identical to the public one. | R+A |
| K2 | Owner-act verifier | **Built (aweb-acgh.16.5).** `aweb_naapp.hooks.owner_act` checks in the order `docs/owner-act.md` states, reads the current AWID team key fresh, and consumes the nonce in the act's effect transaction (`hooks/migrations/001_owner_act_nonces.sql`). **Open (aweb-acgh.16.28):** moving these nonces onto the shared nonce store `aweb_naapp.nonces` (decision 81). | R+A |
| K3a | Producer: enqueue, gate, transport, core resolver interface | **Built (aweb-acgh.16.6).** `HookProducer.enqueue` signs inside the caller's transaction, mints `event_id` once and takes `producer.seq` per (producer, team, hook); the audit-critical gate; the drain resolver interface (`hook_targets`); `HookTransport` re-checks the binding before each send (`Cancelled` if revoked) and follows the shared egress guard. | R+A |
| K3b | App-producer resolver | **Built (aweb-acgh.16.7).** `aweb_naapp.hooks.resolver` over the runtime's `runtime.hook_resolver()` (decision 69), with the ≤ 60 s fail-closed view. | R+A |
| K5 | Owner-act evidence in the approval primitive | **Built (aweb-acgh.10).** The approval primitive takes `VerifiedOwnerAct` (`runtime/passkeys/service.py`); designation prepares the act before its transaction and consumes it inside. | R+A |
| K4 | `post-manifest-command-hook` firing | **Built (aweb-acgh.16.8).** `runtime/hooks.py` and `runtime/manifest_hooks.py` fire for admitted mutation tool calls, attributable refusals and the production's `reads`, with tool precedence. `request_sha256` is the producer-keyed HMAC of decision 70. K4 owns the runtime producer per installation and the hooks drain, on `runtime.hook_resolver()`. The signed `trace_id` is taken from the verified team-auth payload. | R+A |
| K4 helper | Independent commitment helper | **Built (aweb-acgh.16.8.1).** `aweb_naapp.hooks.commitment` (decision 76), shared by K4 and S13. | R+A |
| P1 | Publish `aweb-naapp` as a release artifact | **Built (aweb-acgh.16.9).** `aweb-naapp` 0.5.1; the server declares `aweb-naapp[egress,hooks]>=0.5.1`. | R |

### Decision 73: secret-use contract re-freeze and S13 dependency

The `post-secret-use-hook` shape is re-frozen in catalog v1 in place because
no deployed producer/consumer or pending use exists. This contract delta
updates the public catalog, its managed package copy, secret-use transition
examples and their consumers together. It adds the paired child secret/grant
creation linkage and specifies separately keyed request/parameter MACs in
`docs/hook-events.md`. The envelope vector's obsolete plain-SHA demonstration
is removed; its signing cases remain unchanged. The contract is on main.

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
**After the first release (aweb-acgh.41):** the child secret/grant pair, since
derived issuance (`store_as_secret`) is parked (decision 95).

### Decision 84: retained passkey proof (aweb-acgh.39)

The shared contract and vector (`docs/vectors/passkey-evidence-v1.json`)
preserve secrets §10.4's independent public-key check:
`approval_evidence_sha256` is SHA-256 of length-framed exact proof, key,
challenge preimage and frozen verification context, with the B2 covered
request bound transitively by its existing hash. No rotating commitment key is
needed. B3 holds the one canonical helper and the retained proof
(`naapp-lib/src/aweb_naapp/runtime/passkeys/proof.py`,
`runtime/passkeys/migrations/003_retained_proof.sql`).

S13 and S14 consume the reviewed helper only. Their tests must distinguish
trusted-key verification from an evidence lookup, preserve client-data bytes
and the challenge's null task-answer spelling, verify request/policy/
installation bindings, reject substituted valid proof, and recompute after
rotation without a retired secret. Counters/timestamps/authority history must
not be overstated as signed facts. Lifecycle deletion limits proof retrieval.

No actor field/mode or catalog wire shape is added. Console governance uses
the identity-free system actor, retaining distinct authorizing and affected
subjects; secret-use keeps its requesting-member actor. Audit target/delivery
availability still never gates narrowing.

### Decision 76: independent K4 helper (aweb-acgh.16.8.1)

The generic helper is `aweb_naapp.hooks.commitment`, shared by K4 and S13.
It provides `CommitmentContext`, complete inbound `RequestBytes`, purpose-tagged
`CommitmentKey.request`/`.params`, and `load_commitment_key` through the common
key-file reader. It imports no runtime, reads no HTTP stream and performs no
upstream rendering. The caller supplies authoritative context and complete
bounded bytes. Parameter bytes come from the caller's existing validated typed
canonical-JSON path under B2's value rules, with no B2 prefix/wrapper; the
helper does not introduce a second parameter codec. Runtime key configuration,
MAC/context persistence, rotation/destruction and authorization-path wiring
are K4's (built) and S13's obligations.

## Phase 3: core server

### Terminal revocation amendment

**After the first release (aweb-acgh.16.30, aweb-acgh.16.32).** The
[terminal delivery contract](../hook-terminal-delivery.md) is on main; its
implementation is parked. At the first release, revocation takes effect
immediately: the owner act revokes the binding row in its transaction,
uninstall revokes the install's bindings, and producers cancel deliveries to
a revoked target on their pre-send re-check. The per-gap explanation below
(final record, cancellation tombstones, `hook_delivery.cancelled`) comes after
the first release. Logs ingest admits active registrations only.

- **Shared kit, used by S2 and every app producer (aweb-acgh.16.30):** one
  transactional end-binding fence shared with enqueue/materialization,
  explicit cancellation tombstones for unmaterialized owed events, protected
  terminal targets in the existing hooks outbox, and cancellation summaries
  scoped to their producer. It supplies nonblocking end fencing, attempt
  CAS/leases and deterministic multi-binding order before terminal S2 wiring;
  a network-held row lock plus `cancel` does not meet the no-ACK-wait rule. Do
  not copy kit SQL or implement another sender/outbox in core. Apply new
  ordered kit migrations through its migration module.
- **Signing/verification (aweb-acgh.16.32):** Go-generated public
  terminal-authorization, terminal-credential and binding-seal vectors, with a
  Python consumer in the shared hooks kit. Create the three vector files in
  the shared vector directory and register their Go generator and Python
  consumers with their implementations, rather than adding unconsumed
  placeholder bytes. Preserve all existing ordinary event/delivery cases. A
  current core transport key can retry a historically signed event/capsule;
  each uses its specified window.
- **S2:** atomically commit lifecycle state, local backlog accounting,
  immutable terminal event/capsule and fixed target; integrate owner revocation,
  uninstall and generation supersession. Other sinks get the identical event
  envelope. A target registered for another hook still receives its own final
  record. A never-active target receives none. No ACK gates containment.
- **L2:** cold verification without a current installed read credential;
  exact terminal dispatcher and endpoint binding; per-binding seal and team
  event dedup in one transaction. An event previously appended via another
  binding must seal the addressed binding and return the original receipt,
  with no second append. A receiver-signed seal acknowledgement, bound to the
  exact event/capsule and original receipt, commits with the seal even on that
  duplicate path. Unsigned flags or an older event receipt cannot prove
  completion. The seal's cross-clock bounds reuse the 300-second policy and
  the producer's current response-receipt clock, not an older chain receipt;
  stored ACKs remain reusable on delayed retries. Ordinary activation without
  the optional new receipt purpose stays valid; missing authority makes only
  terminal completion unacknowledgeable. Ordinary admission serializes with
  sealing.
- **Cancellation evidence:** both catalog copies and payload cases are a
  deliberate v1 re-freeze under decision 93, recorded in the terminal
  contract, and are on main. `hook_delivery.cancelled/outbox_state` records
  require shared range-arithmetic, source-producer and system-actor checks in
  addition to the existing data-driven catalog parser. Missing producer
  evidence remains an unexplained gap; no implicit attribution is permitted.
- **Acceptance:** real transactional rollback, unmaterialized backlog,
  concurrent drain/ACK and seal/append races, pad exception, different hook,
  cold uninstall, supersession, separate new generation, historical-key/current
  retry-key rotation and failed current anchoring remaining an outstanding
  reconciliation obligation. E1 revocation includes the actual shared
  producer/receiver path; helper-only or a warm cache is insufficient.

The three fit checks are logs, app-team-api and hooks-producer. They precede
independent naapp review and Athena on the exact implementation delta.

| Id | Task | Status and scope | Review |
| --- | --- | --- | --- |
| S1 | `app_hook_bindings` and owner activation | **Built (aweb-acgh.16.10).** Install or update writes pending rows from the digest-pinned manifest bytes (`write_manifest_bindings_on`); a new generation supersedes, and uninstall revokes. `POST /v1/apps/hook-bindings/{binding_id}/activate` and `/revoke` take an owner act verified by K2 with core's closed vocabulary, whose subject must equal the stored row; the nonce is consumed in the binding's transaction. `active_from = activated_at + 60 s`. Activation refuses a binding without `installation_id` and generation, and a production unless its install was registered from the pinned bytes with a `hook-event` key. **Open (aweb-acgh.16.36):** activation of a `post-mutation-hook` registration requires a valid current core signer, per the [core-signer readiness correction](../hook-signer-unavailable.md); otherwise `409 core_hook_producer_unconfigured`, consuming neither the nonce nor the activation. Main has no such check. | R+A |
| S2 | Core producer | **In flight (aweb-acgh.16.11):** the public half is on main, the producer is not. On main: the core producer's public keys `{kid, did_key, valid_from, valid_until}` from `AWEB_HOOK_PRODUCER_KEYS` (`server/src/aweb/config.py`), served at `GET /v1/hooks/producer-keys`. Remaining:<br>- **Key:** the private core key is operator configuration, loaded by the decision-10 loader (key file by `kid`, refusing writable or non-regular files). It is never a team, controller or agent key.<br>- **Kit:** core applies the kit's outbox migrations to its schema as new ordered migrations and runs the hooks drain in the server lifespan, with an in-process resolver over S1.<br>- **Gating:** an ordinary event is owed only when a fresh view shows an eligible active registration. With a valid signer it shares the mutation transaction; signer unavailability instead commits a typed missing-production sequence reservation with the mutation, per the [signer-loss correction](../hook-signer-unavailable.md) (aweb-acgh.16.31). No unsigned event is sent, and no target is required. Outbox/sequence storage and every scanner distinguish reservations from signed events, through a new ordered kit migration.<br>- **`trace_id`:** a signed `trace_id` member is taken as `signed_request`; otherwise one is minted and marked `producer`.<br>- **Same transaction:** owed `hook_binding.activated` and `.revoked`, and `app.installed` and `.updated`, share the act's transaction as a signed event or, with an unavailable signer, a typed reservation. `activate_binding` and `revoke_binding` take the `in_transaction` callback for this; the routes pass none on main.<br>- **After the first release (aweb-acgh.16.32):** the revoked target's final entry, cancellation of its backlog, and the gap-explaining governance event to the remaining registrations (§A3).<br>- The `on_mutation` seam is unchanged. | R+A |
| S3a | Sites vector, checker and task mutations | **Open (aweb-acgh.16.12).** The vector docs/vectors/post-mutation-hook-sites-v1.json and a second scan in `scripts/check-extension-docs.py`: a literal `mutation_type`, the call lexically inside a transaction block, and counts that match in both directions. The `on_mutation` mapping covers every row of `mutation-hook-call-sites-v1.json` (each mapped or excluded with a reason), and a new `on_mutation` event fails the build. Task mutations `task.created`, `.updated` (one event per update, with `changes`), `.deleted`, `.comment_added` and `.dependency_changed` are enqueued at the service layer; comment and dependency become transactional. A test drives the MCP task tools through the service layer. | R |
| S3b | Messaging mutations | **Open (aweb-acgh.16.13).** In `server/src/aweb/messaging/`: mail send without attachments and ack become transactional; `mail.sent`, `mail.acknowledged` and `chat.message_sent` are enqueued in the effect's transaction from REST and MCP; no bodies, subjects or previews; a failure injected after the insert rolls both back. | R |
| S3c | Identity, app, key and membership mutations | **Open (aweb-acgh.16.14).** `identity_grant.minted` and `.revoked`; `app_key.revoked` in the transaction that sets `revoked_at`, on the per-team key-revoke route (aweb-acgh.17.6; the event is aweb-acgh.17.7); `membership.connected` (`connect` becomes transactional); `membership.workspace_retired` (in the lifecycle cascade); `task.answered` at D1 C2's answer site (aweb-acgg.8), as its own row in the vector. | R |
| S4 | Membership observer (M3) | **Open (aweb-acgh.16.15).** Decision 6. It runs only for teams with an active `post-mutation-hook` registration and reads the team's certificate history from its home AWID with the documented same-operator read credential (`docs/awid-sot.md`), moving to a narrow per-capability read grant once the service-token split lands. It enqueues `membership.certificate_issued` and `_revoked`, marked observed with AWID's timestamps and certificate digest, in the transaction that advances an ordered-migration cursor. A restart resumes without loss or duplicates. The documented limit is that a private team on a foreign registry is not observed. | R+A |

### Core signer-unavailable correction (aweb-acgh.16.31)

The [contract correction](../hook-signer-unavailable.md) is on main. It
specifies typed local reservations when a core event is owed but cannot be
signed, and adds no catalog event type or recovery-signing path. Its
implementation is S2's: S2/shared-kit acceptance must cover real HTTP
activation, revocation and ordinary mutations with absent, runtime-expired and
valid signers; atomic sequence/reservation rollback; scanner exclusion; later
unexplained holes; and the unprovable trailing-loss limit. Terminal
obligations stay owner/operator visible without a fabricated final entry or
seal. Diagnostics use the existing store, one fault per state and a
configurable warning lead of seven days by default, with no validity grace.
Reviewed runtime proof remains necessary before activation.

## Phase 4: `aw` client

| Id | Task | Status and scope | Review |
| --- | --- | --- | --- |
| C1 | `trace_id` minting and propagation | **Open (aweb-acgh.16.16).** In the `cli/go` team-auth request builder: one W3C trace id per command invocation, in the signed `trace_id` member of every request the command makes (core and manifest tools), never inside `operation`. The H2 `trace_id` case passes. A server at an older version accepts the request unchanged (a test against the released verifier behaviour). | R+A |
| C2 | `post-command-hook` | **Open (aweb-acgh.16.17).** A `cli/go` local outbox, resolver and delivery. It fires only for the catalog's command classes with local effects; reads fire nothing. Events are signed by the member key with actor equal to signer, and delivered with the team certificate to client-class registrations listed through acgh.7 (aweb-acgh.17.18). The local outbox survives a crash; a deleted outbox loses events by design, and the docs state that client events are agent-reported. | R+A |
| C3 | Owner-act commands | **Open (aweb-acgh.16.18).** `aw hooks bindings`, `aw hooks activate`, `aw hooks revoke`, `aw app role designate`, `aw app role revoke`, `aw app credential recover` in `cli/go/cmd/aw`, on the library `cli/go/awid/owneract.go`. Before signing, the client fetches the manifest bytes from the origin, checks the pinned digest, resolves the tool, and shows the owner the hook, tool, scopes, `reads` and target. It sorts and de-duplicates scopes and `reads`, which the verifier requires (d76a7d253). Acts are signed under the existing controller custody (BYOT or local); a member without the controller key gets a distinct refusal. Test: the real path against a local AWID and server, through activation. | R+A |

## Phase 5: logs (`naapp/logs`)

Logs is app-local (design §C). It uses the B1 verifier, acgh.4 passkeys and
approvals, the K kit and acgh.7's client unchanged. Its package is `aweb_logs`.

| Id | Task | Status and scope | Review |
| --- | --- | --- | --- |
| L1 | App skeleton | **Built (aweb-acgh.16.19).** Manifest v2 (`naapp/logs/src/aweb_logs/aweb-app.json`) declares `ingest` with `invocation_contexts: ["hook"]`, registered on all five v1 hooks, with no app-event subscriptions. Logs' own receipt and checkpoint key is loaded by the decision-10 loader, on the shared runtime; the Dockerfile serves the `aweb_logs.app:serve` factory. | R |
| L2 | Ingest admission | **Built (aweb-acgh.16.20)** for active registrations: `aweb_logs/ingest.py` admits in the design's §B2 order, each step with a distinct error (transport, own binding with 503 when authority is unavailable, provenance, schema, dedup, append); records key evidence with each event; enforces per-member client quotas (decision 91: 30 events and 128 KiB per minute by default, configurable); refuses a forged core event from an origin not anchored through acgh.7. **After the first release (aweb-acgh.16.32):** terminal admission and sealing. | R+A |
| L3 | Chain, receipts, checkpoints, verify | **Built (aweb-acgh.16.21).** `aweb_logs/chain.py` and `ledger.py`: commitments, `event_hash`, gap-free `team_seq` under a head-row lock, genesis and epochs; `aweb.logs-receipt/1` and `aweb.logs-checkpoint/1`, specified in `docs/logs-chain.md`; periodic checkpoints (`checkpoint_moved_heads`). `aweb_logs/verify.py` reports intact, broken, missing, purged with its act, per-producer and per-hook seq gaps inside binding intervals, conflicts, and contradicted receipts and checkpoints. `docs/vectors/logs-chain-v1.json` carries the negatives. | R+A |
| L4 | Owner-gated reads | **Open (aweb-acgh.16.22).** Readers and the viewer on logs' origin:<br>- **Designation:** each reader is designated by `app-role.designate` through K2 into its own role slot `logs.reader.<hex>`, a random 128-bit opaque value bound before the owner signs. Removing the last reader with team-auth alone is refused, counted across slots.<br>- **Passkeys:** enrolment and login come from B3's passkey primitive on logs' origin. The session is bound to (subject, scope) and ends when the designation is superseded or the credential revoked. The `login_options` route rate-limits per (scope, client) in the app and meters its volume per scope.<br>- **Viewer:** `query`, `tail`, `verify`, `checkpoint` (on demand) and `export` run only in such a session. A member signature, a hosted session or an MCP identity is refused.<br>- **Delegation:** decision 5: delegated `verify` returns no content, and delegated `query` does not exist. The delegation is the owner act `logs.verify.delegate` (Juan's ruling on verify delegation; the act is aweb-acgh.16.34).<br>- **Self-administration:** by the coordinator's ruling on reader self-administration, reader changes are ordinary `post-governance-hook` events: logs' manifest declares the production, the owner activates it, logs signs with a separate `hook-event` kid, each change is one `event_id` through the shared producer, and the chain append joins the caller's transaction (`ledger.append_on`, on main). There is no local-only path.<br>- **Projections:** the §B4 query projections and the derived `mediation` field.<br>- **Surface:** a D1 surface shows no content and only a `link_out` to logs' own origin.<br>- **Copy:** the viewer marks client events as agent-reported, never as mediated fact, and states that a revoked target may see up to 60 s of further redacted activity. | R+A |
| L5 | Retention, erasure, legal hold, export and deletion | **Open (aweb-acgh.16.23).** `logs.retention.set`, `logs.erase` and `logs.legal-hold.*` require owner acts (the verifier knows them on main). Purge removes content, salt, projections, indexes and caches and keeps the skeleton (`purge_act` in `001_chain.sql`); `verify` reports the range and its act. The hosted default is to keep with no automatic expiry (decision 16). A restored database reapplies purge tombstones before it serves. Export produces a self-verifying bundle. Deletion runs as D1's durable job (D1 N1, aweb-acgg.13) and keeps the final checkpoint and a receipt. | R+A |
| L6 | `aw logs` | **In flight (aweb-acgh.16.24):** the Go offline chain verifier is on main, the command is not. On main: `cli/go/logschain`, which passes `logs-chain-v1.json`. Remaining: `aw logs query`, `tail`, `verify` and `export` in `cli/go/cmd/aw`; a device-style flow on logs' origin with the reader's passkey yields a short-lived session bound to an ephemeral CLI key; `aw logs verify --bundle` works offline. | R+A |

## Phase 6: end-to-end and security pass

| Id | Task | Status and scope | Review |
| --- | --- | --- | --- |
| E1 | Real-path end-to-end | **Open (aweb-acgh.16.25).** The Docker e2e harness, over TLS, runs real AWID, aweb, logs, one fixture producer naapp, and `aw`, on a disposable BYOT fixture team whose credentials are referenced by name. The owner activates the logs registration and the fixture production with real owner acts. A core mutation from REST and from MCP appears in the chain, and `verify` reports intact. An audit-critical event with no eligible target is refused (also inside the pad); a narrowing act passes with no target. Revoking a target stops delivery to it; its final entry and an explained gap elsewhere are after the first release (aweb-acgh.16.32). The target-switch order between two logs installs with distinct app ids loses nothing. A client event is shown as agent-reported, and forged core and app events are refused. Conflicting bytes are recorded as a fault, a drain crash causes no loss and no duplicate effect, and a purged range still verifies. It runs only after the coordinator lifts the heavy-run hold. | R+A |
| E2 | Athena security pass | **Open (aweb-acgh.16.26).** Findings on owner-act custody, provenance at ingest, egress, redaction and erasure are resolved on the implementation deltas. | A |

## Hosted-side items (custodial deployment)

Each item is stated generically here. X1, X2, X3 and X6 are carried by
hosted-product tasks, which hold their status. X4 and X5 are operations tasks
on this board.

| Id | Requirement | Carried by | Depends |
| --- | --- | --- | --- |
| X1 | Sign `aweb.owner-act/1` for a managed team only for the organization owner (never an organization admin), after a fresh interactive step-up (passkey or re-authentication). It is never signed with a stored credential, an API key or an MCP token. The signer is a narrow provisioning signer, not controller-key material loaded into every web or worker request process. The owner copy discloses that the custodian can mint owner acts (decision 1; Juan's ruling: organization owners only). **Acceptance:** for a managed team, an organization admin's gesture, a stale session without step-up, and an API or MCP credential are each refused, and no owner act is signed. | D1 L1, aweb-acgg.21, and L3, aweb-acgg.22 | H3, K2 |
| X2 | Hosted MCP mints one `trace_id` per tool call and signs it in the team-auth payload. It never lists or calls `hook`-context tools and logs no parameters or results. | D1 L2, aweb-abzo | H2, C1 |
| X3 | The `aweb.principal-attestation/1` custody and principal attestation (secrets design contract). It is a launch requirement, and policy that needs it refuses until it ships (decision 2). The hosted principal attestation (HO2) is a launch gate. | carried by D1 L1 (aweb-acgg.21), attached by D1 L2 (aweb-abzo) | secrets-lane contract |
| X4 | **Open (aweb-acgh.12).** Run the hosted logs installation: its own origin and key custody, the decision-16 retention default, an evidenced backup-expiry deadline with tombstone reapplication on restore, and inbound reachability for producers. | aweb-acgh.12 | L1–L5 |
| X5 | **Open (aweb-acgh.13).** Core hook producer key configuration and rotation, with retired keys kept listed. Also the same-operator AWID read credential for the M3 observer, the drain worker in the deployed server, and the operator-disclosed delivery horizon. | aweb-acgh.13 | S2, S4, P1 |
| X6 | Publish and backfill `aweb.team-server/1` records for every team whose controller key the deployment holds, before any naapp depends on discovery (decision 3). | D1 L6, aweb-acgg.31 | acgh.7 G1-a |

## Decision 94: refusal recording and shared admission backlog

Built in K4 (`naapp-lib/src/aweb_naapp/hooks/producer.py`,
`outbox/migrations/003_admission_backlog.sql`, 28480ac71).
`HookProducer.enqueue_refusal` and `require_admission` are K4's, and S13
reuses them. The refusal path preserves validation, signing, transaction and
delivery eligibility, exempting only target/backlog gating and permitting no
external effect. No-target refusals have zero owed deliveries, with no
retroactive delivery to a later target. S13 retains its operational/console
record. The local admission check requires a fresh matching view and at least
one current eligible target, counting unmaterialized backlog; it maintains no
parallel tracker. The outbox migration adds its admission-read indexes.
Runtime attachment uses the one decision-69 resolver.

## Decision 92: observed backend versions

The shared catalog maps a successful validated backend observation to
`post-governance-hook` / `resource.version_observed`, non-widening (`narrowing`)
with exclusive `backend_observation` authority. Its refs name the scoped secret
and old/new opaque local versions. Invalid shape or missing/deleted references
activate nothing: pre-S3 use refusals carry `secret_value_invalid` or
`custody_unavailable`; after `dispatching` commits, a final reread failure is
`not_sent`, without a refusal code. See the normative
[observed-version contract](../hook-events.md#observed-backend-versions-decision-92).
The catalog entry is on main.

M1/M2/S13 retain implementation ownership: prove immutable reference/shape,
monotonic version/CAS and stale-no-event behavior, complete prelocks, old approval
and token-cache invalidation, fresh next-use policy, system attribution and
transition/outbox atomic rollback. Target/delivery unavailability never gates
the non-widening transition; storage failure still refuses the use. Shared
codec/ingest support must precede emission. Contract vectors and focused codec
checks do not substitute for these producer and end-to-end release proofs.

## Cross-lane dependencies

- **aweb-acgh.6:** the outbox `channel` addition and the shared egress guard
  (`aweb_naapp.egress`), both on main.
- **aweb-acgh.7:**
  - G1-b: keys from pinned bytes (on main; production activation checks
    them); the per-team key revoke, **Open (aweb-acgh.17.6)**;
  - G1-c: `TeamServerDirectory` (`aweb_naapp.runtime.team_server`, on main);
  - G1-d: resolution endpoints, own bindings and producer keys
    (`server/src/aweb/routes/app_hooks.py`, on main); the member client-class
    listing, **Open (aweb-acgh.17.18)**.

  G1-d itself depends on S1.
- **The decision-10 app-key loader** sits in `aweb_naapp.signing_key`, which
  core can import without the runtime extra, because S2 loads the core hook
  key with it.
- **aweb-acgh.8:** step 1 (team-scoped registrations, `manifest_registration()`
  in `server/src/aweb/app_registry.py`).
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
