# secrets build plan

Status: **build plan for review, aweb-acgh.2 (epic aweb-acgh).** It implements
the accepted design [secrets.md](secrets.md) and the decisions recorded in its
§18. It contains no code. The coordinator creates the board tasks and staffs
them after review. No task has a time estimate.

Section references such as §7.3 point into `secrets.md`. "D1" is the generic
naapp design `docs/design/agent-pages.md`, merged to aweb main at c0864028 and
approved by Juan; its build tasks are aweb-acgg.5–.31 and aweb-abzo. "Hooks
design" is `docs/design/audit-substrate.md` on
`agents/aweb-protocol-expert-hooks-design`.

## 1. Rules for every task

- **Strict TDD.** Write a failing test first, see it fail, then make it pass.
  Tests assert behaviour, never wording.
- **No mocks of the thing under test.** Unit and integration tests run against
  a real Postgres through pgdbm test fixtures. Network tests use real local
  servers that the test starts, with a real resolver and real TLS. End-to-end
  tests (S20) use no mocks at all.
- **Both directions.** Each boundary is tested with a valid neighbouring case
  and the refused case (§16). Each harness states whether it was shown to fail
  for the fault it targets.
- **No secret values anywhere.** That covers fixtures, logs, evidence, task
  comments and mail. Test credentials live in the operator's secret store and
  are referenced only by name.
- **Schema changes** are new ordered pgdbm migrations. Existing migrations are
  never edited.
- **Shared code is generic.** Nothing in `aweb_naapp` names secrets, pages or
  any other app. Its runtime dependencies sit behind an extra, following B1's
  packaging seam.
- **Naming.** The app package is `aweb_secrets`, never `secrets`, because a
  top-level `secrets` package would shadow Python's standard library module.
  The runner package is `aweb_secrets_runner`.
- **Landing.** Single-repository changes merge after their reviewers ACK, per
  the active team instructions. The coordinator integrates cross-repository
  combinations, release tags and production tooling.

**Seats.** Every task names one seat type, and every seat runs Claude Opus 5.5.

- **P**: `aweb-protocol-expert`. Signed artifacts, identity keying, protocol
  vectors, and anything an outside implementation must reproduce byte for byte.
- **E**: `aweb-expert`. Application and shared-runtime implementation.

**Review classes.**

- **R**: one non-author reviewer.
- **R+A**: one non-author reviewer plus Athena. Every task that touches
  credentials, custody, authentication, approvals, the audit path or the network
  boundary is R+A.
- **+D1** adds the D1 lead's fit check, for shared pieces that pages also
  consumes and for manifest v2 use.

**Done-signal.** The same for every task unless the task says more: the
acceptance tests pass on the named branch, the required reviewers ACK, and the
author mails the coordinator the exact SHA with the evidence.

## 2. Order of work

```text
Phase 0  Hook contract (hooks lane, X1)  +  S0 secrets contract vectors
            │
Phase 1  Shared aweb_naapp pieces, in parallel:
            S1 egress guard · S2 idempotency store · S3 dispatch state machine
            S4 console session · S5 role assignments · S6 principal attestation
            │
Phase 2  secrets app (naapp/secrets), in dependency order:
            S7 skeleton → S8 records and admission → S9 custody
            S10 console and change sets → S11 broker path → S12 approvals
            S13 dispatch and audit → S14 containment → S15a/S15b runner
            S16 tool surface → S17 usage
            │
Phase 3  S18 deploy · S19 E2E target and harness · S20 E2E suite
            │
Launch   S21 gate: logs ingests real events end to end (X14), attestation
         issued (S6 + HO2), Athena's final review, Juan's go
```

- **The hook contract lands first** (decision 11). Phase 1 can start alongside
  it, because none of S1–S6 emits hook events. S3 exposes the enqueue points as
  calls made inside the caller's transaction, and S13 fills them with the
  hooks-lane kit.
- **Generic pieces land in `aweb_naapp` before the app uses them.** The app
  never carries a private copy first. If a Phase 2 task needs a shared piece that
  has not landed, it waits for it.
- **aw-hooks, logs and secrets build in parallel** after the hook contract. The
  secrets app can be built and tested against a real hook target (S19) before
  logs exists. Launch waits for logs (S21).

## 3. Dependencies on other lanes (X)

These are owned elsewhere. secrets tasks list them by ID.

| ID | What secrets needs | Owner | State on 2026-10-19 |
| --- | --- | --- | --- |
| X1 | **Hook contract.** Catalog v1 vector with the `post-secret-use-hook` action enum, payload allowlist and `refusal_code` enum, and the `post-governance-hook` act and direction table; envelope `aweb.hook-event/1` and its vectors; `aweb.owner-act/1` and its vector; binding cases with the `active_from` pad. | hooks lane (aweb-acgh.1) | Design at 31206a4d, whose `disposition` enum matches Q8. H1 freezes the catalog from it. |
| X2 | **Hook kit in `aweb_naapp`** behind its own extra: envelope signing, producer outbox with enqueue inside the effecting transaction and `event_id` minted once, drain and delivery client, hook-delivery credential. | hooks lane with B4 (aweb-acgh.6) | The generic outbox is on main. The hook kit is not. |
| X3 | **Owner-act verifier** in `aweb_naapp`, and acgh.10: `Passkeys.designate()` accepts only the verifier's type. | hooks lane; aweb-acgh.10 | Open. No production app may expose owner-gated designation before it. |
| X4 | **B1 verifier** with scope enforcement, the policy hook and `Principal.did_aw`. | aweb-acgh.3 | Closed. `did_aw` is in the principal output on main. |
| X5 | **B2+B3**: admission inside the caller's transaction, `revoke_many`, lockout timings (24 h contact change, 72 h cooling-off) as policy parameters, and the last-owner protection. | aweb-acgh.4 | In progress. `revoke_many`, transactional admission and both timings are on its branch. S10 confirms the last-owner protection (`last_owner_protected`) is there, or asks acgh.4 for it. |
| X6 | **App → team-server API**: server discovery through the approved `aweb.team-server/1` record, purpose-split app auth, grant status with installation ID and generation, and hook resolution that reports `active_from` within the 60 s freshness bound. | aweb-acgh.7 | In progress. The custodial deployment backfills existing teams before any naapp depends on discovery (decision 3). |
| X7 | **App keys**: the emit-key scoping fix (acgh.8) and the one app-key loader (decision 10: kid to key file, fail closed at startup, one 64-hex format). | aweb-acgh.8; loader owner to be assigned by the coordinator | acgh.8 in progress. The loader has no task yet. |
| X8 | **Manifest v2** (D1 C3): `invocation_contexts`, `hooks.productions`, `app_keys` with purposes, the Python serving helpers, and the Go interpreter in `aw` that renders open-request body parameters as flags. | D1 C3, aweb-acgg.9 | In progress. |
| X9 | **Installation identity** (D1 F6): `installation_id`, generation, install state and the admission fence. | D1 F6, aweb-acgg.5 | Open. |
| X10 | **Page format with `link_out`, and the shared renderer** (D1 C1, R1). Juan accepted `link_out`, restricted to the installed app's own origin. | D1 C1, aweb-acgg.7; R1, aweb-acgg.20 | C1 in progress; R1 open. |
| X11 | **Usage contract** `aweb.usage/1` (D1 C5). | D1 C5, aweb-acgg.11 | Open. |
| X12 | **B1b, the did:aw current-key profile.** Not needed for launch: policy that requires a registry-verified principal refuses until it lands (§4.1). | aweb-acgh.11 | In progress. |
| X13 | **The hosted-operator items in §4.** | the board refs listed there | — |
| X14 | **logs ingests real events end to end.** This is the launch gate (decision 11). | hooks lane (logs); hosted logs operation, aweb-acgh.12 | Not built. |

**One mismatch to settle with the D1 lead.** D1 §11's A2 row (aweb-acgg.26) says the external
adapter builds on shared "auth injectors" and "response redaction". Under Q16
those stay app-local in secrets until a second consumer uses them. The egress
guard, dispatch state machine and idempotency store are shared now. If pages'
A2 needs injectors or redaction, A2 is that second consumer, and the piece
moves to `aweb_naapp` as part of A2's work.

## 4. Requirements on a hosted operator (HO)

These are stated generically, as requirements on any custodial deployment or
hosted operator. HO1–HO4 already have board tasks; the plan cites them and adds
no new item for them. HO5 and HO6 operate the secrets deployment itself, in the
way aweb-acgh.12 operates hosted logs. They have no board task yet, and the
coordinator routes them.

| ID | Requirement | Board ref | Needed by |
| --- | --- | --- | --- |
| HO1 | **Owner acts on fresh interactive step-up.** The custodial deployment signs `aweb.owner-act/1` only for an organization owner, and only after a fresh, interactive step-up, never with a stored credential, API key or MCP token. It discloses that the custodian can mint owner acts. | L1, aweb-acgg.21 | S10 bootstrap and recovery |
| HO2 | **Principal attestations** (`aweb.principal-attestation/1`, §4.6) issued under the S6 contract for every request signed under custody, with the issuer key registered as a custodian. L1 carries it; L2 attaches it to MCP calls with `channel: mcp_l2` and the OAuth human handle. | L1, aweb-acgg.21; L2, aweb-abzo | S8 `requires_attestation`; launch (decision 2) |
| HO3 | **L2 exposure follows `invocation_contexts`.** List and call only `agent` tools, mint `trace_id` per call, and never log tool parameters or results. | L2, aweb-abzo | S16, S20 |
| HO4 | **The secrets surface and `link_out`** rendered by the member page surface, with `link_out` opening only the installed app's own origin. | L3, aweb-acgg.22 | S16, S20 |
| HO5 | **Operate the secrets deployment.** Two hosts: the agent API origin and the console origin, with the WebAuthn RP ID equal to the exact console host. A KMS key whose policy lets only the service role decrypt or generate keys. Workload identity to KMS where the platform offers it. An egress allowlist proxy where the platform offers one. A transactional email provider. Core dumps disabled. The KMS provider and these platform facts are Q2, still open; they are inputs to S9 and S18. | none yet | S9, S18 |
| HO6 | **E2E environment.** A KMS key for E2E only; a dedicated 1Password test vault and a service account read-only to it; a dedicated AWS test account and role for the STS case; a host for the S19 test upstream, and a DNS name under our control that answers with a private address. Every credential sits in the operator secret store and is referenced by name. | none yet | S19, S20 |

Team-server discovery also depends on a hosted item: publishing and backfilling
`aweb.team-server/1` (L6, aweb-acgg.31, after acgh.7). secrets reaches it
through X6.

## 5. Tasks

### S0. secrets contract vectors

- **Seat:** P. **Review:** R+A.
- **Repo/path:** `naapp/secrets/vectors/`, with tests in
  `naapp/secrets/tests/`.
- **Depends on:** X1 (to match the action mapping), B2's canonical-bytes rules
  (X5).
- **Scope:** freeze positive and negative vectors for secrets' own contracts:
  - `aweb.secrets.use-approval/1` and `aweb.secrets.change/1` canonical bytes
    (§10.4, §6.3), including integer minor-unit amounts and a refused float;
  - the runner protocol: `aweb.secrets.runner-request/1` and
    `aweb.secrets.runner-assignment/1` signatures, the HPKE suite and `info`
    binding (§9.3);
  - URL canonicalization and destination matching (§7.2): every case in the §16
    scope row, IDNA A-labels, the wildcard rules and the refused encodings;
  - the transition-to-action table (§11.5) as data the S13 tests read.
- **Acceptance:** each vector has a test that consumes it. Negatives include a
  wrong domain prefix, a non-canonical encoding, a duplicate key, a float, an
  assignment for another runner and an expired assignment. The mapping table
  names only actions and refusal codes that exist in the X1 catalog.
- **Done-signal:** vectors frozen by a reviewed commit. Later changes are a new
  version.

### S1. Egress guard in `aweb_naapp`

- **Seat:** E. **Review:** R+A, +D1 (pages' A2 is the second consumer).
- **Repo/path:** `naapp-lib/src/aweb_naapp/egress/`, behind an extra.
- **Depends on:** S0's URL vectors.
- **Scope:** §7.2–§7.4 and the bounds in §7.3, generic: canonical URL,
  destination matching, the app's own resolver with every A and AAAA record
  checked against the denied ranges, one pinned validated address with SNI and
  `Host` set to the canonical name and certificate verification that cannot be
  turned off, redirects returned rather than followed, no proxy from the
  environment, a header allowlist with an always-rejected set the caller can
  extend, connect and total timeouts, body and response bounds, and the
  `internal_destinations` deploy setting.
- **Acceptance:** the S0 URL vectors pass. Against real local DNS and TLS
  servers started by the tests: a name resolving to each denied range is
  refused, including IPv4-mapped, NAT64, 6to4 and Teredo forms; a name with one
  public and one private record is refused; a DNS answer that changes between
  check and connect cannot change the connected address; a 3xx is returned with
  `Location` intact for the caller to redact; `HTTPS_PROXY` in the environment
  has no effect; `internal_destinations: disabled` refuses a `network: internal`
  entry and an IP literal; an exact allowed CIDR passes only under `allowed`.
  The guard has no app names.

### S2. Idempotency store in `aweb_naapp`

- **Seat:** E. **Review:** R, +D1.
- **Repo/path:** `naapp-lib/src/aweb_naapp/idempotency/` with its migration.
- **Depends on:** none.
- **Scope:** keys scoped by an app-chosen tuple (secrets uses installation,
  principal and `request_id`), the canonical request hash, the stored receipt
  reference, per-app retention, `409 idempotency_conflict` for different bytes
  and `410 idempotency_expired` after retention. The store is used inside the
  caller's transaction.
- **Acceptance:** same key and bytes return the stored receipt; different bytes
  return 409; an expired key returns 410 and never re-executes; parallel
  inserts of one key yield one winner; the insert rolls back with the caller's
  transaction.

### S3. Dispatch state machine in `aweb_naapp`

- **Seat:** E. **Review:** R+A, +D1 (pages' A2).
- **Repo/path:** `naapp-lib/src/aweb_naapp/dispatch/` with its migration.
- **Depends on:** S2; X5 (admission inside the caller's transaction).
- **Scope:** §11.1–§11.4, generic: the states and transitions; a fence callback
  run under a row lock in the transaction that writes `dispatching`; `completed`
  and `not_sent` as compare-and-set from `dispatching` only; a sweeper whose
  threshold exceeds the maximum dispatch time plus a margin; late results kept
  as reconciliation evidence; the retry block on an unreconciled
  `outcome_unknown` for the caller's (subject, action) pair, with an exemption
  the caller declares; enqueue callbacks invoked inside each transition's
  transaction so a failed enqueue rolls the transition back.
- **Acceptance:** a crash after `dispatching` is swept to `outcome_unknown`; a
  dispatch still within its time bound is never swept; a late result after the
  sweep does not overwrite it; a `not_sent` retry keeps the same dispatch ID; a
  failing enqueue callback leaves the previous state; a failing fence callback
  refuses before `dispatching`; a new request on a blocked pair is refused until
  reconciliation.

### S4. Console session in `aweb_naapp`

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp-lib/src/aweb_naapp/console/`.
- **Depends on:** X5 (B3 assertion verification).
- **Scope:** passkey login through B3 with user verification required; a
  session of at most 15 minutes in a host-only `__Host-` cookie with
  `SameSite=Strict` and `HttpOnly`; a CSRF token on every state-changing
  request; the console response headers (strict CSP, `frame-ancestors 'none'`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`); refusal of any
  team-auth header on console routes.
- **Acceptance:** with a browser virtual authenticator, login succeeds with UV
  and fails without it; an expired session is refused; a POST without the CSRF
  token is refused; a cookie with a `Domain` attribute is never set; a team-auth
  request to a console route is refused.

### S5. Role assignments keyed by stable principal in `aweb_naapp`

- **Seat:** P. **Review:** R+A, +D1 (pages resolves role targets the same way).
- **Repo/path:** `naapp-lib/src/aweb_naapp/roles/` with its migration.
- **Depends on:** X4.
- **Scope:** §4.1 step 3 and §4.2: the principal key `(team_id,
  member_did_aw)` when the certificate carries it, else `(team_id,
  member_did_key)`; app-named roles; assignments to principals and role
  membership lookups. Nothing calls the key registry-verified.
- **Acceptance:** a reissued certificate under the same `did:aw` keeps its
  assignments; the same `did:aw` on another team gets nothing; a new local key
  is a new principal; a certificate without `did:aw` keys by `did:key`.

### S6. Principal attestation contract

- **Seat:** P. **Review:** R+A. **Approval:** this is an identity-path change.
  Juan's explicit approval is recorded in the commit before it lands; a
  reviewer's ACK is not that approval.
- **Repo/path:** the AWID custodian record (AWID service and `docs/awid-sot.md`),
  the artifact format and vectors (`docs/`, `test-vectors/`), and the verifier
  in `naapp-lib/src/aweb_naapp/attestation/`.
- **Depends on:** X4. HO2 implements the issuing side against this contract.
- **Scope:** §4.6: the controller-signed AWID record that registers a
  custodian's issuer key for a member; the `aweb.principal-attestation/1`
  canonical bytes, claims and `X-AWEB-Principal-Attestation` transport; a
  verifier that checks the issuer against AWID, expiry and the request binding.
- **Acceptance:** vectors cover a valid attestation and each refusal: unknown
  issuer, issuer not registered for that member, expired, binding over other
  request bytes, wrong domain prefix, a custodian record not signed by the
  controller. The verifier never reports self-custody. The design text in
  `secrets.md` §4.6 is updated to cite the frozen contract.

### S7. secrets app skeleton

- **Seat:** E. **Review:** R.
- **Repo/path:** `naapp/secrets/` (package `aweb_secrets`).
- **Depends on:** X4, X6, X7, X8; the shared runtime from B4 (aweb-acgh.6).
- **Scope:** the service on the shared runtime: settings, pgdbm database and
  migrations directory, health reporting the full build commit plus DB, KMS
  canary and oldest-undelivered-outbox age, the manifest v2 document (tools from
  §13.1, `hooks.productions` for both hooks, `app_keys` with purposes), B1
  admission wiring, and separate routing for the API origin and the console
  origin.
- **Acceptance:** health reports the 40-character commit; the manifest passes
  the X8 interpreter vectors; every tool is team-auth signed and none is
  `auth: none`; an API-origin request carrying a cookie gains nothing; a
  console-origin request carrying team-auth is refused.

### S8. Domain records, grants, policy and admission

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/`.
- **Depends on:** S2, S5, S7; X6, X9.
- **Scope:** the records of §4.3–§4.4 and §8.1 (secret, version, destination,
  operation template addressed by digest, job definition addressed by digest,
  grant, immutable digest-addressed policy); the §4.1 admission order with
  `request_id` deduplication through S2; app-local rate buckets and time
  windows charged inside the admission transaction; the `standard` and
  `sensitive` rules; `requires_attestation` refusing with
  `attestation_unavailable` until S6's verifier is wired, then verifying.
- **Acceptance:** no grant, no use, whatever the scope or listing; a
  `sensitive` secret refuses open requests; an edited operation has a new
  digest and an old grant does not cover it; a replayed envelope inside the
  skew window returns the first receipt; rate and window denials are refusals
  with their codes; an uninstalled or new-generation installation is refused.

### S9. Custody backends

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/` (app-local KMS sealing under Q16).
- **Depends on:** S7; HO5 for the KMS provider (Q2); HO6 for the test vault.
- **Scope:** §5: the backend interface; the native store with a fresh data key
  per version, AES-256-GCM, and the encryption context and AAD binding
  installation, team, secret and version; the 1Password backend through a
  service account whose token is sealed in the native store; the item version
  returned by `open()`; `custody_unavailable` on any backend error, with no
  fallback; no read cache (Q4).
- **Acceptance:** against the real KMS and the real test vault: a ciphertext
  copied to another secret or version fails to decrypt; a destroyed version
  cannot be opened; a KMS outage refuses admission and fails readiness; a
  1Password item version change is reported to the caller; no plaintext appears
  in logs, exceptions or responses (checked by scanning captured output for the
  test value's known name-addressed fingerprint, not the value).

### S10. Owner console, value ingress and change sets

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/` (console pages on the shared S4 session).
- **Depends on:** S4, S8, S9; X3, X5; HO1 for the hosted owner act; the email
  provider (HO5).
- **Scope:** §6 and §10.2: console sign-in; creating a secret and entering or
  replacing a value, which never echoes and shows no fingerprint; widening
  changes as `aweb.secrets.change/1` approved through B2/B3 with the rendering
  rules of §6.3; the bootstrap of the first owner and recovery through the owner
  act; the last-owner protection, 24 h contact-change delay and 72 h cooling-off
  as policy parameters (decision 8); freezing `approve_only` uses and widening
  changes during a cooling-off; email notifications.
- **Acceptance:** a value enters only through the console with a passkey; a
  `propose-change` draft stays inert until confirmed; bootstrap with an admin or
  member signature is refused with `owner_required`; a valid owner act starts the
  cooling-off and notifies every earlier contact; IDNA hosts render as Unicode
  and A-label; drafter text renders escaped and labelled untrusted; a
  replacement destroys the old version in the same transaction.

### S11. Brokered request path

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/` (injectors and response handling app-local
  under Q16), on S1.
- **Depends on:** S1, S8, S9.
- **Scope:** §7.1, §7.5, §7.6 and §8: the six auth schemes executed
  server-side, with the OAuth token cached sealed and SigV4 region and service
  owner-set; secrets' additions to S1's always-rejected headers; credential-shaped
  header values rejected; response bounding, header filter, projection
  (required for `sensitive`), known-value redaction in every encoding, and the
  credential-shape detector defaulting to `withheld`; named operations with
  typed parameter slots; token-issuing handling `deny`, `withhold` and
  `store_as_secret` with derived secrets (no `return`, Q8).
- **Acceptance:** each scheme verifies at the S19 upstream; a wrong host gets no
  injection; an agent-chosen SigV4 region or service is refused; a parameter can
  never become a path separator, header name, host or method; a
  credential-shaped body is withheld with the redaction count; an undeclared
  token issuance is withheld and flagged; STS `store_as_secret` returns a
  derived ref and no value.

### S12. approve_only and use approvals

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/`.
- **Depends on:** S0, S10, S11; X5.
- **Scope:** §10: the frozen `aweb.secrets.use-approval/1` request; B2
  admission in the same transaction as the intent and outbox rows; the console
  approval page rendering from frozen bytes; the locator-only email; `status`
  and re-submission by `request_id`; version binding, with replacement and
  1Password version changes voiding approvals; `distinct_approver` per policy,
  `not_required` by default (Q7); a 15 min default TTL (Q14);
  `approval_unrenderable` for open requests the console cannot show in full.
- **Acceptance:** the §16 approval row in both directions, including the
  requester never seeing a link, reuse after consume refused, parameters changed
  after approval refused, and parallel consumers yielding one dispatch.

### S13. Dispatch wiring and the audit outbox

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/`.
- **Depends on:** S3, S11, S12; X1, X2, X6.
- **Scope:** §11 and §11.5: the broker and runner paths on S3; the fence
  re-check of grant, policy, secret state and version, installation, runner and
  approval; the upstream `Idempotency-Key: secrets-<dispatch_id>`; reconcile
  lookups and console resolution; every transition enqueuing its X1 event in
  its own transaction; governance acts on `post-governance-hook` with
  `authority`; refusal with `audit_target_unavailable` and
  `audit_delivery_stalled` under the shared predicate (decision 11); cancelled
  or rejected deliveries recorded as faults.
- **Acceptance:** the §16 state-machine, idempotency and outbox rows in both
  directions. Each emitted event validates against the X1 catalog vector. No
  event ever carries a value, a concrete path or a query value. A registration
  inside its `active_from` pad refuses; a stalled secondary target alone does
  not.

### S14. Containment

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/`.
- **Depends on:** S13; X5 (`revoke_many`).
- **Scope:** every §12 action through the agent API, `aw` and the console:
  revoke a grant, revoke approvals, disable a secret, the installation kill
  switch, replace a value, deregister a runner, revoke an approver credential;
  never gated on a passkey or on audit availability.
- **Acceptance:** each action takes effect at admission and at the fence; a
  revocation committed before the fence stops the dispatch; containment
  succeeds with no audit target and with a stalled one; revoking the last
  owner's passkey or contact through team-auth is refused with
  `last_owner_protected`; re-enabling requires a passkey.

### S15a. Runner protocol, server side

- **Seat:** P. **Review:** R+A.
- **Repo/path:** `naapp/secrets/` (runner endpoints).
- **Depends on:** S0, S10, S13.
- **Scope:** §9.2–§9.3: one-time registration codes stored as hashes, valid
  10 minutes and single use; registration of the runner's Ed25519 and X25519
  keys; the claim long-poll and the `started` and `result` reports; request
  verification with a 120 s skew and stored nonces; signed assignments; HPKE
  sealing of the credential with `dispatch_id` as `info`; `short_lived`
  delivery minted through S11's `store_as_secret` (§9.5); `durable` delivery
  behind its passkey-confirmed flag.
- **Acceptance:** S0's runner vectors pass on the server; a replayed or stale
  runner request is refused; a used or expired code is refused; a lost runner
  after `started` becomes `outcome_unknown`.

### S15b. Runner binary

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/runner/` (package `aweb_secrets_runner`, the
  `aweb-secrets-runner` command).
- **Depends on:** S15a.
- **Scope:** §9.2–§9.6: `register` and the pinned service key; outbound-only
  long-poll; assignment verification and the local journal; two-key pinning
  against a local config; re-hashing the executable and declared files, or the
  image digest, before each run; argv slots with `--` and `option_value`; the
  refused environment names; an empty starting environment; local redaction
  and detection; `doctor`.
- **Acceptance:** the §16 runner row in both directions, run as a real process
  under a separate OS user.

### S16. Tool surface for aw, MCP and the dashboard

- **Seat:** E. **Review:** R, +D1.
- **Repo/path:** `naapp/secrets/` (tools, the `aweb.page/1` surface); no
  secrets-specific code in `aw`.
- **Depends on:** S8–S14; X8, X10; HO3, HO4.
- **Scope:** §13: the nine tools with their contexts and scopes; no value tool
  in any context; the surface with read-only views, containment, `propose-change`
  forms and a `link_out` to the console; the `aw` rendering of named and open
  requests through the generic dispatcher, with exit codes for
  `awaiting_approval`, `refused`, `outcome_unknown` and `result_withheld`.
- **Acceptance:** `aw secrets request` works for a named operation and an open
  request with released `aw` plus X8; `propose-change` and `activity` are not
  listed in an `agent` context; no tool accepts a value field.

### S17. Usage reporting

- **Seat:** E. **Review:** R.
- **Repo/path:** `naapp/secrets/`.
- **Depends on:** S13; X11.
- **Scope:** report `uses_admitted`, `dispatches`, `approvals_requested` and
  `job_runs` under `aweb.usage/1`. Rate and window refusals are never metered as
  economic limits.
- **Acceptance:** counts reconcile with the operational record across a retry,
  a refusal and an `outcome_unknown`.

### S18. Deploy

- **Seat:** E. **Review:** R+A. Production tooling, so the coordinator
  integrates it.
- **Repo/path:** `naapp/secrets/Makefile`, `naapp/secrets/ops/`,
  `naapp/secrets/docs/production-operations.md`, on the shared
  `aweb_naapp.ops` extra.
- **Depends on:** S7; HO5.
- **Scope:** §15 on Library's pattern: the pinned ops topology manifest;
  Make-only `prod-*` operations backed by checked-in scripts with tests; the
  release record; KMS as a readiness dependency; the service signing key (KMS
  asymmetric where Ed25519 is supported, otherwise sealed at deploy) published in
  `app_keys`; two origins; core dumps off; request and response bodies never
  logged; the restore procedure that reapplies the tombstone list before
  serving; the replacement receipt stating when backups expire.
- **Acceptance:** the ops scripts' tests pass; a topology that differs from the
  manifest is refused; readiness fails with KMS unavailable; a restored
  database with a destroyed version does not serve it.
- **Done-signal:** in addition, the first production deploy happens only on
  Juan's go, after S21.

### S19. E2E test target and harness

- **Seat:** E. **Review:** R.
- **Repo/path:** `naapp/secrets/e2e/upstream/` (test-only service) and
  `naapp/secrets/e2e/`.
- **Depends on:** HO6.
- **Scope:** §16: a test upstream that verifies each of the six schemes for
  real against its own copy, by name; an OAuth2 client-credentials token
  endpoint; real SigV4 verification; endpoints for redirects, credential-shaped
  responses, slow and reset responses, idempotency-key echo and status lookup;
  the DNS name answering with a private address; a real hook target that
  verifies signed events until logs exists; a browser with a virtual
  authenticator; the runner under a separate OS user.
- **Acceptance:** each target endpoint is shown to fail its check when given a
  wrong credential or signature; no credential value is in the repository.

### S20. E2E suite

- **Seat:** E. **Review:** R+A.
- **Repo/path:** `naapp/secrets/e2e/`.
- **Depends on:** S8–S19; HO2–HO4 for the hosted paths.
- **Scope:** every row of §16 in both directions, through real `aw`, a real L2
  signing path, real KMS, the real 1Password test vault, the real STS test
  account, a real passkey ceremony and a real runner.
- **Acceptance:** all rows pass; each harness states whether it was shown to
  fail for its target fault; the L2 cases show that a listed tool without a
  grant is refused and that `requires_attestation` passes only with a valid HO2
  attestation.

### S21. Launch gate

- **Owner:** the coordinator.
- **Depends on:** S20; X14 (logs ingests secrets' real events end to end);
  S6 and HO2 (decision 2); Athena's final review across S0–S20.
- **Done-signal:** Juan's go, recorded. Then S18's first production deploy.

## 6. Summary for staffing

| Task | Seat | Review | Lands in |
| --- | --- | --- | --- |
| S0 contract vectors | P | R+A | `naapp/secrets/vectors` |
| S1 egress guard | E | R+A, D1 | `aweb_naapp` |
| S2 idempotency store | E | R, D1 | `aweb_naapp` |
| S3 dispatch state machine | E | R+A, D1 | `aweb_naapp` |
| S4 console session | E | R+A | `aweb_naapp` |
| S5 role assignments | P | R+A, D1 | `aweb_naapp` |
| S6 principal attestation | P | R+A, Juan identity approval | AWID, docs, `aweb_naapp` |
| S7 app skeleton | E | R | `naapp/secrets` |
| S8 records and admission | E | R+A | `naapp/secrets` |
| S9 custody | E | R+A | `naapp/secrets` |
| S10 console and change sets | E | R+A | `naapp/secrets` |
| S11 broker path | E | R+A | `naapp/secrets` |
| S12 approvals | E | R+A | `naapp/secrets` |
| S13 dispatch and audit | E | R+A | `naapp/secrets` |
| S14 containment | E | R+A | `naapp/secrets` |
| S15a runner protocol | P | R+A | `naapp/secrets` |
| S15b runner binary | E | R+A | `naapp/secrets/runner` |
| S16 tool surface | E | R, D1 | `naapp/secrets` |
| S17 usage | E | R | `naapp/secrets` |
| S18 deploy | E | R+A, coordinator integrates | `naapp/secrets` ops |
| S19 E2E target | E | R | `naapp/secrets/e2e` |
| S20 E2E suite | E | R+A | `naapp/secrets/e2e` |
| S21 launch gate | coordinator | Athena, Juan | — |

Every seat runs Claude Opus 5.5.
