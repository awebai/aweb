# secrets build plan

Status: the build plan for the accepted design [secrets.md](secrets.md), with
each task's state on main. Its tasks are the board tasks under the build epic
aweb-acgh.18 (epic aweb-acgh). Each task carries one status: **Built** (on main;
the task names where), **In flight** (partly on main; the task says what is on
main and what is not), **Open** (decided and planned, not on main) or **After
the first release** (decided, deliberately parked). The board holds assignment.
No task has a time estimate.

Section references such as §7.3 point into `secrets.md`. "D1" is the generic
naapp design `docs/design/agent-pages.md`; its build tasks are
aweb-acgg.5–.31 and aweb-abzo. "Hooks design" is
`docs/design/audit-substrate.md`. Decisions are cited by number from the
secrets lane's decision record.

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
  are referenced only by name. A canary that a test generates at runtime (a
  random string sealed as a secret, never a real credential) is not a secret
  value. Leak tests search captured output for that canary itself.
- **Schema changes** are new ordered pgdbm migrations. Existing migrations are
  never edited.
- **Shared code is generic.** Nothing in `aweb_naapp` names secrets, pages or
  any other app. Its runtime dependencies sit behind an extra, following B1's
  packaging seam.
- **Naming.** The app package is `aweb_secrets`, never `secrets`, because a
  top-level `secrets` package would shadow Python's standard library module.
  The runner package is `aweb_secrets_runner`.
- **Landing.** Every change lands through the coordinator's per-repository lane
  train, under a full candidate gate. The author sends a landing request with
  the reviewed head SHA. A shared `aweb_naapp` change may ride the secrets lane
  train when the covering run is the full candidate gate and the coordinator
  grants the push slot (the coordinator's ruling). The coordinator integrates
  cross-repository combinations, release tags and production tooling.

**Review classes.**

- **R**: one non-author reviewer.
- **R+A**: one non-author reviewer plus Athena. Every task that touches
  credentials, custody, authentication, approvals, the audit path or the network
  boundary is R+A.
- **+D1** adds the D1 lead's fit check, for shared pieces that pages also
  consumes and for manifest v2 use.

**Done-signal.** The same for every task unless the task says more: the
acceptance tests pass, the required reviewers ACK the exact head, and the lane
train lands it on main.

## 2. Order of work

```text
Hook contract (X1) + S0 contract vectors                        Built
Shared aweb_naapp pieces: S1 egress · S2 idempotency · S3 dispatch
    S4 console session · S5 role assignments · S6 attestation   Built
secrets app: S7 skeleton · S8 records and admission              Built
    S11 broker path · S12 approvals                             Built
    S9 custody · S10 console · S13 dispatch and audit
    S14 containment · S15a/S15b runner · S16 tool surface       In flight
    S19 E2E target and harness                                  In flight
    S20 E2E suite (M9: the first-release journey)               Open
    S18 deploy (with HO5)                                       Open
Launch: S21 gate                                                Open
After the first release: derived and short-lived issuance (aweb-acgh.41),
    S17 usage reporting (aweb-acgh.18.19)
```

- **The hook contract lands first** (decision 11). S3 exposes the enqueue
  points as calls made inside the caller's transaction, and S13 fills them with
  the hooks-lane kit.
- **Generic pieces land in `aweb_naapp` before the app uses them.** The app
  never carries a private copy first.
- **aw-hooks, logs and secrets build in parallel** after the hook contract. The
  secrets app is tested against a real hook target (S19). Launch waits for logs
  (S21).
- **The first release** goes to 1Password employees and then to customers, at
  the production quality bar (decisions 85 and 87). The runner is in it. Audit
  delivery into logs, end to end, is in it (decisions 11 and 87). A landing
  page is required (decisions 87 and 88): M11, aweb-acgh.18.40.
- **First-release acceptance** is Juan's six-step journey in
  `naapp/secrets/e2e/RELEASE.md`: configure, use from two agents, approve a
  use, run a job, revoke, and inspect access and activity. It is M9, the
  release subset of S20 (aweb-acgh.18.22), run on S19's real path. Full S20
  stays required; its rows for parked features follow those features.
- **After the first release:** derived and short-lived issuance (STS, OAuth
  token minting, `store_as_secret`, runner `short_lived` delivery) on
  aweb-acgh.41 (decision 95), with ordinary-child selection and `short_lived`
  runs on aweb-acgh.41.1; usage reporting S17 on aweb-acgh.18.19 (decision 88).
  The first release releases only a job's own fixed durable slots. Main refuses
  the parked paths: `store_as_secret_unavailable`
  (`naapp/secrets/src/aweb_secrets/operation.py`), and non-durable or minted
  job slots in `run_service.py` and `change_sets.py`.

## 3. Dependencies on other lanes (X)

These are owned elsewhere. secrets tasks list them by ID.

| ID | What secrets needs | Task | Status |
| --- | --- | --- | --- |
| X1 | **Hook contract.** Catalog v1 vector with the `post-secret-use-hook` action enum, payload allowlist and `refusal_code` enum, and the `post-governance-hook` act and direction table; envelope `aweb.hook-event/1` and its vectors; `aweb.owner-act/1` and its vector; binding cases with the `active_from` pad. | aweb-acgh.16.1 (H1), aweb-acgh.16.27, aweb-acgh.16.33 | Built: `docs/vectors/hook-catalog-v1.json` (the same catalog as `naapp-lib/src/aweb_naapp/hooks/catalog-v1.json`), `hook-event-envelope-v1.json`, `owner-act-v1.json`, `hook-binding-cases-v1.json`. The optional `use_ref` on `post-secret-use-hook` is in catalog v1, re-frozen in place under Juan's ruling on the `use_ref` in-place v1 re-freeze. Catalog versioning applies from the first deployment (decision 93). |
| X2 | **Hook kit in `aweb_naapp`** behind its own extra: envelope signing, producer outbox with enqueue inside the effecting transaction and `event_id` minted once, drain and delivery client, hook-delivery credential. | aweb-acgh.16.4, .16.6, .16.7, .16.8 (K1, K3a, K3b, K4) | Built: `naapp-lib/src/aweb_naapp/hooks/` (`envelope.py`, `producer.py`, `delivery.py`, `resolver.py`, `transport.py`), `hooks` extra. |
| X3 | **Owner-act verifier** in `aweb_naapp`, and `Passkeys.designate()` accepting only the verifier's type. | aweb-acgh.16.5 (K2); aweb-acgh.10 | Built: `naapp-lib/src/aweb_naapp/hooks/owner_act.py`, `owner_act_nonces.py`. |
| X4 | **B1 verifier** with scope enforcement, the policy hook and `Principal.did_aw`. | aweb-acgh.3 | Built: `naapp-lib/src/aweb_naapp/runtime/team_auth.py`. |
| X5 | **B2+B3**: admission inside the caller's transaction, `revoke_many`, lockout timings (24 h contact change, 72 h cooling-off) as floors that policy can lengthen but never shorten, and the last-owner protection. | aweb-acgh.4 | Built: `naapp-lib/src/aweb_naapp/runtime/approvals/` and `runtime/passkeys/` (`last_owner_protected` in `passkeys/service.py`). |
| X6 | **App → team-server API**: server discovery through the approved `aweb.team-server/1` record, purpose-split app auth, grant status with installation ID and generation, and hook resolution that reports `active_from` within the 60 s freshness bound. | aweb-acgh.7 (build epic aweb-acgh.17) | In flight (aweb-acgh.7): the discovery client, grant status read, app credential signer and hook resolver client are on main (`naapp-lib/src/aweb_naapp/runtime/team_server.py`, `team_grants.py`, `app_credentials.py`, `hook_resolver.py`), with the server's `/v1/apps/hook-bindings` routes. Server resolution endpoints and the `HookResolver` client (aweb-acgh.17.11, .17.12) are on main. Open: client-class registrations for members (aweb-acgh.17.18), the end-to-end proofs (aweb-acgh.17.13, .17.14) and per-team key revocation (aweb-acgh.17.6, .17.7). The custodial deployment backfills existing teams before any naapp depends on discovery (decision 3). |
| X7 | **App keys**: the emit-key scoping fix (acgh.8) and the one app-key loader (decision 10: kid to key file, fail closed at startup, one 64-hex format). | aweb-acgh.8; the loader is K0 | In flight (aweb-acgh.8): K0 is on main (`naapp-lib/src/aweb_naapp/signing_key.py`, `signing-key` extra), with emit-key scoping and manifest-derived app keys. Key revocation (aweb-acgh.17.6), its revocation event (aweb-acgh.17.7) and required manifest bytes at install (aweb-acgh.17.17) are not. |
| X8 | **Manifest v2** (D1 C3): `invocation_contexts`, `hooks.productions`, `app_keys` with purposes, the Python serving helpers, and the Go interpreter in `aw` that renders open-request body parameters as flags. | D1 C3, aweb-acgg.9; aweb-acgh.23 | Built: `naapp-lib/src/aweb_naapp/manifest.py`, `cli/go/internal/appmanifest/manifest_v2.go` and `interpret.go`. secrets serves a v2 manifest (`naapp/secrets/src/aweb_secrets/aweb-app.json`). |
| X9 | **Installation identity** (D1 F6): `installation_id`, generation, install state and the admission fence. | D1 F6, aweb-acgg.5 | Built: `InstallationFence` and its `admit` in `naapp-lib/src/aweb_naapp/runtime/installation.py`. |
| X10 | **Page format with `link_out`, and the shared renderer** (D1 C1, R1). Juan accepted `link_out`, restricted to the installed app's own origin. | D1 C1, aweb-acgg.7; R1, aweb-acgg.20 | Built: `naapp-lib/src/aweb_naapp/pages/page-format-v1.schema.json` (`widget_link_out`), `pages/assets/page-renderer.js`, `docs/vectors/page-format-v1.json`. |
| X11 | **Usage contract** `aweb.usage/1` (D1 C5). | D1 C5, aweb-acgg.11 | Built: `naapp-lib/src/aweb_naapp/runtime/usage.py`, `docs/vectors/usage-report-v1.json`. Its secrets consumer, S17, is after the first release. |
| X12 | **B1b, the did:aw current-key profile.** Not needed for launch: policy that requires a registry-verified principal refuses until it lands (§4.1). | aweb-acgh.11 | Built: in the shared team-auth verifier. |
| X13 | **The hosted-operator items in §4.** | the board refs listed there | See §4. |
| X14 | **logs ingests real events end to end.** This is the launch gate (decision 11). | hooks lane (logs), aweb-acgh.16.19–.16.25; hosted logs operation, aweb-acgh.12 | In flight (aweb-acgh.16.19–.16.24): the logs app is on main (`naapp/logs/src/`: ingest, ledger, chain, verify). Retention and erasure (aweb-acgh.16.23), the real-path end-to-end (aweb-acgh.16.25) and hosted logs operation (aweb-acgh.12) are open. |

**One mismatch to settle with the D1 lead.** D1 §11's A2 row (aweb-acgg.26)
says the external adapter builds on shared "auth injectors" and "response
redaction". Under decision 12 those stay app-local in secrets until a second
consumer uses them. The egress guard, dispatch state machine and idempotency
store are shared. If pages' A2 needs injectors or redaction, A2 is that second
consumer, and the piece moves to `aweb_naapp` as part of A2's work.

## 4. Requirements on a hosted operator (HO)

These are stated generically, as requirements on any custodial deployment or
hosted operator. HO1–HO4 are delivered by the hosted operator outside this
repository; the plan tracks them by their board refs. HO5 and HO6 operate the
secrets deployment itself, in the way aweb-acgh.12 operates hosted logs.

| ID | Requirement | Board ref | Needed by |
| --- | --- | --- | --- |
| HO1 | **Owner acts on fresh interactive step-up.** The custodial deployment signs `aweb.owner-act/1` only for an organization owner, and only after a fresh, interactive step-up, never with a stored credential, API key or MCP token. It discloses that the custodian can mint owner acts. | L1, aweb-acgg.21 | S10 bootstrap and recovery |
| HO2 | **Principal attestations** (`aweb.principal-attestation/1`, §4.6) issued under the S6 contract for every request signed under custody, with the issuer key registered as a custodian. L1 carries it; L2 attaches it to MCP calls with `channel: mcp_l2` and the OAuth human handle. The verifier side is on main (S6). HO2 stays a launch gate: it gates S21 (decision 2). | L1, aweb-acgg.21; L2, aweb-abzo | S8 `requires_attestation`; S21 |
| HO3 | **L2 exposure follows `invocation_contexts`.** List and call only `agent` tools, mint `trace_id` per call, and never log tool parameters or results. | L2, aweb-abzo | S16, S20 |
| HO4 | **The secrets surface and `link_out`** rendered by the member page surface, with `link_out` opening only the installed app's own origin. | L3, aweb-acgg.22 | S16, S20 |
| HO5 | **Operate the secrets deployment.** **Open (aweb-acgh.14).** Two hosts: the agent API origin and the console origin, with the WebAuthn RP ID equal to the exact console host. AWS KMS, with one dedicated key whose policy lets only the service role encrypt, decrypt or generate data keys, and a least-privilege credential delivered as a platform secret file, with a rotation runbook. Workload identity to KMS where the platform offers it. Approval email through the existing AWS SES setup. A deploy-level egress policy with no internal destinations. **Open (aweb-acgh.18.51):** a deploy setting that lists the deployment's own egress and metadata addresses as denied; secrets has no setting to supply that list. `SECRETS_EGRESS_CA_FILE` is a trust anchor for tests and self-hosting; production leaves it unset, and TLS verification itself is never off. Core dumps disabled. Library's ops pattern. | aweb-acgh.14 | S9, S18 |
| HO6 | **E2E environment.** **In flight (aweb-acgh.15):** the inputs contract (`naapp/secrets/e2e/ENVIRONMENT.md`, with the `AWEB_SECRETS_E2E_*` names of decision 45) and its provisioner (`naapp/secrets/e2e/provision_hosted.py`) are on main; the environment itself is the open part. A KMS key for E2E only; a dedicated 1Password test vault and a service account read-only to it; a host for the S19 test upstream, and a DNS name under our control that answers with a private address. Every credential sits in the operator secret store and is referenced by name. **After the first release (aweb-acgh.41):** a dedicated AWS test account and role for the STS case. | aweb-acgh.15 | S9, S19, S20 |

Team-server discovery also depends on a hosted item: publishing and backfilling
`aweb.team-server/1` (L6, aweb-acgg.31, after acgh.7). secrets reaches it
through X6.

## 5. Tasks

Paths below abbreviate `naapp-lib/src/aweb_naapp/` as `aweb_naapp/` and
`naapp/secrets/src/aweb_secrets/` as `aweb_secrets/`.

### S0. secrets contract vectors

- **Status: Built (aweb-acgh.18.1).**
- **Where:** `naapp/secrets/vectors/use-approval-v1.json` (`aweb.secrets.use-approval/1`
  under B2's prefix) and `hook-actions-v1.json` (the §11.5 transition-to-action
  table). The runner protocol's request and assignment signatures, HPKE suite
  and `info` binding are `docs/vectors/secrets-runner-protocol-v1.json` with the
  spec `docs/secrets-runner-protocol.md`; runner HTTP reports are
  `docs/vectors/secrets-runner-http-v1.json`. `aweb.secrets.change/1` is frozen
  by S10 (decision 30).

### S1. Egress guard in `aweb_naapp`

- **Status: Built (aweb-acgh.18.2).**
- **Scope:** §7.2–§7.4 and the bounds in §7.3, generic, with the
  `internal_destinations` deploy setting.
- **Where:** `aweb_naapp/egress/` behind the `egress` extra; the generic
  vectors `docs/vectors/egress-url-v2.json` and `egress-address-v1.json`.

### S2. Idempotency store in `aweb_naapp`

- **Status: Built (aweb-acgh.18.3).**
- **Scope:** keys scoped by an app-chosen tuple, the canonical request hash,
  the stored receipt reference, per-app retention, `409 idempotency_conflict`
  and `410 idempotency_expired`, used inside the caller's transaction.
- **Where:** `aweb_naapp/idempotency/`.

### S3. Dispatch state machine in `aweb_naapp`

- **Status: Built (aweb-acgh.18.4).**
- **Scope:** §11.1–§11.4, generic. The installation fence is a protocol:
  `prepare` runs before the pair and intent locks and `check` runs under them,
  on both admission and `begin_dispatch` (decision 43, aweb-acgh.18.27). An
  unreconciled `outcome_unknown` blocks its pair, except that a once-linked
  continuation may repeat it once (Juan's ruling on §11.4 safe repeat,
  aweb-acgh.18.47).
- **Where:** `aweb_naapp/dispatch/` (`Fence`), with migrations
  `001_dispatches.sql` and `002_continuations.sql`.

### S4. Console session in `aweb_naapp`

- **Status: Built (aweb-acgh.18.5).**
- **Scope:** passkey login through B3 with user verification; a session of at
  most 15 minutes in a `__Host-` cookie; CSRF on every state-changing request;
  the console response headers; refusal of team-auth on console routes. Login
  is metered per client by `LoginLimiter` on the shared `aweb_naapp.ratelimit`
  (decision 58).
- **Where:** `aweb_naapp/console/`.

### S5. Role assignments keyed by stable principal in `aweb_naapp`

- **Status: Built (aweb-acgh.18.6).**
- **Scope:** §4.1 step 3 and §4.2: the principal key, app-named roles, and
  membership lookups. Role and scope names use `.` (decision 27). `purge_team`
  serves uninstall (decision 48); `hold_role` takes a share lock until commit
  (decision 59, aweb-acgh.18.26).
- **Where:** `aweb_naapp/roles/`.

### S6. Principal attestation contract

- **Status: Built (aweb-acgh.18.7).**
- **Where:** the contract `docs/principal-attestation.md`, the vectors
  `docs/vectors/principal-attestation-v1.json`, and the verifier
  `verify_principal_attestation` in `aweb_naapp/runtime/attestation.py`.
  `secrets.md` §4.6 cites the frozen contract.
- **Known limit:** only the hosted custodial path issues attestations (HO2), so
  a self-hosted surface host cannot call surface-only tools until it can sign
  `aweb.principal-attestation/1` from its own controller. That is a later
  identity-path item, not part of S6.

### S7. secrets app skeleton

- **Status: Built (aweb-acgh.18.8).**
- **Scope:** the service on the shared runtime, health with the build commit,
  DB, KMS canary and oldest-undelivered-outbox age, the manifest v2 document,
  B1 admission wiring, and separate API and console origins.
- **Where:** `naapp/secrets/` (`aweb_secrets/app.py`, `aweb_secrets/aweb-app.json`).
  The production root is `create_service` in `aweb_secrets/composition.py`; it
  mounts the tool, console and runner routers.

### S8. Domain records, grants, policy and admission

- **Status: Built (aweb-acgh.18.9).**
- **Scope:** the records of §4.3–§4.4 and §8.1; the §4.1 admission order with
  `request_id` deduplication through S2; rate buckets on the shared
  `aweb_naapp.ratelimit` (decision 58) and time windows, charged inside the
  admission transaction; the `standard` and `sensitive` rules;
  `requires_attestation` verified against the S6 verifier. Multi-grant
  admission takes direct grants, then role grants, by `grant_id`; the first
  admitting grant wins and only its policy is charged; an unconfirmed secret
  is refused with `secret_disabled` (decision 46). Job definitions and run
  admission belong to S15a (decision 46).
- **Where:** `aweb_secrets/records.py`, `grant.py`, `policy.py`,
  `admission.py`.

### S9. Custody backends

- **Status: In flight (aweb-acgh.18.10):** the backends are on main; the
  real-environment acceptance is not.
- **Scope:** §5: the backend interface; the native store with a fresh data key
  per version, AES-256-GCM, and the encryption context and AAD binding
  installation, team, secret and version; the 1Password backend through a
  service account whose token is sealed in the native store; the item version
  returned by `open()`; `custody_unavailable` on any backend error, with no
  fallback; no read cache.
- **Where:** `aweb_secrets/custody/` (`store.py`, `sealing.py`, `providers.py`
  with `AwsKmsProvider`, `onepassword.py`), with 1Password reference staging in
  the console.
- **Review:** R+A.
- **Open (aweb-acgh.18.10), acceptance owed:** against the real KMS and the real
  test vault (HO6): a ciphertext copied to another secret or version fails to
  decrypt; a destroyed version cannot be opened; a KMS outage refuses admission
  and fails readiness; a 1Password item version change is reported to the
  caller; no plaintext appears in logs, exceptions or responses, checked by
  sealing a runtime canary and searching all captured output for it.

### S10. Owner console, value ingress and change sets

- **Status: In flight (aweb-acgh.18.11):** the console, value ingress and change
  sets are on main and mounted; the real-environment journey and the items below
  are not.
- **Scope:** §6 and §10.2: console sign-in; creating a secret and entering or
  replacing a value, which never echoes and shows no fingerprint; widening
  changes as `aweb.secrets.change/1` approved through B2/B3 with the rendering
  rules of §6.3; the bootstrap of the first owner and recovery through the owner
  act; the last-owner protection; the 24 h contact-change delay and 72 h
  cooling-off as floors (decision 8); freezing `approve_only` uses and widening
  changes during a cooling-off; email notifications; change-set four eyes
  (decision 61).
- **Where:** `naapp/secrets/vectors/change-v1.json`; `aweb_secrets/change.py`,
  `change_sets.py`, `console*.py` and the `console_*` packages, mounted by
  `aweb_secrets/composition.py`.
- **Review:** R+A.
- **Open (aweb-acgh.18.11):**
  - the real-path value-ingress and confirmation journey against HO6 (M9 step 1
    in `naapp/secrets/e2e/RELEASE.md`);
  - console guidance: the warning that upstream logs hold a `query` credential,
    and the notice that host scope does not stop destructive calls, asking owners
    for narrow upstream permissions (§7.5, §8.2);
  - the console's accessibility gaps.
- **In flight (aweb-acgh.18.11.2):** the per-agent access view of release step 6.
  Its reader (`aweb_secrets/access_reads.py`) is on main; no console page uses it.

### S11. Brokered request path

- **Status: Built (aweb-acgh.18.12)** for the first release.
- **Scope:** §7.1, §7.5, §7.6 and §8: the six auth schemes executed
  server-side, with the OAuth token cached sealed and SigV4 region and service
  owner-set; secrets' additions to S1's always-rejected headers; response
  bounding, header filter, projection, known-value redaction and the
  credential-shape detector defaulting to `withheld`; named operations with
  typed parameter slots; token-issuing handling `deny` and `withhold`. The
  handler wiring through S8, S2 and S3 is S13's broker half (decision 67).
- **Where:** `aweb_secrets/injection.py`, `broker.py`, `tokens.py`,
  `operation.py`, `responses.py`, `redaction.py`, `credential_shapes.py`.
- **After the first release (aweb-acgh.41):** `store_as_secret` with derived
  secrets, and its acceptance (STS `store_as_secret` returns a derived ref and no
  value). Main refuses it with `store_as_secret_unavailable`.

### S12. approve_only and use approvals

- **Status: Built (aweb-acgh.18.13).**
- **Scope:** §10 with decision 63: candidates are the covering approver
  records intersected with `policy.approvers`, and an empty set is refused with
  `no_eligible_approver`; `status` only reports and re-submission dispatches;
  version binding; `distinct_approver` `not_required` by default (decision 7);
  a 15 min default TTL (decision 8); `approval_unrenderable`. Follow-ups
  aweb-acgh.18.31, .18.33, .18.37 and .18.38 are on main.
- **Where:** `aweb_secrets/use_approval.py`, `use_approvals.py`, `approvers.py`.

### S13. Dispatch wiring and the audit outbox

- **Status: In flight (aweb-acgh.18.14):** the broker and runner dispatch paths,
  the fence re-check and the outbox events are on main and mounted; console run
  decisions, reconciliation mounting and the automatic repeat are not.
- **Scope:** §11 and §11.5: the broker and runner paths on S3; the fence
  re-check of grant, policy, secret state and version, installation, runner and
  approval; the upstream `Idempotency-Key: secrets-<dispatch_id>`; every
  transition enqueuing its X1 event in its own transaction; governance acts on
  `post-governance-hook` with `authority`; refusal with
  `audit_target_unavailable` and `audit_delivery_stalled` under the shared
  predicate (decisions 11 and 94); cancelled or rejected deliveries recorded as
  faults. Per Juan's ruling on §11.4 safe repeat, an `outcome_unknown` dispatch
  is repeated once automatically, after a short delay, only for a
  `side_effect: none` operation or one whose upstream honours the idempotency
  key, as its own fenced and audited dispatch with the original authority
  re-checked. Anything else, and a repeat of unknown outcome, goes to the owner,
  who resolves it in the console with a fresh passkey approval bound to the
  `reconcile_ref` and the outcome. The first release has no generic upstream
  reconcile lookup.
- **Where:** `aweb_secrets/broker_service.py`, `run_service.py`,
  `use_routes.py`, `status_service.py`, `audit_sink.py`, mounted in
  `aweb_secrets/composition.py`.
- **Review:** R+A.
- **Open (aweb-acgh.18.14):**
  - console run decisions: `decide` refuses a run with `503
    release_context_unavailable` (`aweb_secrets/console_use_approvals/`);
  - the reconciliation stores and page, which `composition.py` does not compose;
  - the §11.4 automatic repeat's caller;
  - acceptance: the §16 state-machine, idempotency and outbox rows in both
    directions on the real root. Each emitted event validates against the X1
    catalog vector. No event ever carries a value, a concrete path or a query
    value. A registration inside its `active_from` pad refuses; a stalled
    secondary target alone does not.

### S14. Containment

- **Status: In flight (aweb-acgh.18.15):** every §12 action is on main through
  the agent API and the console; role-member removal and the real journey are
  not.
- **Scope:** every §12 action through the agent API, `aw` and the console:
  revoke a grant, revoke approvals, disable a secret, the installation kill
  switch, replace a value, deregister a runner, revoke an approver credential;
  never gated on a passkey or on audit availability. Value replacement stays a
  §6 change set, and S14 owns its atomic consequences (decision 82). Owners
  narrow anything; approvers narrow what their coverage includes, plus their own
  credential and contact (decision 83). Uninstall purges the app's role
  assignments, so a reinstall starts with no owner (decision 48).
- **Where:** `aweb_secrets/containment.py`, `containment_routes.py`
  (`/v1/containment`), the console containment router.
- **Review:** R+A.
- **Open (aweb-acgh.18.48):** removing one member from a role as a narrowing
  action, which release step 5 uses.
- **Open (aweb-acgh.18.15), acceptance owed:** each action takes effect at
  admission and at the fence; a revocation committed before the fence stops the
  dispatch; containment succeeds with no audit target and with a stalled one;
  revoking the last owner's passkey or contact through team-auth is refused with
  `last_owner_protected`; re-enabling requires a passkey; deregistering a runner
  cancels its unclaimed assignments and moves claimed ones to `outcome_unknown`;
  the mounted S19 journey with the runner as a dedicated user.

### S15a. Runner protocol, server side

- **Status: In flight (aweb-acgh.18.16):** the protocol is on main and mounted;
  the real-environment acceptance is not.
- **Scope:** §9.2–§9.3: one-time registration codes stored as hashes, valid
  10 minutes and single use; registration of the runner's Ed25519 and X25519
  keys; the claim long-poll and the `started` and `result` reports; request
  verification with a 120 s skew and stored nonces; signed assignments; HPKE
  sealing of the credential with `dispatch_id` as `info`, through the generic
  HPKE helper and nonce store in `aweb_naapp` (decision 81); `durable` delivery
  behind its passkey-confirmed flag. S15a owns job definitions, change/1 jobs
  and run admission (decision 46), and the job registry and current-digest
  resolver; a derived grant template that names a run job is refused with
  `job_unavailable` (decision 80).
- **Where:** `aweb_secrets/runners.py`, `runner_routes.py`
  (`/runner/v1/claim`, `started`, `result`), `runner_protocol.py`, `jobs.py`;
  `aweb_naapp/crypto/` and `aweb_naapp/nonces/`.
- **Review:** R+A.
- **Open (aweb-acgh.18.16), acceptance owed:** S0's runner vectors pass on the
  server; a replayed or stale runner request is refused; a used or expired code
  is refused; a lost runner after `started` becomes `outcome_unknown`; all on
  the production root, with the runner as a separate OS user, against HO6.
- **After the first release (aweb-acgh.41, aweb-acgh.41.1):** `short_lived`
  delivery minted through `store_as_secret` (§9.5), and ordinary-child runs.

### S15b. Runner binary

- **Status: In flight (aweb-acgh.18.17):** the binary is on main; the installed,
  dedicated-user journey is not.
- **Scope:** §9.2–§9.6: `register` and the pinned service key; outbound-only
  long-poll; assignment verification and the local journal; two-key pinning
  against a local config; re-hashing the executable and declared files, or the
  image digest, before each run; argv slots with `--` and `option_value`; the
  refused environment names; an empty starting environment; local redaction
  and detection; `doctor`.
- **Where:** `naapp/secrets/runner/` (package `aweb_secrets_runner`, the
  `aweb-secrets-runner` command).
- **Review:** R+A.
- **Open (aweb-acgh.18.17), acceptance owed:** the §16 runner row in both
  directions, run as a real process under a separate OS user, with the HO6
  installed artifact, config and launcher.

### S16. Tool surface for aw, MCP and the dashboard

- **Status: In flight (aweb-acgh.18.18):** the manifest declares all nine tools;
  six are served.
- **Scope:** §13: the nine tools with their contexts and scopes; no value tool
  in any context; the surface with read-only views, containment, `propose-change`
  forms and a `link_out` to the console. `aw` renders named and open requests
  through the generic dispatcher, which exits 0 below HTTP 400 and 1 otherwise;
  the first release reads MCP structured state. Distinct exit codes for
  `awaiting_approval`, `refused`, `outcome_unknown` and `result_withheld` come
  from a generic manifest outcome-to-exit mapping in `aw` and a CLI release,
  with no secrets-specific CLI code (decision 86).
- **Where:** `aweb_secrets/manifest.py`, `aweb_secrets/aweb-app.json`,
  `naapp/secrets/docs/tool-surface.md`; the generic interpreter
  `cli/go/internal/appmanifest/interpret.go`.
- **Review:** R+A, +D1.
- **Open (aweb-acgh.18.18):** API routes for `cancel`
  (`POST /v1/requests/{request_id}/cancel`), `propose-change`
  (`POST /v1/changes`) and `activity` (`GET /v1/activity`). The API origin
  serves only `list`, `describe`, `request`, `run`, `status` and `contain`; the
  console serves activity on its own origin. The fixed-durable tool guidance;
  hosted and runner acceptance.
- **Acceptance:** `aw secrets request` works for a named operation and an open
  request with released `aw` plus X8; `propose-change` and `activity` are not
  listed in an `agent` context; no tool accepts a value field.

### S17. Usage reporting

- **Status: After the first release (aweb-acgh.18.19)** (decision 88).
- **Review:** R.
- **Repo/path:** `naapp/secrets/`.
- **Depends on:** S13; X11.
- **Scope:** report `uses_admitted`, `dispatches`, `approvals_requested` and
  `job_runs` under `aweb.usage/1`. Rate and window refusals are never metered as
  economic limits.
- **Acceptance:** counts reconcile with the operational record across a retry,
  a refusal and an `outcome_unknown`.

### S18. Deploy

- **Status: Open (aweb-acgh.18.20).** `naapp/secrets/Makefile` has only `test`
  and `lint`; there is no `naapp/secrets/ops/`.
- **Review:** R+A. Production tooling, so the coordinator integrates it.
- **Repo/path:** `naapp/secrets/Makefile`, `naapp/secrets/ops/`, and a
  production-operations document in the app's own docs directory, on the shared
  `aweb_naapp.ops`.
- **Depends on:** S7; HO5.
- **Scope:** §15 on Library's pattern: the pinned ops topology manifest;
  Make-only `prod-*` operations backed by checked-in scripts with tests; the
  release record; KMS as a readiness dependency; the service signing key (KMS
  asymmetric where Ed25519 is supported, otherwise sealed at deploy) published in
  `app_keys`; two origins; core dumps off; request and response bodies never
  logged; every telemetry sink (logs, error reporting, traces) configured with
  no local variables, no request bodies, a header allowlist, and query strings
  and token-bearing URLs stripped; the restore procedure that reapplies the tombstone list before
  serving; the replacement receipt stating when backups expire.
- **Acceptance:** the ops scripts' tests pass; a topology that differs from the
  manifest is refused; readiness fails with KMS unavailable; a restored
  database with a destroyed version does not serve it; a regression test drives
  errors carrying synthetic credential canaries through every telemetry sink
  and finds none of them in the captured output.
- **Done-signal:** in addition, the first production deploy happens only on
  Juan's go, after S21.

### S19. E2E test target and harness

- **Status: In flight (aweb-acgh.18.21):** the test upstream, the
  dedicated-runner-user harness and the production root checkpoint are on main;
  the full startup against HO6 is not.
- **Review:** R.
- **Repo/path:** `naapp/secrets/e2e/upstream/` (test-only service) and
  `naapp/secrets/e2e/` (`runner_harness.py`, `runtime_publication.py`).
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

- **Status: Open (aweb-acgh.18.22).** On main: the acceptance map
  `naapp/secrets/e2e/RELEASE.md`, the inputs contract `ENVIRONMENT.md` with its
  loader `release_environment.py`, and a release preflight (`test_release_preflight.py`) that checks service readiness.
  The executable journey is not.
- **Review:** R+A.
- **Repo/path:** `naapp/secrets/e2e/`.
- **Depends on:** S8–S19; HO2–HO4 for the hosted paths.
- **M9, first:** Juan's six-step journey in `RELEASE.md`, on the real path with
  logs ingest (decisions 85 and 87). It is the first-release acceptance.
- **Scope:** every row of §16 in both directions, through real `aw`, a real L2
  signing path, real KMS, the real 1Password test vault, a real passkey
  ceremony and a real runner. **After the first release (aweb-acgh.41):** the
  rows for derived and short-lived issuance, through the real STS test account.
- **Acceptance:** all rows pass; each harness states whether it was shown to
  fail for its target fault; the L2 cases show that a listed tool without a
  grant is refused and that `requires_attestation` passes only with a valid HO2
  attestation.

### S21. Launch gate

- **Status: Open (aweb-acgh.18.23).**
- **Owner:** the coordinator.
- **Depends on:** S20; X14 (logs ingests secrets' real events end to end);
  S6 and HO2 (decision 2); Athena's final review across S0–S20.
- **Done-signal:** Juan's go, recorded. Then S18's first production deploy.

### Follow-up tasks under aweb-acgh.18

| Task | What | Status |
| --- | --- | --- |
| aweb-acgh.18.24 | `aw` team-key rotation on the atomic path | Built |
| aweb-acgh.18.25 | Seed `aw` rotation test records through the publish routes once Go signs v2 envelopes | Open |
| aweb-acgh.18.26 | S5: `roles.hold_role` (decision 59) | Built: `aweb_naapp/roles/` |
| aweb-acgh.18.27 | S3: fence `prepare`/`check` (decision 43) | Built: `aweb_naapp/dispatch/` |
| aweb-acgh.18.28 | S4: login limiter on `aweb_naapp.ratelimit` (decision 58) | Built: `LoginLimiter` in `aweb_naapp/console/` |
| aweb-acgh.18.29 | Console routes never echo submitted input (decision 72) | Built |
| aweb-acgh.18.30 | S8: derived-secret operation schema and change vectors (decision 71) | Built; issuance is after the first release (aweb-acgh.41) |
| aweb-acgh.18.31 | S12: derived approver coverage and grant-revoke invalidation | Built |
| aweb-acgh.18.32 | B3: app-authorized retirement in the caller's transaction (decision 82) | Built |
| aweb-acgh.18.33 | S12: direct source-grant approvals in the cascade selector | Built |
| aweb-acgh.18.34 | Console login evidence after partial revocation | Built, as aweb-acgh.18.35 |
| aweb-acgh.18.35 | B3: `login_evidence_is_current` | Built |
| aweb-acgh.18.36 | Console sessions require the login passkey to be active | Built |
| aweb-acgh.18.37 | S12: per-slot approvals for run-bound `short_lived` mints | Built; `short_lived` issuance is after the first release (aweb-acgh.41.1) |
| aweb-acgh.18.38 | B2 forest prelocks; S12 replacement selector | Built |
| aweb-acgh.18.39 | B3: retained passkey proof (decision 84) | Built: `docs/vectors/passkey-evidence-v1.json` |
| aweb-acgh.18.40 | M11: landing page and public surfaces (decision 88) | In flight: `mount_public_surfaces` is in `aweb_secrets/surfaces.py`; no root mounts it |
| aweb-acgh.18.41 | Shared producer: ungated narrowing lifecycle events | Built |
| aweb-acgh.18.42 | B2: transaction-bound final fence check | Built |
| aweb-acgh.18.43 | B3: governance lifecycle mapping | Built |
| aweb-acgh.18.44 | B3: caller-transaction current-approver prepare | Built |
| aweb-acgh.18.45 | B3: caller-transaction fence `prepare`/`check` | Built |
| aweb-acgh.18.46 | B3: `PasskeyEffectFence` on `change_contact` and `cancel_pending_contact` | In flight: the `fence` parameter is on both in `aweb_naapp/runtime/passkeys/service.py`; no root caller passes it |
| aweb-acgh.18.47 | S3: once-linked continuation for the §11.4 repeat | Built: `aweb_naapp/dispatch/migrations/002_continuations.sql`; its secrets caller is S13 |
| aweb-acgh.18.48 | Containment: remove one member from a role | Open |
| aweb-acgh.18.49 | Shared chrome without Berkeley Mono; toolkit tokens | Built |
| aweb-acgh.18.50 | Runner accepts a root-owned 0640 config, so a job cannot widen its own pins | Built |

### Related tasks under aweb-acgh

| Task | What | Status |
| --- | --- | --- |
| aweb-acgh.5 | Library onto the shared `aweb_naapp` runtime | Open |
| aweb-acgh.8 | Install-time app emit keys scoped per team (X7) | In flight: see X7 |
| aweb-acgh.9 | Idempotent app-event ingest: core dedups on (team, app, `event_id`) | Open |
| aweb-acgh.14 | HO5: operate the secrets deployment | Open: see HO5 |
| aweb-acgh.15 | HO6: secrets E2E environment | In flight: see HO6 |
| aweb-acgh.20 | Global request-body cap | Built: `RequestBodyCacheMiddleware` in `server/src/aweb/api.py`, capped by `AWEB_MAX_REQUEST_BODY_BYTES` |
| aweb-acgh.41 | Short-lived derived credentials (STS, OAuth token exchange) (decision 95) | After the first release |
| aweb-acgh.41.1 | Ordinary-child selection and `short_lived` runs | After the first release |
| aweb-acgh.42 | aweb's own credentials into secrets, then short-lived (decision 95) | After the first release |
