# S13 consumer interfaces

Status: the S13 consumer boundary (aweb-acgh.18.14), with what main implements.
The member services, member routes and runner adapter are built and mounted.
Anything unmarked is on main; anything else carries a bold **Open**, **In
flight** or **After the first release** lead-in with its task id. Changes
return to both consumers (S16 and S15a). S13 owns the services, shared S3
composition, registry and sole `UseSecretOpener`; adapters receive no
independent dispatch or custody authority.

Sources: [secrets](secrets.md) §§4.1, 7, 9–11, 13; the
[runner protocol](../secrets-runner-protocol.md) §§1–4; and
`manifest.py`, `broker_input.py`, `tool_results.py`, `run_plan.py`,
`run_approvals.py`, `runners.py` and `runner_results.py` in `naapp/secrets`.
**After the first release (aweb-acgh.41.1):** short-lived issuance and
ordinary-child runs. The runner accepts durable slots; it does not silently
convert a short-lived slot to durable. The first release uses the job's own
fixed durable slots. Ordinary-child selection is guarded: a valid `secret`
selector refuses with `job_not_allowed` before an idempotency claim, run preparation or release.

## Member tools: inputs and replay

All routes below use the exact shared B1 dependency on the API origin. Cookie
presence grants nothing. These tools are absent from the human console origin.
JSON inputs use the strict integer/Unicode-scalar value rules; unknown
fields, duplicate keys, floats and invalid types refuse without sending.

| Tool | Method and path | JSON body |
| --- | --- | --- |
| request | `POST /v1/secrets/{secret}/requests` | Named: `request_id`, `operation`, optional `params`, `headers`, `reason`. Open: `request_id`, `method`, `url`, optional `headers`, `data`, `reason`. |
| run | `POST /v1/jobs/{job}/runs` | `request_id`, `runner`, optional `params`, `reason`, `secret`. |
| status | `GET /v1/status/{ref}` | None. Request ID or returned request/approval/reconciliation locator. |

Path parameters are not repeated in the HTTP body. Named input forbids
`method`, `url`, `data`; open input forbids `operation`, `params`. Named headers
are supported by the operation renderer, but only where the operation explicitly
allows the name; fixed, injected and broker idempotency headers cannot be
overridden. `headers` is an ordered array of `"Name: value"` strings in either
form. No credential, source version, job definition, slot ordinal, grant or
approval decision comes from the caller.

Examples (metadata only):

```json
{"request_id":"refund-17","operation":"create-refund","params":{"charge":"ch_17","amount_minor_units":50,"currency":"EUR"}}
{"request_id":"health-17","method":"GET","url":"https://api.example.com/status"}
{"request_id":"backup-17","runner":"home-1","params":{"environment":"staging"}}
```

The last body is for `/v1/jobs/nightly-backup/runs`. `runner` resolves to the
current scoped runner record; it is not an endpoint or key override. Optional
`secret` is the ordinary-child selector for the unique durable slot.
Omission keeps the job's fixed selectors; there is no caller slot map.

Normalization follows `BrokerInput`: omitted `params` becomes `{}`, omitted
`headers` becomes `[]`, and omitted `reason` becomes `""` (at most 1024
characters). Open `data` defaults to the empty string. String data is UTF-8;
object data uses sorted-key compact UTF-8 JSON. The egress canonical
URL is used. Headers retain order, name spelling and value spelling after
removing leading space/tab following the first colon. No sorting or merging
of duplicate headers occurs. Typed parameters are validated without coercion.

S13 claims `(installation_id, stable principal, request_id)` before creating
one intent/dispatch. The private equality hash binds the tool/path secret or
job, runner selection, operation, typed params, open method/canonical URL/body,
ordered headers, reason and optional child selector. Original resolved
job/operation digests and source versions remain pinned to the intent/plan;
an edited current definition cannot replace them on a retry. Job defaults are
`params={}`, `reason=""`, `secret` absent. Absent `secret` differs from an
explicit child ref. A new runner selection or effect field conflicts.

Transport retries and post-approval execution require a **fresh authenticated
POST** with the same request ID and original logical body. New signature time
and nonce are expected. The initial authenticated-byte MAC remains unchanged;
it is separate from the normalized equality hash. A status read never
reconstructs or sends the original request. A
`not_sent` broker retry keeps the same dispatch and upstream idempotency key,
and must still meet its original approval expiry or total time bound. An
uncertain/completed/reconciled attempt never becomes a new send on replay.

**Safe automatic repeat (Juan's §11.4 safe-repeat ruling).** The one background
send is the single repeat of an `outcome_unknown` broker dispatch whose
immutable operation terms opt in with `outcome_unknown_retry`. Validation in
`operation.py` admits the opt-in only with no `reconcile` lookup and either
`side_effect: none` or a declared idempotency header with
`upstream_honours_idempotency_key: true`. After the pinned delay, the repeat
is its own fenced, audited S3 dispatch linked to the original. It rechecks the
original authority at the fence, keeps the original upstream idempotency key
and consumed approval, and rearms nothing. A definite repeat outcome settles
the original as `reconciled_completed` or `reconciled_failed`; a refused,
unsent or uncertain repeat leaves the original for owner settlement. Until the
original settles, the member's status for it stays `outcome_unknown` with its
`reconcile_ref`. Runner jobs and open requests without operation terms are
never repeated, and there is no generic reconcile lookup in the first release.
**In flight (aweb-acgh.18.14):** the operation-term validation and the shared
S3 continuation seam (`Dispatches.continue_dispatch` and `resolve_original` in
`aweb_naapp.dispatch`, migration `002_continuations.sql`; aweb-acgh.18.47) are
on main; the broker call site that schedules and sends the repeat is not.

## Member tools: replies

Replies use the `tool_results` envelope vocabulary, with the pending
and receipt states below. The client reads `state` independently
of HTTP status. `request_id` is the original caller ID; `request_ref` is an
opaque persisted intent locator, never a token. Status lookup by request ID is
scoped to the caller; owner inspection uses a scoped opaque locator. Unknown
and inaccessible locators return the same `404` refusal. Owners inspecting
another member's receipt see its state/code and references, without its
projected result entity (secrets §11.2). Retrieval checks
current read authority and installation generation, including after certificate
renewal; it never rewrites original certificate/plan/audit provenance.

| State | POST HTTP | Fields besides `state`, `request_id` |
| --- | --- | --- |
| `awaiting_approval` | 202 | `request_ref`, `approval_ref`; runs also have `approval_refs` (ordered by slot, deduplicated). |
| `received`, `admitted`, `dispatching` | 202 | `request_ref`; persisted progress only. An admitted run waits for a runner claim. |
| `approved` | status only | `request_ref`, `next: "resubmit"`. All required run-slot decisions must be approved. |
| `completed` | 200 | `request_ref`, `result` (sanitized/projected result). |
| `result_withheld` | 200 | `request_ref`, `code`, `result` (safe status/count metadata, no body). |
| `not_sent` | 503 | `request_ref`, `next: "resubmit"`; fresh-send checks may still refuse a retry. |
| `outcome_unknown` | 200 | `request_ref` and `reconcile_ref` name the same original opaque association. Reading either never sends or retries; §11.4 governs reconciliation. |
| `refused` | refusal HTTP below; 200 on replay of a stored refusal | `code`. A live POST refusal adds `use_ref` when it is attributable (see "Public signed use correlation"). A refusal presented from a stored receipt carries `request_ref`. |
| `cancelled` | 200 | `request_ref`. No `next`. |
| `reconciled_completed`, `reconciled_failed`, `reconciled_unknown` | 200 on retrieval | `request_ref`; sanitized `result` if one exists. No new execution. |

Successful status reads return `200` with this envelope at the top level,
including pending/progress/withheld/refused states. Looking up an approval
locator additionally uses S12's `denied`, `expired`, `revoked` and
consumed `admitted` states; `next: "resubmit"` occurs only for `approved`.
An intent lookup aggregates its slot decisions: still pending is
`awaiting_approval`, every required approval ready is `approved`, and a failed
required slot is `refused` with its fixed approval refusal code. `approval_ref`
names the first unresolved required slot; `approval_refs` lists all unresolved
ones. Clients should poll `request_ref` for the aggregate, not infer readiness
from one approved slot. These references expose no approval link or evidence.

A persisted S3 `cancelled` receipt has one presentation in broker status, run
status and terminal receipt replay: HTTP 200, `state: "cancelled"`, the
original `request_id` and `request_ref`, and no `next: "resubmit"`.
Cancellation covers requester withdrawal and containment, so it is never
presented as `approval_revoked`. A separate observation is an intent still
`awaiting_approval` in S3 whose B2 slot was revoked: its aggregate status is
`refused` with `code: "approval_revoked"`, and a fresh POST that detects the
revocation is refused with 403. Replaying a stored S3 `refused` returns 200
with `state: "refused"` and its persisted refusal code. A new live dependency
or audit failure on a POST can be 503; a new policy or approval denial is 403.
**Open (aweb-acgh.18.52):** run status diverges on main. `RunStatus` presents a
persisted `cancelled` as `refused` with `approval_revoked`, and its POST
receipt returns a stored `refused` as 503. The correction is planned test-first.

```json
{"state":"awaiting_approval","request_id":"refund-17","request_ref":"int_example","approval_ref":"approval_example"}
{"state":"approved","request_id":"refund-17","request_ref":"int_example","next":"resubmit"}
{"state":"admitted","request_id":"backup-17","request_ref":"int_run_example"}
{"state":"refused","request_id":"refund-17","code":"idempotency_conflict"}
```

For broker results, `result` contains `status` (upstream HTTP status), filtered
`headers` (ordered pairs), `body` (string or null), `body_encoding` (`utf8` or
`base64`, absent when withheld), `truncated`, `upstream_bytes`, and
`redaction_count`. A definite upstream 4xx/5xx is still a completed dispatch.
Runner results contain the pinned output projection plus exit/local/server
metadata from `RunnerOutput`; an unavailable original redaction context
(runner protocol §4.3) withholds output with
`code: "release_context_unavailable"` and preserves safe metadata.
The `result_withheld` envelope carries `request_ref` and `code`; the service
attaches the safe `result` metadata.

POST refusals: `400` invalid input, `403` policy/grant/approval/containment
denial, `409 idempotency_conflict`, `410 idempotency_expired`, `429
policy_rate_limited` with `Retry-After`, `503` required dependency/audit
availability. S3 `dispatch_in_flight` and `reconciliation_pending` map to
`409` refused envelopes, not an admitted result. B1 authentication/scope errors
retain the runtime's own HTTP error shape; clients must also handle that shape.
Malformed transport retains `413`/`415` as appropriate. No exception text or
raw input is returned. These refusals add no public hook refusal code.

## Callable boundary and mounting

The following signatures are the S13 member services. `MemberSubmission`,
`ToolReply` and the `JobRunRequests` protocol live in
`aweb_secrets.member_types`. `ToolReply.body` is the JSON envelope above.
`MemberSubmission` is internal data constructed only after B1, using the
matched `Authorization.tool` and the complete original request bytes.
`JSONValue` denotes the strict JSON value domain above. `Authorization` and
`RequestBytes` keep their own modules' definitions.

```python
@dataclass(frozen=True, repr=False)
class MemberSubmission:
    authorization: Authorization
    inbound: RequestBytes  # exact external target, content types, original body
    signed_trace_id: str | None

@dataclass(frozen=True)
class ToolReply:
    status: int
    body: Mapping[str, JSONValue]
    headers: Mapping[str, str]  # Retry-After when applicable

class BrokerRequests:  # aweb_secrets.broker_service
    async def submit(self, *, secret: str, submission: MemberSubmission) -> ToolReply: ...

class JobRunRequests(Protocol):  # aweb_secrets.member_types; RunDispatch implements it
    async def submit(self, *, job: str, submission: MemberSubmission) -> ToolReply: ...

class UseStatus:  # aweb_secrets.status_service
    async def get(self, *, ref: str, authorization: Authorization) -> ToolReply: ...
```

The services own transaction boundaries, parsing/normalization, commitments,
S8/S12 admission, S3, outbox and safe errors. S16 does not call `admit`,
`begin_dispatch`, an opener, or an approval consumer. Broker admission and
dispatching each commit their own required outbox records; the final live
fence follows all awaited writes before dispatching commits. Exact custody
opening then precedes every token-cache lookup and outbound call.

The installation fence comes first in every transaction (decision 43). S3
enforces this through its `Fence` protocol in `aweb_naapp.dispatch`:
`prepare(tx)` takes every lock the fence needs before S3 locks the dispatch row
or pair, and `check(tx, dispatch)` re-reads under those locks and takes none of
its own.

Root mounts `metadata_router(MetadataServices(catalog=...), authorized=...)`
and `use_router(UseServices(broker=..., runs=..., status=...), authorized=...)`
from `aweb_secrets.use_routes`, with request-time getters because runtime
DB/services exist after startup. Both factories go through
`create_app(tool_routers=...)`, which supplies the exact `authorized`
dependency. S16 owns client rendering/tests. The secrets-app seat owns the use
router and the broker/run services; secrets-root owns root composition and
final mounting (`create_service` and `_compose` in `composition.py`; `app.py`
holds the generic `create_app` mount seam), configuration and S19. The root
constructs one shared set of dependencies and injects it into the services;
all admission, dispatch and release transactions and final fences remain in
those services. Human routers use the one shared `OwnerConsole` separately.

### Concrete durable-run construction

`RunDispatch(db, *, fence, opener, committer, response_key, service_key, origin,
producer, registration_view, approvals, use_audit, passkeys, max_backlog_age,
assignment_ttl, sweep_margin, claim_wait, derived_max_ttl_s,
internal_destinations, clock)` implements both `JobRunRequests` and
`RunDispatchAPI`. Root injects the SAME shared installation fence, B2/B3,
producer and use opener as the broker. `service_key` is the runner-pinned
service signing key; `response_key` remains independently provisioned private
material. Assignment TTL is 1–300 seconds; idle claim wait is 0–30 seconds.
The S3 execution bound uses each original job timeout plus `sweep_margin`,
independently of assignment expiry. Root schedules `RunDispatch.sweep`, which
selects only original run contexts and locks the B2 union before S3.

`RunDispatch.status` is its inert `RunStatus` reader. Root constructs one
member-route `UseStatus(db, fence=shared_fence, approvals=shared_approvals,
runs=run_dispatch.status)`, passes that status getter to `UseServices`, and
uses the run instance itself for the member-run and runner-adapter getters.
`BrokerRequests` holds its own broker-only `UseStatus` (`runs=None`) for its
POST receipts; `runs=None` reads no run tables. Status never dispatches or
consumes; another principal's held owner inspection receives state/code/refs
without result contents.

Root applies `apply_run_dispatch_migrations` after app records, shared S3,
S12/run approvals, jobs/runners and use-context migrations, BEFORE constructing
`UseApprovalAudit(enable_runs=True)`. The same use-audit branch then routes
`is_use_approval` and `is_run_approval`; root does not implement either policy
or proof grammar. **Open (aweb-acgh.18.14):** the console still refuses every
run approval decision with 503 `release_context_unavailable`, so a run that
needs approval cannot be decided. Root mounts
`runner_dispatch_router(service=...)` with the run instance on the API origin
outside B1, while `use_router` stays under its exact B1 dependency.
**In flight (aweb-acgh.18.21):** the constructors and routers are on main; the
final root/S19 journey proof is not. Short-lived/internal issuance is
unavailable (**After the first release (aweb-acgh.41.1)**).

## Runner adapter boundary

The concrete immutable `RunnerSubmission` and `RunnerReply` DTOs and structural
`RunDispatchAPI` protocol live in `aweb_secrets.runner_types`. The service
implementation is `aweb_secrets.run_service.RunDispatch`, which root mounts
through `runner_dispatch_router`.

S15a implements bounded HTTP framing and maps `RunnerRefused` using the
runner protocol §4.5. S13's service owns all database transactions. The adapter
passes immutable raw bytes; it does not authenticate in a separate committed
transaction, consume a nonce early, select work, open values or publish an
assignment. Registration keeps its separate code-exchange router.

```python
@dataclass(frozen=True, repr=False)
class RunnerSubmission:
    header: str  # X-AWEB-Secrets-Runner-Request, preserved verbatim
    method: str
    raw_target: str  # exact signed external path and query
    body: bytes  # complete bounded original bytes, not re-encoded JSON

@dataclass(frozen=True, repr=False)
class RunnerReply:
    status: Literal[200, 204]
    body: bytes | None  # exact stored signed assignment bytes, or None

class RunDispatch:  # aweb_secrets.run_service
    async def claim(self, submission: RunnerSubmission) -> RunnerReply: ...
    async def started(self, dispatch_ref: str, submission: RunnerSubmission) -> RunnerReply: ...
    async def result_body_limit(
        self, *, dispatch_ref: str, header: str, method: str, raw_target: str
    ) -> int: ...
    async def result(self, dispatch_ref: str, submission: RunnerSubmission) -> RunnerReply: ...
```

`runner_dispatch_router(service=...)` in `aweb_secrets.runner_routes` sits beside
`runner_registration_router`. It mounts only the three protocol paths
on the API origin, outside B1's member-tool router. It sends `Cache-Control:
no-store` on every success/error and returns `RunnerReply.body` without JSON
re-encoding. It never accepts team-auth or a console session as runner authority.
Claim/started accept exactly `{}`; result has the six-field report and
pinned bounds. The service rechecks semantic shape after runner authentication;
framing/media limits can refuse before unbounded reads. Reports return `204`.

For a result, the adapter first applies the global framing/media/header caps,
then calls `result_body_limit` **before streaming the body**. S13 parses the
signed header, reads the active registered runner key, checks its signature
through `verify_request_signature` (`aweb_secrets.runner_protocol`),
and checks signed origin/method/exact external target/time. Actual body-hash
verification is necessarily deferred. It then resolves the original scoped
dispatch/run association for that runner and its persisted pinned output
bound, never a caller bound or a replacement current job definition. Unknown,
foreign and unassigned references share `404 runner_dispatch_unknown`.

The returned integer is `6 * original_output_max_bytes + 1024`, within the
protocol's global cap. All read transactions and temporary key locks end
**before this method returns and before the body streams**. This is an inert
size hint: no nonce, admission, custody read, state change, assignment or
effect authority. It exposes no plan, key, raw output or alternate dispatch
handle. Dependency failure is `503 runner_unavailable`; other precheck errors
use the runner protocol statuses. The adapter enforces the returned
limit incrementally, aborting an oversized frame with `413
runner_request_too_large`; it then passes the original complete bytes to
`result`. That final method independently resolves scope/bounds and reverifies
the exact body hash, time and current locked key before semantic validation,
state/dedup checks and atomic nonce/report/evidence/outbox effects. A key,
installation or scope change during streaming therefore refuses at the final
check. Neither a returned integer nor an earlier successful preflight is
accepted as final authority. Claim/started retain their fixed 4096-byte bounds.

S13 calls `runner_scope` for routing only, refreshes F6 outside
locks, takes the installation fence first (decision 43) and then the complete authority lock
order (roles/forest/grants/job/runner, then coverage/B2 as applicable, then S3).
Before external preparation, verify the runner signature/binding/time without
committing a nonce or effect; discovery is inert and any read transaction ends
before opening. Repeat current-key verification in the final transaction.
Authentication and nonce consumption use `runners.authenticate_in` **inside the final effect
transaction**, with the current held runner signing key, exact target/body and
live time. S15a retains that implementation and `seal_credential`/
`sign_assignment`; it must not wrap them in independently committed effects.

An admitted run is an internal persisted association of original frozen plan,
S12 joint admission/ordered slots, requester/install/generation and one S3 UUID.
Consumers pass no `AdmittedRun`, `PreparedRun`, key, plaintext or plan as HTTP
authority. A `dsp_` alias is minted once on that UUID record, not another registry.
Credential preparation uses exact original contexts through `UseSecretOpener`
outside all transactions. A fresh final DB-only fence rebuilds the original
plan and checks contexts/backend epochs, current keys, containment, approvals
and expiry; it never consumes an approval again. `seal_credential` uses the
current held registered X25519 key and the immutable `dsp_` alias as HPKE info.
Structured plaintext uses the sole custody codec. `sign_assignment` signs with
the configured pinned service key. Assignment bytes, alias, nonce, S3
dispatching and required outbox rows commit together before returning bytes.

| Call | Permitted effect |
| --- | --- |
| `RunDispatch.submit` | New received/pending or jointly admitted run and required events. No credential release. Fresh same-body resubmission may consume approvals once. |
| `RunDispatch.claim` | Wait at most 30 s without a tx/locks; final authenticated empty claim consumes nonce. Original admitted run may become dispatching with one stored assignment. |
| Claim preparation failure | Recheck for a concurrent published winner first. Only still-admitted attempt may become refused, atomically with nonce/refusal event; return `503 runner_unavailable`. |
| Claim replay | Current registration/key and original scope/generation/containment checks, fresh nonce, exact unexpired stored bytes. No reopen/reseal/new expiry. |
| `started` | Record started once, with nonce; no second S3 dispatch transition or release. |
| `result_body_limit` | Header-only signature/binding/time and scoped pinned-bound read; close the read transaction, return only a byte limit. No nonce or effect. |
| `result` | Sanitize with the runner protocol §4.3 context reopened under the assignment pin; S3 CAS dispatching to completed, or retain sanitized late evidence after unknown/reconciliation. Nonce/report hash/evidence/outbox atomic. |

Only one unresolved released assignment per runner. Unknown blocks claim with
`409 runner_reconciliation_required`; an expired executable assignment still
dispatching yields `409 runner_dispatch_state_conflict`. Idle alone yields
`204`. Identical raw result retries with fresh nonces have no duplicate effect;
different raw report bytes conflict after the first accepted report. Result
does not require started first. The original job timeout plus margin governs
sweeping, not assignment expiry. Redaction reopens each slot under its
assignment pin and checks it against its keyed digest (runner protocol §4.3);
any failure withholds output, and nothing reopens at the current version. Exact HTTP
errors, replay/late-report rules and proof obligations remain the runner
protocol's, without a second lifecycle in an adapter.

## Owner reconciliation control boundary (§11.4)

**In flight (aweb-acgh.18.14):** the types, reader, policy, local audit
branch, `ReconciliationControls` service and the console settlement page
(`aweb_secrets.console_reconciliation`) are on main. Root does not compose
them: its migration list omits `apply_reconciliation_migrations`,
`SecretsAudit` routes only use and run approvals, the console change-set
approval kind passes `enable_reconciliation=False`, and
`console_reconciliation_router` is not among the console routers. Until root
composes them, an owner cannot settle an `outcome_unknown` from the console.

The frozen types live in `reconciliation_types.py`. `ReconciliationOriginal`
names the original installation/team/generation, opaque `reconcile_ref`, caller
request ID, S3 dispatch UUID, original requester and value-free resource/job or
operation pins. `ReconciliationView` adds the current S3 state. It contains no
request parameters, response entity, proof or personal link.

`ReconciliationView` and `ReconciliationControlStatus` append
`repeat_state: State | None = None`. After authorizing the original scope and
generation, the reader observes its unique broker continuation in the same
caller transaction with a plain SELECT. No continuation means `None`; a
mismatched or multiple association refuses. Run originals retain `None`.
Shared S3 migrations, including 002 continuations, must be applied before
constructing or serving this reader. The observation adds no authority and
never changes `ReconciliationOriginal` or the covered control request/hash.
No broker continuation exists until the safe-repeat call site is built (see
"Member tools: inputs and replay"), so on main `repeat_state` is always `None`.
The page can show an admitted/dispatching repeat in flight, an unknown repeat
as uncertain, and a settled original whose unknown repeat no longer blocks
the pair while retaining its result as evidence. The owner may still settle
an uncertain original while the repeat is in flight; status grants no action.

`ReconciliationControl` freezes the original association, chosen
`completed|failed|unknown-closed` outcome, control UUID, actual B2 approval ID,
approval reference and covered-request hash/policy identity, exact owner
scope/subject and expiry. The control uses a real owner-only B2 request.
`ReconciliationControlStatus` exposes its bounded state/delivery metadata;
`ReconciliationReceipt` exposes the persisted original settlement and control
identities. Only `ReconciliationPresentation` has a transient personal token,
excluded from its representation. Status and read DTOs never contain it.

The original-association reader is
`ReconciliationReads(enable_runs=False).get(tx, *, scope, reconcile_ref)`.
`scope` is the authoritative `AdmittedInstallation`; the caller holds current
OWNER, S4 and F6 in this original transaction and performs final F6/session/expiry
checks after the read. The reader returns an immutable `ReconciliationView` or
`None`, and refuses a superseded generation. It accepts only the original
opaque locator. `enable_runs=True` requires the run-dispatch migrations first;
root composes it with the same enabled run path. Reading grants no mutation
authority and takes no row locks.

The control flow uses the same Approvals/Passkeys services and B3 APPROVE.
An explicit S4 POST mints the frozen owner-only B2 LINK control request in the
caller's transaction; ordinary `Approvals.deliver` follows commit and reports
its actual result. The exact owner's token may continue in that current S4
browser, after a postcommit exact-current-owner/F6/session check. The console
keeps it transient, outside logs and browser storage. Custody's common approval
entry dispatches from the actual immutable control association; pre-login it
returns only the personal candidate's scoped sign-in hint. The token is never
authentication.

Fresh APPROVE records the control decision. A subsequent explicit S4 POST
settles in one caller transaction, consuming only that control approval and
atomically reconciling the original S3/B2. The original send approval stays
consumed. OWNER/designation/credential/F6 preparation precedes downstream
approval locks; final live authority and expiry checks follow all waits and
audit writes. The control uses its own provider/audit branch; settlement does
not acquire the positive-use target/backlog availability gate. GET, reload and
status never mint, decide or settle, and a lost reply never triggers automatic
mutation retry. Root injects the same branch into the composite and console
when it composes reconciliation (see the In flight note above).


The concrete control policy and local audit branch are
`ReconciliationPolicies(db, *, owners=shared_directory)`,
`ReconciliationApprovers(*, owners=shared_directory)` and
`ReconciliationAudit(*, reads=shared_reads, approval=plain_original_tx_reader,
passkeys=request_time_shared_passkeys_getter)`. The classifier is
`is_reconciliation_control(event)`. Root routes that classifier before any
fallback and requires the branch. Its `approval(tx, id)` callback must use the
same shared B2 store's plain `get_in(id, tx)`, never a locking read.

`reconciliation_request(original, *, control_id, outcome, owner_scope,
owner_subject)` and `reconciliation_policy_ref(request)` freeze the original
pins, chosen outcome and exact owner into B2's canonical covered request.
The owner-only policy expires within five minutes. Candidate selection returns
only that exact current owner; an empty set remains final. The
OwnerDirectory/UseApprovers current-holder routing still supplies B2's
`is_current`, with no new authority interpreter in root.

Apply `apply_reconciliation_migrations(db)` after shared B2/S3, records and
use-context/audit migrations, before composing the control branch. Enable run
reads only after run-dispatch migrations. `ReconciliationAudit.control(tx, *,
scope, approval_id)` returns the frozen association without tokens or effects.
Control associations, local events and retained-proof commitments are immutable.
No hook producer is injected into this branch. Actual settlement retains the
original S3 reconciled hook. These providers and audit do not themselves mint,
consume or settle; the caller-owned `ReconciliationControls` service below does.


`OwnerReconciliationFence` is the frozen console-owned protocol in
`reconciliation_types.py`. Its readonly `scope`, `owner_scope`, `owner_subject`
and `expires_at` bind the authoritative installation and exact current S4
owner. `prepare(tx)` prepares/caches the complete F6/OWNER/B3 union, then exact
LOGIN and S4 holds, and returns the shared `PreparedCurrentApprovers` handle.
S13 only checks that handle; it does not prepare another B3 union. `check(tx)`
is a plain read under those holds, ending with live F6 and pure session expiry.
Both methods use the identical original caller transaction. A new postcommit
presentation transaction takes a new fence. This credential-holding fence must
never span the separate fresh `Approvals.decide` ceremony.

The frozen `ReconciliationControls(*, reads, audit, approvals, passkeys,
use_audit, broker, runs, clock)` consumes the same shared services. A missing
broker/run backend refuses before any control write. Its methods are:

- `mint(tx, *, reconcile_ref, outcome, fence) -> PendingApproval`. The pending
  is internal, never a reply DTO; expiry clamps to the exact S4 expiry and the
  five-minute policy. Call ordinary `Approvals.deliver` once after commit.
- `status(tx, *, scope, approval_id) -> ReconciliationControlStatus | None`.
  The caller authorizes the read. This inert method has no token and uses no
  credential-holding preparation.
- `present(tx, *, pending, fence) -> ReconciliationPresentation`. A fresh
  postcommit transaction checks the exact owner, persisted B2/link identity and
  live authority; release its token only after that transaction commits.
- `settle(tx, *, approval_id, fence) -> ReconciliationReceipt`. Outcome comes
  only from the frozen control. All tentative consumption, original B2/S3
  consequences and audit records share a savepoint, so a caught refusal cannot
  leave a partial settlement. The complete B2 union precedes S3; final caller
  and shared-handle checks and pure control/session deadlines follow all audit
  waits. A repeated explicit POST may read its identical persisted receipt,
  never replace another settlement or rearm anything.

`ReconciliationRefused` exposes fixed `.code`/`.status` pairs:
`reconciliation_not_found`/404, `owner_required`/403,
`reconciliation_invalid`/400 and `reconciliation_conflict`/409. Shared
`ApprovalRefused` maps to 409 `approval_refused`;
`InstallationRefused` retains its fixed code/status; `UseAuditUnavailable`
remains 503 `release_context_unavailable`. Caller 401 session and 403 owner
refusals pass through; other database failures propagate and roll back.

## Public signed use correlation

For admitted broker/run uses, signed `post-secret-use` payload `use_ref`
is exactly the member response's server-minted `request_ref`. Frozen
audit contexts retain it through approval decisions, resubmission, transport
and result replay, uncertainty and owner settlement. Separate executions have
separate refs; `dispatch_id`, `job_id` and `job_digest` retain their meanings.

An attributable pre-admission refusal commits a fresh random 128-bit `use_`
reference in the signed event and its local correlation in the same outer
refusal transaction. Only after commit does the refused response present
`use_ref`. A repeated refusal creates another attempt/ref without an intent,
idempotency claim, dispatch or rate charge. If the authenticated scoped original
use already exists, the refusal retains that original intent ref. Unattributed
failures and rolled-back recording present no audit ref. The ref grants no
lookup, retry, deduplication or execution authority.

Member input models reject `use_ref`; refs never contain caller request IDs,
parameters, reasons or credential material. Owners join the actual response ref
to signed retained `payload.use_ref`, installation/generation, team and canonical
actor DID. `use_ref` is optional in hook catalog v1; events without it stay
valid and are not backfilled. The field is in catalog v1 in place, under Juan's
ruling on use_ref in place in v1; receivers on earlier published catalogs
refuse events carrying it and must upgrade (CHANGELOG.md).
