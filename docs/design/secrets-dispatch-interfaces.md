# S13 consumer interfaces

Status: **proposed consumer boundary, implementation pending** (aweb-acgh.18.14).
This note lets S16 and S15a build adapters against S13. Consumer fit does not
constitute implementation review or enable routes. Changes return to both
consumers. S13 owns the services, shared S3 composition, registry and sole
`UseSecretOpener`; adapters receive no independent dispatch or custody authority.

Sources: [secrets](secrets.md) §§4.1, 7, 9–11, 13; the
[runner protocol](../secrets-runner-protocol.md) §§1–4; and the existing
`manifest.py`, `broker_input.py`, `tool_results.py`, `run_plan.py`,
`run_approvals.py`, `runners.py` and `runner_results.py` in `naapp/secrets`.
Short-lived issuance remains parked. The first runner implementation accepts
durable slots; it does not silently convert a short-lived slot to durable.

## Member tools: inputs and replay

All routes below use the exact shared B1 dependency on the API origin. Cookie
presence grants nothing. These tools are absent from the human console origin.
JSON inputs use the existing strict integer/Unicode-scalar value rules; unknown
fields, duplicate keys, floats and invalid types refuse without sending.

| Tool | Method and path | JSON body |
| --- | --- | --- |
| request | `POST /v1/secrets/{secret}/requests` | Named: `request_id`, `operation`, optional `params`, `headers`, `reason`. Open: `request_id`, `method`, `url`, optional `headers`, `data`, `reason`. |
| run | `POST /v1/jobs/{job}/runs` | `request_id`, `runner`, optional `params`, `reason`, `secret`. |
| status | `GET /v1/status/{ref}` | None. Request ID or returned request/approval/reconciliation locator. |

Path parameters are not repeated in the HTTP body. Named input forbids
`method`, `url`, `data`; open input forbids `operation`, `params`. Named headers
are supported by the existing renderer, but only where the operation explicitly
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
`secret` is the existing ordinary-child selector for the unique durable slot.
Omission keeps the job's fixed selectors; there is no caller slot map.

Normalization follows `BrokerInput`: omitted `params` becomes `{}`, omitted
`headers` becomes `[]`, and omitted `reason` becomes `""` (at most 1024
characters). Open `data` defaults to the empty string. String data is UTF-8;
object data uses sorted-key compact UTF-8 JSON. The existing egress canonical
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
it is separate from the normalized equality hash. Neither a status read nor a
background broker task reconstructs and sends the original request. A
`not_sent` broker retry keeps the same dispatch and upstream idempotency key,
and must still meet its original approval expiry or total time bound. An
uncertain/completed/reconciled attempt never becomes a new send on replay.

## Member tools: replies

Replies use the existing `tool_results` envelope vocabulary, with the pending
and receipt states below added by S13. The client reads `state` independently
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
| `outcome_unknown` | 200 | `request_ref`; no automatic retry. |
| `refused` | refusal HTTP below | `code`; `request_ref` only if an intent exists. |
| `cancelled`, `reconciled_completed`, `reconciled_failed`, `reconciled_unknown` | 200 on retrieval | `request_ref`; sanitized `result` if one exists. No new execution. |

Successful status reads return `200` with this envelope at the top level,
including pending/progress/withheld/refused states. Looking up an approval
locator additionally uses S12's existing `denied`, `expired`, `revoked` and
consumed `admitted` states; `next: "resubmit"` occurs only for `approved`.
An intent lookup aggregates its slot decisions: still pending is
`awaiting_approval`, every required approval ready is `approved`, and a failed
required slot is `refused` with its fixed approval refusal code. `approval_ref`
names the first unresolved required slot; `approval_refs` lists all unresolved
ones. Clients should poll `request_ref` for the aggregate, not infer readiness
from one approved slot. These references expose no approval link or evidence.

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
metadata from `RunnerOutput`; loss of original redaction context withholds
output with `code: "release_context_unavailable"` and preserves safe metadata.
The existing `result_withheld` helper needs its safe-result/receipt extension;
this note does not claim that helper or any route is already implemented.

POST refusals: `400` invalid input, `403` policy/grant/approval/containment
denial, `409 idempotency_conflict`, `410 idempotency_expired`, `429
policy_rate_limited` with `Retry-After`, `503` required dependency/audit
availability. S3 `dispatch_in_flight` and `reconciliation_pending` map to
`409` refused envelopes, not an admitted result. B1 authentication/scope errors
retain the runtime's own HTTP error shape; clients must also handle that shape.
Malformed transport retains `413`/`415` as appropriate. No exception text or
raw input is returned. No new public hook refusal enum is introduced here.

## Callable boundary and mounting

The following signatures name the planned S13 implementation modules; they are
design declarations, not callable shipped stubs. `ToolReply.body` is the JSON
envelope above. `MemberSubmission` is internal data constructed only after B1,
using the matched `Authorization.tool` and the complete original request bytes.
`JSONValue` denotes the strict JSON value domain above. Types from existing
modules (`Authorization`, `RequestBytes`) retain their existing definitions.

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

class JobRuns:  # aweb_secrets.run_service
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

Keep `metadata_router(MetadataServices(catalog=get_catalog), authorized=...)`.
S13 adds `use_router(UseServices(broker=get_broker, runs=get_runs,
status=get_status), authorized=...)` in `aweb_secrets.use_routes`, with request-time
getters because runtime DB/services exist after startup. The app owner passes
both factories through `create_app(tool_routers=...)` and uses the exact
`authorized` supplied by that factory. S16 owns client rendering/tests and can
supply its metadata factory. The secrets-app seat owns the use router and the
broker/run services; secrets-root owns `app.py`, configuration, final root
mounting and S19. The root constructs one shared set of dependencies and injects
it into the services; all admission, dispatch and release transactions and final
fences remain in those services. Human routers use the one shared OwnerConsole
separately.

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

`RunDispatch.status` is its inert `RunStatus` reader. Construct the ONE shared
`UseStatus(db, fence=shared_fence, approvals=shared_approvals,
runs=run_dispatch.status)`, pass that status getter to `UseServices`, and use
the run instance itself for the member-run and runner-adapter getters. Status
never dispatches or consumes; another principal's held owner inspection
receives state/code/refs without result contents. `runs=None` preserves the
existing broker-only status path without querying run tables.

Root applies `apply_run_dispatch_migrations` after app records, shared S3,
S12/run approvals, jobs/runners and use-context migrations, BEFORE constructing
`UseApprovalAudit(enable_runs=True)`. The same use-audit branch then routes
`is_use_approval` and `is_run_approval`; root does not implement either policy
or proof grammar. This replaces the reserved run failure branch only when the
actual service is composed. Mount `runner_dispatch_router(service=get_runs)`
on the API origin outside B1, while `use_router` stays under its exact B1
dependency. These constructors and routers alone do not establish the final
root/S19 journey proof. Short-lived/internal issuance remains unavailable.

## Runner adapter boundary

The concrete immutable `RunnerSubmission` and `RunnerReply` DTOs and structural
`RunDispatchAPI` protocol live in `aweb_secrets.runner_types`. The actual service
implementation remains `aweb_secrets.run_service.RunDispatch`; publishing the
transport types does not implement or activate its transactions.

S15a implements bounded HTTP framing and maps `RunnerRefused` using the existing
runner protocol §4.5. S13's service owns all database transactions. The adapter
passes immutable raw bytes; it does not authenticate in a separate committed
transaction, consume a nonce early, select work, open values or publish an
assignment. Registration keeps the existing separate code-exchange router.

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

S15a can implement `runner_dispatch_router(service=get_run_dispatch)` beside
`runner_registration_router`. It mounts only the three existing protocol paths
on the API origin, outside B1's member-tool router. It sends `Cache-Control:
no-store` on every success/error and returns `RunnerReply.body` without JSON
re-encoding. It never accepts team-auth or a console session as runner authority.
Claim/started accept exactly `{}`; result has the existing six-field report and
pinned bounds. The service rechecks semantic shape after runner authentication;
framing/media limits can refuse before unbounded reads. Reports return `204`.

For a result, the adapter first applies the global framing/media/header caps,
then calls `result_body_limit` **before streaming the body**. S13 parses the
signed header, reads the active registered runner key, checks its signature
through `verify_request_signature` (source-reviewed helper at `9a98d8600`),
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
use the existing runner protocol statuses. The adapter enforces the returned
limit incrementally, aborting an oversized frame with `413
runner_request_too_large`; it then passes the original complete bytes to
`result`. That final method independently resolves scope/bounds and reverifies
the exact body hash, time and current locked key before semantic validation,
state/dedup checks and atomic nonce/report/evidence/outbox effects. A key,
installation or scope change during streaming therefore refuses at the final
check. Neither a returned integer nor an earlier successful preflight is
accepted as final authority. Claim/started retain their fixed 4096-byte bounds.

S13 calls the existing `runner_scope` for routing only, refreshes F6 outside
locks, takes the installation fence first and then the complete authority lock
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
| `JobRuns.submit` | New received/pending or jointly admitted run and required events. No credential release. Fresh same-body resubmission may consume approvals once. |
| `RunDispatch.claim` | Wait at most 30 s without a tx/locks; final authenticated empty claim consumes nonce. Original admitted run may become dispatching with one stored assignment. |
| Claim preparation failure | Recheck for a concurrent published winner first. Only still-admitted attempt may become refused, atomically with nonce/refusal event; return `503 runner_unavailable`. |
| Claim replay | Current registration/key and original scope/generation/containment checks, fresh nonce, exact unexpired stored bytes. No reopen/reseal/new expiry. |
| `started` | Record started once, with nonce; no second S3 dispatch transition or release. |
| `result_body_limit` | Header-only signature/binding/time and scoped pinned-bound read; close the read transaction, return only a byte limit. No nonce or effect. |
| `result` | Sanitize with original transient context; S3 CAS dispatching to completed, or retain sanitized late evidence after unknown/reconciliation. Nonce/report hash/evidence/outbox atomic. |

Only one unresolved released assignment per runner. Unknown blocks claim with
`409 runner_reconciliation_required`; an expired executable assignment still
dispatching yields `409 runner_dispatch_state_conflict`. Idle alone yields
`204`. Identical raw result retries with fresh nonces have no duplicate effect;
different raw report bytes conflict after the first accepted report. Result
does not require started first. The original job timeout plus margin governs
sweeping, not assignment expiry. Original redaction values stay transient;
restart/context loss withholds output, never reopens custody. Exact HTTP
errors, replay/late-report rules and proof obligations remain the runner
protocol's, without a second lifecycle in an adapter.
