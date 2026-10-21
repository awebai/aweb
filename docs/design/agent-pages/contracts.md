# D1 wire sketches and review cases

These sketches supplement [agent-pages.md](../agent-pages.md). All interfaces
here are **proposed**, not shipped. JSON examples use synthetic data and
signature placeholders. They are not cryptographic conformance vectors.
C1–C5 must freeze byte vectors and semantic cases after review.

## Resource and mutation API sketch

Routes below describe the pages naapp, not hardcoded Cloud routes. A manifest
maps tools to them; the independent fixture deliberately uses other paths.
Member requests use existing team-auth v2 in addition to the typed body.

| Operation | Draft route | Preconditions and result |
| --- | --- | --- |
| List/read | `GET /v1/pages`, `GET /v1/pages/{id}` | Actor/row/field authorized snapshot, `rev`, layout version, bounded projections/cursors; no cross-member cache. |
| Layout version | `POST /v1/pages/{id}/layouts` | Expected page revision, layout, key; append immutable version. |
| Record create/update/delete | `POST /v1/pages/{id}/records` | Collection, operation, record ID, expected revisions, values/patch, key; one transaction. |
| Display state | `POST /v1/pages/{id}/widgets/{widget}/state` | Allowlisted display patch, expected page revision, key. |
| Action submit | `POST /v1/pages/{id}/actions` | Action definition, input, revisions, key, task authorization for task creation; receipt. |
| Action progress | `POST /v1/pages/{id}/actions/{action}/progress` | Assigned executor, expected action/page revision, key; explicit picked-up evidence. |
| Action resolution | `POST /v1/pages/{id}/actions/{action}/resolve` | Assigned executor, result, patches, expected revisions, operation/approval evidence, key. |
| Decision answer | `POST /v1/pages/{id}/decisions/{task}/answer` | Same conditional answer coordinator as acah.4; current assignee human signature, task/proposal revision/hash, answer key. |
| Pending recovery | `GET /v1/pages/requests/pending` | Only the actor's authorized journals, bounded cursor; sponsor also gets its configured anonymous pending entries. |
| Export/delete | Manifest lifecycle tools | Durable job receipt and coverage, authorized independently after uninstall; never ordinary read/write scope resurrection. |

Successful local edit is `200 {transaction_id,page_rev,record_revs,audit_id}`.
Task-creating action is `202 {action_id,page_rev,delivery:"pending",execution:
"not_started"}`. Only stored task acknowledgement changes `delivery` to
`queued`; a retried transport is not a new intent. Status reads include action
revision, task ID/revision, task synchronization state, one-line result,
external operation status and observed health separately. These projections
are derived from authenticated sources; page authors cannot type them into
widget state to claim a task was completed.

| Status | Stable error code | Meaning |
| --- | --- | --- |
| 401 | `signature_invalid`, `certificate_revoked` | No authenticated member/capability proof. |
| 403 | `scope_denied`, `action_denied`, `target_mismatch` | Authenticated actor lacks this operation; don't expose hidden resource identifiers. |
| 404 | `resource_not_found` | Absent or invisible resource; same outward error to prevent enumeration. |
| 409 | `revision_conflict`, `idempotency_conflict`, `approval_changed` | Re-read or correct the request; nothing partially committed. |
| 410 | `link_unavailable`, `idempotency_expired` | Only when the caller already knows/has authority over that capability/key; otherwise generic unavailable. |
| 422 | `schema_invalid`, `target_unresolved` | Bounded JSON pointer details to authorized fields; no private record values in error. |
| 428 | `precondition_required` | Expected revision missing. |
| 429 | `safety_rate_limited` | Security bound, with bounded retry-after; not a price/plan cap. |
| 503 | `authority_unavailable`, `delivery_unavailable` | No stale authority fallback; an accepted journal remains inspectable pending recovery. |

Log the real error and safe correlation ID; user errors distinguish signature,
permission, conflict and unavailable authority. Don't log body, tokens or guest
content. Error outward status must respect visibility even when the internal
cause is specific.

## Task ingress and task authorization

A new public `POST /v1/tasks/app-requests` accepts:

```json
{
  "task": {
    "title": "Review app request",
    "assignee": "stable-agent-identity",
    "app_request": {
      "team_id": "demo:example.com",
      "app_id": "fixture",
      "installation_id": "installation-1",
      "external_request_id": "fixture-op-1",
      "resource_ref": "opaque-page-id",
      "action_ref": "opaque-action-id",
      "proposal_rev": 1,
      "proposal_sha256": "<digest>"
    }
  },
  "task_authorization": {
    "payload": "<canonical typed payload described in design section 4>",
    "signature": "<base64 Ed25519 signature>",
    "certificate": "<member team certificate>"
  }
}
```

`task_body_sha256` covers canonical `task` bytes exactly. Signing bytes for the
nested authorization are UTF-8 `aweb.app-task-authorization/1\n` followed by
canonical payload bytes (sorted keys, no insignificant whitespace, no floats).
This prefix is **literal newline**, not two characters backslash+n. Payload
is presented as an object with detached signature; consumers re-canonicalize
and compare exact bytes per frozen vectors, reject duplicate keys/nonfinite
numbers and any unknown security fields. Member DID and certificate must agree
with the outer member request at naapp acceptance. The task service independently
reverifies member signature/current authority at delivery, not the naapp's claim
that it did so. It checks task target ID, approved app/installation, proposal
reference and expiry as well as body digest. HTTP app transport uses the new
`app-request` purpose from the design, with exact external target binding.

The response is `201` on creation or `200` on a matching replay, returning
`{task_id,task_rev,external_request_id,request_sha256,originator,transport_app}`.
A `GET /v1/tasks/app-requests/{external_request_id}` reconciles a lost receipt,
scoped to the registered installation/request; an app cannot enumerate other
team tasks. The naapp verifies receipt via this authenticated authoritative
runtime API at the configured task origin, not a caller-provided status object
or URL. HTTPS authenticates that runtime; no invented task-service signing key
is silently trusted. The app's receipt-read scope cannot create/answer tasks.

Task authorization expires before initial delivery, but an accepted task's
existence survives that expiration. Matching replay after expiry can retrieve
an existing receipt only after current transport and receipt-read authorization;
it cannot create an absent task. Reinstalled apps cannot replay an old
installation's requests. Cancellation/installation revocation fences first
creation; races with already committed creation return its receipt and enqueue
cancellation rather than claiming nonexistence.

## Conditional answer and approval receipt

Both the page and acah.4 dashboard call one answer coordinator. Input is
`{task_id,expected_task_rev,proposal_ref,proposal_rev,proposal_sha256,answer,
answer_key,expected_page_rev}` plus retained member-signed request evidence.
Answer content is staged under app ACL first, with immutable digest. The task
runtime then conditionally commits one answer reference/commitment against the
current task/assignee/proposal, and returns an answer receipt. The naapp verifies
that receipt through the authoritative task runtime and activates the matching
approval in a local transaction. Lost receipts reconcile by `(task_id,answer_key)`;
different answer bytes under that key conflict. Staged content without a task
answer is not approved; a task answer without activated app approval is visibly
pending and cannot dispatch. Rejection needs no external execution authority.

The task remains the answer ledger. Its comment carries the answer's full text,
which the team sees (Juan's ruling of 2026-10-20), and the app keeps its
structured answer verified against that text's digest, not as another
independently editable answer state. No other guest content is mirrored
implicitly.
The task's typed answer cannot be changed by plain comment/close; reopening
creates a new question revision, invalidating prior approval before dispatch.
Current page policy and eligibility as an approving human are checked from
trusted membership/app policy, not an `is_human` field in input.

An approval record binds task answer receipt, human signer/certificate, proposal
hash/revision, target executor, exact external destination/operation/constraints,
source version, expiry and stable operation ID. External adapter admission
checks the record online at the naapp, current revocation/policy and operation
binding, then returns durable admission status. There is no offline reusable
approval bearer token in the draft. No dispatch if the authorization service is
unavailable. After admission, reconcile the operation ID/provider receipt;
repeated requests cannot create a second send. A member-readable task comment
is never such an admission record.

## Version discovery sketch

Preserve `/.well-known/aweb-app.json` as the legacy v1 manifest during rollout.
New consumers discover `/.well-known/aweb-app-versions.json`:

```json
{
  "catalog_version": 1,
  "app_id": "fixture",
  "variants": [
    {"manifest_version": 1, "url": "/manifests/v1.json", "digest": "sha256:<exact bytes>"},
    {"manifest_version": 2, "url": "/manifests/v2.json", "digest": "sha256:<exact bytes>"}
  ]
}
```

Choose highest supported version, fetch same-origin bounded bytes, verify digest
and all app-origin/ID/version constraints; no redirects or fallback after a
corrupt catalog/digest. A missing catalog (404) alone permits legacy discovery;
a present invalid catalog fails. Admin approves the chosen bytes and semantic
scope diff. Each catalog response is public metadata, not authority replacing
the installed pin. Old manifest tools remain mapped to identical authorized
operations in the v2 migration; a local v1 manifest doesn't have to become v2
for its existing tool request to work. Removed mappings require a separate
measured compatibility change. Registry's active generation grants/scopes are
authoritative at call admission; a request's stale cached digest is never a
permission bypass. C3 freezes bounds, error vectors and mapping before rollout.

## Manifest capability additions

In v2, optional `usage` is `{format:"aweb.usage/1",snapshot_tool:<tool>}`;
optional `lifecycle` maps `export_tool`, `delete_tool`, `status_tool` to same-
manifest tool names. Lifecycle policies and byte/retention definitions come
from authenticated app/status responses, never trusted as admin authority just
because a public manifest claims them. `surfaces` fields and list/read/invoke
results are defined in the main design. All capability fields have strict
unknown-field rejection, bounded arrays and local references. Manifest events
must be declared in the same namespace before binding a surface.

v2 declares app keys as `app_keys: [{kid, did_key, purposes}]`, with distinct
`kid` values and distinct purposes per key; a v1 `event_emitters` entry reads
as purpose `app-event` only and stays emit-only. App-request and app-usage credentials require separate
purpose-specific verifiers and authorization scopes even when the registered
app key is the same physical Ed25519 key, and a verifier accepts a key only
for a purpose it declares. Both bind installation ID/generation, timestamp and
body/target/audience. No event credential is accepted at those endpoints.
Retired installations have only their explicit terminal lifecycle grants.

## Hook registration slot and invocation contexts

The exact v2 slot is the main design's `hooks` object with
`registration_version: 1` and `registrations`. Each registration strictly binds
`catalog: {id,version}`, `hook`, local `tool` and distinct `scopes`. Manifest
scope names are requests, not authority. `productions` entries strictly bind
`catalog: {id,version}`, `hook` and optional distinct `reads`, each a local
non-mutating tool name. Owner activation binds the resolved same-manifest
tool/origin or producer, the current installation ID/generation/digest and
`active_from`; an ordinary admin install leaves both pending, and a new
generation returns both to pending. Catalog values in examples
are neutral placeholders; no hook catalog is frozen by these drafts.

Tool `invocation_contexts` is a nonempty unique array of `agent`, `surface`,
`hook`; absent means `agent,surface` for normal backward-compatible tools.
Registrable hook targets require exactly `hook`. A surface's `answer_tool` requires exactly `surface`; `invoke_tool` never
carries an `answer`, and an agent-visible answer path refuses the manifest. L2/CLI expose only `agent`,
surfaces reference only `surface`, and both list/call enforce current context
including cached tools. The endpoint requires verified caller-context authority;
context labels and informational team-auth metadata do not create that proof.
Hook envelope, target-resolution API, trace_id and producer outbox are downstream.
The app-event observer is never a hook firing site or delivery stream.

## Shared approval and one-use capability options

The [joint primitive](../agent-pages.md#joint-approval-primitive-pages-and-secrets)
has an [illustrative record](examples/approval-record.json) and is a proposed
runtime in naapp-lib (`aweb_naapp`, built as B2/B3) with each app owning its
records and trusted adapters. Its request digest framing, state machine and
one-use link fields are the draft defaults in the main design's joint
primitive section. `authenticator` is constrained to `member_session` or `passkey`, derived
from verified proof and checked against owner-controlled action policy. Proposed
minimum: passkey for external/irreversible effects and all secrets approvals;
member_session only permitted internal reversible decisions. **Juan must approve
this new assurance/UX recommendation.** The passkey adapter is app-local and on
the app origin; a dashboard does not manufacture that assertion. App-owned
credential records/enrolment/recovery require explicit owner control; they do
not create AWID membership or a generic Folio login/session.

C4 capability adds optional `request_sha256`, `one_use` and
`approver_policy_ref`. A successful authenticated action atomically compares
unused state/hash/policy/expiry/revocation and stores its operation ID; competing
consumes cannot both succeed. Reads/previews/failed challenges do not consume.
Matching retries only retrieve the prior result. Store token verifier hashes,
never raw bearer tokens. Approval-purpose links are issued/delivered outside
requester authority; agent tool output is `{request_id,delivery_status}` with no
link/token/capability. Task metadata refers to an approval by its opaque reference
and never carries its link, token or capability. Other delegated read/action capabilities do not become human
approval capabilities.

For the task adapter, earlier conditional-answer and exact-member-proof rules
remain mandatory; where the proposed policy requires passkey, add its app-origin
transaction proof mapped to the same designated human/task/proposal. For secrets
link presentation, `task_answer_ref` is absent and no task/chat/dashboard account
is required. Same approval record/hash/atomic dispatcher consume in either case.
Unknown upstream outcome must reconcile; a new dispatch needs a fresh approval,
while retrieving existing operation status never consumes/rearms the old one.

## Draft validation and review coverage

[Draft cases](draft-cases.json) names required positive/negative cases, not an
executed harness. Schema validation covers shape; semantic lint additionally
checks unique IDs, field/ref types, collection modes, schema safety/depth/size,
action policy/target resolution, task binding, upload constraints and unknown-
widget inertness. Inline record schemas permit a bounded JSON Schema subset
with local references only; deny remote/file refs, unbounded recursive forms and
excessive regex/validation work. Schema validity is not an authorization proof.

Future conformance freezes exact signature/body/query examples and both sides
of each boundary: valid neighboring actor/row/action versus wrong actor/row/
revision, approved exact operation versus changed destination, member task
request versus event credential or anonymous assertion, signed usage retry
versus overlap/gap, and reconnect after the event lookback. Runtime tests must
state whether the harness was actually demonstrated to fail for its target
fault; D1 has no such harness result and makes no implementation pass claim.
