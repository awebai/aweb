# Page actions, decisions and approvals

Status: **draft contract** (C2, aweb-acgg.8). It defines what a pages naapp
does with the actions an `aweb.page/1` page declares
([page-format.md](page-format.md)), how a person's decision on a proposal
becomes an approval, and which approval adapters accept it. Task creation and
task answers are [app-task-requests.md](app-task-requests.md). The design is
[agent-pages.md](design/agent-pages.md) §4.

Routes are the pages naapp's. A manifest maps tools to them, and other apps
may use other paths. Every member request is team-auth v2
([team-auth-envelope-v2.md](team-auth-envelope-v2.md)), with the typed body
below.

## 1. Action kinds

A page's `actions` define each action's `id`, `kind`, `label`,
`input_schema` and `policy_ref`, and optionally `target`, `operation` and
`requires_approval`. Layout only references them, and the naapp acts on its
own stored definition, never on the copy a caller sends.

- **`edit`** changes only declared local data or display state, immediately,
  without an agent. It is validated against the input schema, the field
  policy, the expected revisions and the idempotency key, and commits in one
  naapp transaction.
- **`intent`** asks an agent for work. The naapp journals it and creates a
  task for the resolved target ([app-task-requests.md](app-task-requests.md)).
  It returns a receipt before any agent runs.
- **`answer`** answers the existing task assigned to the signed-in person,
  tied to the exact proposal on the card (§4). It never creates a new
  request. Answers arrive only through the surface's `answer_tool`. The
  invoke handler refuses any request whose action, resolved from the stored
  definitions, is `answer`-kind ([app-manifest.md](app-manifest.md),
  "Surfaces and answers").

## 2. Targets

A target is resolved once, when the naapp accepts the action, and is then
frozen in the journal and in the task authorization's `target_did`:

- **Absent:** the page owner's agent principal.
- **`did:aw:…` or `did:key:…`:** that principal. It must be a current member of
  the team.
- **Anything else:** a role name in the grammar of `aweb_naapp.roles`
  (dot-separated, lowercase, at most 128 bytes). It resolves through the
  app's current role assignments to exactly one principal.

Zero or several principals is 422 `target_unresolved`. There is no fallback
and no silent reassignment. A later retarget is a separate, audited
operation by an authorized member.

## 3. Submitting an action: `POST /v1/pages/{page_id}/actions`

```json
{
  "action_id": "request-cleaner",
  "input": {"date": "2026-10-24"},
  "expected_page_rev": 12,
  "expected_record_revs": {"bookings/b-17": 3},
  "idempotency_key": "k_8e1…",
  "task_authorization": {"payload": { … }, "signature": "…", "certificate": "…"}
}
```

- `input` validates against the stored `input_schema`, using the same bounded
  checks as record values ([page-format.md](page-format.md)).
- `expected_page_rev` is required: missing is 428 `precondition_required`.
  `expected_record_revs` maps `<collection>/<record_id>` to revisions the
  action depends on.
- `idempotency_key` (`^[A-Za-z0-9._-]{1,128}$`) is scoped to the signing
  member and the page. The same key with the same body returns the first
  result. With a different body it is 409 `idempotency_conflict`.
- `task_authorization` is required for an `intent`, and is refused for `edit`
  and `answer`. The naapp checks that its `actor_did_key` and `certificate_id`
  equal this request's verified signer, its `target_did` is the target
  resolved by §2, its `action_id` is this action, and its `task_body_sha256`
  is the task body the naapp will send. It stores the authorization with the
  journal entry and the outbox row.

Responses:

- `edit`: 200 `{transaction_id, page_rev, record_revs, audit_id}`.
- `intent`: 202 `{request_id, page_rev, delivery: "pending", execution:
  "not_started"}`. `request_id` is the task request's
  `external_request_id`. `delivery` becomes `queued` only once the naapp has
  stored a verified task receipt.

A stale revision is 409 `revision_conflict`, and nothing is partially
committed.

## 4. Proposals and their digest

A proposal is a record that a person decides on. Its digest binds the
record's identity and exact value:

```text
proposal_sha256 = "sha256:" || hex(SHA-256("aweb.page-proposal/1\n" || C(proposal)))
proposal        = {"collection": <collection id>, "record_id": <record id>, "value": <record value>}
```

`C` is the canonical JSON of [app-task-requests.md](app-task-requests.md),
and the prefix ends in one literal newline byte. The record's `rev` is not
hashed. It is bound next to the digest, in the decision card's `record_rev`,
the bundle item's `record_rev` and the task's `proposal_rev`. So the same
content at a new revision has the same digest, while any change to the
content, to the record it lives in or to its collection has a different one.
Re-editing a proposal therefore needs a fresh answer.

A bundle's digest is the C1 rule ([page-format.md](page-format.md) §5): the
digest of its ordered `{record_id, record_rev, proposal_sha256}` items, each
item's `proposal_sha256` computed as above over its record in
`items_collection`.

The host computes the digest from the member-signed read and refuses the card
if it differs from the card's `proposal_sha256`. For a bundle, it refuses if
any item's revision or digest differs.

## 5. Deciding: the page answer flow

A decision card renders an `answer`-kind task assigned to the signed-in
person. Answering takes three member-signed steps, each idempotent and
recoverable. Steps 1 and 3 are two bodies of the one route the surface's
`answer_tool` maps, `POST /v1/pages/{page_id}/decisions/{task_id}/answer`, so
the answer path stays a single surface-only tool that the manifest's
answer-route checks cover:

1. **Stage.** A body `{"stage": {expected_task_rev, choice, input,
   proposal_rev, proposal_sha256, answer_key}}`. The naapp checks that the task
   is the card's and that the proposal is still current. It then stores the
   answer (choice and input) with the page, and returns
   `{answer_key, body_md, answer_sha256, approval_id, challenge}`. `body_md`
   is the answer's full text as the naapp renders it from the choice and
   input, deterministically, and `answer_sha256` is the bare hex SHA-256 of its
   UTF-8 bytes. The task comment shows that text to the team
   ([app-task-requests.md](app-task-requests.md) §4).

   `challenge` is the approval adapter's challenge (§7).
2. **Answer the task.** The same member answers the task with that
   `answer_key`, `body_md` and `answer_sha256` ([app-task-requests.md](app-task-requests.md)
   §4). A host that embeds the task service calls `answer_task_on`; any other
   caller uses `POST /v1/tasks/{ref}/answer`. The result is the answer receipt.
3. **Confirm.** A body `{"confirm": {answer_key, task_answer_ref, proof}}`,
   where `proof` is the adapter's proof. A body carrying both or neither of
   `stage` and `confirm` is 422 `schema_invalid`. The naapp reads the
   receipt itself (`GET /v1/tasks/answers/{task_answer_ref}`) and requires it
   to be `current`, with the staged `answer_sha256`, `choice` and proposal
   fields, and `answered_by` equal to the signer. It then decides the approval
   (§6) in one local transaction.

Staged content with no task answer is not approved. A task answer whose
approval is not yet decided is visibly pending and cannot dispatch. If step 3
is lost, the naapp finds the answer through its reconciliation read of the
task request and completes it; the person does not answer again. A rejection
closes the request without any execution authority.

Approve-and-edit stages a new immutable proposal record, so it has its own
digest. The person's approval covers the resulting bytes.

## 6. Approvals for page decisions

Page decisions use the shared approval primitive in `aweb_naapp` (B2). Its
request digest is:

```text
request_sha256 = hex(SHA-256("aweb.approval-request/1\n" ||
                 C({"policy": {"ref": <policy_ref>, "version": <policy version>}, "request": <request>})))
```

This is bare lowercase hex. The policy reference and version are inside the
hash, so changing the policy version needs a new approval. For a page
decision, `request` is:

```json
{
  "v": 1,
  "type": "aweb.page-decision",
  "app_id": "pages",
  "installation_id": "inst_01JB…",
  "page_id": "pg_4hd…",
  "action_id": "approve-price",
  "task_id": "…",
  "collection": "proposals",
  "record_id": "week-43",
  "record_rev": 2,
  "proposal_sha256": "sha256:<64 hex>",
  "operation": {"kind": "pms.rate.update", "destination": "pms:listing/7"},
  "source_version": "pms-sync-2026-10-20T11:58Z",
  "executor_did": "did:aw:…",
  "expires_at": "2026-10-21T12:00:00Z"
}
```

`operation` and `source_version` are `null` for an internal decision with no
external effect. For a bundle, `record_id` and `record_rev` name the bundle
record and `proposal_sha256` is the bundle digest. The request is fixed when
the card is shown. Changing any covered value needs a new approval.

- The approval is minted when the decision task is created, with
  `presentation: task` and `requested_by` set to the proposing principal's
  DID.
- It is decided only at step 3 of §5, with the receipt's `task_answer_ref`.
- It is executable only while that receipt is `current`. A reopen therefore
  invalidates it before dispatch.
- The executor admits it through the primitive's atomic consume before any
  external effect, under one stable operation ID. An unknown outcome
  reconciles before any retry, and a new dispatch needs a new approval.

**Requester and approver.** The primitive refuses at mint with
`requester_is_approver` when the approver's subject equals `requested_by`,
unless the action policy sets `allow_requester_approval` (default false), which
a policy may do only for an internal reversible action (aweb-acgh.25).
`requested_by` and member approver subjects are both principal DIDs, so the
comparison is exact. Until that change lands, the pages naapp makes the same
refusal before minting.

## 7. Approval adapters and minimum assurance

**Minimum assurance** (Juan's decision of 2026-10-19):

- `passkey` for every external or irreversible effect and every secrets
  approval.
- `member_session` only for internal, reversible decisions that the action's
  policy allows.

The action policy, held by the naapp, sets `min_assurance`. A caller cannot
choose it. The approval record stores the verified `authenticator`, and
admission rechecks it.

### `member_session`

A B2 `Authenticator` with assurance `member_session`. It returns evidence only
when every check passes. Otherwise it raises `AuthenticationFailed`, and never
returns partial evidence:

1. **Team-auth v2** verifies the confirm request and yields the member's
   certificate.
2. **Caller context.** The request carries an `aweb.principal-attestation`
   with `channel: dashboard`, verified per
   [principal-attestation.md](principal-attestation.md) §4. No attestation,
   or any other channel, fails. A member's own agent signs as the same
   custodial member, so this is what tells a person at the surface from that
   agent.
3. **One person.** `read_member_person` returns a valid record with
   `single_person: true` for the certificate
   ([member-person.md](member-person.md)). Absence, `false`, a stale record or
   an invalid one fails. A registry failure is `authority_unavailable`.
4. **Stable subject.** The certificate carries `member_did_aw`. A member
   without one cannot give a `member_session` approval, because a `did:key`
   rotation would orphan pending approvals.
5. **The task answer.** The receipt is current, `answered_by` derives the same
   principal and certificate, and the approval's challenge binding
   (`aweb.approval-challenge/1`, which commits to the purpose and
   `task_answer_ref`) is the one the surface committed to when it requested
   the decision.

Evidence: `subject` is the member's `did_aw`, `subject_type` is `member`, and
`evidence_ref` references the stored request and attestation. The approver
directory returns the same pair for member approvers.

### `passkey`

The app-local WebAuthn adapter in `aweb_naapp` (B3), at the app's own origin.
For a page decision, its challenge binds the same `task_answer_ref`, and the
credential maps to the owner-designated person for this action. The host
opens the app origin for the ceremony and accepts only the naapp's verified
status on return. A return URL or parameter never approves anything.

### What a requester can never do

The requesting principal, and any agent, can propose. It can never:

- approve;
- designate an approver or contact;
- control how an approval reaches the approver;
- mint, read or consume an approval token or link;
- dispatch.

Tools and responses an agent can see return only `{request_id,
delivery_status}`. Task text, comments and agent-readable projections never
carry an approval link, token or capability.

## 8. Progress and resolution

- `POST /v1/pages/{page_id}/actions/{request_id}/progress`: the assigned
  executor only, with expected revisions and a key. Records explicit
  picked-up evidence.
- `POST /v1/pages/{page_id}/actions/{request_id}/resolve`: the assigned
  executor only, signed, with `{result, patches, expected_action_rev,
  expected_page_rev, expected_record_revs, operation_id?, idempotency_key}`.
  It requires the admitted approval when the action has one. In one naapp
  revision it writes the execution status, the local data changes, audit,
  usage and the event and task-mirror outbox. A conflicting patch commits
  nothing.

External writes and task closure are outside that transaction. A delayed
task mirror shows "result saved; task sync pending" and reconciles.

## 9. Designatable roles

An app declares the roles a person can be designated to in its v2 manifest:
`roles: [{name, label, description?}]` ([app-manifest.md](app-manifest.md),
"Designatable roles"; shared vectors `roles_*` in
`test-vectors/app-manifests/app-manifest-v2-v1.json`). The resolved view lists
`[{name, label, description|null}]`, empty when the manifest declares none. The
admin approves the roles as part of the exact-digest install.

- The host reads `roles` only from the installation's verified manifest
  bytes, and renders each role's `label` and `description` in its own chrome.
- Every host surface that shows a role shows it as the pair (app, name), and
  never the bare name. That covers the install diff, the designation UI,
  audit and member views. A role name means nothing without its app: an app
  `evil` may declare `secrets.owner`, and must not be mistaken for the secrets
  app's owner role. Test: install two apps that both declare
  `secrets.owner`, designate a member to one, and require every surface to
  identify it by app, and audit to record the pair.
- `app-role.designate` accepts only a `name` declared by the installation's
  current generation. Any other name is refused (422 `schema_invalid`), so
  roles are never free entry.
- When a new generation drops a role, existing designations of it become
  inert. They grant nothing until a generation declares the role again and
  the owner re-approves.

## Errors

The codes of [app-task-requests.md](app-task-requests.md) "Errors" apply, plus:

| Status | Code | When |
| --- | --- | --- |
| 401 | `attestation_required`, `attestation_invalid` | The `member_session` caller-context check fails. |
| 403 | `action_denied` | The action's policy refuses this member, or a requester tries to approve. |
| 409 | `approval_changed` | The proposal digest or revision on the card is no longer current. |

## Conformance vectors

- `docs/vectors/page-proposal-v1.json`: `proposal_sha256` over single records
  (with non-ASCII, nested and boundary integer values), and the refusal cases.
- `docs/vectors/approval-request-v1.json`: `request_sha256` for page
  decisions and generic requests, the challenge binding (a raw 32-byte
  digest, a hex nonce, and a `task_answer_ref` that is always present and
  `null` when there is no task answer), and the refusal cases.
