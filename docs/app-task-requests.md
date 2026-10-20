# App task requests and conditional answers

Status: **draft contract** (C2, aweb-acgg.8). The task service side is built
against it in aweb-acgg.32. The page side is [page-actions.md](page-actions.md).
The design is [agent-pages.md](design/agent-pages.md) §4 and its
[wire sketches](design/agent-pages/contracts.md).

This contract lets an installed app create an aweb task on behalf of a team
member, and lets the person a task is assigned to answer it, in a way that
survives lost responses, crashes and retries without creating a second task,
a second answer or an approval nobody gave.

## Model

- **The member authorizes.** A member signs one `aweb.app-task-authorization`
  for one task. It names the app, the installation, the request, the target,
  the exact task body and an expiry. The app never holds the member's key and
  cannot change any of those values.
- **The app transports.** The installed app sends the request with its own
  registered key, under the `app-request` purpose. The transport proves which
  app and installation delivered it, not who asked.
- **The task service verifies both, independently.** It re-verifies the member
  signature, certificate and current revocation itself, rather than trusting
  the app's claim that it did. It records the originating member and the
  transporting app separately.
- **The task is the ledger.** Task state and the task's answers are
  authoritative. The app's action state is a projection, kept current from
  authenticated task reads.
- **Answers are conditional.** An answer commits only against the task
  revision, assignee and proposal it was given for. Each question revision
  has at most one answer, and every answer has an immutable receipt.

## Canonical JSON and digests

Every signed or hashed object in this contract uses AWID's canonical JSON
(`awid/src/awid/signing.py`, `canonical_json_bytes`): keys sorted, no
insignificant whitespace, UTF-8 without escaping non-ASCII, and safe integers
only (magnitude at most 2^53−1). Floats, `NaN` and `Infinity` are refused.
Duplicate keys are refused on input. A verifier re-canonicalizes what it
parsed and requires the exact bytes it received.

Two digest spellings are used, each in fixed places:

| Spelling | Where |
| --- | --- |
| Bare lowercase hex, 64 characters | Values bound inside signatures and transport: `task_body_sha256`, `body_sha256`, `answer_sha256`, the approval `request_sha256`. |
| `sha256:` followed by 64 lowercase hex | Digests that appear in page data and task metadata: `proposal_sha256` and bundle digests ([page-format.md](page-format.md)). |

A field never accepts the other spelling.

## 1. Task authorization, `aweb.app-task-authorization/1`

### Payload

```json
{
  "v": 1,
  "type": "aweb.app-task-authorization",
  "aud": "https://app.aweb.ai",
  "app_origin": "https://pages.example.com",
  "team_id": "backend:acme.com",
  "app_id": "pages",
  "installation_id": "inst_01JB…",
  "installation_generation": 3,
  "external_request_id": "act_9f2c…",
  "actor_did_key": "did:key:z6Mk…",
  "certificate_id": "…",
  "target_dids": ["did:aw:…"],
  "task_body_sha256": "<64 hex>",
  "action_id": "request-cleaner",
  "proposal_rev": null,
  "proposal_sha256": null,
  "issued_at": "2026-10-20T12:00:00Z",
  "expires_at": "2026-10-21T12:00:00Z",
  "nonce": "<32 hex>"
}
```

| Field | Rule |
| --- | --- |
| `v`, `type` | Exactly `1` and `"aweb.app-task-authorization"`. |
| `aud` | The task service's public origin, in canonical origin form: `require_canonical_server_origin` (`awid/src/awid/log.py`) returns it unchanged. |
| `app_origin` | The installed app's origin, in the same canonical form. |
| `team_id`, `app_id` | The team and the installed app. |
| `installation_id`, `installation_generation` | The installation and its generation at signing (F6). The generation is a safe positive integer. |
| `external_request_id` | `^[A-Za-z0-9._-]{1,128}$`, chosen by the app, unique per originating member within the installation. |
| `actor_did_key` | The signing member's `did:key`. It equals the certificate's `member_did_key`. |
| `certificate_id` | The signing member's team certificate. |
| `target_dids` | The principals who may answer (§3): for a decision request, the task's `eligible_dids`; otherwise `[assignee_did]`. 1–16 distinct principal DIDs, sorted. The member's signature binds the whole set. |
| `task_body_sha256` | Bare hex SHA-256 of the canonical bytes of the `task` object (§3). |
| `action_id` | The page action that produced the request, `^[A-Za-z0-9._-]{1,128}$`. |
| `proposal_rev`, `proposal_sha256` | Both `null`, or both set: a safe non-negative integer and a `sha256:` digest. Set when the request asks a person to decide a proposal. |
| `issued_at`, `expires_at` | RFC 3339 UTC, `Z`, second precision. `expires_at` is after `issued_at` and at most 24 hours later. |
| `nonce` | 32 lowercase hex characters (128 random bits). |

No other field is accepted.

### Signing

```text
signing bytes = "aweb.app-task-authorization/1\n" || canonical_json(payload)
signature     = Ed25519(member signing key, signing bytes)
```

The prefix ends in one literal newline byte. The signature is base64url
without padding, with exactly one accepted encoding, as in
[principal-attestation.md](principal-attestation.md) "Signed bytes". The
prefix differs from every other signed artifact, so a task authorization never
verifies as a team-auth payload, an attestation or another record.

On the wire the authorization is:

```json
{"payload": { … }, "signature": "<base64url>", "certificate": "<base64 certificate JSON>"}
```

`certificate` uses the same encoding as the `X-AWID-Team-Certificate` header
of [team-auth-envelope-v2.md](team-auth-envelope-v2.md).

Self-custodial members sign with `aw`. Hosted custody signs for the member it
holds, only for an act that member performed. In both cases the app receives
the signed object with the member's own request, and must check that its
`actor_did_key` and `certificate_id` equal the verified signer of that
request before persisting it.

## 2. App transport, purpose `app-request`

The installed app sends task requests with a key its manifest declares for
the `app-request` purpose (`app_keys`, manifest v2). It is one more purpose of
the app credential family in `server/src/aweb/app_credentials.py` and uses the
same headers:

```text
Authorization: AWEB-App-Request DIDKey <did:key> <signature>
X-AWEB-App-ID, X-AWEB-App-Key-ID, X-AWEB-Team-ID, X-AWEB-Timestamp, X-AWEB-Signed-Payload
```

The signed payload is the family's payload with the installation bound:

```json
{
  "v": 1, "auth": "app-request", "aud": "<task service origin>",
  "method": "POST", "path": "/v1/tasks/app-requests",
  "team_id": "…", "app_id": "…", "kid": "…", "did_key": "did:key:…",
  "installation_id": "…", "installation_generation": 3,
  "body_sha256": "<64 hex>", "timestamp": "2026-10-20T12:00:00Z"
}
```

The signature covers the canonical payload bytes, as for every purpose of the
family. The `auth` field separates the purposes: an `app-event`,
`app-grant-read` or `hook-resolve` credential never passes the `app-request`
verifier, and an `app-request` credential passes no other. The key must be
registered for `app-request` under the installation's current digest, the
installation must be active, and `installation_generation` must equal its
current generation.

## 3. Creating a task: `POST /v1/tasks/app-requests`

### Body

```json
{
  "task": {
    "title": "Review a page request",
    "description": null,
    "assignee_did": "did:aw:…",
    "app_request": {
      "external_request_id": "act_9f2c…",
      "resource_ref": "pg_4hd…",
      "action_ref": "request-cleaner",
      "proposal_rev": null,
      "proposal_sha256": null,
      "choices": null,
      "eligible_dids": null,
      "role": null
    }
  },
  "task_authorization": {"payload": { … }, "signature": "…", "certificate": "…"}
}
```

| Field | Rule |
| --- | --- |
| `title` | 1–200 runes, with no control character (Unicode `Cc`) and no bidi control: U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069 (the set manifest role labels refuse). |
| `description` | `null`, or 1–2,000 runes with the same character rule. |
| `assignee_did` | The target's principal DID: the `member_did_aw` of the target member's current certificate when it carries one, otherwise its `member_did_key`. |
| `app_request.external_request_id` | Equals the authorization's. |
| `resource_ref`, `action_ref` | Opaque references, `^[A-Za-z0-9._-]{1,128}$`. |
| `proposal_rev`, `proposal_sha256` | Equal the authorization's. |
| `eligible_dids` | Required on a **decision request** (one whose `proposal_rev` and `proposal_sha256` are set) and `null` otherwise: 1–16 distinct principal DIDs, sorted, of individually designated people, including `assignee_did`. Frozen at create: they are who may answer. |
| `role` | On a decision request, the role name (`aweb_naapp.roles` grammar: dot-separated lowercase segments, at most 128 bytes) the eligible set was resolved from, or `null` when the target named the principals directly. `null` on any other request. The app is the installation's own; hosts show the pair (app, role). |
| `choices` | `null`, or 1–10 distinct strings `^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$` that an answer may choose from. These are a decision card's option `value`s ([page-format.md](page-format.md) §5), copied unchanged. |

Unknown fields are refused at every level. `task_body_sha256` is the hex
SHA-256 of `canonical_json(task)`.

**Content rule.** A task is team-visible, like everything else the team works
on. No task field carries a capability, token or link: not the title, the
description, the references or an answer. The task service cannot detect a
violation; the app is responsible for it. Assignment grants no access to the
app's resources: the assignee reads them with its own credentials.

### Verification, in order

Each step fails closed. Nothing is written before step 8.

1. **Transport.** Verify the `app-request` credential (§2). Failure: 401, with
   the existing app credential messages.
2. **Body.** Strict JSON: duplicate keys, floats, non-finite numbers and
   unknown fields are refused. Failure: 422 `schema_invalid`.
3. **Authorization shape and signature.** Check every field rule in §1 on the
   parsed payload, canonicalize it, and verify the signature with
   `actor_did_key` over the signing bytes. The signature is the one accepted
   base64url encoding of 64 bytes. Failure: 401 `signature_invalid`.
4. **Certificate.** The certificate verifies against AWID team authority, is
   not revoked, and its `team_id`, `certificate_id` and `member_did_key` equal
   the payload's `team_id`, `certificate_id` and `actor_did_key`. Revoked:
   401 `certificate_revoked`. Registry failure: 503 `authority_unavailable`,
   with no stale fallback.
5. **Binding.** `aud` is this service's public origin. `team_id`, `app_id`,
   `installation_id` and `installation_generation` equal the transport's.
   `app_origin` equals the installed app's origin. `task_body_sha256` equals
   the digest of the body's `task`. `target_dids` equals `task.app_request.eligible_dids` for a decision request and `[task.assignee_did]` otherwise.
   `external_request_id`, `proposal_rev` and `proposal_sha256` equal
   `task.app_request`'s, and `action_id` equals `action_ref`. Failure: 403
   `target_mismatch`.
6. **Time.** `issued_at` is at most 60 s ahead of the service clock and
   `expires_at` has not passed. Failure: 401 `authorization_expired`. Time is
   checked after steps 1–5, so an authorization that fails only on time has
   passed its transport, signature, current certificate and bindings. Only
   then may it serve a matching replay of a task that already exists
   (step 7); it never creates one.
7. **Replay.** Look up the request by its dedup key
   `(team_id, app_id, installation_id, originator principal DID,
   external_request_id)`, where the originator principal DID is derived from
   the certificate as for `assignee_did`.
   - Found with the same `task_body_sha256`: the installation must be the
     request's own, active, and currently hold `requests.create` or
     `requests.read`; otherwise 403 `scope_denied`. Then return 200 with the
     stored receipt. The time check of step 6 and the create checks of step 8
     do not apply, and nothing is written. A replay is a read: once read
     authority is gone, so is the receipt.
   - Found with a different `task_body_sha256`: 409 `idempotency_conflict`.
8. **Scope, installation and target.** Under the installation row lock
   (`for_update`): the installation is active, its generation is unchanged,
   and it holds the granted scope `requests.create`. Otherwise 403
   `scope_denied`. Each DID in `target_dids` resolves to exactly one current,
   unrevoked member of the team; otherwise 422 `target_unresolved`, with no
   identifiers in the error. Role holding is the app's to check, at acceptance
   and again at answer time (§4); the task service never reads an app's roles.
9. **Commit.** In one transaction: create the task with `rev` 1 and
   `question_rev` 1, its `app_request`, the originator
   `{principal_did, certificate_id}`, the transporting app
   `{app_id, installation_id, installation_generation, kid}`, and the
   authorization `{payload, signature, certificate}` exactly as received.
   Return 201.

A concurrent create with the same dedup key commits once; the other caller
gets the receipt, by step 7, on its retry.

### Receipt

```json
{
  "task_id": "…", "task_ref": "…", "task_rev": 1,
  "external_request_id": "act_9f2c…",
  "task_body_sha256": "<64 hex>",
  "originator": {"principal_did": "did:aw:…", "certificate_id": "…"},
  "transport_app": {"app_id": "pages", "installation_id": "inst_01JB…", "installation_generation": 3, "kid": "…"},
  "created_at": "2026-10-20T12:00:01Z",
  "cancellation": null
}
```

201 on creation and 200 on a matching replay return the same receipt. The app
records it, and only then reports `delivery: "queued"`.

### Reconciling a lost receipt: `GET /v1/tasks/app-requests/{external_request_id}?originator=<principal DID>`

The same `app-request` transport, with the installation's `requests.read`
scope. It returns the receipt and the current task state:

```json
{"receipt": { … }, "task": {"status": "open", "rev": 4, "question_rev": 1, "assignee_did": "did:aw:…", "picked_up": true, "answer": null, "cancellation": null}}
```

`answer` is the current answer receipt (§4) or `null`. An app reads only
requests its own installation created; anything else is 404
`resource_not_found`, the same as an absent request. `requests.read` cannot
create or answer tasks.

An authorization that expired before first delivery cannot create a task. The
app shows the request as pending and asks the member to renew it. A renewed
authorization keeps the `external_request_id` and the exact task body, so if
the first create did commit, the renewal is a matching replay and returns that
task. A request is never re-signed by another actor.

### Cancellation and installation changes

A request's receipt and task read carry `cancellation`: `null`, or
`{"reason": "requested" | "installation_retired", "at": <RFC 3339>}`.

- **Requested.** `POST /v1/tasks/app-requests/{external_request_id}/cancel?originator=<principal DID>`,
  with the `app-request` transport and `requests.create`, cancels the
  request: it sets `cancellation`, closes the task if it is open, adds the
  comment `Request cancelled · <external_request_id>`, and increments `rev`.
  Repeating it returns the same state. An answered request can still be
  cancelled; its answer receipt stays and is no longer `current`.
- **Uninstall.** The transaction that retires an installation (F6) also
  cancels, in the same transaction, every open task created by that
  installation's requests, with reason `installation_retired`, by calling the
  task service's `cancel_installation_requests_on(tx, team_id, app_id,
  installation_id)` on its own transaction; that call never commits. Tasks and the
  installation live in the same database, and creates take the installation
  row lock (step 8), so a create either commits before the retirement and is
  cancelled by it, or sees the retired installation and is refused. No
  separate queue is involved, and nothing claims that a committed task does
  not exist.
- **Update.** A new generation cancels nothing. Authorizations signed for the
  old generation are refused at step 8, and the member renews them. A
  reinstalled app has a new `installation_id` and cannot replay an old
  installation's requests.

## 4. Conditional answers

### Task fields

A task gains:

- `rev`: a safe integer, starting at 1, that increases with every committed
  change to the task (fields, status, comments, answers, cancellation). It is
  monotone, not necessarily by exactly 1: one answer may raise it more than
  once. A receipt's `task_rev` is the task's `rev` after that commit.
- `question_rev`: a safe integer, starting at 1, incremented only by a
  reopen.
- `assignee_did`: the principal DID the task is assigned to, its display
  owner. The alias is a display projection. An alias is never answer authority, so reusing an alias
  after a member leaves cannot answer.

Existing task-create, update and comment requests are still accepted. A task
created without `assignee_did` resolves it from its alias at assignment.

### The answer coordinator

One coordinator serves every answer: the page decision answer, the dashboard's
"waiting on you" answer, and self-custodial CLI answers. It is exposed two
ways with identical semantics:

- `answer_task_on(tx, …)`, a server service function that runs on the
  caller's open database transaction. A host that embeds the task service
  calls it in-process, so that its own effects (a notification mail, a
  client-message record) commit in the same transaction.
- `POST /v1/tasks/{ref}/answer`, signed with team-auth v2 by the answering
  member. The route opens its own transaction.

Request:

```json
{
  "expected_task_rev": 4,
  "answer_key": "ans_3c1…",
  "answer_sha256": "<64 hex>",
  "choice": "approve",
  "proposal_rev": 2,
  "proposal_sha256": "sha256:<64 hex>",
  "body_md": "Approve. The new rate is 120 EUR per night."
}
```

| Field | Rule |
| --- | --- |
| `expected_task_rev` | The `rev` the person was shown. Required: missing is 428 `precondition_required`. |
| `answer_key` | `^[A-Za-z0-9._-]{1,128}$`, chosen by the caller and stable across its retries. |
| `answer_sha256` | The bare hex SHA-256 of the UTF-8 bytes of `body_md`. The coordinator recomputes it and refuses a mismatch (422 `schema_invalid`). |
| `choice` | `null`, or one of the task's declared `choices`. Required when the task declares choices. |
| `proposal_rev`, `proposal_sha256` | Required, and equal to the task's, when the task carries a proposal; otherwise both `null`. |
| `body_md` | The answer's full text, 1–20,000 runes, Markdown. It becomes the team-visible comment. |
| `stage_receipt` | Required on a decision task, refused elsewhere: `{payload, signature}` of an `aweb.app-answer-stage/1` (below). |

The answering identity is the verified team-auth signer. For the in-process
form, it is the verified identity the host passes. It is never a body field.

### Rules

The request is validated before any rule runs: field shapes, `body_md`'s
length, `answer_sha256` equal to the digest of `body_md` (otherwise 422
`schema_invalid`), and `expected_task_rev` present (otherwise 428
`precondition_required`). Then, in order:

1. **Replay first.** If `(task_id, answer_key)` already has an answer:
   - the same `answer_sha256`, `choice` and proposal fields return the
     original receipt, at any time, even after close, reopen or later answers;
   - anything else is 409 `idempotency_conflict`.
2. **Answerer.** The answering certificate is current (not revoked, expired
   or replaced) and belongs to a current member of the team, and the
   principal DID it derives is the task's `assignee_did`, or, on a decision
   task, one of its `eligible_dids`. A decision task's answer also carries the
   app's stage receipt (below), which must verify for this answer and this
   answerer. Otherwise 403 `target_mismatch`. A principal removed from the role
   gets no receipt, so the others can still answer.
3. **Open.** The task is open, and `expected_task_rev` equals its `rev`.
   Otherwise 409 `revision_conflict`.
4. **Proposal.** The proposal fields equal the task's. Otherwise 409
   `approval_changed`.
5. **Choice.** `choice` satisfies the task's declared choices. Otherwise 422
   `schema_invalid`.
6. **One answer per question.** The current `question_rev` has no answer yet.
   Otherwise 409 `revision_conflict`. Of two concurrent distinct answers, one
   commits.
7. **Commit**, in the caller's transaction: record the answer with a fresh
   opaque `task_answer_ref`; add the team-visible comment (below); close the
   task; increment `rev`. Return 201 with the receipt.

### Stage receipt, `aweb.app-answer-stage/1`

On a decision task, the app is the only party that knows whether a principal
still holds the task's role, because role assignments live in the app's own
schema (`aweb_naapp.roles`). It says so for exactly one answer, before the
answer commits:

```json
{
  "v": 1, "type": "aweb.app-answer-stage",
  "team_id": "backend:acme.com", "app_id": "pages",
  "installation_id": "inst_01JB…", "installation_generation": 3,
  "kid": "pages-request-1", "did_key": "did:key:z6Mk…",
  "task_id": "…", "question_rev": 1,
  "answer_key": "ans_3c1…", "answer_sha256": "<64 hex>",
  "choice": "approve", "proposal_rev": 2, "proposal_sha256": "sha256:<64 hex>",
  "answerer_did": "did:aw:…",
  "issued_at": "2026-10-20T12:05:00Z", "expires_at": "2026-10-20T12:10:00Z",
  "nonce": "<32 hex>"
}
```

- The app issues it from its staging step ([page-actions.md](page-actions.md)
  §5) only after checking, in one transaction, that the answerer is in the
  task's frozen `eligible_dids`, currently holds its `role` when it has one,
  and is a current approval candidate.
- Signing bytes are `"aweb.app-answer-stage/1\n" || canonical_json(payload)`,
  signed with the app's key declared for the `app-request` purpose; the
  signature is base64url without padding, as in §1. The lifetime is at most
  300 s, and `issued_at` at most 60 s ahead.
- The coordinator verifies it before any rule that commits:
  - `did_key` and `kid` name a key registered for `app-request` under the
    installation that created the task, which is active at
    `installation_generation`, its current generation;
  - `task_id` and `question_rev` are the task's current ones; `answer_key`,
    `answer_sha256`, `choice`, `proposal_rev` and `proposal_sha256` are this
    request's, so the receipt covers the whole answer and a client cannot stage
    one choice and commit another; `answerer_did` is the principal of the
    verified answering certificate;
  - the time window holds, checked after the bindings;
  - its `nonce` is recorded with the answer, and a nonce already recorded for
    the installation is refused, so one receipt serves one answer and its
    replays only.
  Any failure is 403 `target_mismatch`, or 401 `authorization_expired` for
  time alone, and nothing commits. A replay of an existing answer (rule 1)
  does not re-verify the receipt: it returns the original receipt even after
  the stage receipt has expired.
- A verifier compares the full binding set: `team_id`, `app_id`,
  `installation_id`, `installation_generation`, `task_id`, `question_rev`,
  `answer_key`, `answer_sha256`, `choice`, `proposal_rev`, `proposal_sha256`
  and `answerer_did`. `aweb_naapp.runtime.task_requests.verify_stage_receipt`
  refuses to run with any of them missing, rather than skipping a check.

### Receipt

```json
{
  "task_answer_ref": "tar_7Hq…",
  "task_id": "…", "question_rev": 1, "task_rev": 5,
  "answer_key": "ans_3c1…", "answer_sha256": "<64 hex>", "choice": "approve",
  "proposal_rev": 2, "proposal_sha256": "sha256:<64 hex>",
  "answered_by": {"principal_did": "did:aw:…", "certificate_id": "…"},
  "answered_at": "2026-10-20T12:05:00Z",
  "current": true
}
```

`task_answer_ref` is an opaque string, `^[A-Za-z0-9._-]{1,128}$`, unique per
answer. `current` is `true` while this answer belongs to the task's current
`question_rev`. Receipts are immutable; only `current` is computed at read.

- `GET /v1/tasks/{ref}/answer?answer_key=…` (team-auth, the answerer or a
  team member with task read) returns that answer's receipt.
- `GET /v1/tasks?eligible_did=<principal DID>` lists the tasks that principal
  may answer: decision tasks whose `eligible_dids` contains it, and other
  tasks whose `assignee_did` is it, with the usual status filters. A
  dashboard's "waiting on you" view reads it.
- `GET /v1/tasks/answers/{task_answer_ref}` with the `app-request` transport
  and `requests.read` returns a receipt for a task the installation created.
  Anything else is 404 `resource_not_found`.

### Reopen

Reopening a closed task increments `question_rev` and `rev` and reopens it.
Earlier receipts stay retrievable with `current: false`. A new answer needs a
new `answer_key` and the new `rev`. An approval bound to an earlier receipt is
no longer executable ([page-actions.md](page-actions.md)), because a reopened
request is a new question.

A plain comment or close never answers a task and never mints approval.

### Team-visible comment

Every answer, whoever gives it and whatever the task, writes one comment
carrying the answer's full text, `body_md`, exactly as given. The team sees
what was answered, as it sees the rest of the task. There is no projection
choice.

`body_md` must not carry a link, token or capability; approval capabilities
never reach the person through a task ([page-actions.md](page-actions.md) §7).

## 5. Request lifecycle in the app

The app keeps an action journal and a task-delivery outbox in its own
database. The task is authoritative. The app's state is a projection:

| App state | Meaning | Source |
| --- | --- | --- |
| `pending` | Accepted and journaled; the task is not created yet. The UI says "saved; sending". | The app's commit (202). |
| `queued` | The task exists. The UI may say "sent". | A stored, verified receipt. |
| `picked_up` | The assignee accepted it. | The task read's `picked_up: true`, set only when the assignee itself claims the task or sets it `in_progress`. |
| `done`, `failed` | Executed, or failed with a one-line reason. | The executor's resolution ([page-actions.md](page-actions.md)). |

Cancellation and an uncertain external outcome are explicit sub-states with
reasons. Health is a separate field and never triggers a transition. A
member's close of the task does not mean the work succeeded.

The outbox delivers until it holds a receipt. After an ambiguous response, it
reconciles with the `GET` of §3 before retrying, and retries with the same
authorization while it is valid. Recovery runs on every read of a pending
request and on a schedule, so a missed wake cannot strand a request.

## Errors

| Status | Code | When |
| --- | --- | --- |
| 401 | `signature_invalid` | The authorization's signature, shape or canonical bytes fail. |
| 401 | `certificate_revoked` | The member's certificate is revoked. |
| 401 | `authorization_expired` | The authorization is outside its time window, and no matching task exists. |
| 403 | `target_mismatch` | A bound field disagrees with the body, transport or task, or the answerer is not the assignee. |
| 403 | `scope_denied` | The installation is retired, its generation moved, or it lacks `requests.create` / `requests.read`. |
| 404 | `resource_not_found` | Absent, or not visible to the caller. |
| 409 | `idempotency_conflict` | A known key with different content. |
| 409 | `revision_conflict` | Stale `expected_task_rev`, a closed task, or the question already answered. |
| 409 | `approval_changed` | The proposal fields differ from the task's. |
| 422 | `schema_invalid` | Body shape or choice. |
| 422 | `target_unresolved` | The assignee does not resolve to exactly one current member. |
| 428 | `precondition_required` | `expected_task_rev` is missing. |
| 503 | `authority_unavailable` | The registry could not be read. |

Errors carry no member identifiers, record values or other team tasks.
Services log the real cause with a correlation id, and never log bodies,
signatures or certificates.

## Conformance vectors

- `docs/vectors/app-task-authorization-v1.json`: payloads, signing bytes,
  signatures under a fixed test key, the task body digest, and refusal cases.
- `docs/vectors/app-request-credential-v1.json`: the transport payload and
  signature, and cross-purpose refusals.
- `docs/vectors/task-answer-v1.json`: answer digests, the stage receipt's
  signing bytes, signature and verification refusals, and one decision task's
  answer, replay, reopen, eligible-colleague and conflict steps with the
  expected result of each.

`aweb_naapp` builds and verifies the signed artifacts, and `aw` signs task
authorizations for self-custodial members. Both run the vectors.
