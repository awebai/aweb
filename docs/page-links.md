# Page links: capability links and approval links

Status: **draft contract** (C4, aweb-acgg.10). It defines the links an app
mints so that someone without a team account can see part of a page, make a
bounded local edit, ask for work, or reach an approval, and what such a link
can never do. The design is [agent-pages.md](design/agent-pages.md) §7, with
Athena's ruling on link authority. Page actions are
[page-actions.md](page-actions.md); the approval primitive is the one in
`aweb_naapp` (B2) that both use.

## Model

- **A link is a bearer capability, not an identity.** Whoever holds it can do
  exactly what it was minted for, and nothing else. It never proves who is
  acting, never produces approval evidence, never answers a member's decision
  task, and never consumes or dispatches an external-effect approval.
- **Two classes, never merged:**
  - a **capability link** grants a bounded projection of one page and an
    explicit list of allowed actions;
  - an **approval link** only locates one approval for one candidate, who then
    decides by passkey at the app's origin (decision 53b). The link is not the
    proof.
- **The creator delegates; the link cannot exceed the creator.** A member can
  mint a capability link only for a projection and actions they could perform
  themselves, now and at every later use.
- **The renderer never holds a link secret.** The host page exchanges it once
  for a short-lived, key-bound link session, and the renderer sees only the
  authorized projection (the shared renderer's host adapter, R1).
- **Every use re-checks** expiry, revocation, the creator's current authority
  and the rate limits, for reads, submits, streams, assets and dispatch alike.

Folio's existing presentation links (`/present/{token}`) keep their current
semantics and are not capability links. Their redaction measures belong to
Folio's migration (N7).

## 1. Capability links

### The record

The app stores, per link, an immutable record and its mutable lifecycle:

```json
{
  "link_id": "lnk_01JC…",
  "verifier_sha256": "<64 hex>",
  "team_id": "backend:acme.com",
  "installation_id": "inst_01JB…",
  "page_id": "pg_4hd…",
  "mode": "pinned",
  "page_rev": 12,
  "projection": {
    "collections": [{"collection": "bookings", "record_ids": ["b-17"], "fields": ["arrival", "departure", "status"]}],
    "assets": []
  },
  "actions": [{"action_id": "mark-cleaned", "constraints": {"record_id": "b-17"}}],
  "answers": null,
  "intent_sponsor_did": null,
  "one_use": false,
  "created_by": {"principal_did": "did:aw:…", "certificate_id": "…"},
  "created_at": "2026-10-20T12:00:00Z",
  "expires_at": "2026-10-27T12:00:00Z",
  "rate_policy": "link-default-v1"
}
```

Lifecycle: `revoked_at`, `used_at` (one-use links) and the stored receipts.

| Field | Rule |
| --- | --- |
| `link_id` | Opaque, `^[A-Za-z0-9._-]{1,128}$`. Public: it names the link, it is not the capability. |
| `verifier_sha256` | Bare hex SHA-256 of the secret's UTF-8 bytes. The secret itself is never stored. |
| `mode`, `page_rev` | `pinned` serves the page at `page_rev` only. `live` serves the current revision, and `page_rev` is `null`. |
| `projection` | The only records, fields and assets the link can read. 1–16 collections, each with 1–200 `record_ids` (or `"*"` for every record the creator could read at mint, frozen as that list) and 1–64 `fields`. 0–64 asset IDs. |
| `actions` | 0–16 `{action_id, constraints}`: allowed page actions of kind `edit` or `intent`, each with fixed input values the submission must equal. Empty means read-only, the default. Never an `answer`-kind action. |
| `answers` | `null`, or the one bounded request the holder may answer, `{request_ref, input_schema}` (for example a guest reply). The answer is recorded as anonymous input. |
| `intent_sponsor_did` | Required when `actions` contains an `intent`: the agent principal that routes the holder's intents (§5). `null` otherwise. |
| `one_use` | `true`: the first admitted action uses the link up (§4). Reads before it consume nothing. |
| `expires_at` | After `created_at` and at most 30 days later. |

### Minting: `POST /v1/pages/{page_id}/links`

Team-auth v2 by the creating member, with the record's grantable fields. The
app checks, at mint:

- every projected collection, record, field and asset is one the creator can
  read now, under the page's row and field ACLs;
- every action is one the creator could perform now, on those records, with
  those constraints, and is of kind `edit` or `intent`;
- an `intent` link names a sponsor that is a current team member agent;
- nothing in the request names another team, page, installation or link.

A request outside these bounds is 403 `action_denied` or 422
`schema_invalid`. The response, given once:

```json
{"link_id": "lnk_01JC…", "url": "https://pages.example.com/l/lnk_01JC…#k=<secret>", "expires_at": "…"}
```

The secret is 32 random bytes, base64url without padding (43 characters), and
travels only in the URL fragment, which browsers never send to a server or a
referrer. It is never logged, never put in task, mail or comment text, and
never returned again. Minting records an audit row and emits no secret.

### What a link can never grant

No team or page enumeration; no other page; no general collection read; no
field outside the projection; no installation, ACL, schema or layout change;
no link minting; no answer to a member's decision task; no approval evidence;
no consumption or dispatch of an external-effect approval. An old pinned link
never gains an action added to the page later. A link's authority is the
intersection of what it was minted with and what its creator holds at each use:
if the creator loses access to a record, field or action, the link loses it
too.

## 2. Exchange: `POST /v1/links/{link_id}/session`

The app's link page reads the secret from the fragment and strips it from the
address bar (`history.replaceState`) before any other script runs and before
any fetch. The page loads no third-party script, and its Content Security
Policy matches the host console's. It generates a non-extractable Ed25519 key
pair with WebCrypto (a browser without Ed25519 fails closed with a message;
there is no second key type), and exchanges the secret:

```json
{"secret": "<43 chars>", "session_did_key": "did:key:z6Mk…"}
```

`session_did_key` must be a canonical Ed25519 `did:key`; anything else is 422
`schema_invalid`, before any lookup. The app hashes `secret`, finds the link
whose `verifier_sha256` matches, and
checks that the link is usable now (not revoked, not expired, not used up, and
its creator still holds at least the read projection). It then creates a link
session:

```json
{"session_id": "lks_01JC…", "expires_at": "2026-10-20T12:15:00Z", "link": {"page_id": "…", "mode": "pinned", "actions": ["mark-cleaned"]}}
```

- A session lasts at most 15 minutes and never past the link's expiry. The
  holder renews it with a fresh exchange of the same secret while the link is
  usable. A link may have several live sessions; each is bound to its own key.
- After the exchange the host page keeps the secret in memory only, to renew.
  It never writes it to `localStorage` or IndexedDB and never passes it to the
  renderer. After a reload the holder reopens the link.
- The app never logs or traces request bodies on `/v1/links/*/session`, and
  scrubs that route from error reports and performance capture. The verifier
  is plain SHA-256, which suffices for 256 random bits.
- The response carries `Cache-Control: no-store` and `Referrer-Policy:
  no-referrer`, as does every link response.
- A wrong secret, an unusable link and an unknown `link_id` all get the same
  404 `link_unavailable`, after a constant-time comparison.
- The exchange is rate-limited (§6). Only successful exchanges count against
  the link's bucket, so someone who knows a public `link_id` cannot lock its
  holder out with wrong secrets. Failures count against the client address.

## 3. Using a session: `AWEB-Link-Request`

Every request a link holder makes after the exchange (reads included) is
signed with the session key:

```text
Authorization: AWEB-Link-Request <session_id> <signature>
X-AWEB-Signed-Payload: <base64url canonical payload>
```

```json
{
  "v": 1,
  "type": "aweb.link-request",
  "link_id": "lnk_01JC…",
  "session_id": "lks_01JC…",
  "method": "POST",
  "path": "/v1/pages/pg_4hd…/actions",
  "body_sha256": "<64 hex>",
  "nonce": "<32 hex>",
  "issued_at": "2026-10-20T12:01:00Z"
}
```

Signing bytes are `"aweb.link-request/1\n" || canonical_json(payload)`, with
the canonical JSON of [app-task-requests.md](app-task-requests.md). The
signature is Ed25519 by the session key, base64url without padding, one
accepted encoding. The app verifies, in order, failing closed:

1. **Shape and signature.** The `X-AWEB-Signed-Payload` header is the one
   base64url encoding (no padding) of bytes that are canonical JSON with no
   duplicate key, exactly as received, so that every reader of the request sees
   the same fields; the payload has exactly the fields above, and the signature
   is by the session's `session_did_key` over the prefix and those bytes.
   Failure: 401 `signature_invalid`. `verify_link_request_bytes` in
   `aweb_naapp.runtime.link_requests` is the serving app's entry point.
2. **Binding.** `link_id` and `session_id` name this live session; `method`,
   the raw `path` with query, and `body_sha256` equal the request. Failure:
   401 `signature_invalid`.
3. **Time.** `issued_at` is within 60 s of the app's clock, either way.
   Failure: 401 `authorization_expired`.
4. **Nonce.** The `(session_id, nonce)` pair has not been seen. The app records
   it until the later of the session's expiry and `issued_at` plus 60 s, so a
   nonce never ages out while its timestamp is still accepted. A replay: 409
   `idempotency_conflict`. A client retrying after a lost response signs again
   with a fresh nonce; the action's idempotency key carries the retry and
   returns the stored receipt.
5. **Origin.** A state-changing request carries an `Origin` header equal to the
   app's origin. Failure: 403 `action_denied`.
6. **Link lifecycle and authority**, under the link's row lock: §4.

The key tells a repeat browser apart from a typed-in name, not a verified
person. A holder with the secret can always start another session. The
capability, not the key, is the authority, and the audit records the action
as anonymous, via link `link_id` and session `session_id`. It never claims the
trust of an AWID member signature.

## 4. Lifecycle at every use

Each read, submit, stream subscription, asset fetch and dispatch takes the
link's row lock (`FOR UPDATE` for writes, `FOR SHARE` for reads) and, in the
same transaction, requires:

- `revoked_at` is null, `expires_at` is in the future, and, for a one-use link,
  `used_at` is null;
- the creator's current authority still covers what is asked (§1);
- the request is within the projection, or is an allowed action whose input
  equals its constraints.

**Revocation race.** `POST /v1/pages/{page_id}/links/{link_id}/revoke` (team-auth,
by the creator or an owner) sets `revoked_at` under the same lock. Whichever
transaction commits first wins: an action admitted before the revocation
commits keeps its receipt, and nothing is admitted after it. An open stream
re-runs the whole check above, the creator's current authority included, at
least every 15 s, and closes on the first failure; a revocation therefore
ends it within 15 s.

**One use.** For a one-use link, the first admitted action sets `used_at` and
records its operation ID in the same transaction. Competing submissions block
on the lock, and only one is admitted; the other gets 410 `link_unavailable`.
A read, a preview, a failed signature or a refused action consumes nothing. A
retry of the admitted action with its idempotency key returns the stored
receipt, never a second action.

Every refusal that would reveal whether a link exists is 404
`link_unavailable`. A holder who already has a live session gets 410
`link_unavailable` for a link revoked, expired or used up since.

## 5. What a holder can do

- **Read** its projection, at the pinned revision or live. The app applies the
  page's row and field ACLs as the creator, then the projection. Assets are
  served only if listed, from the app's asset origin.
- **Edit**, by an allowed `edit` action, with the action's schema, field
  policy, expected revisions and idempotency key (page-actions.md §3). The
  input must equal the link's constraints for every constrained field. The
  edit commits without an agent.
- **Ask for work**, by an allowed `intent` action. The app commits an anonymous
  journal entry, "anonymous, via link `link_id`", and notifies the link's
  sponsor agent. Its recovery read lists pending link entries even after lost
  wakes. The sponsor creates a task as itself, after its own policy checks,
  carrying the holder's input as structured fields labelled anonymous and
  untrusted. Until then the holder sees "saved; awaiting routing". The
  sponsor's task grants no approval, and the holder never inherits the
  sponsor's key.
- **Answer its own bounded request**, when `answers` is set: one answer,
  validated against its input schema and recorded as anonymous input, never as
  approval.

**Anonymous intent rule.** No external or privileged effect follows from a
link alone. When an intent needs one, the sponsor's work raises a decision for
an assigned member, or an owner-designated passkey approver
([page-actions.md](page-actions.md) §6–§7). A holder's text is data to the
agent, never instructions that bypass that decision.

## 6. Rate limits

`link-default-v1`, enforced per link and per client address, with token
buckets that refill continuously:

| Bucket | Limit |
| --- | --- |
| Successful exchanges, per link | 10 per minute |
| Exchanges (successful or not), per client address | 30 per minute |
| Reads, per session | 120 per minute |
| Writes (edit, intent, answer), per link | 20 per minute |
| Writes, per client address | 60 per minute |
| Uploads, per link | 10 per hour, each within the action's byte bound |

Exceeding one is 429 `safety_rate_limited` with `Retry-After`. These are
safety bounds, not price or plan caps. An app may set lower limits per link at
mint, never higher.

## 7. Approval links

An approval link (decision 53b) is minted by the approval primitive, one per
candidate, never by the requester:

- one single-use link per candidate, each with its own verifier, all bound to
  the same `approval_id` and `request_sha256`; only the verifier is stored;
- delivered by the app's own delivery path directly to the candidate's
  registered contact. The requester, and any agent, sees only
  `{request_id, delivery_status}`;
- opening it shows the request and starts the candidate's passkey ceremony at
  the app's origin. A GET, a prefetch or a failed ceremony consumes nothing.
  The link is personal: another candidate's proof through it is
  `approver_mismatch`;
- the first successful decision, by any candidate, revokes every other
  candidate's link and outstanding challenge in the same transaction, so a
  later attempt gets `link_unavailable`;
- the decision is the passkey proof, recorded by the primitive as
  `decided_by`. The link only locates the request.

An approval link never doubles as a capability link, and a capability link
never locates an approval.

## Errors

| Status | Code | When |
| --- | --- | --- |
| 401 | `signature_invalid` | A link request's shape, signature or binding fails. |
| 401 | `authorization_expired` | `issued_at` is outside its window. |
| 403 | `action_denied` | Outside the projection or allowed actions, a constraint is not met, the creator's authority no longer covers it, or the `Origin` is wrong. |
| 404 | `link_unavailable` | Unknown link, wrong secret, or an unusable link before any session. |
| 409 | `idempotency_conflict` | A replayed nonce, or a known idempotency key with different content. |
| 409 | `revision_conflict` | Stale expected revisions on an edit. |
| 410 | `link_unavailable` | Revoked, expired or used up, for a holder with a session. |
| 422 | `schema_invalid` | Body shape, or an input that fails the action's schema. |
| 429 | `safety_rate_limited` | A rate limit (§6). |

Errors carry no record values, no other link's existence and no secret.

## Conformance vectors

- `docs/vectors/link-request-v1.json`: the exchange's verifier hashing, link
  request payloads, signing bytes and signatures under fixed test keys, and
  refusals (wrong key, path, method or body binding, stale and future
  `issued_at`, replayed nonce, and canonical-encoding faults).
- `docs/vectors/link-capability-v1.json`: delegation (a projection or action
  the creator lacks is refused, and authority lost later narrows the link),
  constraint matching, one-use admission and revocation-race orderings, with
  the expected result of each step.

`aweb_naapp.runtime.link_requests` computes verifiers and builds and verifies
link requests, and runs `link-request-v1.json`.
