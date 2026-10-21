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
  "intent_sponsor_did": null,
  "one_use": false,
  "created_by": {"team_id": "backend:acme.com", "principal_did": "did:aw:…", "certificate_id": "…", "team_did_key": "did:key:…"},
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
| `projection` | The only collections, rows, fields and assets the link can read. 1–16 collections with 1–64 minted fields each; `record_ids` is a literal list of 0–200 IDs, or `"*"` with the mode-specific rules below. An empty list always means zero rows. 0–64 asset IDs. |
| `actions` | 0–16 `{action_id, constraints}`: allowed page actions of kind `edit` or `intent`, each with fixed input values the submission must equal. Empty means read-only, the default. Never an `answer`-kind action. |
| `intent_sponsor_did` | Required when `actions` contains an `intent`: the agent principal that routes the holder's intents (§5). `null` otherwise. |
| `created_by` | Host-derived immutable mint evidence: scope `team_id`, canonical ACL `principal_did`, and `certificate_id` plus `team_did_key` from the verified mint-time Principal. Not grantable request fields; never returned to a holder. |
| `one_use` | `true`: the first admitted action uses the link up (§4). Reads before it consume nothing. |
| `expires_at` | After `created_at` and at most 30 days later. |

**Current creator membership uses two phases.** N5 retains the mint-time team,
certificate ID and team key in immutable `created_by`; a bare DID or historical
observed-principal row is insufficient. `load_link_creator(db, *, link_id)`
loads the immutable internal `LinkCreator` evidence without retaining a lifecycle
lock or claiming current authority. It is not a holder endpoint.
`LinkCreator` is frozen: `{scope: LinkScope, principal_did, certificate_id,
team_did_key}`. The canonical `principal_did` is PageStore's ACL identity,
separate from the membership evidence.

Before opening the joined transaction, the host calls
`runtime.check_current_member(creator.scope.team_id,
certificate_id=creator.certificate_id, team_did_key=creator.team_did_key)`.
It uses the request verifier's AWID facts/cache, requires an active known
certificate and the same current team key, and returns the shared frozen
`MembershipProof {team_id, certificate_id, team_did_key, checked_at, fresh_until}`.
Both times are monotonic and retain the facts' original fetch-start and expiry;
a cache hit never extends that expiry. The window is at most 60 seconds.
The proof is an in-process object, never request JSON, stored data or a token.
Phase 1 refuses unknown/revoked/rotated/incomplete evidence with 403
`current_member_required`; unavailable facts remain 503
`current_membership_unavailable`.

The host supplies `proof` to `exchange`, `read` or `admit`. Under its existing
verified secret/session and link lock, N5 reloads `created_by`, requires the
proof's team to match both scope and stored creator team, and matches the
certificate and team key exactly. It reads its injected `proof_clock` (default
`time.monotonic`) **after acquiring the lock**. Missing, mismatched or expired
proofs refuse 403 `current_member_required`; a lock wait never refreshes them.
Only then does `authority.require_current_creator(tx, *, creator, proof)` run.
This callback performs local checks only: no AWID refresh or network operation
inside the transaction. Subsequent creator/store callbacks use the canonical
ACL identity. The exchange mount accepts a required phase-1 callback. It validates the body,
commits exactly one per-client rate charge, and verifies the supplied secret and
lifecycle locally before invoking that callback. Unknown links and wrong
secrets therefore return the same `link_unavailable`, spend the failed-exchange
budget and never trigger AWID. All short SQL operations finish before the
network call. After phase 1, the joined transaction reloads and revalidates the
secret/lifecycle under the link lock before its local proof gate. Valid-secret
holders retain membership 403/503 and all link privacy headers; the per-link
bucket is charged only on success.

Old records missing evidence fail closed; nothing reconstructs membership from
observations. No certificate bytes, copied verifier, private link SQL or
fabricated member Principal are needed in the host/store. `LinkRead.created_by`
and `LinkAction.created_by` carry the checked internal context, never serialized
to holders.

This membership check precedes even admission's receipt lookup. Matching
retries still bypass link lifecycle and action-policy checks after the current
creator passes membership, preserving receipt semantics for a used or revoked
link without letting a departed creator continue authorizing holder requests.
Management revocation by an authorized owner remains available after creator
membership loss; it does not depend on that departed creator passing the check.
Future asset and stream adapters must use this same boundary before content.

**Rows in pinned and live views.** For pinned links, `record_ids:"*"` is
expanded at mint to the creator's authorized named rows, including `[]` for an
empty collection, with at most 200 rows. An action-bearing link also expands
its wildcard to a bounded named list. Named lists are always literal: `[]`
means no rows, never all rows. Empty collections are valid in both modes and
retain their authorized collection/schema, returning count zero and no cursor.

Only a **live read-only** link (`mode:"live"`, `actions:[]`) may retain
`record_ids:"*"` in its immutable record and checked read projection. This
scopes the read to the minted collection and fields; its row set follows the
creator's current visibility, so rows added later may become visible. Current
ACLs, hidden rows, field narrowing and deletion are re-evaluated on every
page; loss of collection access removes it from the view. No new collection,
field or action is granted. The action list never grows. A live action must
target a row currently exposed by its checked projection, re-check the
creator's current write authority, and belong to the minted action set;
otherwise it is refused. Action-bearing named-row grants do not gain targets
added after mint.

The dynamic marker is accepted **only** by the live query entry point:
`query_widget_on(tx, scope, *, creator_id, widget_id, bind, link_id,
expected_page_rev=None, projection=None)`. The app passes only the checked
`LinkRead.projection` and the verified `LinkCaller.link_id`, never a link ID
from request JSON. A missing projection is refused. The query intersects the
minted collection/fields and current creator row/field ACLs before filtering,
sorting, counting and pagination. Each page has at most 200 rows; a collection
may contain more. Cursors bind to the link, creator, scope, complete checked
projection, query and page revision. They never work across links, even for
the same creator. A changed page revision invalidates the cursor: restart at
page one within the capability's ceiling. N5 retains its caller transaction
and link lock until the page is loaded; every page re-checks session, expiry
and revocation. `read_projection_on`, `capture_link_snapshot_on` and
`project_link_snapshot_on` remain bounded named-row APIs and never accept `"*"`.

**Disclosure and mode choice.** Wherever a person mints a live link to share,
the chooser and link view must say that anyone holding it sees rows added
later, within the creator's current access, until expiry or revocation. Pinned
is the default wherever a person chooses a mode. A dashboard Documents click
that mints a short-lived link for the viewer is a self-view, with no share
chooser; its view still labels the mode as live.

At mint, pinned mode materializes one complete authorized `aweb.page/1`
snapshot at `page_rev` in the same transaction as the link. It holds the
projected collection schemas and values, layout, widget state, and only the
definitions of actions the link allows. N5 stores that immutable source with
its link ID, revision and digest. Ordinary edits never replace its values,
layout or state, or make the link break. The app's
`capture_link_snapshot_on(tx, scope, creator_id, projection,
allowed_action_ids, expected_page_rev)` uses its shared store redactor:
excluded widgets become inert placeholders, action lists and definitions are
narrowed to the whitelist, and only captured widget IDs retain state. No
asset fetch URL or grant enters the snapshot.

The whole snapshot obeys the page-format limits: at most 10 MiB, 2,000 widgets,
widget depth 8, JSON depth 64 and 1,000,000 JSON values, plus this contract's
16 actions, 64 distinct asset IDs and projection bounds. At use, that same
redactor only narrows the stored view under the creator's **current** ACLs and
action authority. It never substitutes current layout, state or values, or
adds an action definition absent at mint. A missing or corrupt source fails
closed as `link_unavailable`, with the cause logged; it never falls back to
live data. Link expiry and revocation still apply.

Captured asset IDs are bound to immutable content versions outside the page
data. While a link is neither revoked nor expired, its references retain
those versions against ordinary asset garbage collection. Revocation and
expiry release the references. Explicit owner deletion of an asset or page
wins; an unavailable asset produces an unavailable-media placeholder for that
asset, not replacement bytes or failure of the rest of the view. The asset
adapter resolves versions on the mint transaction under its lifecycle lock;
ordinary garbage collection takes that lock and checks all live references
in the installation before deleting an unreferenced version. Snapshot and
retained-asset content belong to the page's export, content-purge and declared
backup/retention coverage. Purging the page's links purges their snapshots,
sessions and references in the same transaction; backup expiry remains
separate coverage in the deletion receipt.

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
intersection of its minted ceiling and what its creator holds at each use.
For live read-only wildcards, that ceiling is the collection and fields rather
than a frozen row list. If the creator loses access to a row, field or action,
the link loses it too.

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
{"session_id": "lks_01JC…", "csrf_token": "<22 chars>", "expires_at": "2026-10-20T12:15:00Z", "link": {"page_id": "…", "mode": "pinned", "actions": ["mark-cleaned"]}}
```

`csrf_token` is 16 random bytes, base64url without padding, bound to the
session and stored only as its SHA-256. The host's `csrfToken()` returns it,
from the same in-memory closure as the secret, and every state-changing link
request carries it as `X-AWEB-CSRF`; the app compares it in constant time. It
adds a check the session key does not replace, and is never given to the
renderer as page data.

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
5. **Origin and CSRF.** A state-changing request carries an `Origin` header
   equal to the app's origin and the session's `X-AWEB-CSRF`. Failure: 403
   `action_denied`.
6. **Link lifecycle and authority**, under the link's row lock: §4.

The nonce is recorded in its own committed write as soon as steps 1–3 pass,
under a uniqueness constraint shared by every worker, before step 5 and before
any action runs. A refused or failed action therefore leaves its nonce
recorded, and the same signed request can never be presented again. Of two
concurrent requests with one nonce, exactly one is recorded; the other gets
409.

The key tells a repeat browser apart from a typed-in name, not a verified
person. A holder with the secret can always start another session. The
capability, not the key, is the authority, and the audit records the action
as anonymous, via link `link_id` and session `session_id`. It never claims the
trust of an AWID member signature.

## 4. Lifecycle at every use

Each read, submit, stream subscription, asset fetch and dispatch takes the
link's row lock (`FOR UPDATE` for writes, `FOR SHARE` for reads). Every request
also requires its session to be unexpired and the current creator membership
check above to pass. For a submit, the first action-layer step under
the lock is the **receipt lookup**: if the link has an admitted operation with
this idempotency key, the same body returns its stored receipt, and a
different body is 409 `idempotency_conflict`. Nothing else below runs for a
matching retry, so a retry gets its receipt even after the link was used up
or revoked, as long as its session is live and the creator passes current
membership; it never admits a second
operation. A session never outlives its link, so once the link has expired
there is no session left to retry with. Otherwise, in the same transaction, the request requires:

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
retry of the admitted action, with a fresh nonce and the same idempotency key
and body, returns the stored receipt through the receipt lookup above. A nonce
replay (the same signed request again) is a different case: it is refused at
§3 step 4, whatever happened to the action.

**Assets.** The browser loads images and video natively, so those requests
cannot carry `AWEB-Link-Request`. A signed read instead returns, for each
asset in the projection it shows, a URL on the app's asset origin carrying an
**asset grant**: 16 random bytes, base64url, stored only as its SHA-256, bound
to `(link_id, session_id, asset_id)`, valid for at most 5 minutes and never
past its session. Every request to the asset origin with a grant, each Range
request of a video included, re-runs this section's checks for that asset
under `FOR SHARE`; a revocation therefore stops a video at its next range
request. A grant may be used any number of times within its window, for range
requests and retries, and grants nothing beyond that one asset. The asset
origin never logs query strings, sends `Cache-Control: private, no-store` and
`Referrer-Policy: no-referrer`, and the link page's policy keeps grants out of
referrers. A new grant needs a new signed read.

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
- **Answer its own bounded request**, such as a guest reply: this is an
  ordinary `intent` action the creator allowed, constrained to that request's
  reference, submitted through the host's generic action path and recorded as
  anonymous input. It never uses the decision answer path (the host's
  `answer`), which is the member flow of [page-actions.md](page-actions.md)
  §5.

**Anonymous intent rule.** No external or privileged effect follows from a
link alone. When an intent needs one, the sponsor's work raises a decision for
an assigned member, or an owner-designated passkey approver
([page-actions.md](page-actions.md) §6–§7). A holder's text is data to the
agent, never instructions that bypass that decision.

**Where this runs.** The exchange, the request verifier, the nonce and receipt
stores, the link row locks and asset grants are the capability-link runtime in
`aweb_naapp` (D1 §7: N5 builds page action links on it, beside B2's approval
links). The shared renderer calls only its host adapter. It never receives the
link secret, the session key or the CSRF token as page data. For media it
receives only opaque, single-asset URLs on the pinned asset origin, which carry
their grant; it neither parses nor stores the grant, and issuing or checking
grants is never renderer authority.

## 6. Rate limits

`link-default-v1`, enforced per link and per client address, with token
buckets that refill continuously:

| Bucket | Limit |
| --- | --- |
| Successful exchanges, per link | 10 per minute |
| Exchanges (successful or not), per client address | 30 per minute |
| Signed attempts, per session | 240 per minute |
| Reads, per session | 120 per minute |
| Writes (edit, intent, answer), per link | 20 per minute |
| Writes, per client address | 60 per minute |
| Uploads, per link | 10 per hour, each within the action's byte bound |

After signature, binding, time and session verification, every signed attempt
charges the session bucket in the nonce transaction. That charge commits before
Origin/CSRF and operation checks, including duplicate-nonce attempts; a later
refusal or rollback does not refund it. An exhausted bucket refuses before
recording a new nonce. Invalid signatures do not write a bucket or nonce.

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
| 403 | `current_member_required` | Creator membership evidence is incomplete, unknown, revoked or rotated. |
| 503 | `current_membership_unavailable` | Current AWID membership facts cannot be obtained. |
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

### Current collection metadata for checked link adapters

`LinkAuthority.readable(tx, *, creator, page_id, collection, link_mode,
record_ids)` receives the checked link mode and selection. The host passes them
as `collection_access_on(..., link_mode=link_mode, record_ids=record_ids)`;
the store's returned `mode` describes an owned/synced collection, not the link.
`Readable.records=None` explicitly means dynamic rows and is valid only for a
live read-only wildcard. The outer `Readable | None` result still uses `None`
for an unavailable collection or no visible fields. A live wildcard metadata
check must not enumerate record IDs; `query_widget_on` applies current row
permissions before filtering, counting and paging.

Named selections, including `[]`, require a tuple of at most 200 current visible
IDs. Pinned wildcard mint inspects at most 201 IDs and refuses above 200. An
action-bearing wildcard mint requests this same bounded expansion with
`link_mode="pinned"`, even when the content mode is live; its stored rows remain
named. Dynamic results cannot satisfy named, pinned or action-bearing checks.
