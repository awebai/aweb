# Terminal hook delivery

Status: proposed consistency amendment to [hook events](hook-events.md),
assigned by the secrets coordinator on 2026-10-23. It requires receiver,
resolution and producer fit, then independent review and Athena. Until the
amendment and its shared implementation are accepted, active-only admission
continues. This document specifies the exception; it does not claim it ships.

## Authority and scope

The team controller authorizes a registration. The operator's separate core
hook key attests the binding's end and authorizes delivery of its final record.
Neither an app key, a member key nor a controller key is a core producer key.
The receiver discovers core authority through the team's current
`TeamServerDirectory` anchor. An event-supplied origin, a self-signature or a
bare key listing never establishes that authority.

An `active` registration that becomes `revoked` or `superseded` is owed exactly
one logical `post-mutation-hook` event with `mutation_type=hook_binding.revoked`.
It receives that event even if registered for another hook. This is also a
deliberate exception to the `active_from` pad: an owner-activated registration
ended inside the pad receives its own final record, and no earlier activity.
A never-active `pending` registration receives nothing. A production has no
target endpoint and receives no terminal delivery. Their state changes still
produce the ordinary governance evidence owed to other active registrations.

The exception is limited to that event and that exact old binding. It neither
reactivates the registration nor grants reads, production, general ingest or a
new generation's activation. The new generation starts pending. Existing
event envelopes, catalog event identity and ordinary delivery v1 stay intact.

## Producer transaction and backlog

The lifecycle service calls one shared `aweb_naapp` end-binding operation in
the transaction that ends the binding. Core supplies the locked old binding
and verified transition; the kit supplies outbox storage, cancellation,
terminal materialization and transport. Core has no second outbox or custom
network sender. Any schema additions are new ordered kit migrations, applied
to core through the kit's migration module.

Under a per-producer/team/binding fence shared with enqueue and materialization:

1. Preserve the old registration's identity, installed digest, resolved tool
   endpoint, activation evidence and active interval. Never resolve its
   destination from a later installation or from the incoming event.
2. Account for outstanding local events owed to that binding. This includes
   eligible events not yet materialized: retain an explicit cancelled
   `(event_id, binding_id)` tombstone for each, alongside cancellation of its
   materialized pending/stalled deliveries. Do not mark an entire event
   materialized or drained just to cancel one target; its other deliveries
   remain owed. Already acknowledged events are not counted as cancelled.
   Retain rejected/conflicting delivery faults distinctly; cancellation must
   not erase them or relabel them as delivered.
3. Allocate one terminal event ID and core sequence, build and sign the normal
   revocation envelope, and retain one terminal authorization capsule below.
   Persist its fixed old target with the event in the hooks outbox, even when
   ordinary registration resolution returns no target. The terminal event is
   excluded from cancellation and cannot be lost by an empty normal resolver.
4. Commit the binding transition, local cancellation evidence, immutable event,
   capsule and terminal obligation together. A rolled-back transaction exposes
   none of them. Ordinary active post-mutation registrations receive the same
   signed event bytes through ordinary delivery; the ended target receives a
   different wrapper around those unchanged bytes.

The fence closes the race with a drain that already selected an event. A
committed cancellation cannot be overwritten by an in-flight attempt's later
ACK/retry result. A request already on the wire may reach the receiver; the
receiver seal below resolves that race. No network operation or receiver ACK
holds the transition transaction open. Containment does not wait for remote
availability. A database failure is a failed local commit, not a reason to
retain active authority while waiting for a target.

The event's optional cancellation count and sequence range describe **core's
own** exact cancellations, including unmaterialized owed events. A range is
per producer, team and source hook; it never describes all producers. Separate
non-contiguous ranges remain separate accounting evidence; a bounding interval
must not claim that acknowledged events inside it were cancelled.

Each other producer applies the same shared-kit fence to its own outbox when
it learns the binding has ended, within the existing 60-second resolution
bound. It retains cancelled tombstones for unmaterialized owed events too.
Events committed through a stale view inside that window are cancelled, never
backfilled into the ended target or a new generation. Other targets keep their
own delivery obligations. Each app producer records its own cancellation
governance evidence as specified below. There is no cross-database atomic
count. A gap without its producer's explaining evidence remains unexplained.

## Immutable authorization capsule

Use the hook envelope's strict canonical JSON, depth and scalar rules, strict
unpadded base64url for byte strings, and its unique 86-character unpadded
standard-base64 Ed25519 signature spelling. No field permits free text or
credential values. Unknown fields, duplicate keys, nulls, floats and alternative
encodings are refused.

Let `E` be the **ordinary** canonical delivery body containing exactly
`hook_event` (the base64url of the event's complete signing bytes, prefix
included) and `signature` (its detached signature). Define:

```text
event_sha256 = hex(SHA-256("aweb.hook-terminal-event/1\n" || E))
capsule_signing_bytes = "aweb.hook-terminal-authorization/1\n" || canonical(C)
```

`C` has exactly these required fields:

| Field | Meaning |
| --- | --- |
| `v` | Integer `1`. |
| `team_id`, `binding_id`, `event_id` | Exact team and old registration, and its one terminal event UUID. |
| `event_sha256` | The commitment above, including the immutable event signature. |
| `authorized_at`, `ended_at` | Canonical millisecond UTC times. `ended_at` equals the event's `occurred_at`; `authorized_at` equals `fired_at` and is no earlier. |
| `ended_state`, `reason` | `revoked` with `owner_act` or `uninstalled`; `superseded` with `superseded`. |
| `issuer` | Exactly `{origin, kid, did_key}` of the core event signer. |
| `target` | The exact old owner-activated registration snapshot below. |

`target` has exactly `kind` (`registration`), `app_id`, `installation_id`,
`generation`, `digest`, `origin`, `tool`, `method`, `path`, `catalog_id`,
`catalog_version`, `hook`, `activated_at`, `active_from`, and
`activation_act_sha256`. Types and spellings are those of the binding and
owner-act contracts. `path` is the resolved external raw path and query;
`method` is `POST`. The snapshot is derived from stored owner-activated bytes,
not installer-supplied substitute keys or a new tool resolution. Its IDs,
catalog and original hook equal the event payload's binding identity. The
envelope's team and producer equal the capsule's team and issuer. The event
has `result_status=success`; its reason equals the capsule's reason. The
event's owner-act commitment remains required for an owner-act revocation.

The core key that signs the event signs the capsule in the same transaction.
The capsule is never rebuilt on retry or after an install changes. Persist
its bytes and signature with the terminal target. It is authority only for
the committed old-binding transition and the committed event hash, not a
general assertion that this target is active. It is carried with delivery;
no public binding-history endpoint or restored `hook-resolve` grant is needed.

## Separate terminal request credential

Dispatch by an exact new scheme and auth value. Ordinary v1 delivery continues
to require its two-field body, matching event/transport signer and active
binding. It never accepts a terminal wrapper or silently relaxes a check.

The terminal HTTPS request to the pinned old endpoint has canonical body:

```text
{hook_event, signature, terminal_authorization, terminal_signature}
```

The first two fields are unchanged from `E`. `terminal_authorization` is strict
base64url of the complete capsule signing bytes; `terminal_signature` is its
detached signature. It uses these headers:

```text
Authorization: AWEB-Hook-Terminal DIDKey <current-core-did:key> <signature>
X-AWEB-Signed-Payload: <strict base64url canonical credential payload>
```

The signed credential payload has the ordinary delivery fields, with `v=1`,
`auth=hook-terminal-delivery`, and `producer=core`. Its `kid` and `did_key`
identify the **current transport signer**; `body_sha256` commits to the whole
four-field body. Its team, binding and event IDs equal the capsule's. Audience,
method and raw path bind the actual old endpoint; timestamp is canonical UTC
to the second with the existing 300-second skew bound. Signature and canonical
encoding checks follow ordinary delivery. There is no client certificate.

Unlike ordinary v1, this scheme permits a different **core transport key**
from the immutable core event/capsule key. It permits no different producer
kind, team or core origin. A parsed terminal body under `AWEB-Hook`, or an
ordinary body under `AWEB-Hook-Terminal`, is refused. No fallback to the other
scheme occurs after refusal. Existing HTTPS, no-redirect and egress rules apply.

### Key windows and authority changes

Resolve the team's current core server and public key set through the shared
`NaappRuntime.team_server_directory()` and `hook_resolver()` accessors. Do not
construct a parallel resolver or use the event/capsule origin to select one.
Fetch evidence outside chain/authority locks; fail closed if its freshness
expires before admission. No expired cache is an authority fallback.

Require both immutable signatures to verify under the same listed core
`kid/did_key`, whose validity interval covers event `occurred_at`, `fired_at`
and capsule `authorized_at`. Intervals are `[valid_from, valid_until)`, with
null `valid_until` denoting no end. A retired public key can establish those
historical signatures; it cannot authorize a fresh retry signature. The
transport key must be listed and valid both at the signed request timestamp
and at receipt. Rotation therefore retains historical public evidence while
the active private key signs fresh retries. No retired private key is needed.

The current anchored origin must equal both event origin and capsule issuer
origin. A controller rotation with the same server triggers normal fresh
discovery and key checks; the old controller key is not a producer verifier.
After a team-server move, deletion or unverifiable predecessor anchor, this
contract does **not** infer historical authority from a cached old record or
automatically re-sign/re-route the event. The terminal obligation remains
pending/stalled with `terminal_reconciliation_required`, surfaced to the
owner. It is not delivered, ordinarily cancelled, silently expired, or proved
complete. A supported migration/reconciliation must establish authority before
any dispatch resumes; this amendment invents no historical registry service.

Uninstall and app origin changes do not remove the capsule or historical core
evidence. They never change the old destination. If that endpoint no longer
exists or cannot accept the record, retries remain outstanding and surfaced.
Keeping the old endpoint reachable until terminal receipt is orderly rollout,
not a condition that delays revocation. Supersession of an already-ended
binding creates no second terminal event; its first obligation remains for
that old binding. A later-active new generation has its own independent end.

## Receiver admission, dedup and sealing

For terminal requests, validate the new transport credential and immutable
envelope/capsule under the fresh anchored evidence above. Require the exact
`post-mutation-hook/hook_binding.revoked`, core producer, successful transition,
matching event commitment, old binding identity and reason. Compare capsule
target app ID/origin/tool/method/raw path to the receiving app's configured
hook-only endpoint. Retain its digest as authenticated historical binding
evidence; do not demand the now-deleted installed grant or current generation.
An active registration on some other team/hook is never substitute evidence.
The only bypasses are ended registration state, its original hook, and the
pad for this one event. All schema, team, endpoint and provenance checks remain.

Serialize ordinary admission and terminal sealing under the same per-team,
per-binding transaction fence, with consistent lock ordering before the chain
head. The ordinary path checks this durable seal even with an otherwise fresh
active cache. An ordinary transaction either appends before sealing or refuses
after it; it cannot commit later using a pre-seal check.

Within that transaction:

1. Reject a different terminal event/hash/capsule for an already-sealed binding
   with `409 terminal_conflict`. Same event ID with different immutable event
   bytes is the existing `409 event_conflict`. Nothing is overwritten.
2. Dedup the event on **`(team_id, event_id)`**, as for ordinary ingest. If it
   already arrived through another active registration, return its original
   receipt and do not append it again. This duplicate path still seals the
   addressed old binding atomically. Dedup never skips the seal.
3. Otherwise append the immutable event once to the team chain. Insert the
   binding seal, capsule and historical/current key evidence with that append
   in the same transaction. Retain the original receipt and the exact evidence
   mapping binding to event, including for a duplicate through another binding.

After commit return the normal appended/duplicate result and original event
receipt, plus `binding_id` and `terminal_sealed=true`. The terminal producer
accepts success only when these match its obligation. Identical terminal
retries return that same event result and maintain the same seal. Changing a
transport timestamp/key during legitimate rotation does not change event or
capsule identity. No receipt claims exactly-once network delivery.

The seal closes only that registration. Other registrations of this logs
installation, other teams and the team's continuing chain remain open. The
terminal event may precede its seal in global chain order when it arrived
through another binding; the authenticated binding-to-event seal evidence,
not a second copy of the event, records completion of that binding. Export and
`verify` retain and check that relation and distinguish an outstanding final
obligation from an acknowledged seal.

Ordinary delivery after sealing returns `410 binding_ended`; the producer
cancels only that ordinary delivery, retaining the reason. A terminal request
never treats that response as completion. Missing/stale anchor or key evidence
returns 503 without append/seal; malformed signatures return 401, unauthorized
target/event/capsule combinations 403, and conflicts 409. All failures are
distinctly logged without event content or credentials. Permanent faults remain
surfaced; network/5xx retries and the disclosed stalled horizon remain durable.

## Each app producer's cancellation evidence

An app with an active `post-governance-hook` production emits the generic
`hook_delivery.cancelled` act from its local end-binding transaction. Direction
is `narrowing`, authority is `outbox_state`, and actor is exactly
`{"authority_mode":"system","attestations":[]}`. The app signs only its own
outbox facts, not the owner's revocation or another producer's activity. This
act grants no new production authority. Unsupported or no-longer-authorized
producers leave a visible unexplained gap; they do not fabricate a record.

Required fields are `source_binding_id` (UUID), `source_hook` (one of the
three app-produced server hooks), `source_seq_first`, `source_seq_last` and
`cancelled_count` (positive safe integers), plus `reason_code=binding_ended`.
The event's team and complete app producer identity identify the source
sequence namespace. One record describes one contiguous range, with
`first <= last` and `count = last - first + 1`, derived from persisted
cancellation tombstones. Disjoint cancellations produce separate records.
No resource/role/approval fields, owner/passkey commitments, human identity,
raw requests or cancelled event contents are included. These fields and this
authority are forbidden on all other governance acts.

The shared kit atomically enqueues each summary with its local cancellation
and preserves an emission marker so recovery cannot mint the summary twice.
No target/backlog gate delays this narrowing transition; without targets its
record persists without retroactive delivery to future registrations. The
remaining active governance registrations receive it under ordinary app
production/key verification. `verify` attributes an explained gap only to the
matching producer/team/source hook and affected binding; the source producer
must match, and the range arithmetic must hold. An unrelated summary never
explains another producer's missing events. No summary means unexplained.

## Deliberate catalog re-freeze and implementation evidence

The coordinator authorized an in-place v1 re-freeze under decision 93 on
2026-10-23 (`c00d8528-4b9d-457e-8c53-e2e3e8d2f0cb`). Its evidence receipt is
`e09dce11-f2dc-4baa-8a3b-3fdcbb9790ed`, against public main `38cc429d2c0f`:
the only concrete governance producer is Secrets; Folio/Library/core have no
emitter; no mounted Logs receiver is landed; the coordinator's DNS/manifest
checks find neither hosted Secrets nor Logs, and no hosted Secrets deployment
has been authorized. Open tasks and published parser packages alone are not
deployment evidence. These are scoped first-party findings, not a claim to
have inventoried every third-party source checkout. A third party could
self-host unreleased public source; that residual is explicit in the ruling.
If a deployed v1 consumer is found, stop this re-freeze and use the next catalog
version with Juan's decision. No previously accepted payload is removed.

This delta updates the public catalog and its byte-identical packaged copy,
adds positive and single-fault payload cases for the new act, and preserves
the existing signed-envelope and ordinary-delivery vectors. Range arithmetic
and system-actor coupling additionally require shared semantic verification;
the generic catalog rule language alone does not prove them.

Before enabling the exception, the shared kit must implement the capsule and
terminal credential with Go-generated public conformance vectors and Python
verification against those same bytes. New terminal vectors cover each
signature, framing/hash, alternate scheme, key rotation/window and mismatch;
existing ordinary v1 cases stay byte-identical. Shared lifecycle cases cover
never-active refusal, pad-only final entry, cold uninstall, supersession,
different original hook, rollback, unmaterialized cancellation, drain/ACK
races, terminal retry, duplicate-via-another-binding sealing, seal/append
rollback, ordinary ingress racing a seal, independent new generation, and
unanchorable authority remaining an outstanding reconciliation obligation.
App cancellation cases cover multiple/disjoint ranges, incorrect count,
wrong producer/hook, forbidden fields/authority/actor, unavailable targets and
unexplained gaps. S2 supplies core integration, L2 supplies receiver integration;
neither copies the shared implementation. Production activation waits for the
reviewed paired implementation and real revocation end-to-end acceptance.
