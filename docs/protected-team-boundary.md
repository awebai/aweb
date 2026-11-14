# Protected team verifier boundary

Implementation contract for aweb-acxy.15. Approved by Juan 2026-11-13, via
coordinator, approval receipt `8bad48a7-e8ed-4673-b47e-9c4823533df7`. This is a
narrow extension of human-assurance-contract §7 for explicitly cut-over teams,
not a release or activation claim. Unmarked teams retain their existing rules.

Namespace authority appoints a controller; the controller authorizes membership
and team acts. Custody is separate. An existing controller signature proves no
protected-signer or passkey use. A protected team additionally requires a
service attestation from a distinct, isolated service key; the v1 artifact and
certificate encodings remain unchanged. Profiles remain pinned configuration,
not authority or discovery.

## Binding and cutover

The registry retains `team_protection` by canonical domain/team name, outside
replaceable namespace/team UUIDs. Its protected binding is exactly `mode`,
`service_id`, `service_did_key`, `history_id` and positive safe-integer
`generation`. History is a stable UUID; generation advances on every protection
transition and team/controller incarnation change. A tombstone survives
namespace/team deletion and recreation. Service-key replacement, recovery and
deprotection use the recorded operator provisioning path and advance generation;
no controller-key-only worker endpoint can make those changes.

Private status-only callers may negotiate `?protection=1` on the existing
public certificate-status read. It adds the current protection projection and
exact retained `certificate_sha256`, under the same canonical-team guard as
the current controller/status read. No member fields or private metadata
permission are disclosed. Calls without the query preserve their exact
four-field response, because released consumers check that exact shape.
Missing negotiated evidence is unknown; a new caller never infers legacy
from an old registry's unchanged four-field answer.

An upgraded registry projects absence of a protection row explicitly as
`{"mode":"legacy"}`. A missing response field, unknown/malformed binding,
older registry or failed lookup is unavailable evidence, never inferred legacy.
Upgrade the selected registry before protected consumers/cutover. Existing
callers that ignore the additive metadata keep working on unmarked teams.

Every AWID controller effect takes the namespace guard then canonical-team
guards in lexical order, including when a protection row is absent. Team effects
and activation share the namespace guard; namespace cascade takes it exclusively.
Binding/proof verification and the write share one transaction. A stale
pre-cutover absence cannot authorize a post-cutover write. Final row locks fence
controller, history and generation. No network work belongs under effect locks.

Remote consumers cannot share that transaction. Before activation and EVERY
subsequent generation transition, the operator inventories all consumers,
clients, pending artifacts and exact historical membership evidence, drains
in-flight effects, invalidates cached/prepared authority, applies the transition
and resumes upgraded consumers. An unenumerated or undrained consumer blocks
cutover. Governance uses fresh authoritative observations with the original
60-second maximum; the effect rechecks that deadline synchronously after its
last await. This is coordinated cutover, not distributed atomicity. Package .8
owns each installation's authorization, historical baseline, restore and rollback
limits; a restored database counter alone cannot establish safe history.

Core certificate authentication retains that original observation through
identity binding, ID-chain authentication and local identity resolution.
Projection updates and grant mint/revoke effects check it inside their
transaction after the final await, so expiry rolls back their writes. A later
read never renews evidence already used by the operation.

## Detached proof

`X-AWEB-Protected-Effect` contains unpadded base64url of canonical JSON
`{"proofs":[PROOF,...],"v":1}`. There are 1..64 proofs, at most 65536 header
bytes, and at most one proof for a canonical team. PROOF is exactly `payload`
(unpadded base64url canonical JSON) and `signature` (unpadded standard-base64
Ed25519 signature of `aweb.protected-effect/1` + LF + those payload bytes).
Unknown/duplicate fields, noncanonical JSON, floats, booleans, null, unsafe
integers, depth over eight and non-printable-ASCII strings refuse.

Payload fields are exactly:

| Field | Binding |
| --- | --- |
| `v`, `type` | `1`, `aweb.protected-effect` |
| `service_id`, `team_id` | Current service and canonical team |
| `history_id`, `generation` | Current protection incarnation/version |
| `controller_did_key` | Current team controller |
| `operation`, `variant`, `operation_id` | Closed typed operation and original UUID |
| `artifact_type`, `artifact_sha256` | Exact retained signed artifact |
| `consumer` | Closed destination/request binding below |
| `issued_at`, `expires_at` | Original UTC seconds deadlines, never refreshed |

The artifact digest is SHA256 of `aweb.protected-artifact/1` + LF, the unsigned
signing byte length as an unsigned 64-bit big-endian integer, those exact signing
bytes and the decoded 64-byte controller signature. Existing artifact-specific
domain separation remains part of those signing bytes.

An HTTP consumer is exactly `kind=http`, `audience` (pinned canonical origin),
`method`, `path` (exact external raw target including query), `body_sha256`, and
`controller_envelope_sha256` (digest of the complete covering controller envelope,
or empty bytes when none exists). A separately approved offline artifact
consumer is exactly `kind=artifact`, `audience`, `scope`; it cannot authorize an
HTTP effect. The operation definition fixes this choice and all serializers,
routes and bodies. A namespace cascade requires one proof for EVERY affected
protected team, each bound to the same complete cascade request.

The signature attests release of one locally authorized retained effect, not
completed remote application. The typed executor retains artifact, signature,
proof and final delivery bytes under its existing approval/policy/authority
transaction before release. The service key is isolated from worker OS users,
mounts, sockets, keychains and backups, distinct from controller/H/member keys.
There is no generic sign-bytes or proof-construction endpoint. A self-hosting
administrator changing the software is outside the claim.

Only committed retained bytes may leave. Remote application follows separately,
using a durable release claim, exact delivery and independent confirmation.
Retries reuse the original proof, artifact, request, operation ID, nonce,
timestamps and deadlines. They cannot refresh the covering envelope. If its
authentication expires or the outcome is unknown, reconcile by an authorized
exact read; do not blindly re-sign. The proof expiry is capped by the original
operation/approval/artifact deadlines. The original 300-second UV-at-signing
bound remains independent. Existing nonce, head, expiry, revocation and
idempotency checks remain mandatory. Proof expiry does not revoke membership.

## Effects and membership

Protected effects include certificate register/revoke, visibility, team
create/recreate/delete/rotate, namespace deletion cascade (including teams with
already-revoked certificates), team-server artifact publication, and custodian,
member-custody and member-person publication. Rotation proof covers the complete
`resigned_records` batch. Ordinary member, identity and self authority is not
silently replaced by controller authority. Core/app owner-act consumers check
the same binding/proof before their nonce/effect transaction.

Every protected membership acceptance compares the full authoritative signed
certificate; a registered ID alone is insufficient. The registry's certificate
history projection adds `certificate_sha256`, the SHA256 of canonical JSON of
the retained complete signed certificate. Null or invalid historical blobs
produce unavailable exact evidence, never a manufactured binding. A presentation
with a changed member key, alias, scope or other signed field under an active ID
refuses. Existing signature/revocation/current-key rules still apply.
An explicit fresh revoked status overrides earlier cached revocation evidence
on legacy and protected teams alike. Active legacy presentations do not require
the protected-only artifact digest.

Retained identity/grant/stream/hook references must match every membership field
they consume against a full-artifact-backed current registry row (ID, subject
key, alias, identity scope, stable ID and address). Compare an original retained
artifact digest where present. A projection predating exact admission is usable
only under .8's expressly inventoried field-exact historical baseline. Never
backfill its original evidence with a guessed digest. This check grants no new
resource or delegation rights.

Registration and legacy invite admission without proof return HTTP 403
`protected_admission_required`. Other protected controller acts without valid
proof return 403 `protected_controller_required`. A presented mismatched
certificate is 401 `certificate_binding_mismatch`; unavailable/unknown protection
or exact membership evidence is 503 `protected_state_unavailable`, with the real
failure logged. aw names the configured protected service/root admission path;
it never retries the legacy invitation, remints an identity or swaps registry.

Protected service-owned delivery is explicitly negotiated/versioned. It returns
a safe application status/reference alongside the public signed artifact; it
never exposes private delivery authentication. aw skips its old local POST in
that mode, and an older client refuses an unknown mode. Legacy sign-only results
retain their existing format and cannot claim service-owned application.

The negotiated applied result is closed JSON:
`{"v":2,"type":"aweb.protected-delivery","artifact":{"signing":BASE64,"signature":BASE64},"delivery":{"mode":"service_owned","state":"applied","reference":{"operation_id":UUID,"artifact_sha256":DIGEST}}}`.
The reference binds the saved operation and the digest above; it contains no URL
or private authentication. Only actual effect confirmation permits `applied`.
The CLI verifies its original signed intent and structural/lifetime bounds as
history, so receipt recovery after artifact expiry creates no new authority.
It never POSTs an applied result. The legacy pair still requires current artifact
freshness before its local POST; unknown versions/modes/references refuse.


## Exact consumer confirmation

A protected consumer records an immutable historical reference in its actual
business-effect transaction, after the effect and its audit/nonce fences:
`operation_id`, canonical `team_id`, `service_id`, typed `operation` and
`variant`, `artifact_sha256`, and SHA256 of the complete retained detached
header bytes. Failure rolls back both effect and reference. Nonce consumption
alone is never application confirmation. An exact duplicate may recover the
same reference; another artifact/header under the same team/operation ID must
refuse rather than overwrite it. Cascade references cover every protected team
in that same transaction and match the complete per-team proof association.

The signer reads only
`GET /.well-known/aweb-protected-effect-receipts/{operation_id}` on the retained
pinned consumer origin, with the complete original `X-AWEB-Protected-Effect`
header. Neither the operation ID alone nor a supplied header digest permits a
read. This is a proof-gated historical read, distinct from the signer's full
receipt API and its unchanged current reader authority. No proof bytes belong
in URLs, access/error logs or tracing. Every response has `Cache-Control:
no-store`. There is no discovery, response-selected URL or redirect forwarding.

An exact match returns only
`{"v":1,"operation_id":UUID,"artifact_sha256":DIGEST}`. The adapter strictly
checks all three fields and refuses duplicate/unknown fields. Unknown ID and
header mismatch both return 404; unavailable storage returns 503. A 404,
including one racing an effect commit or following purge/restore, leaves the
outcome unresolved. It never permits re-signing, refreshed deadlines or a blind
retry. The original confirmation observation deadline remains bounded by 60
seconds from read start and is checked after the final await.

The retained header may match an already committed reference after proof expiry,
controller/service-key replacement or a new protection generation. The read does
not reauthorize an effect, consume a nonce or extend any lifetime. Only that exact
historical match can produce the negotiated applied result. Admission/removal
clients verify the same closed v2 reference as owner-act clients, then verify the
unchanged artifact against the saved prepared operation. Legacy public pairs
remain unchanged. Wire controls are in `vectors/protected-effect-receipt-v1.json`.
