# Human channels: P0 public seam v1

Status: P0 contract freeze candidate, aweb-acft.12. Juan authorized the build on
2026-10-21 (integrations message 41221f08). This supplies definitions and
conformance readers, **not service implementations or permission to enable
membership**. The [decided design](human-channels-contract-proposal.md) and
[build tasks](human-channels-oss-build-plan.md) govern its authority.

The [machine grammar](vectors/human-channels-profile-v1.json) defines exact closed
DTO field sets, primitive types, enum values and nested references; the
[signed vectors](vectors/human-channels-v1.json) define canonical bytes, hashes,
Ed25519 signatures, valid structural neighbors and refusals. Python's public
`aweb.human_channels.contract` and Go's `awid.DecodeHumanChannelsRecord` consume
that grammar. Their compiled grammar is tested against the public authority.
`ContractRecord` / `HumanChannelsRecord` identify a named DTO plus its field map;
Go also exports participant, group-context and capability structures.
**A structurally valid record is not verified identity or authorization.**

Current main's [vector authority](vectors/README.md) is `docs/vectors`, replacing
the planning placeholder `test-vectors/human-channels`. No second vector root or
consumer-local fixture is created. Generation is deliberate via
`scripts/freeze_human_channels_profile.py`; any change to frozen outputs needs
contract review, not automatic re-freezing to match a changed implementation.

## Compatibility, bytes and signatures

New control records use canonical UTF-8 JSON: recursively sort object keys by
Unicode code point, no insignificant whitespace, literal Unicode (including
U+2028/U+2029), and JSON escaping for quotes, reverse solidus and C0 controls.
Reject duplicate keys, unpaired surrogates, invalid UTF-8, floats, null for a
required field, unsafe integers, trailing JSON, unknown fields and unsupported
schemas. Counters are integers in 0..9007199254740991; positive counters start
at 1. UUIDs are lowercase hex with hyphens; digests are `sha256:` plus 64 lowercase
hex characters; private-policy commitments use `commitment:` plus 64 lowercase
hex characters. New control timestamps are UTC second-precision `...Z`.

`SignedArtifact = {signed_payload, signature}` preserves the exact canonical
JSON string, signed directly with Ed25519; signature is standard base64 without
padding, 64 decoded bytes. The payload's `version` domain-separates artifact
families. Its `signer` and `signing_key_id` must match an independently verified
current identity / operation-time authority chain, never a key fetched from an
untrusted payload URL. A receiver verifies original signed bytes; it does not
reconstruct a payload by dropping fields. `sha256` commitments refer to the
UTF-8 payload/envelope string itself, not JSON encoding of that string.

Endpoint wrappers retain the design's names: membership/presence/native calls
carry `SignedArtifact`; checkpoint HTTP carries
`{signed_checkpoint: signed_payload, signature}`. Service receipts are returned
as `SignedArtifact` of the specified receipt schema. Service signatures attest
acceptance/order only; they cannot replace owner/author/recipient signatures.
The session route's service/key binding is independently authenticated.

This grammar applies only to named new profiles. It does not replace legacy
native signing serialization, remove accepted fields, or narrow accepted native
mail/chat/session shapes. Existing native-v2 header/AAD/key-wrap bytes and explicit
encryption refusal stay binding. There is no plaintext retry. Old consumers keep
reading old sessions; new managed sessions refuse unsupported consumers instead
of projecting a guest as an ordinary verified native author. No in-place upgrade
without all affected consumers' capability/consent compatibility.

`NativePlaintext` freezes P1's optional `via` placement in existing signed payloads
for mail/chat, with omission unchanged. `NativeV2Content` freezes its placement in
protected inner content, **not** the outer envelope/AAD/header hash. Its identity
refs/attachment descriptors retain the exact existing E2EE/acfn validators; these
opaque nested native values are not a new key assertion grammar. P1 must preserve
all admitted extensions and existing fixed inner-header projection. Mail/chat ×
absent/telegram/msteams structural signature vectors accompany the new records;
P1 adds real encrypt/decrypt and released-client journeys before emission.
A supplied `via` uses ASCII `[a-z][a-z0-9_]{0,31}`. Unknown well-formed kinds
are retained in verified/decrypted content and safely displayed as an unfamiliar
channel kind, with no authority or routing behavior. Malformed values refuse;
omission grants no extra authority. Known producer kinds and MS Teams display
remain as in the decided proposal; producers never encode external identifiers
as platform kinds.

## Capabilities and failure results

`Capabilities` separates **implemented**, **enabled** and **refused**. P0 itself
advertises none. A later server may enable a known implemented capability only
after its acceptance/release gates; package installation alone is insufficient.
Readers preserve/ignore unknown advertised tokens so adding a capability does
not invalidate known native neighbors; explicit selection of an unknown or
deferred token returns unsupported (`require_capability` / `RequireCapability`).
The registry contains `signed-via-v1`, `human-alias-v1`, `human-send-uow-v1`,
`bridged-participants-v1`, `managed-chat-policy-v1`, `shared-control-history-v1`,
`chat-export-checkpoints-v1`, `presence-intents-v1`,
`presence-binding-intents-v1`, `native-chat-receipts-v1`.

`managed-chat-encrypted-v1`, `group-reshare-v1` and `group-federation-v1` are
reserved **refused** boundaries, not frozen wire algorithms. X-E2/X-GF supply
their annexes; Athena must review each exact annex SHA before freezing/enabling.
Owner-chain-advisory federation is refused. None of these spikes may weaken
chain-verify-before-wrap, owner transfer/freeze, narrow-only stop, checkpoint
commit order, recipient inbound policy, custody or explicit encryption.

P4 may ship storage/verifiers, but servers and published clients keep new-mode
membership unadvertised/refused until P5's J9 consent and minimal whole-session
bridge-readable label land together. P6's full interaction follows. Bridge
admission to an encrypted session without consent or the label refuses before
wrap/wake. All participants see **not E2EE** from the bridge-readable epoch;
hosted custodial DMs likewise say **not E2EE**, even with native encrypted-v2 to
a hosted key. `via` never supplies that custody decision.

New service calls return `Refusal` on a known pre-commit refusal. Its `family`
identifies resolve/prepare/accept/membership/history/checkpoint/presence/native/
attachment; `effects=none` means this refusal creates no new message, wake,
charge or membership operation. It does not assert that a prior unknown tool or
remote-send attempt did nothing. Native uncertainty is a durable operation state,
not permission to execute again. Transport loss after a possible commit requires
receipt recovery, not inference from an absent response.

| Code | HTTP status | Retry behavior |
| --- | --- | --- |
| invalid | 422 | never; fix shape/signature input |
| unsupported | 409 | never under this capability; publish/negotiate support |
| forbidden / consent_required | 403 | never until authority/consent changes |
| stale | 409 | refresh verified authority/head, explicitly recompose and re-sign |
| replay_conflict | 409 | never with changed bytes under the same ID |
| not_found | 404 | never; includes non-disclosing denied historical lookup |
| authority_unavailable | 503 | backoff; no authority/fallback inferred |
| native_unavailable | 503 | backoff/recovery; suppression remains |
| outcome_unknown | 409 | reconcile only; prior external effect may have occurred |
| limit_exceeded | 429 | backoff under existing rate/quota policy |

The schema's retry enum is a typed transport value; implementations must enforce
this code/row relation. Existing APIs keep existing error shapes/codes. In
particular checkpoint stale/replay wire details remain
`chat_checkpoint_stale` / `chat_checkpoint_replay_conflict`; adapters normalize
them to family=`checkpoint`, code=`stale|replay_conflict`. Unknown exception text,
private IDs and credentials never become public errors. Existing acfn errors
remain authoritative for attachments.

## Public calls needed by C0–C3

Python `aweb.human_channels.service.HumanChannelsService` and
`HumanChannelsUnitOfWork` are public embedding ports. They take existing verified
`MessagingAuth`, including team/grant restrictions; constructing a claimed DID,
owner or DTO is not authentication. HTTP uses existing identity/team/session
authentication; MCP calls the same service after authentication. Implementing
P tasks must supply these ports. P0 adds no routes or bypass for Cloud.

| Port / DTO input → output | Additive public HTTP projection; implementation task |
| --- | --- |
| capabilities → Capabilities | `GET /v1/messaging/capabilities`; P0 definitions, P1/P3/P8 acceptance implementations advertise their own floors |
| resolve(ResolveRequest) → AuthorityFacts | `POST /v1/messaging/resolve`; P2a, P3 typed session lookup |
| prepare(PrepareRequest) → PreparedSend | `POST /v1/messaging/prepare`; P2b; no send effect |
| unit_of_work / ingress_result(IngressKey) → IngressResult | Embedded transaction below; remote `GET /v1/messaging/ingress-results/{namespace}/{key}` with authenticated issuer and input-hash binding; P2b |
| list(PageRequest) → PageResult | `GET /v1/messaging/mail`, `GET /v1/chat/sessions`, existing session messages/participants, and control/capture paths below; P2/P3/P5/P7 |
| session(session_id), create_session(SessionCreate) → SessionView | existing session ID remains the handle; additive managed create/get on `/v1/chat/sessions`; P3/P4/P5 |
| change_membership(SignedArtifact of MembershipIntent) → SessionView | `POST /v1/chat/sessions/{id}/policy`; P4/P5; includes consent, delegation, succession and interval grants |
| checkpoint(SignedArtifact of CheckpointIntent) → signed CheckpointReceipt or NarrowStopAck | existing proposed `POST .../{id}/export-checkpoints`; P7 |
| checkpoint_receipt(session,transition) → signed original CheckpointReceipt | `GET .../{id}/export-checkpoints/{transition}`; P7, explicit control-history grant |
| message_acceptance(session,message) → signed MessageAcceptance | `GET .../{id}/messages/{message}/acceptance`; P7, message-interval grant |
| verify_presence(SignedArtifact of PresenceIntent) → VerifiedPresence | public verifier library for native suppression only; P8; Cloud owns its registration API |
| verify_presence_binding(SignedArtifact of PresenceBindingIntent) → VerifiedPresenceBinding | distinct public verifier for shared/dedicated bind/rebind/unbind; P8 public proof verification + C1/C2 private resource/CAS; native suppression approval never authorizes this call |
| native_operation(SignedArtifact of NativeOperationRequest) → signed NativeOperation | `POST /v1/chat/sessions/{id}/native-operations`; N1 |
| commit_native_reply(SignedArtifact of NativeReply) → AcceptedSend | `POST /v1/chat/sessions/{id}/native-replies`; N1 uses the same P2b/P7 acceptance, no unsigned guest echo |

C0 itself needs only published acfn `AttachmentDescriptor`; its platform events,
locators and `ChannelAttachment`/authenticated fetch stay private. C1–C3 obtain
all public values above or through existing acfn stage/bind/read/delete/capability
ports in [attachments](attachments.md), `aweb.attachments` and
`aweb.attachment_service`. No private OSS table name or hosted insert callback
is part of this seam. New port implementations cannot call an existing private
insert path without supplying the public transaction/authorization semantics.

### Identity, custody and enumeration

`ResolveRequest` has exactly one selector alternative: `{version,team_id,selector}`
for a selected-team alias, or `{version,session_id,participant}` for an exact typed
participant in an already authorized session. Mixed or partial alternatives
refuse. Session-only lookup requires no invented team membership, filler team ID
or alias; current session authorization and independent identity/bridge proof
suffice, including for bridged guests. Result actor/team IDs are omitted where
inapplicable. Authenticated human+team → actor in the alias lane is the existing
custody/access authority's job, not arbitrary roster-DID substitution. `AuthorityFacts` returns immutable native/guest principal,
current signing key, optional immutable actor/team IDs where applicable, pinned
service/audience, active/access/inbound verdict,
actual custody, confidentiality, authorization revision and capabilities. Key
assertions retain their original identity signatures. Missing assertion prevents
explicit encryption; an owner/controller credential cannot substitute for it.
Grant/membership/profile consent restrictions remain in force. No public human
address is minted and arbitrary bare-DID first contact remains refused.

For native authors, verification means existing identity/recipient/session
verification. For bridged authors, `AuthorProjection` always has
`author_assurance=platform_attested`, `trust_status=external_untrusted`,
`verified=false`; `signer_verified` describes the independently checked bridge.
A linked human uses their existing native actor only under actual custody and
current ingress/account/org/access/activation authority. Anonymous observations
cannot choose that actor. One session has one chosen author per human.

Enumeration must cover every authorized mail thread and chat session, not just
one dashboard pair. `PageRequest.resource` chooses mail/sessions/messages/
participants/policy_chain/checkpoints/acceptances; session resources require its
exact ID. `PageResult.items` uses existing public mail/message representations,
SessionView, typed participant refs, signed control records or signed original
receipts respectively; it never embeds a private row or provider projection.
For an individual message use the existing mail/chat message GET contract; exact
preserved envelope and signed/decrypted provenance remain authoritative.

Pages limit 1–200 (default 100 at HTTP), bind encrypted/server-side opaque cursors
to viewer/session/resource, authorization revision and committed upper bound.
Filter authorization before pagination, recheck every page/cache/direct read and
reject stale cursors; no excluded-message stubs/IDs/hashes are returned. Messages
are ordered by authoritative committed acceptance, not source timestamps. Reading
metadata does not mark read or emit wakes; existing explicit participant-authorized
read acknowledgments remain separate. No menu, hidden insert, pair-only list or
private route workaround satisfies C3/R-UI enumeration.

### Embedded prepared send and idempotency

`prepare` performs bounded signature/key/content/capability verification outside
the transaction and preserves exact author bytes, UUID, kind, session and group
head. Native preparation requires exact resolved target facts; managed-session
preparation instead requires its protected group context and no pair target.
`PreparedSend` includes checked author assurance, recipient facts, validated acfn
attachment refs and protected policy head, with a service-retained preparation ID, envelope
hash, authority revision and expiry; that ID is not a bearer authorization.
The implementation binds it to verified caller, immutable content and intended
recipient/session. Caller-supplied fields cannot override retained preparation.
After preparation loss it is safe to prepare the same original envelope again;
acceptance replay still uses the same message ID and bytes.

```python
prepared = await service.prepare(auth, request)
async with service.unit_of_work(auth) as uow:
    previous = await uow.claim_ingress(ingress_key)
    if previous is not None:
        result = previous                   # no new send, sequence, wake or charge
    else:
        accepted = await uow.accept(prepared)
        result = ingress_result(ingress_key, accepted, caller_result)
        await own_ingress_repository.store(uow.transaction, result)
        await uow.finish_ingress(result)
# Context exit committed; result/receipt may now be returned. Durable publisher
# sees only committed mutation intents; no manual pre-commit notification call.
```

The service owns one supported asyncpg/PostgreSQL transaction and exposes that
exact connection for the embedding's **own** tables. The embedding cannot read
OSS tables, independently commit, run network operations while holding session
locks or publish events directly. `claim_ingress` serializes
`(authenticated issuer, namespace, key)` with immutable input hash. Exact retries
return the original committed `IngressResult` (including original signed receipt
and caller result); conflicting hash/bytes/message kind or UUID refuses. New
claims remain transaction-local, not a lasting lease. Unfinished claims,
exceptions or failure in either message/result write roll back all effects.
`finish_ingress` requires the same claimed key/input and its accepted envelope;
it cannot change an existing result. The caller's result is bounded canonical
JSON, local/issuer-only, never public message content or a general read grant.

`accept` revalidates current caller/key/grant/custody/recipient/session authority
under the same session lock as membership/checkpoints. It captures the current
head and exact audience in that transaction; stale signed group context refuses
for explicit recomposition. Message, original acceptance/ingress receipt, caller
result, attachments binding, logical usage and durable mutation/outbox intents
commit or roll back together. Notifications/SSE/wakes run from committed outbox
state after commit, with durable retry after a crash. At-least-once event hints
are allowed; no duplicate logical message/charge or native runtime execution is
inferred from the event count. Never publish a provisional receipt before commit.

These are interface obligations for P2b/P7, not transaction tests claimed by P0.
No migration is applied now. P2b owns any next ordered generic ingress-result/
outbox migration; later M-P3/P4/P5/P7/P9 allocate their next actual SQL numbers.

Remote HTTP cannot join a Cloud database transaction. It prepares/sends the
original envelope with fixed message UUID through existing native HTTP send
paths (managed session send in P3/P4), durably records its local intent first,
and recovers the original receipt using stable IDs and public acceptance/ingress
reads. Idempotency request headers are `X-AWEB-Ingress-Namespace`,
`X-AWEB-Ingress-Key`, `X-AWEB-Ingress-Input-Hash`; the authenticated issuer is
never taken from a header. This is durable reconciliation, **not cross-DB
atomicity**. A timeout after possible acceptance stays unresolved until lookup or
an exact retry proves the result. Changed bytes never get a fresh UUID to force
success. Public native acceptance retains current receiver-wide replay rules.

## Membership, history and checkpoint records

`MembershipIntent` signs session ID, operation ID/type, epoch, previous record
hash, exact subjects, complete resulting `PolicyState`, consents, audience,
signer/key and freshness. Creation starts epoch0 with zero previous hash;
continuations increase epoch exactly once and name the verified preceding head.
The next head is the SHA256 of the canonical signed **payload**; retain its
signature and independently validated identity/authority proof alongside it.
Checkpoint intents are control-chain entries too; their original service receipt
records the resulting epoch/head. A timestamp is not a serialization boundary.

`ManagedPlaintext` is the explicitly negotiated plaintext chat shape, not a
native-author envelope with an unsigned guest sidecar. Its signature binds the
full GroupContext, identical message/session IDs, typed recipient set, body,
reply linkage, optional via, actual signer/key and timestamp. Derive the exact
recipients from the verified policy; do not accept an omitted bridge or hidden
sub-audience. For guest authors only their admitted bridge signs, with the exact
subject bound in GroupContext. Native authors sign as themselves. Managed group
encryption and historical re-share remain refused pending their annexes; this
plaintext profile does not assert an encrypted-v2 extension or add plaintext
attachments to acfn.

The complete state contains owner, members and their consent IDs/admission epochs,
bounded delegations, exact interval grants, admitted bridges/platforms/guest limits,
confidentiality, fixed join-forward/shared-control-history modes, authority mode,
service binding and advertised freshness limits. Bridge admission is not implicit
in a guest observation. A valid native encryption assertion binds each native or
bridge wrap key; subjects sharing a bridge key retain distinct authorization.
A server-readable authority mode is explicitly labelled and cannot claim E2EE.

`AdmissionConsent` signs the current preceding `membership_hash`, operation and
consent IDs, subject, service audience, proposed policy hash, J9 notice and
confidentiality plus freshness. `policy_hash` is SHA256 of canonical
`{session_id,operation_id,operation,subjects,state}` from the proposed intent.
State uses consent **IDs**, not signature hashes, so computing this commitment
has no circular dependency on the consent signatures. Consent cannot authorize
another policy/audience by swapping the signature's wrapper. History grants
carry these consent IDs and exact `(after_seq,through_seq]` intervals. Creation
and every add/rejoin require independently checked recipient inbound consent.

Every sender verifies the complete owner/delegate chain from independently
verified creation before deriving recipients/wraps. Current authority freshness,
no forks/replayed old records/stale epoch, exact delegated operation/scope and
recipient consent are required; all additions reach members before new content.
A delegated bridge admission may touch only authorized bridge/subject/platform
scope and guest limit, never native identity keys or team membership. Leaving is
self-only; successor transfer requires the outgoing owner and admitted consenting
successor. Without it, owner leave/removal/revocation/unavailability freezes
future sends/wraps/management visibly; retained authorized history remains.

`shared_control_history_v1` grants consenting current members the original chain
including pre-join/gap membership identities, removals, checkpoint identifiers and
global counters. It grants no excluded message IDs/hashes/content/attachments.
Removal ends future control access; a bounded historical grant sees only its
ending control head. Rejoin renews control disclosure and creates a new message
interval, not gap access. No redacted signed chain or concealed global-counter
claim is permitted. The unselected snapshot alternative is not implemented.

`CheckpointIntent`, `CheckpointReceipt`, `ExportCapture`, `MessageAcceptance`
implement the [checkpoint contract](human-channels-contract-proposal.md#public-export-checkpoint-acceptance-capture-and-read-contract).
Owner activation/widening has expected head/generation/digest CAS; own-stream
bridge/independent revoker pause/revoke omits those head fields and needs no read
grant. It cannot activate/resume/widen; revocation is terminal. A narrower lacking
control-history access receives only signed `NarrowStopAck`, no sequence/head.
Authorized exact retry can recover the old receipt without reactivation; changed
bytes, stale CAS or tombstoned execution refuse before new effects.

Managed messages and controls serialize under one commit fence; checkpoint at
sequence s applies only after s. Capture signs original message envelope hash,
accepted epoch/head and per-stream generation/digest/transition/checkpoint/state.
No checkpoint-bound capture applies outside its acceptance range. `legacy_unknown`
contains no invented order/exports or eligibility. Paused/revoked/absent streams
stay ineligible; later settings cannot reclassify them. The bound service signs
these attestations independently of author proof. Policy-chain/checkpoint reads
use the control grant; acceptance pages/direct reads use authorized message
intervals. A narrow stop confers neither grant.

## Presence and native operation records

`PresenceIntent` binds register/replace/remove, exact typed subject, platform,
platform/session scope, native mode, service audience, expected generation,
request ID, signer/key, authorization lane and freshness. Subject signing and
independently verified owner signing are distinct; owner lane includes original
ownership proof, never a caller-asserted owner string. `OwnershipProof` is the
configured ownership authority's signed assertion of exact subject/owner,
platform/scope/permitted operations/audience/revision/freshness. Only an
independently pinned authority for that subject/service may issue it. It grants
presence administration only, not native signing or team-controller authority. Verification returns
`VerifiedPresence` for that exact request/head/revision only; Cloud persists
settings/CAS and rechecks ownership before applying it. It is no bearer grant.
Owner transfer/revocation invalidates future operations. Platform-wide suppression
wins overlapping scopes; scoped mixed native/dedicated operation remains disabled
pending explicit Juan scope approval. Stale health never enables fallback;
`native_unavailable` is visible delivery failure, not silent loss.

Shared/dedicated bindings use **separate** `PresenceBindingIntent`,
`BindingOwnershipProof` and `VerifiedPresenceBinding` families. The intent signs
bind/rebind/unbind, exact subject, `mode=shared|dedicated`, platform/scope,
blinded `binding_digest`, service audience, expected generation, request ID,
subject/owner authorization lane, signer/key and freshness. The digest commits
to the exact private binding/presence target without exposing a bot/account ID
or credential. Both lanes recheck current rights; owner lane requires a signed
BindingOwnershipProof from the independently pinned ownership authority for that
subject/service, matching owner, mode, platform/scope, operation and freshness.
Native OwnershipProof/PresenceIntent payloads have different signed versions and
cannot authorize this verifier; the inverse conversion is equally refused.

`verify_presence_binding` returns only the same purpose/mode/scope/digest and
verified revision/request/hash/expiry. It grants no native suppression, message
authority, key custody, audience expansion or team role. C1/C2 separately verify
actual platform resource ownership/intake and commit the exact private binding
at that expected generation; token possession never replaces subject/owner
approval, nor does a valid public intent prove token/resource ownership.
Rebinding cancels pending old routes and obeys existing consent/checkpoint rules.

`NativeOperationRequest` signs claim/start/renew/complete/reconcile/resolve plus
stable canonical **aweb** input message ID/hash, agent/session, owner generation
and expected fence. Source platform IDs never enter these public records.
`NativeOperation` is a service-signed state: claimed → started → completed, or
outcome_unknown/blocked. Reassignment before started advances a durable fence;
all writes/replies/transport intents require its current value. Start is durable
before model/tools. After started, lease expiry/crash never implies safe retry.
Resolve requires explicit verified owner/operator decision/evidence; resume only
from a proven safe checkpoint or known idempotent effect. Unknown prior external
effects remain blocked; explicit duplicate-risk retry is recorded as such.

`NativeReply` is signed by the actual agent, binds operation/fence/slot and exact
original signed chat envelope/UUID/hash; the authority checks both. One reply slot
commits its message and outbox atomically, replaying the original bytes thereafter.
A bridge-observed bot post is not native output. Reply correlation is an aweb
message ID; private provider delivery/part refs remain at the adapter. These rules
promise one input owner and deduplicated committed replies, never exactly-once
model/tool execution. Persist budgets/circuit breakers across restart; fresh bot
IDs do not bypass them. Owner-authorized recovery is distinct from bot reset.

## Scope of verification now

P0 tests each new DTO family's exact canonical bytes/hash/signature and structural
refusal neighbors in Python and Go. Cryptographic vectors authenticate only the
public test key, not a real membership/ownership decision. Existing native
identity/E2EE vector tests provide compatibility neighbors. P1/P2/P3/P4/P5/P7/P8/
N1 own the real service, transaction and runtime journeys before capabilities can
be emitted. The X-E2/X-GF annexes remain unavailable until their separately bounded
spikes and Athena review. No active identity-path change, migration, service
implementation or Cloud table access is included in this P0 definition change.
