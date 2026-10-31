# Identity and Messaging Contract

Status: **canonical current cross-component protocol** between AWID, `aw`, and
the aweb server for identity-scoped mail and chat. It follows the global/local model
in [`global-local-identity-routing.md`](global-local-identity-routing.md).

## Scope and document authority

This contract governs identity binding, first-contact routing, delivery policy,
stored participant routes, and federation compatibility. It does not restate
user commands, presentation acknowledgement, event reconnect, or cryptographic
envelope rules:

- [`mail-and-chat.md`](mail-and-chat.md) is the current user guide for durable
  mail, chat, reply, and read state.
- [`receiving-events.md`](receiving-events.md) governs wake, presentation, and
  reconnect behavior.
- [`e2e-messaging-contract.md`](e2e-messaging-contract.md) governs encrypted
  content, custody, and downgrade rules.
- [`messaging-contract-matrix.md`](messaging-contract-matrix.md) is a subordinate
  maintainer test inventory and cannot override this contract.
- CLI and MCP references own command/tool inventory; they do not redefine the
  protocol authority above.

## Authority Boundaries

| Component | Authority | Not authority |
|-----------|-----------|---------------|
| awid | Global truth for `did:aw`, current `did:key`, DID logs, namespace address rows, address-route origins, team public keys, and certificate revocation events. | Message delivery, local aliases, mailbox state, private key custody, active membership oracle, or bare-`did:aw` delivery route. |
| Self-custodial client | Holds the identity private key, signs message envelopes, and can bind a recipient address to the resolved `did:aw` and current `did:key`. | Namespace address assignment unless it also holds the namespace controller key. |
| Hosted signer | Holds the private key for a custodial identity and signs the same message envelopes as a self-custodial client. | A separate trust model; hosted identities must satisfy this same contract. |
| aweb server | Authenticates transport requests, routes and stores mail/chat, validates signed recipient bindings, and stores participant route state for continuations. | Registry authority, caller private-key authority, address reachability authority, or conversation-id-only routing authority. |
| Local route state | Stored participant/session route authority for local `did:key` continuations. | Global identity authority or first-contact authorization by itself. |

## Global And Local Identities

- **Global identity**: durable `did:aw` and AWID-registered current `did:key`.
  It may have zero, one, or many address aliases. Delivery routes belong to
  addresses, not to the identity row. An addressless global identity remains
  global but has no address-based first-contact route. Address-based first
  contact requires a concrete assigned address; identity registration does not.
- **Local identity**: `did:key` only, no AWID row, no `did:aw`, no stable/global
  ID, and no global first-contact address.

Team certificates remain valid for team membership, local ACLs, and certificate
verification flows. They are not an address reachability or message routing
oracle.

Global recipients expose an explicit delivery-time `inbound_mode`. It is an
identity property across every non-deleted row for the exact `did:aw`, including
retired or inactive memberships. The effective policy is the strictest valid
mode present: `contacts_only`, then `team_and_contacts`, then `open`. Any missing
or invalid row policy fails closed with the migration-required refusal. A mode
change by the identity updates all those rows; a new membership inherits the
current effective mode. Team ownership alone does not authorize a policy change.
A global-scope row without a raw `did:aw` has no link to other memberships:
its policy is its own explicit mode, with NULL or invalid still migration-required.
This does not grant it authority to set an identity-wide policy.
The identity-signed "my inbound mode" route uses the authenticated, AWID-bound
`did:aw` for the change; a stored membership claim cannot select its write scope.

The modes are:

- `open`: accept valid senders after address route and identity binding
  validation. User-facing label: **All**.
- `team_and_contacts`: after the same route and identity validation, accept
  verified same-team members or an exact active identity contact for the
  verified sender address. User-facing label: **Team and contacts**.
- `contacts_only`: after the same route and identity validation, accept only an
  exact active identity contact bound to the recipient, verified sender address,
  and sender `did:aw`. Verified team membership does not authorize delivery.
  User-facing label: **Contacts only**.

Rows without an explicit `inbound_mode` require migration and must fail with an
explicit migration-required diagnostic rather than silently widening to open.

An authenticated global subject participates as its `did:aw`; its current
`did:key` proves signatures and is not a second participant reference. Local
subjects participate as their literal `did:key`. Thread visibility, unread/ack
scope and continuation use that participant reference. Hosted plaintext signing
keeps the original key in the signed payload without replacing the participant
or stored author identity with that key.

Migration 045 normalizes historical participant keys to a global DID only from
an unambiguous current verified key binding. Duplicate participant rows merge
without losing join/read state; signed message identity fields remain unchanged.
The normalized participant retains its key as thread-local attribution evidence,
not as another participant authority. An ambiguous verified mapping aborts the
migration rather than guessing the owner.

Inside a thread, canonical participant membership authorizes exact message reads
as well as the whole thread. A message's original sender/recipient matches that
participant's canonical DID or its own `current_did_key` in that same thread.
Inbox, unread and acknowledgements use this attribution and exclude own sends;
acknowledgements remain incoming-only. There is no cross-thread key lookup.
Pre-thread messages keep literal-DID access. Older rotated keys not retained on
the participant remain readable through the thread, without unread attribution.

## Direct Address Send Protocol

For a send to a global address (`domain/name`):

1. The client/server classifies the target as a registry address, not a local
   alias.
2. AWID resolves the address to the target `did:aw`, current `did:key`, and
   address-route delivery origin. Legacy reachability metadata is not consulted
   as a resolver or authorization gate; non-neutral legacy rows are a migration
   state and fail closed until explicitly normalized.
3. The client signs the mail or chat payload, including the target address and
   resolved recipient identity binding (`to`, `to_stable_id`, `to_did`).
4. The aweb server authenticates the sender and validates that behavior-shaping
   outer fields match the signed payload.
   A thread participant is the identity (`did:aw` for a global identity), not
   a per-team actor. The address selects that identity and its route, never a
   different address from a membership projection. `agent_id` is nullable
   display/admission metadata: explicit-address participants leave it null;
   a team-scoped alias may record its selected membership. Read access and
   continuation compare participant DIDs, not actor IDs or address equality.
   Native admission's actor/team facts are a separate current membership
   projection for the target identity in the authenticated endpoint team.
5. Federation delivery uses the resolved delivery origin and the target identity
   binding. The recipient server re-resolves the target address/key and fails
   closed on mismatch.

Direct bare `did:aw` first-contact sends are unsupported: use a concrete
address (`domain/name`) or an existing conversation/session with stored route
state. Direct local `did:key` sends require stored route state; a bare
self-asserted `did:key -> origin` claim is not enough.

## Strict Cross-Registry Sender Authority

A receiving service keeps its configured home AWID client for its own
identities, teams, and ordinary same-registry reads. It does not widen that
client, use its fallback registry, or key a cache by bare `did:aw` when a global
sender's address belongs to another registry. `POST /v1/federation/messages` is
the single inbound route for plaintext-v1 and encrypted-v2. Cross-registry
ingress uses a separate strict external-address authority path:

1. Verify the preserved plaintext or encrypted-v2 message signature under the
   presented sender key before external DNS or HTTP work.
2. Extract authority from `signed_payload.from` for plaintext or
   `encrypted_envelope.from.address` for encrypted-v2. A wrapper address, when
   present, must canonicalize to exactly the protected address. A missing
   wrapper is filled only when the protected value is `domain/name`. Historical
   stored-route payloads with a protected DID retain no sender address and use
   only their exact stored participant locator. A sender-supplied registry URL
   is never authority and is not contacted.
3. Discover the external registry from the signed address's `_awid` DNS
   authority, fetch the exact namespace and address there, and require the DNS
   controller, namespace, address, stable `did:aw`, current `did:key`, and
   delivery origin to agree. Missing sender origin is derived from this verified
   evidence; a present origin must equal it.
4. Verify a genesis-anchored DID log, or an adjacent head extending the exact
   durable checkpoint. Degraded, unavailable, truncated, forked, or rollback
   evidence never authorizes delivery.
5. Commit the checkpoint and the complete address-authority cohort through
   fenced compare-and-swap in PostgreSQL before recipient policy or message
   effects are accepted.

A successful cohort may be reused for at most 60 seconds.
`AWEB_FEDERATION_AUTHORITY_REUSE_SECONDS` defaults to 60 and accepts only 1..60.
Expiry forces a complete DNS/namespace/address/key-or-log/origin read,
even while general caches remain live. This is a receiver reuse ceiling, not a
revocation, reassignment, rotation-detection, or global freshness SLA. A DNS or
registry authority that continues serving an old but cryptographically valid
state can suppress an unseen transition indefinitely; detecting that requires a
non-suppressible witness, transparency, or gossip mechanism outside this
protocol.

PostgreSQL is the shared authorization and coordination store for checkpoints,
cohorts, leases, fences, limits, and publication. Redis and process-local caches
cannot authorize or serve as an outage fallback. PostgreSQL coordination
failure therefore fails cross-registry ingress closed. A new address uses one
DNS discovery and one pinned authoritative HTTP chain. Shared failed reads
publish the same stable failure for five seconds; a wrong claimant cannot poison
valid evidence for a concurrent correct claim.

Same-registry outbound resolution first checks locally visible recipients before
registry resolution and keeps the signed address/DID/key/origin contract. A
client identity's configured registry is an explicit pin for its own address
domain. For a foreign first-contact address, the CLI and channel runtimes use
that domain's valid `_awid` record (including bounded parent inheritance) when
present; absence of a record, a DNS timeout, a temporary server failure, an
unreachable resolver, or connection-refused transport falls back to the
configured identity registry so private/offline deployments retain their
operator-selected path. Refused or malformed DNS responses and malformed or
ambiguous AWID records remain errors. This fallback
is outbound address resolution policy only: explicit registry pins on
namespace/team/address
administrative operations always win and never consult DNS, while strict
inbound federation authority retains its no-fallback rules above. First
contact checks target address, DID, current key, and origin. Stored continuation
requires exact active conversation/session participants and target current-key
compatibility. Local `did:key` continuation remains separate: it requires that
exact learned participant route, and supplied address/origin fields may only
equal it. Unknown local first contact and route injection fail closed. Target
registry or PostgreSQL/lease publication dependency failure uses
`federation_authority_coordination_unavailable` (503, retryable).

## Continuations

Conversation IDs are UX/thread/idempotency metadata. They are not routing or
authorization authority by themselves.

Mail/chat continuations must use stored participant/session route state:

- recipient identity (`did:aw` or local `did:key`),
- current `did:key` when global,
- address when present,
- delivery origin / transport hint.

Missing, stale, malformed, mismatched, or revoked route state fails closed.
Stored route state is not a policy bypass: continuations still apply the
recipient's current `inbound_mode` at delivery time.

For a signed mail continuation after key rotation, an unmarked local projection
may lack the current recipient binding. Verify the message signature before
using its recipient claims; its stable DID and any signed address must match the
stored participant exactly. If the gated projection cannot establish that signed
recipient, require current AWID binding evidence outside database transactions.
This context validates only the signature: delivery keeps the stored participant
agent ID, and neither routing facts nor verification markers are populated from
it. A mismatch refuses delivery; unavailable evidence returns 503.

Federation first-contact target validation checks the cached address binding
against the envelope's stable DID, current key and exact delivery origin. If
those facts do not validate, it reads the address once fresh and repeats the
same checks before refusing. Successful cached validation requires no extra
registry read. The refresh happens before database locks; unavailable evidence
returns retryable 503, while a fresh mismatch retains its specific refusal.
Local recipient selection still requires the verified projection marker.

## Receiver-Wide Replay And Contact Compatibility

Every accepted mail or chat message—local or federated, plaintext or encrypted—
claims one `message_ingress_receipts` row whose sole identity is `message_id`.
An exact federated retry with the same canonical signed/protected envelope and
metadata returns the stored established result without duplicating message,
conversation/session, participant, contact, route, or event effects. Local-path
receipts are `legacy_unreplayable`: they never authorize federation/cross-kind
replay and permanently block a later insert claim after message deletion, while
existing local API idempotency may still return its row before an insert.
Reusing the UUID with a different kind, sender, target, conversation/session,
signature, signed payload, or
protected encrypted bytes returns `federation_message_replay_conflict`.
Receipts survive ordinary message garbage collection.

Migration backfill marks historical rows whose exact original envelope cannot
be reconstructed as `legacy_unreplayable`; any attempt that reaches a new
receipt claim conflicts rather than being guessed idempotent. A historical
mail/chat UUID collision must stop migration for explicit operator repair. Security checkpoint/cohort
state may advance after valid authority even when policy rejects. Phase B
rechecks the committed checkpoint/cohort token under lock and current recipient
policy; its receipt, message/ciphertext metadata, conversation/session, both
participant stores, contact/route fields, chat read receipt, and event effects
commit atomically or not at all. Policy, storage, or hook failure rolls all of
those effects back and permits retry. The transaction also commits one durable
`federation_mutation_outbox` row; concurrent replay locks pending rows with
`FOR UPDATE SKIP LOCKED`. Publication
is at-least-once across a crash after Redis accepts but before PostgreSQL records
`delivered_at`.

For `contacts_only`, every sender (including a verified teammate), and for
`team_and_contacts`, every non-team sender, is authorized only by an exact active
contact bound to the recipient identity, canonical sender address, and sender
`did:aw`. Address-only legacy contacts are migration-required and inert for
cross-registry authorization until their owner explicitly binds them by exact
owner/contact/address compare-and-swap after fresh authority resolution through
`POST /v1/contacts/{contact_id}/bind`. Contact bindings are either all-null
legacy state or a complete `contact_did_aw`, `binding_controller_did`, and
`binding_accepted_at` tuple. Creating a new contact
is that explicit acceptance. Accepted global-to-global ingress atomically
creates an identity-bound sender contact only if no row occupies the exact
owner/address and never rewrites an existing legacy or differently bound row.
An in-place old-DID to new-DID replacement additionally requires exact old DID,
current strict new DID/controller evidence, a fresh controller-signed
old/new/address/timestamp announcement, `accept_reassignment=true`, an exact-old
compare-and-swap, and the authenticated recipient owner's explicit acceptance.
Address reassignment and remove/recreate never silently transfer the old contact
or conversation. Normal signing-key rotation that preserves the same `did:aw`
requires no contact reapproval; conversation continuity remains bound to its
participant DID.

## Federation Compatibility

Federation envelope version 1 has a bounded release-window tolerance for four
fields emitted by older servers:
`sender_active_team_id`, `sender_team_certificate`,
`target_address_lookup_authorization`, and `target_address_lookup_timestamp`.
New senders omit these fields. New receivers may accept them only as ignored,
deprecated input so mixed-version public/global federation does not fail at
schema validation. They must not affect routing, lookup, authorization, policy,
recipient selection, or signed-payload validation.

Federated delivery responses must be uncompressed. Senders must request
`Accept-Encoding: identity` and reject any non-identity `Content-Encoding`.
Federation peers are untrusted by construction; decompression before enforcing
the response-size bound is a memory-exhaustion primitive on the trust path. A
peer or intermediary that compresses despite the identity request is therefore
incompatible with the federation v1 transport contract.

Failure responses use the complete stable reason/status/retryability vocabulary
in the generated [federation error reference](federation-error-reference.md).
The JSON body always carries matching `detail` and `reason`, plus `retryable`
and `correlation_id`; only rate limiting emits `Retry-After: 1`.

## Forbidden Shortcuts

- Do not route global direct-address mail or chat solely because a matching local
  row exists.
- Do not pass a caller `did:key`, team certificate, or forwarded lookup header to
  AWID as private address-read authority.
- Do not treat address reachability, `visible_to_team_id`, contact membership,
  or conversation ID as routing authority. Contacts authorize only the explicit
  delivery-time `team_and_contacts`/`contacts_only`/local-contact gate and never create a
  route. Verified team membership also authorizes `team_and_contacts`, but does
  not create routes.
- Do not use stale cache entries as evidence for a recipient binding.
- Do not infer a canonical sender address by listing all addresses for a
  `did:aw`; use the selected identity address for that context.
- Do not select external sender authority from the receiver's home registry,
  general cache, TOFU pin, wrapper registry hint, or bare `did:aw`.
- Do not treat the 60-second receiver reuse ceiling as a source freshness or
  revocation guarantee.
- Do not authorize a legacy address-only contact, transfer a contact on address
  reassignment, key replay by composite fields, or downgrade encrypted-v2
  delivery to plaintext after an encryption assertion failure.

## Test And Release Gates

Changes touching identity resolution, address lookup, mail, chat, hosted custody,
certificates, local aliases, or registry caching must prove:

- global direct-address first contact succeeds through AWID resolution,
- local identity continuations use stored route state and fail closed without it,
- bare external `did:aw` first-contact fails closed without stored route state,
- stale local rows and conversation IDs do not bypass AWID or stored routes,
- federation verifies target identity and delivery-origin binding,
- an external sender is resolved through signed-address-selected strict
  authority independently of the receiver's home registry,
- receiver cohort expiry performs a full reread while source suppression remains
  an explicit non-SLA residual,
- receiver-wide message-id receipts return exact federated replay results,
  reject cross-kind/changed-envelope claims, and keep local/historical receipts
  `legacy_unreplayable` without removing existing local per-path idempotency,
- legacy address-only contacts remain inert until explicit identity binding and
  controller-proved replacement requires recipient acceptance, and
- every stable federation error and encrypted-v2 no-downgrade branch matches the
  generated error reference.

## Received global senders without an address

A received mail or chat message may be signed by a global `did:aw` identity
with no address. Its team display alias is not a public address and is never
expanded to select registry authority. This does not enable bare-`did:aw`
first-contact sending.

HTTP and MCP mail/chat preserve an empty sender address when the authenticated
actor has `identity_scope=global`, a `did:aw`, and no address. Team membership,
team ID and display alias remain intact; they do not manufacture an address.
Chat read projections preserve the same empty address and keep the member name
in `from_agent`. An explicit global address is unchanged. For compatibility
with released clients, LOCAL actors and adapters that omit identity scope keep
the existing team-scoped routing label in this release. Removing that legacy
label requires a separate released-client review.

Embedded adapters constructing MCP `AuthContext` should provide the optional
`identity_scope` from their authenticated certificate/member projection.
`mcp_messaging_auth` preserves it along with the delivery team; clearing team
context to suppress an address is not supported.

Participant-authorized reads include a separate `sender_membership` projection
computed at read time for the stored sender in the stored delivery team. The
server derives the stable ID from its certificate-derived member row. `active`
requires an active, nondeleted member with a certificate that is not revoked
under the existing revocation check. A revoked or inactive member is
`inactive`; missing provenance or unavailable revocation authority is `unknown`.
The projection includes humans without publishing them in the agent roster.
Encrypted-envelope normalization never overwrites this server-attested field.

For an addressless global sender, the client reports `verified` only when the
message signature verifies, recipient binding passes, the projection is active
and binds the signed stable ID to the selected delivery team, and the public
DID key/log read at that team's registry establishes that the signer is the
current key. Identity proof comes from AWID; current membership comes from the
delivery server. Self-custodial and grant recipients use the same checks. A
grant recipient binds delivery to its resident identity, not its session key.
No private AWID member read or additional custody permission is needed.

The registry is selected from the delivery team's configuration/authority,
never a sender-supplied URL, alias, or unrelated global identity's home registry.
Key/log caches and durable receive checkpoints are scoped by registry and stable
ID. Existing rotation/log and anti-rollback checks apply. A wrong key or inactive
membership gives `identity_mismatch`; an unavailable registry, missing projection
(including old servers), or unknown membership gives `verification_stale`.
Neither a failed signature nor an existing recipient mismatch is promoted.

Own-authored mail read through the server-authorized sender-visible route keeps
its existing authorship result when the signed stable ID is the client's own
and the signature uses its current key (the resident key for a grant client).
A claimed stable ID alone never establishes authorship; incoming reads still
require the received-sender proof above.


## Received cross-team local senders

A local outbound sender remains a `did:key` identity with no AWID row. On a
participant-authorized read, the authenticated delivery server vouches for the
stored sender's membership in the **sender's** team, which can differ from the
recipient's selected team. This receive attestation does not authorize first
contact or create a global address; the delivery service still validates routing
under the local outbound and stored-return-route rules above.

For that cross-team local receive path, Go and channel-core require a valid
message signature and recipient binding, no signed stable ID, an active
`sender_membership` with empty `member_did_aw`, and agreement between the
server-projected sender DID and the signed `did:key`. Any protected sender
`team_id` must equal the attested team. A signed legacy namespace/member label
must name that team's namespace (or its explicit team ID). The label remains a
display/routing label: neither client looks up its address or alias or creates a
global address pin. Same-team locals retain the authenticated live roster path;
global `did:aw` senders retain their existing key/log and address checks.

Both clients implement this decision matrix, exercised by
`TestReceivedLocalSenderMatrix` and channel-core's `cross-team received local
sender` tests. Real two-team mail tests cover a global resident grant, plaintext
and encrypted-v2, CLI reads, channel presentation and wake presentation.

| Evidence after signature and recipient checks | Result |
| --- | --- |
| Active local membership, agreeing protected team/label and projected DID | `verified` |
| Missing/unknown membership or missing projected DID | `verification_stale` |
| Inactive membership, nonempty member stable ID, contradictory team/label or projected DID | `identity_mismatch` |
| Failed signature or recipient mismatch | Preserve failure; never promote |

The encrypted sender's `from.team_id` is protected envelope data, not membership
authority. The read-time server field supplies membership authority and survives
decryption separately. Old servers lacking that field cannot establish this
cross-team local receive proof and report `verification_stale` when the protected
sender reference establishes a cross-team sender.

## Negotiated human-channel definitions (P0)

[Human channels contract v1](human-channels-contract-v1.md) defines the new closed
DTOs, exact signed bytes, capability/refusal boundaries and public prepared-send/
unit-of-work port. It adds no accepted endpoint or identity path in P0. Existing
native mail/chat identity, current-key, recipient, first-contact and receiver-wide
replay rules above remain binding. A valid bridge signer never authenticates an
external subject as a native author; typed participation requires the explicitly
negotiated session profile. Owner/controller authority is not native key custody.
