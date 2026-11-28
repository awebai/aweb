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

`aw` refuses a mail or chat send to an alias when recipient lookup fails,
instead of passing the bare alias to the server without confirming its
recipient.

Address discovery distinguishes not requested, observed empty, verified value,
and unavailable evidence. A failed address read is optional UNKNOWN enrichment,
not proof that an identity has no address: it never clears a stored binding,
caches an empty result, or changes the sender's From. Identity displays report
unknown when discovery is unavailable. Independent DID/key authentication and
membership checks still apply.

Sender, From and routing uses require address evidence. A stored binding
already verified for the authenticated current key supplies that evidence,
including a verified empty address, which still permits addressless sending
during a registry outage. Only when no such binding is available and discovery
fails does the operation refuse with HTTP 503 `address_evidence_unavailable`,
before delivery or other effects. Conflicting stored bindings do not select a
different From. DID-only reads do not acquire this address dependency.

Global recipients expose an explicit delivery-time `inbound_mode`. It is an
identity property across every non-deleted row for the exact `did:aw`, including
retired or inactive memberships. The effective policy is the strictest valid
mode present: `contacts_only`, then `team_and_contacts`, then `open`. Any missing
or invalid row policy fails closed with the migration-required refusal. A mode
change by the identity updates all those rows; a new membership inherits the
current effective mode. Team ownership alone does not authorize a policy change.
A global-scope row without a raw `did:aw` has no link to other memberships:
its policy is its own explicit mode. Migration 056 backfills legacy NULL rows
to `contacts_only` and preserves explicitly selected policies. The old rows
were closed to delivery and their original policy cannot be recovered.
This does not grant it authority to set an identity-wide policy.
The identity-signed "my inbound mode" route uses the authenticated, AWID-bound
`did:aw` for the change; a stored membership claim cannot select its write scope.

`aweb.messaging.delivery_policy.authorize_delivery` owns this rule for native
and federated sends. Same-team admission intersects all current active team
memberships of both verified identities through the native member owner. A
caller-selected team, retired row, superseded team key or revoked admitting
certificate adds no membership. The same native certificate-standing owner used
by authentication checks revocation and the staged registration requirement.
Address residence and human classification remain independent of membership.
Exact active identity-contact matching has one owner and retains contact locks
through an existing delivery transaction. Send refusals end with a concrete
recovery sentence. A named `recipient_policy_rejected` refusal retains that code
as `reason` in both HTTP and MCP, beside its actionable human detail. Federation
retains its stable reason separately from that human detail.

Native sends keep their current policy decision through the message commit.
Mail rechecks admission inside its new-thread or continuation transaction.
Local chat locks the identity's policy rows and rechecks the same shared rule
inside the transaction that stores the session/message. Registry contact
resolution and host callbacks run after that transaction commits; a refused
native chat leaves no newly created session or conversation behind.

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
   Plaintext send admission also verifies the original signed bytes under the
   authenticated sender's current signing key before storing any message or
   conversation effects. Optional recipient claims remain optional for released
   clients; supplied claims must match the resolved recipient. Stored rows can
   predate this admission check. Readers independently verify their original
   signature and report `failed` for an invalid signature or `unverified` when
   signed bytes or a signature are absent; storage alone never establishes
   `verified`. These checks preserve the original signed bytes and conversation
   ID.
   A thread participant is the identity (`did:aw` for a global identity), not
   a per-team actor. The address selects identity and route, not a membership.
   Originating address sends leave recipient membership metadata null; a team
   alias may retain its selected member. Receiving services retain known native
   row references for storage and delivery events, without identity/team authority.
   Continuations preserve known references; access still compares participant DIDs.
   Native admission's actor/team authority uses a separate current-membership
   projection for the target identity in the authenticated endpoint team.
5. Federation delivery uses the resolved delivery origin and the target identity
   binding. The recipient server re-resolves the target address/key and fails
   closed on mismatch. The sending server connects only to an `https` delivery
   origin whose host resolves to public addresses (or private ones, for an
   origin its operator lists in `AWEB_FEDERATION_PRIVATE_DELIVERY_ORIGINS`), at
   the address it checked, and does not follow redirects. A server whose
   operator set `AWEB_FEDERATION_OUTBOUND` to `off`, or to a list of origins
   that does not include this one, refuses the send with `403` naming the
   setting before resolving or connecting. A failed delivery
   returns the status and one fixed reason (`delivery_origin_refused`,
   `delivery_address_refused`, `delivery_origin_unreachable`,
   `delivery_timeout`, `delivery_unavailable`, `HTTP <status>`, or the
   recipient server's typed
   federation `reason`); other response text is not relayed.

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

Inbound and outbound federation first-contact HTTP source budgets share
`aweb.client_address.request_client_address`. Mounted MCP sends and contact
lookups use `mcp:<authenticated sender DID>` instead, so users behind one proxy
retain independent budgets even without a trusted client-address header.
The HTTP source budget uses the socket peer by default and
ignores forwarded client-address headers. A deployment behind a trusted proxy
can set `AWEB_CLIENT_ADDRESS_HEADER` to the header carrying the client address.
The shared `aweb_naapp.client_identity.ClientIdentity` resolver uses its final
comma-separated entry; an absent or blank final entry falls back to the peer.
The proxy must strip or overwrite client-supplied values, and direct untrusted
access to the server must be blocked. The final entry represents the client
when exactly one trusted proxy appends to the header. With a proxy chain,
configure a dedicated header the trusted edge overwrites with the client
address, rather than a header every hop appends to.

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
Generic local key/membership selection still requires the verified projection
marker. After an address has independently resolved to its canonical `did:aw`
and current key, locality is residence of that exact DID, independent of a
membership's superseded key or invalidated marker. The address resolution
supplies the recipient key and route; this residence lookup supplies no actor
or team authority and does not restore a verification marker.

If that exact identity is not resident and the resolved delivery origin is this
server's configured public origin (including any accepted ingress origins), mail
and chat refuse with
`recipient_identity_not_found` (404, non-retryable), before federation. The
caller is directed to ask the recipient or operator to check the address and
messaging setup. This also applies to stored routes and route refreshes: refuse
before persisting an own-origin remote route or retrying federation. A resident
identity is handled locally with the same delivery-time policy. For a global
stored route, the historical participant key is not current binding evidence:
local handoff requires current AWID binding and validates the signed/encrypted
target against it before delivery. This validation does not rewrite participant
routes or membership verification markers; unavailable evidence refuses with
503. A matching alias
for a different DID does not supply residence; a foreign-origin route remains
eligible for federation.

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

For native signed mail, an exact retry whose identical signed payload is
already stored returns that stored result before applying the attestation age
limit. Signature, sender/recipient binding, encryption and current delivery
admission checks still precede returning the stored answer. An exact encrypted
artifact may identify its own recorded mail target when the outer selector
carries only the key and its protected routing binds the recorded stable
identity. This lookup locates only that accepted target, supplies no new-send
authority, and does not skip ordinary encryption freshness or current policy.
A stored answer is not a new
attestation; a new message still requires a timestamp within the accepted skew.
Age refusal is HTTP 422 with the existing human `detail` plus a signing action
and additive `X-AWEB-Error-Code: message_timestamp_outside_skew` header. Shape
errors do not carry that age code. A client may re-sign a new submission after
that specific age refusal; it must retain the original payload for exact retry.

The same plaintext age exemption applies to an exact stored outbound mail or
chat projection and to an established federation ingress receipt. The outbound
projection must match the sender, conversation, message ID, signature and signed
payload; the receiver requires its identical canonical envelope receipt. The
signature, recipient binding and current authority checks still run. An outbound
mail retry retains the remote call to recover its original established response,
then returns the existing local projection without another send event. Chat
create and continuation return the identical accepted message from local storage
after current admission; they do not repeat session, wait, contact or event effects.
If an exact chat artifact's requested participants differ from the stored
conversation, the caller is told to retry the original conversation and recipient
identities unchanged. It must not choose a new message ID merely to recover a
lost answer: that would submit another message. Choosing a new ID is appropriate
only when intentionally sending a different signed artifact.
A departed party is removed from the session's participants. A plaintext
continuation compares the recorded parties that remain. A named retry can recognize an original local
`did:key` party as the currently admitted global `did:aw` only when that identity's
current key is still the exact recorded key; this acknowledgement does not rewrite
participants or grant another membership. Signature and current admission checks
remain in front of the answer; encrypted integrity and freshness checks are unchanged.
Inside the existing encrypted window an exact encrypted chat retry also returns
its stored message; it does not gain the plaintext age exemption. A changed
artifact or missing proof is a new attestation and takes the age check, including
a changed artifact reusing an accepted UUID. The encrypted ingestion window is
unchanged. Native, outbound and attachment retries use the same stored-artifact
comparison; an established federation receipt additionally matches its complete
outer envelope hash and kind. Ingress and Phase B share that receipt identity
check, and Phase B binds its canonical metadata under current authority. Stored
proof does not by itself mean signature verification or current admission.
This is Antares ruling69b3a50a (relay a491ccc8).


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
HTTP and MCP inbox and contact-mail reads use this same projection owner after
participant authorization; MCP carries the stored delivery team and sender ID
rather than selecting a different membership row. Incoming attribution lives
in `aweb.messaging.mail_attribution`. Event wakes consume its preloaded
thread-evidence form, retaining the establishment/reconcile snapshot rather
than querying succession tables on every tick.

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

The [`sender-standing-v1` vector](../test-vectors/trust/sender-standing-v1.json)
pins the same registered, unregistered and revoked evidence in the native
Python server, Python AWID certificate helper and Go registry status reader.
Go and channel-core also consume the resulting server projection and check
the received-message outcomes in the matrix below. Channel-core has no
certificate on these reads and uses the delivery server's standing
attestation. Real two-team mail tests cover plaintext and encrypted-v2,
including CLI reads, channel presentation and wake presentation.

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
