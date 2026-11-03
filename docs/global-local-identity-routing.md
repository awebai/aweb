# Global/local identity routing

Status: **current supporting protocol** for shipped route-level global/local
messaging behavior.

The canonical concepts live in [identity.md](identity.md). The normative
cross-component summary lives in
[identity-messaging-contract.md](identity-messaging-contract.md). This page
explains the route model and clearly separates current behavior from legacy
compatibility input.

## Identities and routes are different facts

A **global identity** has a stable `did:aw`, a current `did:key`, and zero or
more addresses. A **local identity** has only a `did:key` and team/service-local
routing state.

A global `did:aw` identifies one actual key-holding principal. It may rotate its
current key, hold several addresses, and join several teams, but it must not be
used to represent several independently routable agents.

An address such as `example.com/alice` is a first-contact route to a global
identity. A bare `did:aw` is an identity binding, not a delivery route. Multiple
addresses may resolve to the same `did:aw`; those addresses are handles for the
same principal and may carry different route origins.

A local `did:key` is not globally discoverable. A remote service can reply only
when an authenticated earlier message established a valid learned return route.

## Authority boundaries

- **AWID** is authoritative for global `did:aw` key history, address bindings,
  and each address route's delivery origin.
- **The sender identity key** signs message and recipient-binding fields.
- **The aweb server** validates, routes, stores, and delivers messages; it stores
  participant route state for continuations.
- **Team certificates** prove team membership. They do not create addresses,
  resolver visibility, or delivery routes.
- **Contacts** can authorize delivery under `team_and_contacts` only when the
  recipient-owned row binds the canonical address to the verified sender
  `did:aw`; they do not create routes or registry facts.
- **Conversation/session ids** group UX and retries. They are not routing or
  authorization capabilities.

## Current route model

### Global first contact uses an address

1. The sender targets `recipient.example/bob`.
2. AWID resolves that concrete address to Bob's stable `did:aw`, current
   `did:key`, and address-route delivery origin.
3. The sender signs the message with the target address and resolved recipient
   binding.
4. The sending aweb service delivers to the resolved origin.
5. The receiving service revalidates the signed outer fields and recipient
   binding before storing the message.
6. After route and identity validation, the recipient's current `inbound_mode`
   decides whether delivery is authorized.

`inbound_mode=open` accepts valid routed senders.
`inbound_mode=team_and_contacts` accepts verified same-team senders plus exact
active identity contacts. `inbound_mode=contacts_only` accepts only exact active
identity contacts; verified teammates also require a contact. These settings do
not change AWID resolution.

When sender and receiver use different AWID registries, the receiving service
selects external sender authority from the client-signed sender address, not
from its configured home registry, a wrapper hint, or bare `did:aw`. It verifies
the `_awid` DNS controller, exact namespace/address row, stable DID, current key,
route origin, and genesis-anchored identity log through the separate strict
external-address path. The receiver's home client remains unchanged for its own
identities and ordinary same-registry reads.

A complete verified address-authority cohort may be reused from PostgreSQL for
at most 60 seconds, configurable only downward. Expiry forces the whole
DNS/namespace/address/key-or-log/origin chain to be read again. That receiver
reuse bound is not a global freshness or revocation SLA: an authoritative DNS or
registry source can indefinitely suppress an unseen change by continuing to
serve an old cryptographically valid state.

### Global continuation uses stored participant route state

A reply may use the participant identity/address/origin recorded by the earlier
message. The conversation id is only a lookup/threading input. The stored route
must still match the signed sender/recipient bindings and current delivery
policy.

A direct bare external `did:aw` send fails closed when no stored participant
route exists.

### Local outbound to global

A local agent signs as its `did:key` and sends to a global address through its
home aweb service. The local sender is not inserted into AWID and does not
become globally discoverable. Recipient policy is unchanged: after route
validation, only a recipient whose `inbound_mode` is `open` admits a local
sender. Contacts bind an address and a `did:aw`, and a local sender has
neither. Members of one team share that team's server, so their messages
never federate.

#### Same server

If the target address resolves to a `did:aw` that is resident on the sender's
home server, delivery is local. The home server has already authenticated the
sender, so no route assertion is used and no federation request is made. A
server never federates to its own public origin. If an address's route origin
is this server but its `did:aw` is not resident here, the result is
`recipient_identity_not_found`.

#### Different servers: the team vouches for the return route

The local sender's return route is vouched for by its **team**, through AWID.
The sending service does not vouch for it. The vouched route is made of three
existing facts:

- the sender's team certificate, signed by the team key, binding the sender's
  `did:key`, alias, and team;
- the team's `aweb.team-server/1` record, signed by the team's current key,
  naming the team's server; and
- the sender's message signature, which binds the team to this message.

aweb services have no registry-anchored identity, so a service-signed assertion
would add a new trust root. It would also let a compromised sending service
vouch for any key. The team key is already AWID-anchored, already the authority
for membership, and the team-server record is already its signed statement of
where the team's server is. Partial-service compromise is in scope of the trust
model. Under this design, a compromised sending service can route only keys
its team certified, and only to the server the team key named.

**Sender binding.** The sender's signed message binds its **full canonical team
ID**, for example `backend:example.com`. Certificate IDs are unique only within
a team. Two teams in one namespace can each certify the same `did:key` under the
same alias and the same certificate ID, so the team domain and a certificate ID
together do not select a certificate.
- **Plaintext:** the signed `from` label is `<team_id>/<alias>`, taken from the
  certificate, for example `backend:example.com/alice`. Received-local-sender
  clients already accept a label that names the team ID. Because of the `:`, the
  label is not a valid address.
- **Encrypted-v2:** the protected `from.team_id` is the certificate's team ID,
  and is required on this path. Any `from` label follows the plaintext rule.
  `from.team_id` is already part of the signed identity map in the released
  Python and Go verifiers, so no new protected field is added.

Inside the bound team, any certificate a relay could substitute must be signed
by the same team key, name the same `did:key` and alias, and be `active`. The team
controller is already the authority for that membership and for the team-server
record, so binding a certificate ID as well would stop no additional attack.

The label is display-only. It is never resolved, never pinned as an address,
never stored as a participant `address`, and never matched against contacts.
When a federated plaintext `from` contains `/`, the envelope parser projects it
into `sender_address`. For a local `did:key` sender, ingress clears that value
after the label check, before any storage or policy use.

**Sending server.**
- It attaches the certificate the sender authenticated with as
  `sender_certificate`. This is a new federation envelope field: base64 of the
  exact certificate JSON, the `X-AWID-Team-Certificate` encoding.
- The field is part of the federation envelope hash.
- Before federating, the sending server checks three things:
  - the certificate's `member_did_key` is the signer;
  - its `team_id` and `alias` equal the signed team binding;
  - the team's current team-server record verifies and names this server's
    public origin.
- A failure is refused locally (see Refusals). Nothing is sent to the recipient.

**Receiving server.** These steps run in order. The envelope signature,
recipient binding and the 300-second timestamp skew are verified first, as
today. A message outside the skew is refused before any receipt lookup.

1. **Receipt.** Look up the receiver-wide `message_id` receipt. The lookup does
   not depend on the vouched route:
   - **Exact established receipt:** same kind and same envelope hash (the hash
     covers the signature and `sender_certificate`). Return the stored result.
     There is no certificate-status or team-server read, no route update, and no
     message, participant or event effect. This holds after a revocation, after
     a server move, and while AWID or DNS is unavailable. These exact bytes were
     already admitted, and refusing them now would report a delivered message
     as refused.
   - **Same `message_id` with any other kind or hash:**
     `federation_message_replay_conflict`.
   - **No receipt:** a new admission. Continue.
2. Decode `sender_certificate` and check its fields:
   - `member_did_key` equals the sender `did:key`;
   - `identity_scope` is `local`, and `member_did_aw` and `member_address` are
     empty;
   - its `team_id` and `alias` equal the signed binding (plaintext label;
     encrypted `from.team_id` and any label).
3. Select the team's registry from the team ID's domain, the same way strict
   sender authority selects from a signed address domain:
   - use the receiver's home registry when it serves that namespace;
   - otherwise use the domain's `_awid` record through the strict external
     path, with no fallback.

   A registry URL supplied by the sender is never consulted.
4. Read the certificate status by `(team_id, certificate_id)`. The read is
   anonymous, also for private teams.
   - It must be `active`.
   - Its current `team_did_key` must equal the certificate's `team_did_key`.
   - The certificate signature must verify under that key.
5. Read the team-server record (anonymous) and verify it under the same current
   team key.
   - Its `server_url` is the sender's return route.
   - A supplied `sender_delivery_origin` must equal it.
   - If it names this server, the sender is resident here, so arriving by
     federation is refused.
6. Cache entries are keyed by registry and `(team_id, certificate_id)` for
   status, and by registry and `team_id` for the record. Each entry is reused
   for at most 60 seconds. A cached entry never answers a different key. A
   registry, DNS or coordination failure is retryable and fails closed. If the
   evidence reaches its 60 seconds during a later wait (for a lock or a database
   call), re-read it after the last such wait and before the write.
7. Apply recipient policy: a local sender is admitted only under `open`. This
   holds for first contact and for every continuation, mail and chat,
   plaintext and encrypted-v2.
8. On acceptance, store the sender's participant route (see Storage). The
   recipient's reads report `sender_membership` from the stored certificate,
   with the certificate status read again under the same cache. Clients
   keep the "Received cross-team local senders" rules in the messaging contract
   unchanged.

**Continuations from a team-vouched sender.** A stored participant with a team
route (`route_team_id` set) is not held to strict equality with its stored
origin. Each new message from it repeats steps 2-7 with its own certificate:
- the certificate's `team_id` must equal the stored `route_team_id`; a
  different team is `local_sender_route_mismatch`;
- the certificate may be a reissue, for example after a team key rotation;
- the supplied `sender_delivery_origin` must equal the freshly verified record,
  not the stored row.

If the verified `server_url` differs from the stored `delivery_origin`, the
stored route is updated to the new origin and certificate in the same
transaction that stores the message. An unverified change, meaning a missing,
invalid or unverifiable certificate or record, is refused with the first-contact
codes and changes nothing.

Participants without a team route are unchanged: legacy learned local routes,
same-server participants and `did:aw` participants keep strict equality with
the stored row.

**Freshness and replay.** The vouched route has no lifetime of its own. It is
the current AWID state read at acceptance, by the receiver's clock, so
membership is checked when a new message is admitted, not at a time the sender
chooses. Replay protection is the existing machinery: the timestamp skew, the
receipt order above, and the signed recipient binding, so a captured message
cannot be redirected to another recipient. There is no separate assertion
nonce.

As with address authority, 60 seconds is a receiver reuse bound, not a global
revocation guarantee. An authoritative registry or DNS source that keeps serving
an older valid state can delay a revocation the receiver has not yet seen.

There is no allowlist of origins. Any server a team's current key names is that
team's server. Abuse control stays where it is: rate limits and recipient
policy.

### Global reply to local

A remote reply targets the local `did:key` through the stored learned route. A
local-key signature proves the key, but a self-asserted `did:key -> origin`
field is not route authority.

**Storage.** For a local sender learned across servers, the conversation and
chat participant rows store:

- `did` = the sender `did:key`;
- `address` = NULL;
- `delivery_origin` = the verified team-server URL;
- `route_team_id`, `route_certificate_id`, and `route_certificate`, which is the
  exact certificate as received. All three are set for this kind of participant
  and NULL for every other kind.

The route columns live on the participant row, not on a message. Message
garbage collection never removes the certificate a reply needs for validation.

**Before each reply**, the replying server re-reads the status of
`(route_team_id, route_certificate_id)` and the team-server record, under the
same 60-second caches:

- **Active, current team key equal to the stored certificate's
  `team_did_key`:** send to the record's current `server_url`. Update the stored
  `delivery_origin` only when that server accepts the reply.
- **The record names the replying server itself:** do not federate.
  - If the target `did:key` is resident here, deliver locally as a stored-route
    continuation.
  - Otherwise refuse with `local_recipient_route_missing`.
- **Revoked, unknown, or deleted team; old team key; missing or unverifiable
  record:** refuse locally and send nothing.
- **Registry unavailable:** retryable. The stored route is kept.

**Reply envelope.**
- `target_did_aw`, `target_current_did_key` and `target_address` are all the
  local `did:key`; a local target has no address.
- `target_delivery_origin` is the team-server URL.
- The signed `to` and `to_did` are the `did:key`.

**At the local sender's home server**, a reply to a local `did:key` is accepted
only as a stored-route continuation:
- the conversation exists;
- the target is a resident participant of it;
- the replying sender is a stored participant, verified by the existing strict
  global-sender authority.

A local target needs no address, and there is no first contact to a local
`did:key`. A server that lacks the conversation or the resident participant
refuses with `local_recipient_route_missing` and stores nothing. It never
treats the reply as a new conversation.

**Server moves.** A newer team-server record redirects the route, but it does
not move the conversation.
- **The conversation and its resident participants are present at the new
  origin** (for example, the same deployment under a new public URL): replies
  follow the record, and the sender's own next message updates the route.
- **They are not present at the new origin:** the new server refuses as above.
  The sender's agent can start again by writing a new message.

**What changes end a route:**

| Change | Effect on the learned route |
| --- | --- |
| Sender identity replaced (a local `did:key` cannot rotate in place; a new key is a new identity and a new certificate) | Old certificate revoked: route ends. The new identity can write again. |
| Sender removed from its team, or the team deleted | Status revoked or not found: route ends. |
| Team key rotated | Certificates under the old key no longer verify, so replies are refused until the sender writes again with its reissued certificate. That message renews the route. |
| Team moves to another server | Replies follow the newer record if the new server holds the conversation. Otherwise the new server refuses with `local_recipient_route_missing` and the sender writes again. |
| AWID unavailable | Retryable; the route is kept. |

#### Refusals

Every refusal tells the person what to do next.
- **Receiver-side codes** are federation errors in `awid/federation_errors.py`
  and the generated reference.
- **Sender-side checks** refuse with the same codes before any network call to
  the recipient.

| Reason | HTTP | Retry | When | Text shown to the sender |
| --- | ---: | :---: | --- | --- |
| `local_sender_certificate_required` (new) | 422 | no | Cross-server message from a local sender without `sender_certificate` or without the signed team binding | "This team-only agent's message did not carry its team certificate. Upgrade aw and resend." |
| `local_sender_certificate_invalid` (new) | 422 | no | Malformed certificate, bad signature, or disagreement on key, scope, team or alias | "This agent's team certificate does not match it. Reinstall it with `aw id team fetch-cert` and resend." |
| `local_sender_certificate_revoked` (new) | 403 | no | Status revoked, or certificate/team not found | "This agent is no longer a member of team <team>, so it cannot write outside it." |
| `local_sender_team_key_stale` (new) | 409 | no | Certificate signed by a superseded team key | "Team <team> rotated its key. Its controller must reissue this agent's certificate." |
| `local_sender_team_server_missing` (new) | 424 | no | No team-server record, or it does not verify under the current key, or it names another server than the sending one | "Team <team> has not published its server at AWID, so replies could not reach this agent. The team controller runs `aw id team set-server`; hosted teams publish automatically: contact support." |
| `local_sender_route_mismatch` | 422 | no | Supplied `sender_delivery_origin` disagrees with the record; the record names the receiver itself; or a continuation's certificate names a different team than the stored route | "This agent's server does not match its team's published server. Check `aw id team show-server`." |
| `sender_registry_unresolvable` and the other `sender_registry_*` discovery reasons | as today | as today | The team domain's registry cannot be discovered or validated | "<domain> has no AWID record, so other servers cannot check this agent's team. Publish an `_awid` record for <domain>, or write from an agent with a public address (`aw init --global`)." |
| `sender_registry_unavailable`, `federation_authority_coordination_unavailable` | 503 | yes | Registry or coordination dependency failure | "The recipient's server could not reach AWID. Retry shortly." |
| `recipient_policy_rejected` | 403 | no | Recipient `inbound_mode` is not `open` | "<address> accepts first messages only from its team and contacts. A team-only agent cannot be a contact; write from an agent with a public address (`aw init --global`)." |
| `local_recipient_route_missing` | 404 | no | Replying to a learned local route that has ended (revoked, team deleted, old team key, record gone), or the route's current server does not hold the conversation | "<label> can no longer receive replies here: its team membership or server changed. It can write to you again." |

A client sending as a local identity to another server gets
`federation_envelope_invalid` or `local_sender_route_mismatch` from a receiver
that predates this contract. It shows the reason plus: "The recipient's server
may not yet accept first messages from team-only agents."

#### Required end-to-end evidence

Two real servers, each with its own AWID and real `_awid` DNS. Plaintext and
encrypted-v2, mail and chat. Reads through the CLI, channel and wake.

1. Self-hosted local sender to a hosted `open` address: delivered, read as
   `verified`, reply reaches the sender, and the sender's answer continues the
   thread.
2. Hosted local sender to a self-hosted `open` address: the same.
3. Hosted to hosted, same server: local delivery with zero federation requests;
   reply works.
4. Hosted to hosted, different servers sharing one registry: delivered; reply
   works.
5. Policy: `team_and_contacts` and `contacts_only` targets refuse with
   `recipient_policy_rejected`; no message or route is stored. A recipient that
   changes to `team_and_contacts` mid-thread refuses the next continuation, in
   both formats and both kinds.
6. Forged:
   - a certificate under another key;
   - another member's certificate;
   - **the same namespace, the same certificate ID, the same alias:** a second
     team `attacker:example.test` certifies the same `did:key`, and its
     certificate is substituted on an unchanged message signed for
     `honest:example.test`. It is refused on the team binding, in plaintext and
     encrypted-v2;
   - a label mismatch;
   - an encrypted `from.team_id` that disagrees with the certificate;
   - a foreign `sender_delivery_origin`;
   - a sender-supplied registry URL, which is ignored;
   - the label used as a contact or an address target, which matches and
     resolves nothing.
7. Stale:
   - certificate revoked before send;
   - revoked after the first message (reply refused locally, nothing sent);
   - team key rotated without reissue (refused), then the same identity writes
     with its reissued certificate (accepted, route renewed);
   - team moved server with the conversation present (reply follows, and the
     sender's next message updates the stored origin);
   - team moved server without the conversation (new server refuses with
     `local_recipient_route_missing`, nothing stored, no first contact to the
     `did:key`);
   - a continuation whose certificate names another team
     (`local_sender_route_mismatch`);
   - record missing (sender-side refusal);
   - AWID down (retryable, then success after recovery).
8. Replayed, all within the 300-second window:
   - an exact retry returns the stored result with zero new message,
     participant, route or event rows, including after the certificate is
     revoked and the cache has expired, after a server move, and while AWID or
     DNS is down;
   - the same `message_id` with a changed certificate or body conflicts;
   - a new `message_id` after revocation is refused;
   - a captured message sent to another recipient fails recipient binding;
   - a timestamp beyond 300 seconds is refused.
9. Self-federation:
   - a federated message whose sender's team server is the receiver is
     refused;
   - no send path federates to its own origin;
   - a reply whose revalidated record names the replying server delivers
     locally to a resident target, refuses a nonresident one, and makes zero
     federation requests.
10. Caches: a warm entry is reused within 60 seconds and re-read after it; one
    team's or certificate's entry never answers another; DNS and registry
    failures are retryable; evidence that expires during a database wait is
    re-read before the write.
11. Mixed versions: new sender to an old receiver gets the mapped refusal; old
    sender to a new receiver gets `local_sender_certificate_required`. The
    released CLI, channel and wake readers read new plaintext and encrypted-v2
    messages as `verified` through an upgraded server. Through a server without
    `sender_membership`, readers never report `verified`: mail (plaintext and
    encrypted-v2) and encrypted-v2 chat report `verification_stale`; plaintext
    chat reports `failed`, because that server's chat history projection
    replaces the signed `<team_id>/<alias>` sender with the alias. This is a
    fail-closed legacy limitation, reachable only when a server older than actf
    serves rows accepted by an actf server (a downgrade or mixed-version rolling
    deploy). No compatibility path strips the team binding or falls back to
    plaintext.
12. Encrypted-v2 integrity:
    - tampering with `from.team_id` or the label fails the signature;
    - the inner header mirrors `from.team_id`;
    - builders refuse to send without it on this path;
    - the existing goldens for messages without a team route are unchanged.
13. Every refusal text names its next step.

### Unknown local first contact fails

This rule is about the **target**. A bare unknown `did:key` has neither an AWID address route nor learned return
route. The sender must receive a not-routable/not-found result. The server must
not guess from member names, old participant rows, trust pins, or certificates.

## Signed recipient binding

For global first contact, signed content binds the behavior-shaping fields,
including the target address, target stable identity and current key, message
identity/type/content, and timestamp. Mail and chat carry their own additional
fields.

If a request supplies several recipient selectors (`to_stable_id`, `to_did`,
`to_address`, local member name, or agent id), every supplied selector must
resolve to the same recipient. Conflicts fail with a validation error instead
of being resolved by precedence.

Trust pins are not route authority. A pinned identity helps detect continuity
changes, but it cannot make an unresolved address deliverable or authorize an
address to move to a different `did:aw`.

## Address route origin

Delivery origin is route-level metadata. In the current AWID schema an address
inherits it from `dns_namespaces.default_delivery_origin`; address resolution
returns it as the concrete route's delivery metadata.

A single `did:aw` may therefore have:

- `example.com/alice` delivered to one origin; and
- `partner.example/alice` delivered to another.

Clients and servers must not collapse those routes into one canonical
identity-level origin. `GET /v1/did/{did_aw}/key` resolves a key and never
invents a delivery route.

## Current storage responsibilities

AWID stores:

- stable identity mapping and append-only key log;
- namespace/address bindings;
- namespace default delivery origin used by concrete address routes;
- team public keys and certificate publication/revocation facts.

Aweb stores:

- team-local agent/workspace projections;
- mail/chat state;
- conversation participants with address, delivery origin, and current-key
  hints;
- local learned return routes; and
- UX conversation/thread metadata.

Aweb copies are operational cache/route state, not registry authority.

## Compatibility: removed reachability and visibility fields

AWID migration `003_drop_address_reachability.sql` is current shipped schema. It
refused to run while any active row had non-neutral legacy visibility, then
dropped both `public_addresses.reachability` and
`public_addresses.visible_to_team_id`.

Therefore those columns are **not current resolver schema**. Current AWID API
models may still accept or decode `reachability` and `visible_to_team_id` from
older clients/servers as ignored compatibility fields. They must not affect:

- address lookup or listing;
- route origin;
- delivery authorization;
- team-certificate powers; or
- current `inbound_mode`.

Old five-value messaging-policy concepts are likewise not current delivery
policy. The live surface is `open|team_and_contacts`. Rows without a valid
current `inbound_mode` fail with an explicit migration-required diagnostic;
they are not silently widened.

## Compatibility: stored selectors and old envelopes

Existing conversations keep their ids and display history, but continuations
must be authorized by signed identity/route bindings. Mixed-version federation
may accept the four deprecated v1 routing fields named in
[identity-messaging-contract.md](identity-messaging-contract.md) only as ignored
input during its release window.

Legacy clients may still decode old address visibility fields or older
`lifetime` identity vocabulary. Normalization at a read boundary does not make
those fields current authority.

Address-only legacy contacts are also compatibility data, not cross-registry
authority. They remain inert for `team_and_contacts` until the authenticated
recipient explicitly binds the contact to the freshly resolved `did:aw`. A new
address holder does not inherit a contact or conversation. In-place replacement
requires current namespace-controller proof, strict authority for the new DID,
exact-old compare-and-swap, and explicit recipient acceptance.

One receiver-wide `message_id` receipt covers local/federated mail/chat and
plaintext/encrypted content. Exact federated retries return the stored
established result; any changed envelope or cross-kind reuse conflicts. Local
and backfilled historical receipts are `legacy_unreplayable`, never authorize
federation replay, and block later UUID reuse after message deletion. Existing
local per-path idempotency may still return its row before an insert.

The generated [federation error reference](federation-error-reference.md) is the
support vocabulary for strict external authority, route, replay, contact,
coordination, and encrypted assertion failures.

## Required evidence

Changes to address resolution, identity lookup, participant routes, local member
selectors, contacts, mail, chat, federation, or registry caching must prove:

- global address first contact through AWID resolution;
- global continuation through stored participant route state;
- local outbound plus remote reply through a team-vouched learned route, with the
  end-to-end matrix in [Local outbound to global](#local-outbound-to-global);
- failed first contact to an unknown local `did:key`;
- failed bare external `did:aw` first contact without stored route state;
- no route/policy bypass through stale local rows, trust pins, contacts, team
  certificates, or conversation ids; and
- recipient identity and delivery-origin binding at federation boundaries;
- signed-address external registry selection independent of the home registry;
- full reread after the 60-second maximum reuse interval without a source
  suppression freshness claim;
- PostgreSQL-only shared authority with no Redis/process fallback;
- receiver-wide federated exact-retry and local/changed-envelope/cross-kind
  replay outcomes;
- identity-bound contact migration, explicit replacement acceptance, and no
  address-based transfer; and
- local `did:key`, same-registry, and encrypted no-downgrade compatibility.
