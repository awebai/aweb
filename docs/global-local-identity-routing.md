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
- the sender's message signature, which binds the certificate to this message.

aweb services have no registry-anchored identity, so a service-signed assertion
would add a new trust root. It would also let a compromised sending service
vouch for any key. The team key is already AWID-anchored, already the authority
for membership, and the team-server record is already its signed statement of
where the team's server is. Partial-service compromise is in scope of the trust
model. Under this design, a compromised sending service can route only keys
its team certified, and only to the server the team key named.

**Sender binding.** The sender's signed message binds `from_certificate_id`:
the `certificate_id` of its active team certificate.
- For plaintext it is a field of `signed_payload`.
- For encrypted-v2 it is a field of the protected `from` object.

The signed `from` label is `<team domain>/<alias>` taken from that
certificate. It is a display label and is never resolved as an address. Without
this binding, a team that certified the same `did:key` without its consent
could have its own certificate substituted onto the sender's message. Replies
would then go to that team's server and show its label.

**Sending server.**
- It attaches the certificate the sender authenticated with as
  `sender_certificate`. This is a new federation envelope field: base64 of the
  exact certificate JSON, the `X-AWID-Team-Certificate` encoding.
- The field is part of the federation envelope hash.
- Before federating, the sending server checks three things:
  - the certificate's `member_did_key` is the signer;
  - its `certificate_id` equals the signed `from_certificate_id`;
  - the team's current team-server record verifies and names this server's
    public origin.
- A failure is refused locally (see Refusals). Nothing is sent to the recipient.

**Receiving server.** At ingress, after the message signature verifies and
before receipts and recipient policy:

1. Decode `sender_certificate` and check its fields:
   - `member_did_key` equals the sender `did:key`;
   - `identity_scope` is `local`, and `member_did_aw` and `member_address` are
     empty;
   - `certificate_id` equals the signed `from_certificate_id`;
   - the signed `from` label names the certificate's team domain and alias.
2. Select the team's registry from the team ID's domain, the same way strict
   sender authority selects from a signed address domain:
   - use the receiver's home registry when it serves that namespace;
   - otherwise use the domain's `_awid` record through the strict external
     path, with no fallback.

   A registry URL supplied by the sender is never consulted.
3. Read the certificate status (anonymous, also for private teams).
   - It must be `active`.
   - Its current `team_did_key` must equal the certificate's `team_did_key`.
   - The certificate signature must verify under that key.
4. Read the team-server record (anonymous) and verify it under the same current
   team key.
   - Its `server_url` is the sender's return route.
   - A supplied `sender_delivery_origin` must equal it.
   - If it names this server, the sender is resident here, so arriving by
     federation is refused.
5. Cache the status and the record for at most 60 seconds each, and fail
   closed. A registry or dependency failure is retryable.
6. Apply the receiver-wide receipt and replay rules, then recipient policy
   (`open` only).
7. On acceptance, store the sender's participant route (see Storage). The
   recipient's reads report `sender_membership` from the stored certificate,
   with the certificate status read again under the same cache. Clients
   keep the "Received cross-team local senders" rules in the messaging contract
   unchanged.

**Freshness and replay.** The vouched route has no lifetime of its own. It is
the current AWID state read at acceptance, by the receiver's clock, so
membership is checked when the message is accepted, not at a time the sender
chooses. Replay protection is the existing machinery:

- the 300-second message timestamp skew;
- the receiver-wide `message_id` receipt (an exact retry returns the stored
  result; the same id with any changed envelope, including a different
  certificate, conflicts);
- the signed recipient binding, so a captured message cannot be redirected to
  another recipient.

There is no separate assertion nonce.

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
- `route_team_id` and `route_certificate_id`, both set for this kind of
  participant and NULL for every other kind.

Each later accepted message from that sender replaces the route with its newly
verified one.

**Before each reply**, the replying server re-reads the certificate status and
the team-server record, under the same 60-second caches:

- **Active, current team key:** send to the record's current `server_url`. If
  the team moved servers, the reply follows the newer record and updates the
  stored `delivery_origin`.
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

A local target needs no address. There is no first contact to a local
`did:key`.

**What changes end a route:**

| Change | Effect on the learned route |
| --- | --- |
| Sender identity replaced (a local `did:key` cannot rotate in place; a new key is a new identity and a new certificate) | Old certificate revoked: route ends. The new identity can write again. |
| Sender removed from its team, or the team deleted | Status revoked or not found: route ends. |
| Team key rotated | Certificates under the old key no longer verify, so the route ends until the sender writes again with its reissued certificate. |
| Team moves to another server | A newer team-server record: replies follow it. |
| AWID unavailable | Retryable; the route is kept. |

#### Refusals

Every refusal tells the person what to do next.
- **Receiver-side codes** are federation errors in `awid/federation_errors.py`
  and the generated reference.
- **Sender-side checks** refuse with the same codes before any network call to
  the recipient.

| Reason | HTTP | Retry | When | Text shown to the sender |
| --- | ---: | :---: | --- | --- |
| `local_sender_certificate_required` (new) | 422 | no | Cross-server message from a local sender without `sender_certificate` or a signed `from_certificate_id` | "This team-only agent's message did not carry its team certificate. Upgrade aw and resend." |
| `local_sender_certificate_invalid` (new) | 422 | no | Malformed certificate, bad signature, or key, scope, id or label disagreement | "This agent's team certificate does not match it. Reinstall it with `aw id team fetch-cert` and resend." |
| `local_sender_certificate_revoked` (new) | 403 | no | Status revoked, or certificate/team not found | "This agent is no longer a member of team <team>, so it cannot write outside it." |
| `local_sender_team_key_stale` (new) | 409 | no | Certificate signed by a superseded team key | "Team <team> rotated its key. Its controller must reissue this agent's certificate." |
| `local_sender_team_server_missing` (new) | 424 | no | No team-server record, or it does not verify under the current key, or it names another server than the sending one | "Team <team> has not published its server at AWID, so replies could not reach this agent. The team controller runs `aw id team set-server`; hosted teams publish automatically: contact support." |
| `local_sender_route_mismatch` | 422 | no | Supplied `sender_delivery_origin` disagrees with the record, or the record names the receiver itself | "This agent's server does not match its team's published server. Check `aw id team show-server`." |
| `sender_registry_unresolvable` and the other `sender_registry_*` discovery reasons | as today | as today | The team domain's registry cannot be discovered or validated | "<domain> has no AWID record, so other servers cannot check this agent's team. Publish an `_awid` record for <domain>, or write from an agent with a public address (`aw init --global`)." |
| `sender_registry_unavailable`, `federation_authority_coordination_unavailable` | 503 | yes | Registry or coordination dependency failure | "The recipient's server could not reach AWID. Retry shortly." |
| `recipient_policy_rejected` | 403 | no | Recipient `inbound_mode` is not `open` | "<address> accepts first messages only from its team and contacts. A team-only agent cannot be a contact; write from an agent with a public address (`aw init --global`)." |
| `local_recipient_route_missing` | 404 | no | Replying to a learned local route that has ended (revoked, team deleted, old team key, record gone) | "<label> can no longer receive replies here: its team membership ended or changed. It can write to you again." |

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
   `recipient_policy_rejected`; no message or route is stored.
6. Forged:
   - a certificate under another key;
   - another member's certificate;
   - a substituted certificate from a second team that certified the same
     `did:key` (signed id mismatch);
   - a label mismatch;
   - a foreign `sender_delivery_origin`;
   - a sender-supplied registry URL, which is ignored.
7. Stale:
   - certificate revoked before send;
   - revoked after the first message (reply refused locally, nothing sent);
   - team key rotated without reissue;
   - team moved server (reply follows);
   - record missing (sender-side refusal);
   - AWID down (retryable, then success after recovery).
8. Replayed:
   - exact retry returns the stored result without duplicates;
   - the same `message_id` with a changed certificate or body conflicts;
   - a captured message sent to another recipient fails recipient binding;
   - a timestamp beyond 300 seconds is refused.
9. Self-federation: a federated message whose sender's team server is the
   receiver is refused, and no send path federates to its own origin.
10. Mixed versions: new sender to an old receiver gets the mapped refusal; old
    sender to a new receiver gets `local_sender_certificate_required`.
11. Every refusal text names its next step.

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
