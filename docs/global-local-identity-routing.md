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
active identity contacts. Neither setting changes AWID resolution.

The approved full-federation target for senders and receivers using different
AWID registries selects external sender authority from the client-signed sender
address, not from its configured home registry, a wrapper hint, or bare
`did:aw`. It verifies
either the exact `_awid` DNS controller or a complete parent-signed delegation
chain from inherited DNS to the exact namespace controller, followed by the
exact namespace/address row, stable DID, current key, route origin, and
genesis-anchored identity log through the separate strict external-address
path. The receiver durably checkpoints delegation links as well as identity
history. Its home client remains unchanged for its own identities and ordinary
same-registry reads.

Until portable parent delegation lands, the shipped strict path supports only
the exact-DNS branch and fails closed for inherited DNS with a distinct child
controller.

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
home aweb service. The transport supplies an authenticated return-route
assertion or equivalent vouched route state. The remote service records the
local sender key and validated return route.

The local sender is not inserted into AWID and does not become globally
discoverable.

### Global reply to local

A remote reply targets the local `did:key` through the stored learned route. A
local-key signature proves the key, but a self-asserted `did:key -> origin`
field is not sufficient route authority.

A learned local route must bind at least:

- local `did:key`;
- home delivery origin or concrete return route;
- issuing service/origin;
- route scope;
- issuance/expiry information; and
- revocation semantics.

Missing, stale, malformed, mismatched, or revoked learned routes fail closed.

### Unknown local first contact fails

A bare unknown `did:key` has neither an AWID address route nor learned return
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
- local outbound plus remote reply through a vouched learned route;
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
