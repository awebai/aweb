# Global/local identity routing SOT

Status: supporting SOT for the shipped route-level global/local messaging
contract. The normative behavior summary lives in
[`identity-messaging-contract.md`](identity-messaging-contract.md); this document
explains the model, migration direction, and deleted legacy concepts.

This document replaces the old persistent/ephemeral + reachability model with a
simpler global/local model:

- **Global agent**: an agent with a registered `did:aw`. It is globally routable
  and reachable by any other global agent.
- **Local agent**: an agent with only a `did:key`. It is local to an aweb
  server/team until it writes outward and the remote side learns a return route.

## Goals

1. Make identity routing understandable: `did:aw` means global, `did:key` only
   means local.
2. Preserve one durable identity invariant: a `did:aw` names one actual agent.
3. Treat multiple addresses for one `did:aw` as aliases, not separate routable
   principals.
4. Remove reachability and visibility gates from the resolver/auth model.
5. Remove conversation/thread identifiers as routing authority or authorization
   capabilities.
6. Keep migration deliberate for existing rows that still carry reachability,
   visibility, messaging-policy, and conversation-auth state.

## Definitions

### Actual agent

An **actual agent** is the key-holding principal that sends and receives
messages. It may be a self-custodial CLI workspace or a hosted custodial MCP
runtime. Runtime workspaces, team memberships, and addresses are projections of
that agent; they do not create independent routable principals.

### Global agent

A **global agent** has:

- a `did:aw` row in AWID;
- a current `did:key` bound to that `did:aw`; and
- zero or more address aliases such as `acme.com/alice`.

A global agent is globally identifiable to global senders and reachable by any
sender with a valid address route and signed payload. First contact starts from
an address alias, not a bare `did:aw`. A local agent
can also write outbound to a global agent through its home server. The sender and
recipient still prove key possession with signed envelopes. No team
certificate, address visibility flag, or conversation id creates a route or
resolver visibility. Contacts do not create routes or resolver visibility, but
an exact active identity contact is required for delivery when the recipient's
`inbound_mode` is `contacts_only`; for `contacts_or_teammates`, a verified team
certificate for the recipient's team is also a delivery-authorization input
after address route and identity binding have already succeeded.

### Local agent

A **local agent** has:

- a `did:key`;
- no `did:aw`;
- no AWID identity row; and
- local routing state on one aweb server/team.

A local agent is not globally discoverable. A remote sender cannot first-contact
`did:key:z6Mk...` unless it already has a learned return route from a previous
inbound message by that local agent.

Local agents may send outbound messages to global agents. Their outbound signed
message includes their `did:key` and return-route metadata supplied by their
home aweb server. The global recipient may reply using that learned route. The
learned route is scoped to the observed local sender and route; it does not make
that bare `did:key` globally routable.

## Invariants

### `did:aw` maps to one actual agent

`did:aw <-> actual agent` is a system invariant.

- A `did:aw` may rotate its current `did:key` through the AWID DID log.
- A `did:aw` may have many address aliases.
- A `did:aw` may hold team memberships in many teams.
- A `did:aw` must not represent multiple independently routable agents.

If product UX wants several named bots, create several `did:aw` identities. Do
not model them as multiple addresses for one identity and then route them as if
they were independent principals.

### Addresses are aliases

An address (`domain/name`) resolves to a `did:aw`. It is a human-friendly alias,
not the agent itself. Multiple addresses that resolve to the same `did:aw` are
aliases for the same global agent.

Consequences:

- Message delivery binds to the resolved `did:aw`, not to a separate address
  principal.
- Recipient history may display the addressed alias for UX, but authorization
  and routing use the identity.
- Address replacement changes which `did:aw` the alias points to; it does not
  mutate the old identity.

### Delivery origin is route-level

The target model uses **route-level delivery origin**.

First contact to a global identity uses a concrete address (`domain/name`). AWID
address resolution returns the address route: target `did:aw`, current
`did:key`, and delivery origin for that address. In the current schema that
origin may be inherited from `dns_namespaces.default_delivery_origin`; it is
still metadata for the address route, not an identity-level canonical route.

A single `did:aw` may have multiple addresses with different route origins. No
resolver or server path may collapse them to one canonical identity origin.
Direct bare `did:aw` first contact is unsupported unless an existing
conversation/session supplies stored participant route state.

Rationale:

- It preserves explicit route authority: address first contact or stored
  participant route continuation.
- It lets one global identity participate through multiple authorized address
  routes without one alias overwriting another.
- It avoids inventing delivery routes from `did:aw` key lookup alone.
- It keeps namespace `default_delivery_origin` as address-route inheritance, not
  identity routing authority.

### Conversation IDs are metadata only

Conversation IDs, chat session IDs, message thread IDs, and in-reply-to fields
are UX/local metadata. They may group messages, dedupe retries, and help a client
choose a reply target, but they must not be routing authority or an authorization
capability.

A reply is valid because the sender signs it and the recipient route is either a
global identity route or a learned local return route. It is not valid merely
because the request contains a known `conversation_id`.

### Learned local return routes are vouched capabilities

A learned return route for a local `did:key` is learned from authenticated
inbound transport and the local home server's route assertion. It is not learned
merely from arbitrary fields inside the local agent's sender-signed payload. A
local `did:key` signature proves the local agent key, but it does not prove that
a claimed delivery origin is authoritative for that key.

The route should be represented as a server-verifiable route assertion or
capability (or an equivalent transport primitive) that binds at minimum:

- local `did:key`;
- home delivery origin or concrete return route;
- issuing server identity or origin;
- timestamp and expiry;
- route scope; and
- revocation semantics.

Replies to local `did:key` require a valid learned route. Stale, missing,
malformed, mismatched, or revoked route assertions fail closed. A receiving
global server must not treat a bare self-asserted `did:key -> origin` claim in a
signed message as sufficient routing authority.

## Deleted concepts

The target model deletes these concepts as resolver/auth layers:

- AWID address reachability values: `public`, `org_only`,
  `team_members_only`, and `nobody`.
- `visible_to_team_id` on address rows.
- Private address lookup authorization through team certificates.
- Team-certificate address visibility gates.
- The old five-value recipient policy gate as a live delivery authorization
  surface. The replacement live surface is the explicit global
  `inbound_mode=open|contacts_or_teammates|contacts_only`; old broader
  team/org/block-all semantics are not renamed or preserved. Contacts may
  authorize the explicit `contacts_only`, `contacts_or_teammates`, or
  local-contact gates, but they remain exact address-book state and never
  resolver visibility or routing authority. A verified team certificate for the
  recipient's team authorizes delivery only for `contacts_or_teammates`, after
  route and identity binding have already succeeded. Recipient-side blocklists,
  abuse throttles, and spam controls may still run after identity/route
  resolution; they are not resolver visibility rules.
- Known-pin or local-row fallback that bypasses global identity resolution for a
  global address.
- Conversation-id auth bypasses for mail/chat continuation.

Team certificates remain the credential for team-scoped coordination endpoints:
tasks, claims, roles, locks, instructions, workspace state, and presence. They do
not grant special powers to discover a global address and do not create a route.
They are, however, an explicit delivery authorization input for global recipients
whose `inbound_mode` is `contacts_or_teammates` when the certificate verifies for
the recipient's team.

## Routing model

### Global first contact by address

1. Alice is global (`did:aw:alice`) and sends to `beta.example/bob`.
2. Alice's client resolves `beta.example/bob` at AWID.
3. AWID returns Bob's `did:aw`, current `did:key`, and the address-route delivery origin for `beta.example/bob`.
4. Alice signs the message payload binding:
   - Alice `did:aw` and current `did:key`;
   - selected sender address, if any;
   - target alias `beta.example/bob`;
   - resolved recipient `did:aw` and current `did:key`;
   - recipient delivery origin;
   - message id, type, body, and timestamp.
5. Alice's aweb server delivers to Bob's address-route delivery origin.
6. Bob's server verifies the signed payload, re-resolves or verifies the
   recipient identity binding, and stores the message.

No reachability flag, contact membership, or conversation id creates the route.
After route and identity binding, the recipient's `inbound_mode` decides delivery:
`open` accepts, `contacts_or_teammates` accepts exact contacts or verified
same-team certificate senders, and `contacts_only` accepts exact contacts only.

### Global reply

1. Bob replies to Alice.
2. Bob's client uses the participant identity/route metadata from the received
   message as a convenience input.
3. The reply is signed by Bob and binds Alice's global `did:aw`, current key,
   and stored participant route origin.
4. Alice's server accepts only if the signed sender identity and recipient
   identity/route verify.

The existing conversation id may be included to thread the UI. It is not the
reason delivery is allowed.

### Local outbound to global

1. Local agent `did:key:zLocal` has no `did:aw` and is known only to its local
   aweb server/team.
2. It sends to global `beta.example/bob`.
3. The local server resolves Bob's global address route and delivery origin.
4. The local agent signs the message as `did:key:zLocal`.
5. The local home server/transport adds a verifiable route assertion that
   identifies where replies for this local key should be delivered.
6. Bob's server stores both the local sender key and validated learned return
   route with the message participant record.

The local sender is not inserted into AWID and does not become discoverable by
other global agents.

### Global reply to local via learned route

1. Bob replies to `did:key:zLocal` from the inbound message.
2. Bob's server uses the learned return route captured from that inbound message.
3. Bob signs the reply payload to the local `did:key` and route context.
4. The local agent's home server accepts the reply only if the route assertion is
   still valid, the route matches the learned local route, and the signed payload
   binds the expected sender and recipient keys.

The learned route is a return path, not a global directory entry. It can expire,
be revoked, or be scoped to the server/team that issued it. If it is stale,
missing, or revoked, the reply fails closed.

### Failed first contact to unknown local `did:key`

1. Bob tries to send a first-contact message to `did:key:zUnknownLocal`.
2. There is no `did:aw` resolver row and no learned route.
3. The client/server must fail closed with a not-routable/not-found result.
4. The server must not guess from local aliases, stale participant rows, known
   pins, or team certificate records.

Bare local `did:key` values are not globally routable.

## Data model direction

### AWID

Target AWID identity records need to represent:

- `did_aw`;
- current `did_key`;
- DID log / rotation state;
- address aliases bound to the identity.

Delivery origin is address-route metadata, inherited from namespace default in
the current schema, not identity record metadata.

Address records should no longer carry reachability or `visible_to_team_id` as
auth fields. Reads of addresses and address-route metadata are public
resolver operations. Write authority remains unchanged: identity key controls DID
state; namespace controller controls address alias assignment.

### aweb server

The aweb server needs distinct routing tables for:

- stored participant routes (`did:aw`, current key, address, delivery origin);
- local agents (`did:key`, local server/team/workspace projection);
- learned routes from inbound local-origin messages; and
- UX thread/conversation metadata.

Team-scoped projections can still store alias, team id, certificate id, role,
workspace, and presence. Those fields do not authorize global message delivery.

### CLI and channel clients

CLI/channel send paths should classify targets as:

- global address alias (`domain/name`) -> resolve to `did:aw` + key + address-route
  delivery origin;
- global identity (`did:aw`) -> unsupported for first contact unless stored route state exists;
- local alias in the active team -> same-server local routing only;
- local `did:key` -> allowed only with a learned route.

Signed payloads must include enough binding for recipient servers to reject
mismatched outer fields and stale routes.

## Migration phases

### Phase 0: design and inventory

- Land this SOT.
- Inventory all uses of address reachability, `visible_to_team_id`, private
  address lookup auth, legacy aweb delivery policy gates, conversation-id auth,
  known-pin fallback, and namespace/address delivery origin.
- Add conformance cases for the five routing examples above before broad code
  deletion.

### Phase 1: route-level delivery origin

- Remove unshipped identity-level delivery-origin artifacts.
- Use namespace `default_delivery_origin` as address-route inheritance.
- Make address resolution return route origin for the concrete address.
- Fail bare external `did:aw` first contact closed; use address first contact or stored participant route continuation.

### Phase 2: global resolver reads ignore reachability

- Make address and identity resolver reads return global identity bindings
  without reachability gates.
- Keep deprecated reachability columns readable for rollback/diagnostics, but do
  not use them for authorization.
- Stop requiring team certificates for private address reads.

### Phase 3: route by address routes, participant routes, and learned local routes

- Update mail/chat send and receive paths to route global first contact by
  address-route delivery origin and continuations by stored participant route.
- Add learned-return-route storage for local outbound senders.
- Make direct local `did:key` first contact fail closed unless a learned route is
  present.
- Preserve thread IDs only as metadata.

### Phase 4: compatibility reads and UX cleanup

- Keep old CLI/API fields as deprecated no-ops for one compatibility window.
- Render old reachability settings as ignored/deprecated in dashboard/support
  views with repair guidance.
- Contacts remain exact address-book state. They do not route or affect resolver
  visibility, but exact active identity contacts authorize delivery for the
  `contacts_only`, `contacts_or_teammates`, and local-contact gates. Verified
  recipient-team certificates additionally authorize `contacts_or_teammates`;
  they still do not route or affect resolver visibility.

### Phase 5: delete dead code and schema

- Remove reachability and `visible_to_team_id` write paths.
- Remove AWID private address lookup authorization.
- Remove aweb messaging-policy enforcement.
- Remove conversation-id authorization bypasses.
- Remove fallback code that routes global messages from local rows/pins without
  resolver proof.
- Drop deprecated columns only after production data has been audited and the
  rollback window has closed.

## Compatibility rules for existing users

- Existing persistent identities become global identities once they have a
  `did:aw`; first-contact delivery additionally requires an address route.
- Existing ephemeral identities become local identities. They retain team-local
  coordination behavior and may send outward to globals through learned-route
  capable aweb servers.
- Existing neutral/public address rows resolve by address-route metadata.
  Existing non-neutral legacy rows (`reachability != public` or
  `visible_to_team_id IS NOT NULL`) are migration-blocked for public address
  resolution until an explicit owner/operator action normalizes them. During the
  compatibility window, writes may be accepted for old clients but must not
  affect resolver or delivery authorization.
- Existing conversations continue to display and thread by their old ids, but
  continuation requests must be authorized by signed identity/route bindings,
  not by the id alone.
- Existing namespace/address delivery origins are route metadata. The target
  invariant is no canonical identity delivery origin; each address route may have
  its own origin.

## Blast radius

Implementation touches at least:

- `docs/awid-sot.md`, `docs/aweb-sot.md`, and
  `docs/identity-messaging-contract.md`;
- AWID schema/API/client models for address-route delivery origin and address reads;
- aweb server mail/chat resolver, federation, signed-payload verification,
  conversation participant storage, contacts/messaging-policy enforcement, and
  known-peer fallback;
- CLI target classification, signed payloads, diagnostics, and channel wake-up
  metadata;
- AC/dashboard identity UI, legacy reachability support views, support tools,
  and migration repair flows;
- e2e/conformance suites for global first contact, global replies, local to
  global sends, global replies to local via learned route, and failed first
  contact to unknown local `did:key`.

## Evidence gates

Changes to routing, authorization, identity resolution, address lookup, mail,
chat, local alias handling, contacts, or registry caching must provide e2e or
conformance evidence that matches this SOT. Isolated unit tests are useful for
local mechanics but are not sufficient proof for the routing/auth model.
