# Global/local identity routing SOT

Status: target architecture for epic `aweb-aapf`; design gate for `aweb-aapf.1`.
No production code is changed by this document. Implementation subtasks must update
`awid-sot.md`, `aweb-sot.md`, `identity-messaging-contract.md`, schemas, APIs,
CLI/channel behavior, and tests to make this target executable.

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
- a current `did:key` bound to that `did:aw`;
- a canonical delivery origin for the identity; and
- zero or more address aliases such as `acme.com/alice`.

A global agent is globally discoverable to global senders and reachable by any
sender with a valid route and signed payload. First contact can start from an
address alias or, when the sender already knows it, from `did:aw`. A local agent
can also write outbound to a global agent through its home server. The sender and
recipient still prove key possession with signed envelopes, but no team
certificate, address visibility flag, contact list, or conversation id is needed
to authorize first contact.

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

### Delivery origin is identity-level

The target model uses an **identity-level canonical delivery origin**.

AWID should expose the canonical delivery origin for a global `did:aw`, and
address resolution should return that identity origin alongside the resolved
identity key. All address aliases for the same `did:aw` therefore route to the
same origin by construction.

Write authority for this field belongs to the `did:aw` identity authority: the
current identity key, or the hosted custodial service acting for that identity.
Namespace and address controllers may assign or change aliases, but they must not
be able to redirect an existing global agent's canonical delivery origin merely
by adding, deleting, or changing an address alias.

Transitional namespace/address delivery origins are migration inputs only. They
are not ongoing authority after identity-level delivery origin exists. If the
migration sees conflicting alias origins for one `did:aw`, global delivery for
that identity must fail closed until an operator repairs the conflict and the
identity authority (or hosted custodial service acting for it) sets the canonical
origin.

Rationale:

- It matches the `did:aw <-> actual agent` invariant.
- It avoids routing one actual agent's aliases to different inbox servers.
- It makes direct `did:aw` first contact possible without guessing from an
  arbitrary address.
- It simplifies delivery-origin rotation: rotate the identity route once rather
  than chasing every alias.

Compatibility note: the federation v1 design in `docs/federation-architecture.md`
proposed namespace-level delivery origin. `aweb-aapf` supersedes that direction:
namespace or address delivery metadata may remain as transitional input, but the
steady-state resolver must enforce one canonical identity delivery origin for all
aliases of a `did:aw`.

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
- aweb recipient messaging policy as a delivery authorization gate
  (`everyone`, `contacts`, `team`, `org`, `nobody`). Contacts may remain as UX
  labels or address-book state, not as delivery auth. Recipient-side blocklists,
  abuse throttles, and spam controls may still run after identity/route
  resolution; they are not resolver visibility rules.
- Known-pin or local-row fallback that bypasses global identity resolution for a
  global address.
- Conversation-id auth bypasses for mail/chat continuation.

Team certificates remain the credential for team-scoped coordination endpoints:
tasks, claims, roles, locks, instructions, workspace state, and presence. They no
longer grant special powers to discover or message a global address.

## Routing model

### Global first contact by address

1. Alice is global (`did:aw:alice`) and sends to `beta.example/bob`.
2. Alice's client resolves `beta.example/bob` at AWID.
3. AWID returns Bob's `did:aw`, current `did:key`, and identity delivery origin.
4. Alice signs the message payload binding:
   - Alice `did:aw` and current `did:key`;
   - selected sender address, if any;
   - target alias `beta.example/bob`;
   - resolved recipient `did:aw` and current `did:key`;
   - recipient delivery origin;
   - message id, type, body, and timestamp.
5. Alice's aweb server delivers to Bob's identity delivery origin.
6. Bob's server verifies the signed payload, re-resolves or verifies the
   recipient identity binding, and stores the message.

No reachability flag, team certificate, contact membership, or conversation id is
needed for authorization.

### Global reply

1. Bob replies to Alice.
2. Bob's client uses the participant identity/route metadata from the received
   message as a convenience input.
3. The reply is signed by Bob and binds Alice's global `did:aw`, current key,
   and delivery origin.
4. Alice's server accepts only if the signed sender identity and recipient
   identity/route verify.

The existing conversation id may be included to thread the UI. It is not the
reason delivery is allowed.

### Local outbound to global

1. Local agent `did:key:zLocal` has no `did:aw` and is known only to its local
   aweb server/team.
2. It sends to global `beta.example/bob`.
3. The local server resolves Bob's global identity and delivery origin.
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
- canonical identity delivery origin; and
- address aliases bound to the identity.

Address records should no longer carry reachability or `visible_to_team_id` as
auth fields. Reads of addresses and identity delivery metadata are public
resolver operations. Write authority remains unchanged: identity key controls DID
state; namespace controller controls address alias assignment.

### aweb server

The aweb server needs distinct routing tables for:

- global identities (`did:aw`, current key, canonical delivery origin);
- local agents (`did:key`, local server/team/workspace projection);
- learned routes from inbound local-origin messages; and
- UX thread/conversation metadata.

Team-scoped projections can still store alias, team id, certificate id, role,
workspace, and presence. Those fields do not authorize global message delivery.

### CLI and channel clients

CLI/channel send paths should classify targets as:

- global address alias (`domain/name`) -> resolve to `did:aw` + key + identity
  delivery origin;
- global identity (`did:aw`) -> resolve key + identity delivery origin;
- local alias in the active team -> same-server local routing only;
- local `did:key` -> allowed only with a learned route.

Signed payloads must include enough binding for recipient servers to reject
mismatched outer fields and stale routes.

## Migration phases

### Phase 0: design and inventory

- Land this SOT.
- Inventory all uses of address reachability, `visible_to_team_id`, private
  address lookup auth, aweb messaging policy, conversation-id auth, known-pin
  fallback, and namespace delivery origin.
- Add conformance cases for the five routing examples above before broad code
  deletion.

### Phase 1: additive identity delivery origin

- Add identity-level delivery origin to AWID through a new ordered migration.
- Backfill hosted global identities with the hosted aweb origin.
- For existing namespace-level delivery origin rows, derive candidate identity
  origins only when all active aliases for the `did:aw` agree. If aliases
  disagree, mark the identity as migration-conflicted and fail closed for global
  delivery until operator repair and identity-authorized origin publication are
  complete.

### Phase 2: global resolver reads ignore reachability

- Make address and identity resolver reads return global identity bindings
  without reachability gates.
- Keep deprecated reachability columns readable for rollback/diagnostics, but do
  not use them for authorization.
- Stop requiring team certificates for private address reads.

### Phase 3: route by global identity and learned local routes

- Update mail/chat send and receive paths to route global recipients by identity
  delivery origin.
- Add learned-return-route storage for local outbound senders.
- Make direct local `did:key` first contact fail closed unless a learned route is
  present.
- Preserve thread IDs only as metadata.

### Phase 4: compatibility reads and UX cleanup

- Keep old CLI/API fields as deprecated no-ops for one compatibility window.
- Render old reachability settings as ignored/deprecated in dashboard/support
  views with repair guidance.
- Contacts remain as labels/address book entries; remove any language implying
  contacts authorize delivery.

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
  `did:aw` and an identity delivery origin.
- Existing ephemeral identities become local identities. They retain team-local
  coordination behavior and may send outward to globals through learned-route
  capable aweb servers.
- Existing address reachability settings are migrated to no-op/deprecated state.
  During the compatibility window, writes may be accepted for old clients but
  must not affect resolver or delivery authorization.
- Existing conversations continue to display and thread by their old ids, but
  continuation requests must be authorized by signed identity/route bindings,
  not by the id alone.
- Existing namespace delivery origins are migration inputs only. The target
  invariant is one canonical identity delivery origin for all aliases of one
  `did:aw`.

## Blast radius

Implementation touches at least:

- `docs/awid-sot.md`, `docs/aweb-sot.md`, and
  `docs/identity-messaging-contract.md`;
- AWID schema/API/client models for identity delivery origin and address reads;
- aweb server mail/chat resolver, federation, signed-payload verification,
  conversation participant storage, contacts/messaging-policy enforcement, and
  known-peer fallback;
- CLI target classification, signed payloads, diagnostics, and channel wake-up
  metadata;
- AC/dashboard identity UI, reachability controls, support tools, and migration
  repair flows;
- e2e/conformance suites for global first contact, global replies, local to
  global sends, global replies to local via learned route, and failed first
  contact to unknown local `did:key`.

## Review gates

No implementation task may proceed until this design is reviewed and approved by
Athena for `aweb-aapf.1`.

Each dependent implementation task should provide e2e or conformance evidence
that matches this document. Isolated unit tests are useful for local mechanics
but are not sufficient proof for the routing/auth model.
