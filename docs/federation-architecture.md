# Federated Messaging Architecture

Status: separate architecture model, not yet implemented and not part of the current SOT.

This note describes a proposed federation model for OSS aweb and awid. It is
kept separate from the SOTs for now; if the model is accepted, the SOTs should
be updated explicitly in a later step.

Tracking epic: `aweb-aaou` — Federated messaging architecture: namespace
delivery origins. The epic links back to this document and owns the implementation
subtasks listed in [Implementation Plan](#implementation-plan).

## Goal

An agent on one aweb server must be able to send verified mail or chat to an
agent whose address is hosted by another aweb server, and the recipient must be
able to reply without either side sharing a local database.

Example:

```text
aweb.alpha.example/alice -> beta.example/bob
beta.example/bob         -> aweb.alpha.example/alice
```

The trust model must remain the same:

- awid is the source of truth for identities, namespace addresses,
  reachability, team public keys, certificates, and revocation.
- aweb is the source of truth for coordination state: mail, chat,
  conversations, tasks, presence, work queues, roles, and instructions.
- A coordination server must not invent address authority from local rows.
- A message must carry a verifiable signed binding to the resolved recipient.

## Current State

The code already has the identity half of federation:

- `domain/name` address lookup goes through awid.
- awid resolves the address to `did:aw` plus current `did:key`, subject to
  reachability.
- aweb mail/chat can build an "external recipient" when the recipient address
  resolves at awid but is not present in the local aweb database.

The missing half is delivery:

- awid namespace/address records currently do not return a destination aweb
  server for mail/chat delivery.
- aweb external-recipient handling stores the message in the sender's local
  database instead of POSTing it to the recipient's home aweb server.

Local bootstrap state does carry an aweb URL (`.aw/workspace.yaml`,
`.aw/teams.yaml`, local invite tokens, hosted invite responses), but that is
not globally discoverable by another sender. Federation needs discoverable
delivery metadata.

## Granularity

Mail/chat delivery should be **namespace/address-scoped**, not team-scoped.
Team coordination remains team-scoped.

The important split is operation type:

```text
Identity-scoped mail/chat to domain/name -> namespace default delivery origin
Team-scoped tasks/work/presence/roles/instructions -> team coordination origin
```

### Why Not Identity

An identity can belong to multiple teams and can hold addresses in multiple
namespaces. Putting a delivery server on `did:aw` would collapse those contexts
into one global home server and would not compose with BYOIDT or multi-team
identities.

### Why Not Team For Mail/Chat

Mail/chat is identity-scoped. The recipient can belong to several teams, the
sender can belong to several teams, and they may or may not share any team.
Choosing one recipient team as the delivery route is a phantom decision: the
message is addressed to `domain/name`, not to one of the recipient's teams.

The sender's active team still matters for sender context and for presenting a
team certificate to awid when a non-public address requires one. It should not
choose the recipient's inbox server.

### Why Namespace

A namespace controls addresses under `domain`. If a sender addresses
`domain/name`, the namespace is the natural authority for where that address's
mailbox lives.

This also matches the authority model: a namespace controller can already assign
or reassign `domain/name` to a `did:aw`, so allowing it to declare the namespace
mail/chat delivery origin does not introduce a stronger authority.

### Proposed Rule

```text
Namespace owns the default mail/chat delivery origin.
Address inherits the namespace delivery origin.
Team owns team-scoped coordination origin.
Identity can belong to many teams.
Sender selects active team when sending.
Recipient address selects delivery origin when receiving first contact.
Conversation participants store the concrete return route for replies.
```

## Proposed Registry Model

Add a default mail/chat delivery origin to awid namespace metadata:

```text
dns_namespaces.default_delivery_origin = "https://aweb.example.com"
```

Address records inherit that value. Do not add per-address override in the first
cut; it is easy to add later and complicates authority and migration now.

Add a separate coordination origin to awid team metadata for team-scoped state:

```text
teams.coordination_origin = "https://aweb.example.com"
```

Address lookup would return identity and delivery metadata:

```json
{
  "address": "beta.example/bob",
  "did_aw": "did:aw:...",
  "current_did_key": "did:key:...",
  "reachability": "public",
  "delivery": {
    "origin": "https://aweb.beta.example",
    "source": "namespace_default"
  }
}
```

Namespace lookup would return:

```json
{
  "domain": "beta.example",
  "controller_did": "did:key:...",
  "verification_status": "verified",
  "default_delivery_origin": "https://aweb.beta.example"
}
```

Team lookup would return:

```json
{
  "team_id": "backend:beta.example",
  "domain": "beta.example",
  "name": "backend",
  "team_did_key": "did:key:...",
  "visibility": "private",
  "coordination_origin": "https://aweb.beta.example"
}
```

The namespace controller authorizes `default_delivery_origin`. The team
controller authorizes `coordination_origin`.

## Sending Path

When Alice sends to `beta.example/bob`:

1. Alice's local client selects her active team.
2. Alice signs an awid address lookup for `beta.example/bob`.
3. If the target address is non-public, Alice also presents her active team
   certificate to awid.
4. awid returns:
   - target `did:aw`
   - target current `did:key`
   - target delivery origin inherited from the namespace
5. Alice signs the message envelope with:
   - sender `did:aw` and current `did:key`
   - sender selected address, if any
   - sender active team id, if any
   - sender active team certificate, when it was presented to awid to satisfy
     non-public target reachability
   - target address
   - resolved target `did:aw`
   - resolved target current `did:key`
   - target delivery origin
   - message body, message id, conversation id if present, and timestamp
6. Alice's aweb server sends the signed envelope to the target delivery origin.
7. The recipient aweb server verifies the envelope and stores the message in
   the recipient's local inbox/chat state.

The sender's local aweb server may keep a local conversation projection, but
the authoritative recipient inbox lives on the recipient delivery server.

## Recipient Server Verification

The recipient server must verify:

1. The sender DIDKey signature over the message envelope.
2. The sender `did:key` is current for sender `did:aw`, unless a valid rotation
   window or signed key evidence is explicitly accepted by the SOT.
3. The signed `to_address` still resolves through awid to the signed recipient
   `did:aw` and current `did:key`.
4. The resolved namespace delivery origin matches this server's origin, or this
   server is explicitly authorized to accept for that origin.
5. If the address was resolved through non-public reachability, the envelope
   carries the team certificate that was presented to awid, and the recipient
   server re-verifies that certificate rather than trusting the sender's server.
6. The timestamp is inside the accepted skew window.
7. The message id has not already been accepted for this sender/recipient route.
   Duplicate message ids are idempotent, not double-delivered.
8. The sender is allowed by recipient messaging policy.
9. Conversation continuation is valid if `conversation_id` is present.

If any identity, address, or delivery binding disagrees, the recipient server
must fail closed.

The recipient server should store an inbound federation dedupe row keyed by
sender identity, recipient identity, message id, and message type before
emitting delivery side effects. This prevents network retries from creating
duplicate mail or chat messages.

## Replies

Replies should not require rediscovering an ambiguous human name or bare alias.
The conversation participant record should store enough route metadata:

```text
did
address
delivery_origin
transport_hint
```

When the recipient replies, their server sends to the sender's stored
`delivery_origin` with the stored participant identity binding. The reply still
carries a signed envelope and is verified by the original sender's server.

This is what lets a non-public address reply after an authorized first contact:
conversation participation authorizes the reply path; address reachability only
controls first discovery.

## Direct `did:aw` Sends

An address lookup can return delivery metadata because an address selects a
namespace. A bare `did:aw` lookup does not select a namespace, so it does not
select a delivery origin.

For the first federation cut, a bare `did:aw` send across servers should require
one of:

- an existing conversation participant route, or
- an explicit delivery hint supplied by the caller and verified against the
  recipient server's accepted identity.

It should not guess a home server from arbitrary local rows or by listing all
addresses for the identity. A later design can add a DID-level service record if
we need first-contact `did:aw` sends without an address.

## Multi-Team Identities

An identity can belong to multiple teams:

```text
did:aw:athena
  address aweb.example/athena -> https://app.aweb.example
  member of aweb:aweb.example -> https://app.aweb.example
  member of backend:alpha.example -> https://aweb.alpha.example
```

Sending always uses the active team context. That selected team determines:

- sender certificate
- sender policy context
- sender address for that team, if any
- sender route metadata for replies

Receiving by address uses the address namespace's delivery origin. Team
memberships are not part of receive routing. If an identity has addresses in
multiple namespaces, each namespace can route to a different delivery origin;
a unified local view can poll those inboxes, but first-contact routing remains
address-scoped.

## Cross-Server Teams

For v1 federation, a team should have one canonical coordination server for
team-scoped state. Agents can be on different machines and can have identities
from different namespaces, but the team's shared state has one home:

```text
team backend:alpha.example -> https://aweb.alpha.example
```

This keeps tasks, presence, work queues, roles, and instructions simple.
Multi-primary team replication is a separate problem and should not be part of
the first federation cut.

Cross-server membership is still supported because membership is a certificate,
not a local account row. A member from another namespace presents the team
certificate to the team's home server for team-scoped operations.

## Required OSS Changes

### awid Schema

Add new migrations, never editing existing `001_registry.sql`:

- Add `default_delivery_origin` to `dns_namespaces`.
- Add `coordination_origin` to `teams` for team-scoped operations.
- Decide migration/backfill behavior for existing namespaces and teams. The
  likely safe behavior is no implicit delivery origin by default, with
  hosted/operator tooling setting values explicitly. Do not guess production
  defaults.

### awid API

Extend:

- namespace create/update/read responses with `default_delivery_origin`
- team create/update/read/list responses with `coordination_origin`
- address read/list responses with inherited delivery metadata

Add or update authorization:

- namespace controller authorizes namespace default delivery origin
- team controller authorizes team coordination origin

Validation:

- `default_delivery_origin` and `coordination_origin` must be canonical HTTPS
  origins for public federation; local/dev registries may allow
  `http://localhost`.
- Address resolution without delivery metadata must fail closed for federated
  delivery.

### Go awid Client

Extend data structures:

- `Namespace`
- `Address`
- `Team`
- namespace update requests
- team create/update requests

Extend resolver behavior so CLI and aweb server can read delivery metadata from
normal address resolution.

### aweb Server

Add remote delivery capability for mail and chat:

- When recipient address resolves to this server's delivery origin, keep the
  local path.
- When recipient address resolves to a different delivery origin, send a signed
  federation request to that origin.
- Add a recipient-side federation endpoint for mail.
- Add a recipient-side federation endpoint for chat session create and message
  continuation.
- Store participant route metadata for replies.
- Preserve existing fail-closed recipient-binding checks.

The endpoint can be new (`/v1/federation/messages`,
`/v1/federation/chat/...`) or folded into existing `/v1/messages` and
`/v1/chat` routes, but the auth mode must be explicit. A remote server should
not need a local workspace row for the sender; it should authenticate the
signed identity envelope and any presented team certificate.

### aweb CLI

Update send paths:

- resolve target address
- include delivery metadata in signed payloads or request context
- preserve active-team sender selection
- avoid local-only assumptions when target has a remote delivery origin

Update diagnostics:

- `aw doctor` should report whether the sender address and target address have
  delivery metadata
- `aw id address show` or equivalent should show inherited namespace delivery
  origin

### MCP

MCP tools should not need a separate federation model. They call the same
mail/chat implementation as CLI/REST. Hosted OAuth/custodial MCP remains an
operator layer, but once the core sender path supports remote delivery, MCP
senders inherit it.

### Tests

Required OSS tests before shipping:

- namespace lookup returns default delivery origin
- address lookup returns inherited delivery metadata
- team lookup returns coordination origin
- public cross-server mail first contact
- public cross-server chat first contact
- reply by conversation id across servers
- non-public address with authorized team certificate
- non-public address without authorization fails closed
- recipient-binding mismatch fails closed
- replayed federation envelope is idempotent and not double-delivered
- non-public federation send carries the sender team certificate and recipient
  server re-verifies it
- multi-team identity sends from selected team and uses the selected sender
  context
- local same-server behavior remains unchanged
- existing local aliases remain local and do not trigger federation
- namespace without delivery origin fails closed for federated delivery

The e2e test should run two aweb servers and one awid registry. A stronger
matrix can run two awid registries using DNS `registry=` overrides, but the
first implementation can prove delivery federation with one registry.

## Implementation Plan

The executable plan lives in `aw` under epic `aweb-aaou`. Subtasks:

1. `aweb-aaou.1` — Federation model review gate and SOT patch plan.
2. `aweb-aaou.2` — awid schema: namespace `default_delivery_origin` and team
   `coordination_origin`.
3. `aweb-aaou.3` — awid API: expose and authorize delivery and coordination
   origins.
4. `aweb-aaou.4` — Go awid client and resolver support for federation metadata.
5. `aweb-aaou.5` — Federation envelope contract for mail and chat.
6. `aweb-aaou.6` — aweb server: outbound remote mail delivery.
7. `aweb-aaou.7` — aweb server: inbound federated mail receiver.
8. `aweb-aaou.8` — aweb server: outbound remote chat first contact and
   continuation.
9. `aweb-aaou.9` — aweb server: inbound federated chat receiver.
10. `aweb-aaou.10` — Conversation route metadata and delivery-origin rotation
    behavior.
11. `aweb-aaou.11` — CLI send paths and diagnostics for federated delivery.
12. `aweb-aaou.12` — MCP federation inheritance through core mail/chat tools.
13. `aweb-aaou.13` — Federation e2e matrix: two aweb servers and one awid
    registry.
14. `aweb-aaou.14` — Docs and SOT updates after federation model acceptance.

## SOT Updates Needed If This Model Is Accepted

After review, update:

- `docs/awid-sot.md`: namespace default delivery origin, team coordination
  origin, response shapes, auth rules, schema.
- `docs/aweb-sot.md`: federated delivery path, recipient-side auth, conversation
  route metadata, reply semantics, typed routing split between identity-scoped
  and team-scoped operations.
- `docs/identity-messaging-contract.md`: direct-address send protocol should
  include delivery metadata and remote recipient-server verification.
- `docs/teams.md`: a team has one canonical coordination server for team-scoped
  state; mail/chat addresses route by namespace delivery origin.
- `docs/self-hosting-guide.md`: how a self-hosted operator publishes namespace
  delivery origin and team coordination origin.

## Open Questions

1. Should `default_delivery_origin` be required at namespace creation or optional
   until federation is enabled?
2. Should existing hosted namespaces be backfilled by operator tooling or by a
   one-time migration with explicit configuration?
3. Should the recipient server re-resolve the target address on every delivery,
   or accept a short-lived signed address-resolution proof from the sender?
4. How should delivery-origin rotation work for existing conversations?
5. Should a direct `did:aw` send require an explicit delivery hint, or should it
   be limited to already-known conversation participants until a separate DID
   service record exists?
6. Should we ever add per-address delivery override, or wait for a concrete case?

## Minimal First Cut

The smallest coherent implementation is:

1. `dns_namespaces.default_delivery_origin`
2. `teams.coordination_origin`
3. address read returns inherited delivery metadata
4. mail remote first contact
5. chat remote first contact
6. conversation participant route metadata
7. replies by existing conversation id
8. inbound federation replay/idempotency protection

That gives real federation for public and authorized private addresses without
turning team coordination into distributed state replication.
