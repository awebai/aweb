# Federated Messaging Architecture

Status: historical architecture note updated to match the current route-level
contract. The normative shipped contract lives in
[`identity-messaging-contract.md`](identity-messaging-contract.md) and
[`global-local-identity-routing.md`](global-local-identity-routing.md). If this
note conflicts with those SOTs, the SOTs win. Epic `aweb-aapg` supersedes this
document's older identity-level-origin notes with the route-level model.

This note describes the federation model for OSS aweb and awid. Treat it as
background and implementation history, not a second authority.

Historical tracking epic: `aweb-aaou` — Federated messaging architecture:
namespace delivery origins. Current shipped guidance is the route-level contract
in the SOTs linked above.

Scope: federation v1 is **messaging-only**. It covers mail and chat. Tasks,
work queues, presence, roles, instructions, team manuals, and other team-scoped
coordination state remain local to one aweb server and are out of scope for this
model.

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
  address-route delivery origins, team public keys, certificates, and revocation.
- aweb is the source of truth for coordination state: mail, chat,
  conversations, tasks, presence, work queues, roles, and instructions.
- A coordination server must not invent address authority from local rows.
- A message must carry a verifiable signed binding to the resolved recipient.

## Implemented Status

The route-level contract is implemented by the `aweb-aapg` simplification work:

- first-contact `domain/name` address lookup goes through awid;
- awid resolves the address to `did:aw`, current `did:key`, and address-route
  delivery origin inherited from namespace `default_delivery_origin`;
- legacy reachability metadata is not a resolver or delivery-auth gate;
- aweb mail/chat use the address route for first contact and stored participant
  route state for continuation;
- bare external `did:aw` first contact fails closed without stored route state.

Local bootstrap state may also carry an aweb URL (`.aw/workspace.yaml`,
`.aw/teams.yaml`, local invite tokens, hosted invite responses), but that local
state is not global route authority for first contact.

## Scope And Granularity

Mail/chat delivery should be **namespace/address-scoped**, not team-scoped.
Team coordination is deliberately not federated in v1.

The important split is operation type:

```text
Federated mail/chat to domain/name -> namespace default delivery origin
Tasks/work/presence/roles/instructions -> local aweb server only
```

### Why Not Identity

An identity can belong to multiple teams and can hold addresses in multiple
namespaces. Putting a delivery server on `did:aw` would collapse those contexts
into one global home server and would not compose with BYOT or multi-team
identities.

### Why Not Team For Mail/Chat

Mail/chat is identity-scoped. The recipient can belong to several teams, the
sender can belong to several teams, and they may or may not share any team.
Choosing one recipient team as the delivery route is a phantom decision: the
message is addressed to `domain/name`, not to one of the recipient's teams.

The sender's active team may select sender context such as the sender address.
It does not choose the recipient's inbox server or authorize recipient delivery.

### Why Namespace

A namespace controls addresses under `domain`. If a sender addresses
`domain/name`, the namespace is the natural authority for where that address's
mailbox lives.

This also matches the authority model: a namespace controller can already assign
or reassign `domain/name` to a `did:aw`, so allowing it to declare the namespace
mail/chat delivery origin does not introduce a stronger authority.

### Route Rule

```text
Namespace owns the default mail/chat delivery origin.
Address inherits the namespace delivery origin.
Identity can belong to many teams.
Sender selects active team when sending.
Recipient address selects delivery origin when receiving first contact.
Conversation participants store the concrete return route for replies.
Team-scoped coordination is not federated in v1.
```

## Registry Model

AWID namespace metadata carries a default mail/chat delivery origin:

```text
dns_namespaces.default_delivery_origin = "https://aweb.example.com"
```

Address records inherit that value. Per-address override is a future extension;
the current route-level contract uses namespace default inheritance.

Address lookup returns identity and delivery metadata:

```json
{
  "address": "beta.example/bob",
  "did_aw": "did:aw:...",
  "current_did_key": "did:key:...",
  "delivery": {
    "origin": "https://aweb.beta.example",
    "source": "namespace_default"
  }
}
```

Namespace lookup returns:

```json
{
  "domain": "beta.example",
  "controller_did": "did:key:...",
  "verification_status": "verified",
  "default_delivery_origin": "https://aweb.beta.example"
}
```

The namespace controller authorizes `default_delivery_origin`. Team metadata is
not changed by messaging federation v1.

## Sending Path

For first contact, Alice sends to `beta.example/bob`:

1. Alice's local client selects her active team.
2. Alice resolves `beta.example/bob` through awid; address lookup is not an authorization surface.
3. awid returns:
   - target `did:aw`
   - target current `did:key`
   - target delivery origin inherited from the namespace
4. Alice signs the normal mail/chat message payload with:
   - sender `did:aw` and current `did:key`
   - sender selected address, if any
   - target address
   - resolved target `did:aw`
   - resolved target current `did:key`
   - message body, message id, conversation id if present, and timestamp
6. Alice's aweb server wraps that preserved signed payload in a federation
   transport envelope that adds:
   - sender delivery origin, as route metadata for replies
   - target delivery origin
7. Alice's aweb server sends the federation request to the target delivery
   origin.
8. The recipient aweb server verifies the preserved sender-signed payload,
   re-resolves the first-contact target address/delivery origin, and stores the
   message in the recipient's local inbox/chat state.

For continuation, the target route comes from stored participant/session route
state rather than address rediscovery. The recipient server validates that stored
route state, including the participant identity binding and current key when
known, before accepting the continued message.

The sender's local aweb server may keep a local conversation projection, but
the authoritative recipient inbox lives on the recipient delivery server.

## Recipient Server Verification

The recipient server must verify:

1. The sender DIDKey signature over the preserved mail/chat message payload.
2. The sender `did:key` is current for sender `did:aw`, unless a valid rotation
   window or signed key evidence is explicitly accepted by the SOT.
3. For address first-contact, the signed `to_address` still resolves through
   awid to the signed recipient `did:aw`, current `did:key`, and address-route
   delivery origin.
4. For continuation, stored participant/session route state validates the
   recipient identity binding, current key when known, and delivery origin. A
   bare `did:aw` or conversation id alone is not routing authority.
5. The resolved or stored delivery origin matches this server's origin, or this
   server is explicitly authorized to accept for that origin.
6. The timestamp is inside the accepted skew window.
7. The message id has not already been accepted for this sender/recipient route.
   Duplicate message ids are idempotent, not double-delivered.
8. The sender is allowed by the recipient's `inbound_mode`.
9. Conversation continuation is valid only when the caller is an existing
   participant and the stored participant route state validates.

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
`delivery_origin` route hint with the stored participant identity binding. The
reply still carries a preserved sender-signed message payload inside a
federation transport envelope and is verified by the original sender's server.

The sender delivery origin carried in the federation transport envelope is
route metadata, not identity authority. The sender identity authority remains
the preserved sender-signed mail/chat payload and AWID current-key check.

This is what lets a local or legacy address reply after first contact:
conversation participation stores the reply route; address rediscovery is not
routing authority.

## Direct `did:aw` Sends

An address lookup can return delivery metadata because an address selects a
namespace. A bare `did:aw` lookup does not select a namespace, so it does not
select a delivery origin.

For the route-level model, a bare `did:aw` send across servers is limited to an
existing conversation participant route. First contact must use a concrete
address route.

It must not guess a home server from arbitrary local rows or by listing all
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

Sending may use the active team context to choose local sender presentation.
That selected context determines:

- sender address for that team, if any
- sender route metadata for replies

Receiving by address uses the address namespace's delivery origin. Team
memberships are not part of receive routing. If an identity has addresses in
multiple namespaces, each namespace can route to a different delivery origin;
a unified local view can poll those inboxes, but first-contact routing remains
address-scoped.

## Team Coordination Is Out Of Scope

Federation v1 does not make teams distributed. A team can have members whose
identities and addresses live in different namespaces, but tasks, presence,
work queues, roles, instructions, and manuals remain on the aweb server that
hosts that team.

Cross-server team membership can still exist because membership is a
certificate, not proof that the member's address inbox lives on the same server.
That certificate does not create a cross-server task store or authorize
recipient delivery.

## Historical Implementation Notes

The original `aweb-aaou` plan was the implementation path for namespace
`default_delivery_origin`, address-route delivery metadata, remote mail/chat
federation, participant route storage, and self-hosting setup. Those proposal
sections are no longer live implementation guidance; the current contract is the
route-level model captured in the SOTs.

Current shipped guidance:

- namespace `default_delivery_origin` is address-route inheritance metadata;
- address reads return the concrete route metadata needed for first contact;
- mail/chat first contact uses concrete address routes;
- replies and continuations use stored participant/session route state;
- recipient servers validate identity binding, current key when known, delivery
  origin, replay/idempotency, and `inbound_mode`;
- MCP and hosted surfaces call the same mail/chat semantics rather than defining
  a separate federation model.

Historical tests from the original plan remain useful as regression categories
when they are phrased against the current contract: cross-server address first
contact for `open` and `contacts_only`, contacts-only rejection without an exact
active identity contact, stored-route replies, recipient-binding mismatch,
replay/idempotency, multi-team sender context, local alias non-federation, and
fail-closed behavior when a namespace/address route lacks a delivery origin.

## Future Design Questions

These are not open gates for the current route-level contract; they are possible
future extensions:

1. Whether to add per-address delivery-origin overrides or keep namespace
   inheritance until a concrete use case requires override authority.
2. Whether direct bare `did:aw` first contact should ever be supported through a
   DID service record. It is unsupported today and requires a separate design.
3. How to represent delivery-origin rotation for long-lived stored participant
   routes beyond the current fail-closed validation model.

The minimal shipped shape is address-routed mail/chat first contact, stored
participant-route continuation, and local-only team coordination.
