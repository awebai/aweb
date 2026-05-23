# Identity and Messaging Contract

This document is the normative contract between awid, the `aw` client, and the
aweb server for identity-scoped mail and chat. It follows the global/local model
in [`global-local-identity-routing.md`](global-local-identity-routing.md).

## Authority Boundaries

| Component | Authority | Not authority |
|-----------|-----------|---------------|
| awid | Global truth for `did:aw`, current `did:key`, DID logs, namespace address rows, address-route origins, team public keys, and certificate revocation events. | Message delivery, local aliases, mailbox state, private key custody, active membership oracle, or bare-`did:aw` delivery route. |
| Self-custodial client | Holds the identity private key, signs message envelopes, and can bind a recipient address to the resolved `did:aw` and current `did:key`. | Namespace address assignment unless it also holds the namespace controller key. |
| Hosted signer | Holds the private key for a custodial identity and signs the same message envelopes as a self-custodial client. | A separate trust model; hosted identities must satisfy this same contract. |
| aweb server | Authenticates transport requests, routes and stores mail/chat, validates signed recipient bindings, and stores participant route state for continuations. | Registry authority, caller private-key authority, address reachability authority, or conversation-id-only routing authority. |
| Local route state | Stored participant/session route authority for local `did:key` continuations. | Global identity authority or first-contact authorization by itself. |

## Global And Local Identities

- **Global identity**: durable `did:aw`, AWID-registered current `did:key`,
  and one or more address aliases. Delivery routes belong to addresses, not to
  the identity row.
- **Local identity**: `did:key` only, no AWID row, no `did:aw`, no stable/global
  ID, and no global first-contact address.

Team certificates remain valid for team membership, local ACLs, and certificate
verification flows. They are not an address reachability or message routing
oracle.

Global recipients expose an explicit delivery-time `inbound_mode`:

- `open`: accept valid senders after address route and identity binding
  validation. User-facing label: **All**.
- `team_and_contacts`: after the same route and identity validation, accept
  verified same-team members or an exact active identity contact for the
  verified sender address. User-facing label: **Team and contacts**.

Rows without an explicit `inbound_mode` require migration and must fail with an
explicit migration-required diagnostic rather than silently widening to open.

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
5. Federation delivery uses the resolved delivery origin and the target identity
   binding. The recipient server re-resolves the target address/key and fails
   closed on mismatch.

Direct bare `did:aw` first-contact sends are unsupported: use a concrete
address (`domain/name`) or an existing conversation/session with stored route
state. Direct local `did:key` sends require stored route state; a bare
self-asserted `did:key -> origin` claim is not enough.

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

## Federation Compatibility

Federation envelope version 1 has a bounded release-window tolerance for four
fields emitted by older servers:
`sender_active_team_id`, `sender_team_certificate`,
`target_address_lookup_authorization`, and `target_address_lookup_timestamp`.
New senders omit these fields. New receivers may accept them only as ignored,
deprecated input so mixed-version public/global federation does not fail at
schema validation. They must not affect routing, lookup, authorization, policy,
recipient selection, or signed-payload validation.

## Forbidden Shortcuts

- Do not route global direct-address mail or chat solely because a matching local
  row exists.
- Do not pass a caller `did:key`, team certificate, or forwarded lookup header to
  AWID as private address-read authority.
- Do not treat address reachability, `visible_to_team_id`, contact membership,
  or conversation ID as routing authority. Contacts authorize only the explicit
  delivery-time `team_and_contacts`/local-contact gate and never create a
  route. Verified team membership also authorizes `team_and_contacts`, but does
  not create routes.
- Do not use stale cache entries as evidence for a recipient binding.
- Do not infer a canonical sender address by listing all addresses for a
  `did:aw`; use the selected identity address for that context.

## Test And Release Gates

Changes touching identity resolution, address lookup, mail, chat, hosted custody,
certificates, local aliases, or registry caching must prove:

- global direct-address first contact succeeds through AWID resolution,
- local identity continuations use stored route state and fail closed without it,
- bare external `did:aw` first-contact fails closed without stored route state,
- stale local rows and conversation IDs do not bypass AWID or stored routes,
- federation verifies target identity and delivery-origin binding.
