# Identity and Messaging Contract

This document is the normative contract between awid, the `aw` client, and
the aweb server for identity-scoped mail and chat. It exists because address
reachability, recipient binding, local routing state, and hosted custody cross
service boundaries. Keeping those boundaries explicit is part of the release
contract.

## Authority Boundaries

| Component | Authority | Not authority |
|-----------|-----------|---------------|
| awid | Global truth for `did:aw`, current `did:key`, DID logs, namespace address rows, address reachability, teams, and certificate records. | Message delivery, local aliases, mailbox state, or private key custody. |
| Self-custodial client | Holds the identity private key, signs private address lookups, signs message envelopes, and can bind a recipient address to the resolved `did:aw` and current `did:key`. | Namespace address assignment unless it also holds the namespace controller key. |
| Hosted signer | Holds the private key for a custodial identity and signs the same lookups and envelopes as a self-custodial client. | A separate trust model; hosted identities must satisfy this same contract. |
| aweb server | Authenticates transport requests, routes and stores mail/chat, evaluates messaging policy, and validates signed recipient bindings supplied by the client. | Registry authority, caller private-key authority, or address reachability authority. |
| Local pin store | Local fallback for already-known peers after registry resolution is unavailable or misses. | Replacement for awid address truth. |

The critical rule is simple: **a persistent public address is owned by awid,
not by aweb local rows**. Local persistent rows are cache and routing state.
They may help find a local recipient, but they do not prove that `domain/name`
currently maps to that recipient.

## Identity And Address Separation

`did:aw` is the durable identity. It maps to a current `did:key` through the
awid DID log. A namespace address such as `example.com/alice` is a separate
fact created and reassigned by the namespace controller. One identity may have
zero, one, or many addresses, and an address may be reassigned to a replacement
identity by the namespace controller.

Team certificates add a third fact. A certificate can carry a
`member_address`, but that value is the selected sender address for a specific
team membership. It is not a global canonical address for the identity.

## Direct Address Send Protocol

For a send to a persistent address (`domain/name`), the expected path is:

1. The client classifies the target as a registry address, not a local alias.
2. The client signs an awid `get_address` lookup with the caller identity key
   or a valid persistent team certificate key.
3. awid resolves the caller `did:key` to `did:aw`, evaluates the target
   address reachability, and returns the target `did:aw` and current `did:key`
   if authorized.
4. The client signs the mail or chat envelope, including the target address and
   resolved recipient identity binding (`to`, `to_stable_id`, `to_did`).
5. The aweb server authenticates the request sender and validates that any
   behavior-shaping outer fields match the signed envelope.
6. The server resolves the route through awid when it can. If awid cannot
   resolve the persistent address, the server may use a local persistent row
   only when the client's signed recipient binding matches that row. A bare
   persistent local fallback must fail closed.
7. The recipient can verify that the message signature and recipient binding
   agree with the addressed identity.

`did:aw` sends can bypass address discoverability because the caller already
knows the identity. Address sends cannot bypass reachability merely because a
local row exists.

## Fail-Closed Rules

- If a direct-address send requires recipient binding and registry or pin
  resolution returns an error, the client must stop before posting the message.
- If a server receives a bare persistent direct-address send and cannot verify
  the address through awid or through a matching signed client binding, it must
  return not found instead of routing through a persistent local row.
- A `did:key` value by itself does not let the aweb server perform a private
  awid address read. The private read requires a signature by the caller's
  private key; the server must not treat a supplied key string as that proof.
- Unauthorized or anonymous reads of non-public awid addresses return not found,
  not forbidden, to avoid leaking address existence.
- Ephemeral local rows are different: they are server-local coordination state
  and may use local alias/address fallback because they are not claiming awid
  address authority.

## Reachability Matrix

| Reachability | Who may discover the address at awid |
|--------------|--------------------------------------|
| `public` | Anonymous callers and signed callers. |
| `org_only` | The owner, or a caller with an active persistent team certificate in the same namespace domain. |
| `team_members_only` | The owner, or a caller with an active persistent team certificate for `visible_to_team_id`. |
| `nobody` | The owner only. A known-agent pin may support a local send to an already-known peer after registry miss, but it is not registry authorization. |

Messaging policy is a separate aweb decision after discoverability. awid answers
"may the sender learn this address binding?" aweb answers "may this sender
deliver to this recipient?"

## Forbidden Shortcuts

- Do not route persistent direct-address mail or chat solely because a matching
  local persistent row exists.
- Do not pass a caller `did:key` to awid from the server and assume that this
  authorizes a private address read.
- Do not let tests mock a successful private address read without proving the
  client-signed lookup path or the server's signed recipient-binding path.
- Do not use stale public cache entries as evidence for private reachability.
- Do not infer a canonical sender address by listing all addresses for a
  `did:aw`; use the selected identity address or the active certificate's
  `member_address` for that context.

## Test And Release Gates

Any change touching identity resolution, address lookup, mail, chat, hosted
custody, certificates, local aliases, or registry caching must run an e2e matrix
that proves both success and fail-closed behavior.

OSS release gates must cover mail and chat for:

- public direct address
- `org_only` address from an authorized persistent teammate
- `team_members_only` address from an authorized persistent teammate
- unauthorized no-pin direct-address send failing closed before delivery
- `nobody` address known-pin fallback to an already-known peer
- direct `did:aw` / stable identity send

Cloud release gates must additionally cover hosted custodial identities from
both dashboard and CLI paths, with and without BYOD/self-custodial participants.
Hosted custody is an implementation choice, not a relaxation of the recipient
binding and reachability rules.

Registry cache invalidation in tests and production tooling must include the
caller-scoped address and domain caches used by private reachability checks.
Tests should avoid broad cache clearing unless the behavior under test really is
cache cold-start behavior.

## Review Checklist

Before accepting a change in this area, reviewers should be able to answer:

- Which component is the source of truth for every identity and address fact
  used by the change?
- Does any server path rely on private-key authority it does not have?
- Does every persistent direct-address path either resolve through awid or carry
  a matching signed recipient binding?
- Are ephemeral local fallbacks kept separate from persistent address authority?
- Do mail and chat have equivalent coverage?
- Do self-custodial and hosted custodial identities exercise the same contract?
