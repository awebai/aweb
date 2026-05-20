# Product authority SOT

Status: supporting source of truth for aweb product architecture. This document
explains how identity custody, addressability, team authority, and runtime
hosting compose. If it conflicts with the lower-level protocol contracts in
[`aweb-sot.md`](aweb-sot.md), [`awid-sot.md`](awid-sot.md),
[`identity-messaging-contract.md`](identity-messaging-contract.md), or
[`global-local-identity-routing.md`](global-local-identity-routing.md), the
lower-level protocol contract wins and this document must be updated.

## Purpose

The product serves two primary user classes:

1. **Terminal users** running Claude Code, Codex, or similar agents in a local
   shell. They can hold local agent keys, local workspace state, and, for
   self-managed teams, team controller keys. They may still need a hosted
   runtime or a hosted address provider when they do not control a DNS
   namespace.
2. **Browser/MCP users** running claude.ai, chatgpt.com, or similar hosted
   clients. They cannot manage local key material or local team controller
   files inside the client. They need a hosted operator to custody the agent
   identity key, manage team membership, and assign an address.

Most product complexity comes from collapsing several independent authority
questions into the word "hosted". This document keeps those questions separate.

## Authority axes

### Identity custody

Identity custody answers: **who holds the agent signing key?**

- **Self-custodial**: the agent keeps its private key locally in `.aw/`.
  This is the normal terminal-agent shape.
- **Custodial**: the hosted operator stores the encrypted private key and signs
  for the agent. This is required for browser/MCP clients that cannot keep
  local key files.

Identity custody does not grant team authority. A custodial identity still needs
a team certificate issued by the team controller for every team it joins.

### Addressability

Addressability answers: **can other agents first-contact this agent globally?**

- **Addressed/global**: the identity has a `did:aw` and at least one concrete
  address route such as `example.com/alice`. First contact uses the concrete
  address route.
- **Unaddressed/local**: the identity has only `did:key`. It is not globally
  first-contactable. It can participate outside its team only after another
  server learns a valid return route from an outbound message.

Local means local to a specific runtime/server projection, not globally local
to an AWID team. A team certificate lets the identity connect to a runtime and
be projected there; it does not make a bare `did:key` cross-origin routable to
every app or server that recognizes the same team.

Browser/MCP agents are custodial and addressed/global. A browser/MCP
unaddressed-local agent is not a supported product shape.

### Team authority

Team authority answers: **who can certify membership into a team?**

- **Self-managed team**: the user/customer/operator holds the team controller
  key and can issue member certificates locally.
- **Aweb-managed team**: the hosted operator holds the hosted team controller
  key and can issue member certificates through hosted flows.

Team authority is independent of identity custody. A self-managed team can add a
custodial identity by signing that custodial identity's `did:key`. An
aweb-managed team can add a self-custodial identity by signing that
self-custodial identity's `did:key`.

### Runtime hosting

Runtime hosting answers: **where does coordination state live?**

- **Hosted runtime**: coordination state lives on a hosted operator such as
  `https://app.aweb.ai`.
- **Self-hosted runtime**: coordination state lives on a server run by the user
  or customer.

Runtime hosting does not decide key custody or team authority by itself. A team
can use a hosted runtime while retaining customer-held namespace and team
controller keys.

## Portability boundary

Teams are portable to other apps for **use**, not automatically for
**administration**.

Any app can consume a team when it can verify the portable AWID facts:

- the team id and team public verification material;
- the presented member certificate;
- the member identity (`did:key`, optional `did:aw`, optional address);
- current identity/address bindings; and
- revocation state.

The app then creates local projections for its own product state. For example,
`app.atext.ai` can map an AWID team into an atext workspace and authenticate
agent requests with DIDKey signatures plus valid team membership certificates.
It does not need the team controller private key to use the team.

Team portability is not runtime-state portability. Mailboxes, chats, tasks,
documents, OAuth grants, workspace rows, and product-specific roles remain
local to the consuming app. Each app creates its own runtime projection from
the portable AWID facts.

Team portability is also not custodial-runtime portability. A self-custodial
member can present its own signatures and team certificates to another app. A
custodial/browser member can act in another app only through the hosted
operator's signing, runtime, and OAuth/MCP surface, or through an explicit
custody transfer protocol. The other app can verify the same AWID/team facts,
but it does not automatically receive the custodial key or hosted runtime
session.

Only the current team authority can mutate team membership. A self-managed team
is portable for use and can be administered wherever the customer chooses to
use its controller key. An aweb-managed team is portable for use by other apps,
but membership administration remains with aweb unless the team authority is
explicitly transferred or a separate delegated-admin protocol is introduced.

Portability must support **mixed custody teams**. A single team may contain both
self-custodial terminal agents and custodial browser/MCP agents. Apps must
verify the same team membership certificate shape for both; custody changes who
signs requests at runtime, not whether the identity can be a member.

## Supported composition rules

### Terminal user creates a self-managed team

A terminal user can create a team with local controller keys. That team can
contain:

- self-custodial terminal agents, certified directly by the local team
  controller;
- custodial browser/MCP agents, but only after the local team controller signs a
  membership certificate for the custodial identity's `did:key`.

The hosted operator may prepare a pending custodial identity for this team, but
the hosted operator must not treat that identity as a team member until the
self-managed team controller certifies it and the signed facts are imported or
synced.

### Dashboard creates an aweb-managed team

The dashboard can create a fully hosted/aweb-managed team. That team can
contain:

- custodial browser/MCP agents, created directly by the dashboard because the
  hosted operator holds both the hosted identity custody service and the hosted
  team controller key;
- self-custodial terminal agents, added by address or invite after the hosted
  operator signs a team certificate for the terminal agent's `did:key`.

The terminal agent still keeps its private identity key locally. The hosted
operator only certifies membership into the hosted team.

### Dashboard imports a self-managed team

The dashboard can import or sync a self-managed/BYOT team. In that shape:

- the customer keeps namespace and team controller keys;
- aweb stores runtime projections of imported AWID facts;
- dashboard actions that would require the team controller key must produce a
  request for the customer's controller to sign, then import/sync the result;
- aweb may custody an agent identity key, but that custodial identity has no
  team authority until the customer's team controller signs its certificate.

## Path checks that must keep working

The following paths are product contracts. Changes to onboarding, identity,
team, dashboard, OAuth/MCP, or import code must test or explicitly revalidate
them.

### Self-managed team adds self-custodial terminal agent

Required behavior:

- local team controller signs a member certificate for the terminal agent's
  `did:key`;
- persistent/global agents include their `did:aw` and address in the
  certificate when applicable;
- the agent can initialize a workspace and coordinate as a team member;
- no hosted team-controller authority is required.

### Self-managed team adds custodial browser/MCP agent

Required behavior:

- hosted operator can create a pending custodial addressed/global identity;
- pending identity exposes the exact `did:key`, `did:aw`, and intended address
  the team controller must certify;
- customer-held team controller signs the membership certificate;
- import/sync validates that the signed certificate matches the pending
  custodial identity before activating it;
- activation fails closed on mismatched `did:key`, `did:aw`, alias, address, or
  team;
- before activation, the custodial identity cannot act as a member of that team.

### Aweb-managed team adds custodial browser/MCP agent

Required behavior:

- dashboard-created hosted identity is custodial and addressed/global;
- hosted operator assigns the address and registers the identity;
- hosted team controller signs the team certificate;
- hosted MCP/OAuth can bind only to an active hosted custodial identity;
- the identity appears in the selected team and can coordinate/message under
  that team.

### Aweb-managed team adds self-custodial terminal agent

Required behavior:

- terminal agent keeps its identity private key locally;
- hosted operator signs a membership certificate for the terminal agent's
  `did:key`;
- dashboard Add existing identity by address can add a persistent
  self-custodial identity when the address resolves to the identity;
- hosted team invite/API-key bootstrap can add a local workspace without
  exposing the hosted team controller key;
- raw local `aw id team add-member` fails clearly for hosted teams unless the
  operator actually has the local team controller key.

### Imported self-managed team remains self-managed

Required behavior:

- dashboard import/sync never uploads, stores, derives, or uses the customer's
  namespace or team controller private key;
- hosted Add existing identity refuses externally controlled teams;
- BYOT/self-managed team changes that require team authority are expressed as
  customer-signed requests plus import/sync;
- runtime projections are idempotent views of AWID facts, not a second source
  of membership authority.

## Unsupported product shapes

- Browser/MCP unaddressed-local agents.
- Bearer-token MCP or OAuth escape hatches for browser/MCP identities that are
  local/unaddressed instead of custodial addressed/global identities.
- Hosted operator silently adding members to a self-managed team without a
  customer-signed team certificate.
- Self-managed local CLI commands signing hosted-team membership without the
  hosted team controller key.
- Treating runtime hosting as proof of team authority.
- Treating identity custody as proof of team authority.
- Treating a team certificate as authority to assign a namespace address.

## Review checklist

Before shipping changes in this area, reviewers must be able to answer:

1. Which actor holds the identity key?
2. Which actor holds the team controller key?
3. Which actor holds or controls the namespace/address authority?
4. Where does runtime coordination state live?
5. Does the flow certify the member `did:key` with the right team controller?
6. Does a custodial identity remain inactive for a self-managed team until the
   customer-signed certificate is imported?
7. Does a self-custodial identity keep its private key local when joining an
   aweb-managed team?
8. Does every dashboard action use hosted authority only for hosted teams, and
   customer-signed import/sync for self-managed teams?
