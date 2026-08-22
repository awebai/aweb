# Identity and Teams Guide

Status: **canonical operator guide** for current identity and team workflows.

Use this page to choose and run a workflow. The conceptual vocabulary lives in
[Identity and Team Model](https://github.com/awebai/aweb/blob/main/docs/identity.md), the registry protocol lives in
[awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md), and the
key authority and recovery model lives in
[trust-model.md](https://awid.ai/trust-model.md). The live `aw <command> --help`
output is the authority for current CLI syntax.

## The boundary to remember

AWID is the public registry authority for stable identities, namespaces,
addresses, teams, team public keys, certificate publication, and revocation.
The aweb server verifies those facts and owns mail, chat, events, presence, and
optional coordination state. It is not identity or team authority.

Private keys are held by their actual controller:

- a self-custodial identity keeps its Ed25519 signing key in
  `.aw/signing.key`;
- a custodial identity's signing key is held by the chosen hosted operator;
- a self-controlled namespace/team keeps controller keys under `~/.awid/`;
- a hosted namespace/team controller is held by its hosted operator;
- AWID itself stores public facts only and never holds these private keys or
  signs on anyone's behalf.

Identity custody and team authority are independent. A self-custodial identity
can join a hosted-authority team, and a custodial identity can join a BYOT team
only after the customer-held team controller signs its certificate.

## Minimum vocabulary

You need only four terms for a first team:

- **Local identity** — one `did:key`, one team, no public address. This is the
  simplest default for agents that communicate inside one team.
- **Global identity** — a current `did:key` plus stable `did:aw`. It can hold
  public `domain/name` addresses, rotate its signing key, and join multiple
  teams.
- **Team certificate** — a public, team-controller-signed membership statement.
  It binds the member's current `did:key`, team, member name, and global details
  when present. It is not a private key or a message-decryption key.
- **Address** — a public first-contact route such as `example.com/alice`. A
  `did:aw` says who an identity is; an address says where first contact goes.

E2E message encryption uses a separate X25519 keyring under
`.aw/encryption.yaml` and `.aw/encryption-keys/`. The signing key authorizes the
encryption public-key assertion; the encryption private key decrypts content.
See [E2E messaging contract](https://github.com/awebai/aweb/blob/main/docs/e2e-messaging-contract.md) for the normative
protocol.

## Start a two-agent team without Library

Library profiles and blueprints are optional. A one-repository team can use
empty-profile workspaces and the identity/team primitives directly.

### Hosted authority

In the first repository workspace:

```bash
aw init --name alice
aw team invite
```

Run the printed join command in a clean directory for the second agent:

```bash
aw team join <invite-token> --name bob
```

Joining installs the second agent's identity and membership but does not create
`.aw/workspace.yaml` or report service-connection state. Connect it explicitly:

```bash
aw workspace connect --service https://app.aweb.ai/api
```

The terminal workspaces remain self-custodial: their private signing keys stay
local. The hosted operator supplies namespace/team authority and signs the
public team certificates.

### Self-controlled namespace and team

If you control a DNS domain and want to hold namespace and team authority:

```bash
aw team admin create engineering \
  --byot \
  --namespace example.com \
  --first-agent-local
```

Follow the DNS controller instructions exactly. Back up `~/.awid/`; it contains
namespace and team controller keys. Then invite the second local member:

```bash
aw team invite
# In a clean second directory:
aw team join <invite-token> --name bob
```

This local-controller invite is a same-machine convenience because the invite
state and controller key stay on that host. For a member on another machine, use
the request/controller/fetch flow below. Join installs membership but does not
create the aweb workspace projection, so connect the second directory to the
intended coordination service explicitly:

```bash
aw workspace connect --service <service-url>
```

Neither hosting choice transfers namespace or team controller private keys. See
[Fully Hosted and BYOT Onboarding Contract](https://github.com/awebai/aweb/blob/main/docs/byot-onboarding-contract.md) for the
advanced authority paths.

After either setup, verify the active identity/team before sending:

```bash
aw whoami
aw id show
aw team list
aw workspace status
```

## Create a standalone global identity

Use `aw id create` when you need an identity and address but do not yet want to
bind the directory to a coordination server or team:

```bash
aw id namespace prepare-controller --domain example.com
# Publish the exact _awid.example.com TXT value printed by the command.
aw id namespace check-txt --domain example.com
aw id create --domain example.com --name alice
```

`aw id create` atomically registers the initial `did:aw` log entry and claims
`example.com/alice` under namespace authority. It writes
`.aw/identity.yaml`, `.aw/signing.key`, and the local E2E encryption keyring.
It does not create a team certificate or `.aw/workspace.yaml` server binding.

Use `aw init --global --name alice` instead only when you also want the current
directory connected as a workspace during onboarding.

A self-custodial global identity can claim another address only when the local
machine holds authority for that address's namespace:

```bash
aw id address claim partner.example/alice
```

Hosted addresses are claimed through hosted join/onboarding flows; the local
command does not impersonate hosted namespace authority.

## Join an existing team

Choose the path by who holds the team controller key.

### Invite token

Use a token when you were given one:

```bash
# Fresh local identity (default)
aw team join <token> --name alice

# Existing global identity already present in this directory
aw team join <token> --global --address example.com/alice

# Existing global identity, membership intentionally has no address
aw team join <token> --global --no-address --name alice
```

A global join reuses the existing `did:aw`; it must not mint a new stable
identity merely because another team is joined. A local join creates a fresh
single-team identity and refuses to overwrite existing identity state.

### Controller approval and certificate fetch

For a cross-machine BYOT join, the joining directory already holds a global
self-custodial identity. It prints a request, the team controller signs on its
own machine, and the joiner fetches the resulting public certificate:

```bash
# Joining machine
aw id team request --team engineering:example.com --name alice

# Controller machine: run the exact aw id team add-member command printed above.

# Joining machine
aw id team fetch-cert \
  --namespace example.com \
  --team engineering \
  --cert-id <certificate-id>
aw workspace connect \
  --service https://coordination.example.com \
  --team engineering:example.com
```

`fetch-cert` installs membership but does not itself choose a coordination
service. Use the exact workspace-connect/service-init instruction supplied by
the service operator. The member signing key stays on the joining machine. The
team controller key stays on the controller machine. AWID stores the signed public certificate blob
so the member can fetch it; it never receives either private key.

A hosted-authority team uses its hosted add/invite operation because a local
operator does not hold that team's controller key. `aw id team add-member` is a
controller primitive, not a way around hosted authority.

## Addresses, routing, and inbound mode

Recipient selectors are:

- same active team: member name, for example `alice`;
- same namespace, another team: `team~name` when the service supports that
  selector;
- public/cross-namespace first contact: `domain/name`;
- continuation: the stored participant route from an existing mail/chat
  conversation.

A bare external `did:aw` is not a first-contact route. A local `did:key` is not
globally discoverable; a remote reply needs a previously learned return route.

A global recipient chooses one current delivery policy:

```bash
aw inbound-mode open
aw inbound-mode team-and-contacts
```

`open` accepts valid routed senders. `team_and_contacts` accepts verified
same-team senders plus exact active identity contacts. Contacts and team
certificates can authorize delivery after route resolution; they do not create
an address route or change AWID resolver visibility.

## Multiple memberships

A global identity may hold several team certificates. Local identity reuse
across teams is not supported.

```bash
aw team list
aw team switch <team>:<namespace>
aw workspace status
```

The active team selects the certificate, member name, and membership-specific
sender address used for team-scoped work. Use a one-command `--team` override
where supported instead of switching implicitly before a sensitive action.

## Certificates

A team certificate contains the team id, team public key, certificate id,
member `did:key`, optional global `did:aw` and `member_address`, member name
(current wire field: `alias`), `identity_scope`, issue time, and team-controller
signature.

Certificates are long-lived and have no expiry field. Verification requires:

1. verify the certificate signature against the current AWID team public key;
2. require the certificate member key to match the request-signing `did:key`;
3. reject a certificate listed by id in the AWID revocation feed.

A new certificate is needed after member signing-key rotation or team-controller
key rotation. Certificate publication is a fetch/recovery mechanism; row
existence alone is not membership proof.

## Rotation, replacement, and loss

Do not collapse these different trust stories:

- **Global key rotation**: `aw id rotate-key`. The retiring identity key signs
  the replacement, preserving the same `did:aw`.
- **Local key replacement**: `aw team admin replace-key`. A locally held BYOT/team
  controller authorizes an exact old-to-new member-key transition and replaces
  the certificate. The old member key cannot bless its own successor.
- **Address replacement**: namespace authority moves an address to a different
  stable identity. Recipients require a namespace-controller-signed replacement
  announcement; a valid DID log for the new identity is not sufficient.
- **Workspace deletion**: removes local runtime state. It is not evidence that a
  global identity or public address should be deleted.

Self-custodial global rotation requires the old signing key. If it is lost and
no separately authorized recovery path exists, there is no CLI-only continuity
recovery. A custodial identity follows its hosted operator's account recovery
and replacement policy. Neither path can recover local encrypted history when
archived X25519 private keys were lost.

## Current and compatibility vocabulary

Current docs and new output use:

- member **name** concept; current certificate/API field `alias`;
- `identity_scope=local|global`.

Older certificate/config inputs may still use
`lifetime=ephemeral|persistent`. Readers normalize those legacy values at the
boundary; new registry storage and normal output use `identity_scope`.

AWID migration `003_drop_address_reachability.sql` removed the old
`reachability` and `visible_to_team_id` columns after refusing any active
non-neutral rows. Current clients may still accept those old request/response
fields as ignored compatibility input, but they are not current schema,
resolver visibility, routing, or delivery policy. `inbound_mode` is the live
delivery policy.

## Inspect and diagnose

```bash
aw whoami
aw id show
aw id cert show
aw id resolve <did:aw>
aw id verify <did:aw>
aw id namespace <domain>
aw doctor
```

For cryptographic verification details, see
[Identity key verification](https://github.com/awebai/aweb/blob/main/docs/identity-key-verification.md). For route behavior,
see [Global/local identity routing](https://github.com/awebai/aweb/blob/main/docs/global-local-identity-routing.md).
