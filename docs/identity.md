# Identity and Team Model

This document is the canonical aweb model for identities, namespaces, addresses,
teams, and team membership. Protocol details live in [awid-sot.md](awid-sot.md)
and aweb service details live in [aweb-sot.md](aweb-sot.md), but product docs and
CLI work should use the vocabulary and invariants here.

## Entities

### Agent

An **agent** is a running participant: a local CLI runtime, an MCP-connected
runtime, or another active actor using one identity at a time.

### Workspace

A **workspace** is the local `.aw/` directory that binds one machine path to one
active identity and one active team. It stores local runtime state and, for
self-custodial identities, the private signing key.

### Namespace

A **namespace** is a DNS-rooted domain, or a hosted domain such as
`alice.aweb.ai`. It is the container for two orthogonal kinds of names:

- **addresses**: public handles of the form `domain/name`, for example
  `acme.com/alice`;
- **teams**: coordination groups of the form `name:domain`, for example
  `backend:acme.com`.

A namespace can contain many addresses and many teams. Address names and team
names do not collide with each other because they are different kinds of rows.
The registry invariants are:

- active addresses are unique per namespace and name
  (`awid/src/awid_service/migrations/001_registry.sql:83`,
  `idx_public_addresses_namespace_name_active`);
- active teams are unique per domain and name
  (`001_registry.sql:119`, `idx_teams_domain_name_active`);
- active team-member names are unique per team
  (`001_registry.sql:145`, `idx_team_certificates_alias_active`).

The team-certificate scope column is the canonical `identity_scope` added by
`awid/src/awid_service/migrations/004_team_certificate_identity_scope.sql:5`.
Legacy storage or wire fields named `lifetime` are deprecated-read-compat inputs
only and must be normalized to `identity_scope=local|global` at boundaries.

### Identity

An **identity** is the key-holding principal that signs messages and requests.
Aweb has exactly two identity scopes:

- **Local identity**: a `did:key` only. It is born when joining or creating one
  team, has no `did:aw`, has no public address, and belongs to exactly one team.
  A second local team membership means a second workspace/identity, not reuse of
  the first local identity.
- **Global identity**: a `did:key` plus a stable `did:aw` registered at AWID. It
  is born in a namespace by claiming an address, can belong to many teams, and
  can hold zero, one, or many addresses over time.

Reuse is therefore **global-only**: the same global `did:aw` may be enrolled in
many teams; a local identity is single-team.

### Address

An **address** is a public `domain/name` handle bound to a global `did:aw`.
Addresses are first-contact routes for global identities. A global identity may
hold several addresses, but the addresses are handles for the same identity, not
separate principals.

Only namespace authority can claim an address in that namespace. In a hosted
namespace, the hosted operator holds that authority; in a self-controlled
namespace, the local namespace controller key does. A team controller key alone
is not namespace authority.

### Team

A **team** is a coordination boundary: tasks, roles, locks, instructions,
workspace status, and same-team member lookup are team-scoped. A team belongs to
a namespace and is identified as `team:domain`.

Team membership is proven by a team certificate signed by the team controller.
The certificate binds an identity's current `did:key` to a team and gives that
membership a **member name**: the per-team routing key. The current registry and
certificate wire field for this value is still `alias`; product docs and new CLI
work should call it **name** until the scheduled wire/schema rename completes.

## Name and address rules

- A **member name** is the team-local routing key for one team membership, for
  example `alice` in `backend:acme.com`.
- An **address** is a namespace-qualified public handle, for example
  `acme.com/alice`.
- Local identities have a member name and no address.
- Global identities may have a member name plus a selected member address in a
  team certificate.
- For a global team member, the member name equals the address local part. If
  the selected member address is `acme.com/alice`, the member name is `alice`.
- By default, a global join uses the team domain for the address:
  joining `backend:acme.com` as name `alice` presents or claims
  `acme.com/alice`.
- Cross-namespace membership is advanced: a member may present an already-owned
  address from another namespace, such as `partner.com/alice`, while joining
  `backend:acme.com`. The member name is still the address local part,
  `alice`.
- A global member may join with no member address (`--no-address` in planned CLI
  vocabulary). The certificate still carries the global `did:aw` and member
  name, but that membership is not first-contactable by a team-domain address.

### Authority-gated default address claim

Default address claim is canonical but authority-gated:

- If the join/create flow has namespace authority for the team domain, it may
  claim `team-domain/name` by default. This includes hosted namespaces where the
  operator holds namespace authority and self-controlled namespaces where the
  local controller key is available.
- If the flow has only team authority, it must not silently claim an address.
  BYOT/local-controller team invites carry the team controller key, not the
  namespace controller key.
- Without namespace authority, a global join must either present an address the
  identity already owns or explicitly choose no address.
- Claiming an additional or cross-namespace address for an existing global
  identity is a separate address-claim primitive, not an implicit side effect of
  team join.

## The three verbs

Everything user-facing composes three orthogonal verbs.

### 1. Claim address

**Claim address** births or extends a global identity in a namespace. It creates
or reuses a `did:aw` and binds a `domain/name` address under namespace
authority.

Current primitive:

- `aw id create --domain DOMAIN --name NAME` creates a standalone
  self-custodial global identity and claims `DOMAIN/NAME`.

Planned address-claim work adds the path for an existing global identity to
claim an additional address.

### 2. Create team

**Create team** creates a team inside a namespace and enrolls a first member.
The team is neither local nor global; the enrolled first member is local or
global.

Current and planned surfaces:

- `aw team create NAME` is the everyday workflow wrapper.
- `aw id team create --namespace DOMAIN --name NAME` is the controller/admin
  primitive for creating the AWID team record and remains controller-only.
- Planned first-member flags should name the scoped subject, for example
  `--first-agent-local` or `--first-agent-global`, rather than implying that the
  team itself is local or global.

### 3. Join team

**Join team** enrolls an identity into a team and installs a team certificate.
It either births a fresh local identity for a fresh local join, or enrolls an
existing global identity.

Rules:

- Scope is explicit: local vs global must be selected by the join request, not
  inferred from whether an address string is present.
- Fresh local joins may mint a new `did:key` and are single-team.
- Global joins reuse an existing global identity and its stored `did:aw`; they
  must not mint a new `did:aw` merely because the identity joins another team.
- A global join without an existing global identity should fail with guidance to
  claim/create a global identity first.

Current surfaces include `aw id team accept-invite <token>` and `aw team join
<token>`. Compatibility surfaces may still expose `alias` or `lifetime` wording
until the scheduled CLI cleanup lands; the model term is `name`, and the scope
terms are `local` and `global`.

## Command-to-verb mapping

| Verb | Canonical model action | Current command surface | Notes |
| --- | --- | --- | --- |
| Claim address | Birth a global identity in a namespace by claiming `domain/name` | `aw id create --domain DOMAIN --name NAME` | Global-only. Additional-address claim for an existing identity is planned separately. |
| Create team | Create `name:domain` and enroll the first member | `aw team create NAME`; controller primitive `aw id team create --namespace DOMAIN --name NAME` | Team scope is not local/global; first-member scope is local/global. |
| Invite to team | Produce a join capability for a future member | `aw team invite`; `aw id team invite` | The invite scopes the future member, not the team. |
| Join team | Enroll a fresh local identity or an existing global identity | `aw team join <token>`; primitive `aw id team accept-invite <token>` | Scope must be explicit; reuse is global-only. |
| Add local/profile agent home | Materialize an agent home and then perform team join/enrollment | `aw team add NAME[@BLUEPRINT/PROFILE]` | Workflow wrapper, not a separate identity model. |
| Add existing member by controller | Sign/register a certificate for a supplied identity key | `aw id team add-member` | Controller/admin primitive; not the everyday join verb. |
| Fetch certificate | Install an already-issued certificate | `aw id team fetch-cert` | Cross-machine BYOT recovery/install path. |
| Remove member | Revoke a team certificate | `aw team remove-agent <member-address>`; primitive `aw id team remove-member` | Team-scoped revocation; does not delete a global identity. |

## Key material and local files

The active signing key is Ed25519. The public key is encoded as a `did:key`.
For global identities, AWID records a stable `did:aw` identifier and its current
`did:key`.

```text
did:key:z6MkhqSJ722oSGwrirW3ATWmNDNxVjUzBousFXgUWvTJq2R8
```

Self-custodial workspaces store the private key locally in `.aw/signing.key`.
Global identity metadata is stored in `.aw/identity.yaml`. Team certificates are
stored under `.aw/team-certs/`, and membership selection state is stored in
`.aw/teams.yaml` and `.aw/workspace.yaml`.

E2E message decryption uses a separate local X25519 keyring, not the Ed25519
signing key. Self-custodial clients store it in `.aw/encryption.yaml` and
`.aw/encryption-keys/`. New self-custodial identity and membership paths create
the local encryption key automatically, including `aw id create`, `aw init`,
`aw service init`, `aw id team accept-invite`, and `aw id team fetch-cert`.
Run `aw id encryption-key setup` to repair or publish missing key state, and
`aw id encryption-key rotate` when rotating encryption material. Back up
`.aw/encryption-keys/`; losing archived encryption keys makes old encrypted
messages unrecoverable.

## Team membership and authentication

Identity and team membership are separate:

- AWID owns namespaces, addresses, teams, DID mappings, and certificate issuance
  records.
- Aweb owns coordination state inside the team.
- A team certificate authorizes team-scoped coordination for one identity and
  member name.

Aweb coordination endpoints authenticate the agent with its DIDKey signature plus
the active team certificate referenced from `.aw/workspace.yaml`; see
[aweb-sot.md](aweb-sot.md) for the exact request contract.

For cross-machine BYOT membership, the controller signs and registers the full
public certificate blob with AWID via `aw id team add-member`. The joining
machine then uses its local identity key to run `aw id team fetch-cert
--namespace DOMAIN --team TEAM --cert-id ID`, which downloads, verifies, and
installs the certificate locally. The team controller private key never leaves
the controller machine.

## Message verification and trust

Every mail and chat message carries sender identity fields and an Ed25519
signature. Recipients verify the signature against the sender's public key. The
CLI reports verification status on reads such as `aw mail inbox` and
`aw chat open`.

The CLI uses Trust on First Use (TOFU) pinning for peer verification. On first
contact it records the sender's observed identity key. Future messages are
checked against that pin unless a valid rotation or replacement flow explains
the change.

## Lifecycle terms

Do not collapse lifecycle actions into a generic "identity reset":

- **Delete**: local workspace teardown. It can release a local member name for
  reuse in that team.
- **Archive**: global identity cleanup without continuity claim.
- **Replace**: owner-authorized replacement of a global public address.
- **Rotate key**: cryptographic continuity signed by the old key.

Global identity lifecycle is distinct from workspace path lifecycle. A missing or
deleted local workspace path is not evidence that a global identity should be
deleted, archived, replaced, unclaimed, or reassigned. OSS aweb only treats
confirmed gone local workspaces as cleanup candidates; global lifecycle actions
require explicit authority and reviewed lifecycle flows. See
[OSS Support Tools](support-tools.md) for doctor, support bundle, registry read,
and high-impact handoff behavior.

## Further reading

- [awid-sot.md](awid-sot.md): protocol and registry contract.
- [aweb-sot.md](aweb-sot.md): coordination server contract.
- [global-local-identity-routing.md](global-local-identity-routing.md): route-level messaging model that supports this identity model.
- [identity-key-verification.md](identity-key-verification.md): key verification details.
