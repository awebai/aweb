# Identity and Team Model

Status: **canonical conceptual authority** for identities, namespaces,
addresses, teams, and membership. Product docs and CLI work use the vocabulary
and invariants here. The operator path is [identity-guide.md](identity-guide.md),
registry protocol details live in [awid-sot.md](awid-sot.md), and aweb verifier,
routing, and coordination behavior lives in [aweb-sot.md](aweb-sot.md).

AWID is authoritative for public identity/team facts. The aweb server consumes
and verifies those facts; it is not identity, address, or certificate-issuance
authority. A hosted operator may hold controller or identity private keys only
for an explicitly hosted-authority or custodial flow. AWID itself never holds
private keys or signs on anyone's behalf.

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
That migration removed the old registry `lifetime` column. Legacy certificate,
config, or wire fields named `lifetime` remain deprecated-read-compat inputs
only and are normalized to `identity_scope=local|global` at boundaries.

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
work call it **name**. Compatibility output may dual-emit `alias` and `name`;
that does not create two concepts.

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
- A global member may join with no member address (`aw team join --global
  --no-address`). The certificate still carries the global `did:aw` and member
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

Current primitives:

- `aw id create --domain DOMAIN --name NAME` creates a standalone
  self-custodial global identity and claims its first `DOMAIN/NAME`;
- `aw id address claim DOMAIN/NAME` claims an additional address for the
  current self-custodial global identity when the local machine holds that
  namespace's controller authority.

### 2. Create team

**Create team** creates a team inside a namespace and enrolls a first member.
The team is neither local nor global; the enrolled first member is local or
global.

Current surfaces:

- `aw init` is the everyday bootstrap path; `aw team admin create NAME` is the
  advanced explicit team-creation and local-orchestration wrapper.
- `aw id team create --namespace DOMAIN --name NAME` is the controller/admin
  primitive for creating the AWID team record and remains controller-only.
- `aw team admin create` accepts `--first-agent-local` (default) and
  `--first-agent-global`; these flags scope only the enrolled creator, not the
  team itself. For CREATE, `--first-agent-global` may reuse an existing global
  identity or create/publish the founding global identity when hosted or
  namespace-authority context is available.

### Agent naming contract

When an `aw team admin create --agent` or `aw team admin add` spec omits `NAME`, aw resolves
it at commit time through the server-authoritative
`POST /api/v1/agents/suggest-alias-prefix` endpoint, which queries the live team
roster. The shared preview sequence for UI clients is the classic list
`alice`, `bob`, `charlie`, ..., `zoe`, then numbered continuations such as
`alice-01`. Local agent names use the returned prefix directly. Global agent
names apply the user's identity prefix to that server prefix:
`{user}-{suggested-prefix}` (for example `maria-alice`). Commit-time CLI
resolution remains authoritative; previews are advisory and must tolerate a
new suggestion if another actor claims the name first.

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
<token>`. During compatibility, CLI JSON output may dual-emit `alias` and
`name`. Legacy certificate/config `lifetime` input is normalized at decode and
normal output emits only `identity_scope`. The deprecated `--alias` flag remains
a hidden, warning compatibility alias for `--name`. New requests, registry
storage, and product language use `name` as the
concept and `identity_scope=local|global` for scope.

## Command-to-verb mapping

| Verb | Canonical model action | Current command surface | Notes |
| --- | --- | --- | --- |
| Claim address | Birth a global identity in a namespace by claiming `domain/name`, or claim an additional address for an existing global identity | `aw id create --domain DOMAIN --name NAME`; `aw id address claim DOMAIN/NAME` | Global-only. Additional-address claims require namespace authority and use the atomic AWID claim primitive. The standalone `aw id address claim` path is for self-controlled namespaces; hosted addresses are claimed during hosted team accept/join. |
| Create team | Create `name:domain` and enroll the first member | `aw team admin create NAME`; controller primitive `aw id team create --namespace DOMAIN --name NAME` | Team scope is not local/global; first-member scope is local/global. |
| Invite to team | Produce a join capability for a future member | `aw team invite`; `aw id team invite` | The invite scopes the future member, not the team. |
| Join team | Enroll a fresh local identity or an existing global identity | `aw team join <token>`; primitive `aw id team accept-invite <token>` | Scope must be explicit; reuse is global-only. |
| Add local/profile agent home | Materialize an agent home and then perform team join/enrollment | `aw team admin add [NAME@]BLUEPRINT/PROFILE[:local\|global][=RUNTIME]` or `aw team admin add NAME[:local\|global]` | Omitted names use the server-authoritative classic sequence; omitted profile scope comes from `profile.yaml`. |
| Add existing member by controller | Sign/register a certificate for a supplied identity key | `aw id team add-member` | Controller/admin primitive; not the everyday join verb. |
| Fetch certificate | Install an already-issued certificate | `aw id team fetch-cert` | Cross-machine BYOT recovery/install path. |
| Replace local member key | Team-authorized compare-and-swap of a local identity key, old certificate revocation, and replacement certificate issuance | Lost key: `aw team admin replace-key NAME --old-did-key OLD --home AGENT_HOME --generate-new-key`; pre-generated key: pass `--new-did-key NEW` instead | Current OSS CLI path requires the locally held BYOT/team controller key; hosted-authority replacement requires an authorized hosted-operator equivalent. |
| Remove member | Revoke a team certificate | `aw team admin remove-agent <member-address>`; primitive `aw id team remove-member` | Team-scoped revocation; does not delete a global identity. |

These identity/team verbs do not require Library. `aw team admin create` without an
`--agent`, `--profile`, or `--blueprint` selector creates an empty-profile team
workspace; identity enrollment and communication remain complete OSS paths.
Library-backed materialization is an optional orchestration layer above this
model.

## Key material and local files

The active signing key is Ed25519. The public key is encoded as a `did:key`.
For global identities, AWID records a stable `did:aw` identifier and its current
`did:key`.

```text
did:key:z6MkhqSJ722oSGwrirW3ATWmNDNxVjUzBousFXgUWvTJq2R8
```

Self-custodial workspaces store the private key locally in `.aw/signing.key`.
For a local team-scoped identity, that key **is the identity**: generating a new
key without a team-authorized replacement creates a different identity, and
existing correspondents will correctly flag the unexpected key as an identity
mismatch. Copying the complete `.aw/` directory is how the same identity and
membership survive a move to another machine; a fresh checkout plus a freshly
generated key is not continuity.

When forced replacement is necessary, preserve the real local home state
(`.aw/workspace.yaml`, `.aw/teams.yaml`, and the old team certificate). If its
signing key was lost, a local-controller/BYOT team operator runs:

```bash
aw team admin replace-key NAME --old-did-key OLD --home AGENT_HOME --generate-new-key
```

The command refuses to overwrite an existing `.aw/signing.key`, generates and
persists the missing key before the remote transition, updates the roster,
records the transition in the service audit log, revokes the old membership
certificate, installs the new one, and re-signs/publishes the active E2E
encryption-key assertion under the replacement identity. If a present key is
compromised, back it up and remove it deliberately before using
`--generate-new-key`. If replacement
key material was provisioned separately, pass its `--new-did-key` instead.
Without `--home`, pass `--old-cert-id`; the command emits the public replacement
certificate and placement instructions but does not generate or install a
private key. Complete loss of `.aw/` still requires restoring the membership
state from backup or operator records first.

Old-key-signed self-service handover is intentionally unsupported: a stolen
member key must not be able to bless its own replacement. The current OSS CLI
path requires a locally held team controller key; hosted-authority replacement
requires an authorized equivalent from that hosted operator and otherwise goes
through operator support.

Because the roster/audit database and AWID certificate registry are separate
systems, the CLI reconciles an ambiguous roster response by replaying the exact
controller-authorized transition. The server returns the original audit result
only when every DID and certificate field matches. Any post-roster failure
reports the precise partial state and emits the exact audited replacement
certificate material needed for operator recovery. If only E2E assertion refresh
fails, the error confirms that key/roster/certificate replacement completed and
instructs the operator to run `aw id encryption-key setup` from the home. A
generated private key is
retained in the home on every later failure; the error names its path and
`did:key`. Never generate another key for that attempt. Follow the error's
phase-specific recovery: a pre-commit failure may reuse the key via
`--new-did-key`, while a completed roster/certificate transition must not be
replayed merely to repair a later E2E publication failure.

Global identity metadata is stored in `.aw/identity.yaml`. Team certificates
are stored under `.aw/team-certs/`, and membership selection state is stored in
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

## Session grants

A session grant lets a worker process act as an identity for a bounded window
without holding the identity's root keys. The identity mints the grant from
its own `.aw` home:

```
aw id grant mint --scope mail.read,mail.send,chat.read,chat.send \
    --ttl 8h --out /path/to/grant-home
```

Minting generates a fresh session Ed25519 keypair, registers its `did:key`
with the server together with the scopes and expiry, and writes a
self-contained grant home (`grant.yaml` plus the session key — never the
identity's `signing.key`). A process pointed at that directory (via
`AWEB_IDENTITY_HOME` or `--identity-home`) runs `aw mail` and `aw chat`
normally; requests are signed per-request with the session key and the server
attributes the results to the identity.

Scopes are `mail.read`, `mail.send`, `chat.read`, and `chat.send`; grant
requests outside them, and every non-messaging surface (team lifecycle,
leases, reservations, minting further grants), are refused server-side. A
grant expires at its TTL and can be revoked early and idempotently with
`aw id grant revoke <grant-id>`; `aw id grant list` shows each grant as
active, revoked, or expired. Root-authority commands refuse to run from a
grant home, and `aw whoami` there reports the subject identity plus the
grant's status, scopes, and expiry.

## Message verification and trust

Every mail and chat message carries sender identity fields and an Ed25519
signature. Recipients verify the signature against the sender's public key. The
CLI reports verification status on reads such as `aw mail inbox` and
`aw chat open`.

The clients use Trust on First Use (TOFU) pinning for globally addressed peer
continuity. A stable identity is pinned by `did:aw` when available, together
with its observed current key and durable DID-log checkpoint; otherwise the
first verified contact is pinned by `did:key`. Future changes require verified
DID-log/rotation continuity or a namespace-controller-signed address
replacement. Local single-team identities are refreshed against the live team
roster rather than persisted as global address pins. See
[trust-model.md](trust-model.md#tofu-pins-and-durable-continuity).

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
