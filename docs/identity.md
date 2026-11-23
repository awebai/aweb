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

The [identity certificates v1 candidate](id-certificates.md) defines a
parent-signed human/agent tree rooted in DNS namespace authority, alongside
unchanged team certificates. The nearest human answers for an agent;
membership, roles and custody stay separate. Implementation follows contract
review. The former [email attribution candidate](drafts/member-attribution.md) is
superseded and must not be implemented.

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

### Pending private-team key confirmation

Hosted creation can return a usable certificate while its registry registration
is pending. The client checks the artifact signature and its binding to the
home's signing key, but an unregistered member cannot read a private team's
metadata. An absent certificate-status response or a private-read refusal is
not evidence that the registry agrees with the supplied team key.

The CLI records this key in the membership's `teams.yaml` entry as
`team_key: {did_key: ..., state: unconfirmed}`. The same field becomes
`state: confirmed` only when an existing registry read independently supplies
the matching key. A public team's metadata may supply that evidence before
certificate registration; a private team's certificate-status read can supply
it after registration. Normal certificate clients recheck an unconfirmed key
before using the credential. A definite mismatch refuses with a sentence
saying the key this agent was given does not match the registry's and to ask
the team's owner. An unreachable registry leaves the key unconfirmed, without
adding a registration requirement to a supported pending flow. Certificate,
request-signature, revocation and server admission rules still apply.

A confirmation is agreement with the selected registry's current-key answer;
it does not authenticate that answer against a new trust root or resolve the
separate question of trusting registry-supplied first team keys. No new
registry endpoint is introduced here. Offline `aw doctor` performs no network
read and explicitly reports an unconfirmed stored key and what will confirm
it. Online doctor probes the same owner and reports unavailable evidence as
unknown, naming the registry; doctor remains read-only. These rules implement
Antares245fb075, relayed in coordinator37ecee52.

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

- `aw init --join-from ...`, `aw init --admission-team-id ...` and
  `aw init --invite ...` follow the same
  rule: local is the default, while `--global` is an opt-in to reuse the current
  self-custodial global identity. They do not silently downgrade `--global` to a
  local join. `aw init --workspace-team` and `aw init --join-from` accept
  `--identity-home` for an explicitly named fresh destination. Hosted
  workspace-team and admission init outcomes also require an explicit expected
  account id (`--expect-account`) chosen from `aw auth status --json`; the CLI
  sends it as `expected_account_id` and fails closed if the logged-in account or
  recorded owner does not match.
- These global init joins preserve the existing identity and signing key, but
  refuse to overwrite an existing `workspace.yaml`. Use ordinary `aw init` to
  reconnect that workspace, or a separate invite acceptance to add membership
  without replacing its workspace binding.

A parent source and a team invite can be selected independently:
`aw init --parent <creator-home> --invite <token>`, or
`aw id team accept-invite --local --parent <creator-home> --token-stdin`.
`aw team join` accepts the same `--parent` option. The creator home must be on
this machine; its own key signs the fresh child's ID certificate. An existing
chain is never changed by joining: omit `--parent` to reuse it. Local identities
still join only their first team; use a global identity to reuse membership
across teams.

`aw team invite --for-human <did:aw>` and `aw id team invite --for-human <did:aw>`
admit agents whose verified nearest human is that person. Without the option,
the issuer's verified nearest human is the default; an issuer with none sets no
condition. The dashboard's generic invite uses that same default. The condition
is stored with the invite, never trusted from the bearer token, and is checked
before membership is granted, including for an issuer-created fresh child.
A conditioned join requires current registry evidence: a revoked or replaced
person refuses, and unavailable status refuses with `evidence_unavailable`.
There is no fallback to admission without this check.

A definitive hosted human-condition refusal releases the pending join when no
earlier submission is uncertain. The identity, key and chain remain available
for a correct invite. An interrupted attempt or unavailable evidence keeps the
original invite and selection for resumption.

On a hosted accept-invite HTTP 409 with code `registry_operation_in_progress`,
`aw` can repeat the same signed acceptance with the same body, key and request
ID. It makes at most three attempts, with replays limited to five seconds
from the start of the original POST. A `Retry-After` that exceeds that budget
ends automatic retries. `aw` returns other 409s and HTTP 503
`registry_operation_incomplete` without sending another POST.

With Cloud 0.8.82, the server itself queues an overlapping acceptance for up
to 20 seconds. If it waits the full 20 seconds and returns
`registry_operation_in_progress` or `registry_operation_incomplete`, `aw`
prints the recovery command without replaying. The client retry helps with
Cloud 0.8.81 and when the lease for the requested name causes an early
overlap response.

For a persistent overlap or incomplete operation, preserve the identity home
and run the printed recovery command from the same directory after the service
is ready. Repeat `aw init --join-from` with the same selection, or reuse the
original supplied invite in `aw team join` or `aw id team accept-invite` as
directed.

If a first submission timed out and its retry then returned 409, or an invite
expired after a possibly applied submission, the earlier attempt may have
succeeded. State stays in `<identity-home>/hosted-invite-creation.json`, with
`init-invite.json` alongside it for `init --join-from`. Check with the hosting
service whether this agent is a member. If it is, obtain its certificate ID and
run `aw --identity-home <identity-home> id team fetch-cert --namespace <domain>
--team <team> --cert-id <certificate-id>`, then retry init. If it is not, with no
join running remove `hosted-invite-creation.json` and, if present,
`init-invite.json` from that home before using a correct invite. Keep the key
and chain.

`init --join-from` retains its issued invite privately (0600) in
`<identity-home>/init-invite.json`. Repeat the same command after interruption:
it reuses that invite and child key and resumes connection if membership is
already installed. A changed source, team, name or scope refuses. Successful
completion removes the record; an expired unsubmitted invite releases it so
init can issue a new invite using the retained identity.

An explicit `--parent` is retained in the child home with its exchange. A retry
may omit it; choosing a different creator refuses. It may be added only before
any submission could have reached the service. Each child of a multi-use invite
has its own exchange, and import retries reuse the parent's recorded issuance.

`aw team admin add --global` uses a registered creator's existing parent exchange
and registers the new child's ID certificate before membership. A local creator
with an installed chain cannot parent a registered child and refuses before
creating identity or address state; the controller can instead use the
unconditional `aw id team add-member` path. Chainless creators keep the existing
behaviour.

For teams whose key is on the host, this changes `--member-global` invites:
when their issuer has a verified human, they previously carried no human
condition. They now default to that human too. A registered identity without a
current valid chain to that person is refused where it could previously join.
To admit an agent regardless of whose it is, use the controller's own
`aw id team add-member` on a host holding the team key, or a person's generic
admission invite on a hosted team. There is deliberately no `anyone` value for
`--for-human`.

A hosted invitation prepares its local creator exchange before requesting a
bearer from the service. If saving the local link fails after the service has
created the invitation, `aw` returns the created token and warns on stderr.
Keep that token; the joiner can select the creator with `--parent <identity-home>`
on the same machine or complete the parent request/import exchange first.

On another machine, an invite for a different human does not authorize the
issuer to become the parent. First obtain a chain from the joiner's own creator
with `aw id child invite`, `aw id parent request --domain <creator-domain>`,
and `aw id parent import --domain <creator-domain>`, then retry the same join in
that key-and-chain home. No prior team membership is required. The refusal
names this exchange; it does not name the invite issuer as the parent.




For a new local agent, `--join-from` completes the existing parent
request/approve/import exchange when a hosted invite names the selected
self-custodial source as its ID parent. The source may be a workspace directory
or an explicit identity home; its verified ancestry is installed in the child
before connection. A chainless source retains the ordinary unknown ancestry.
Hosted invite acceptance on another machine uses the printed parent exchange
before retrying the same invite.
A global acceptor with its own current valid chain joins by membership only,
including when the invite issuer is local. A global identity without a chain
cannot obtain its parent certificate from a local `did:key` issuer.
`--join-from` explicitly selects its source as parent for a chainless joiner;
an existing registered joiner therefore needs a registered source, or direct
person adoption with `aw id parent request --human`. A bare invite or admission
does not select a parent for an existing identity. It preserves parentage and
refuses a conditioned chainless join with `human_required` and creator guidance.

Current surfaces include `aw id team accept-invite <token>` and `aw team join
<token>`. Hosted invite issuance accepts `--member-global` as well as
`--member-local`; it uses the selected member's existing hosted invite
authority and preserves any human condition. The recipient selects `--global`
on acceptance to reuse its existing self-custodial global identity; issuing the
invite does not create that identity.

A hosted local accept into an explicit external `--identity-home`
auto-connects that root when the invite names an aweb service; if connection
fails after membership installation, the printed recovery command is `aw
--identity-home <root> workspace connect --service <url>` and does not reuse the
invite token. Existing accepted external roots can use the same
`workspace connect` command to bind `workspace.yaml` under the root before
running mail/chat. During compatibility, CLI JSON output may dual-emit `alias`
and `name`. Legacy certificate/config `lifetime` input is normalized at decode
and normal output emits only `identity_scope`. The deprecated `--alias` flag
remains a hidden, warning compatibility alias for `--name`. New requests,
registry storage, and product language use `name` as the concept and
`identity_scope=local|global` for scope.

For a fully unowned team, see [how the controller signs a claim and an existing
member submits it](unowned-team-claim.md).

### Acceptance-minted key recovery

An unfinished local acceptance keeps `pending-hosted-accept` in its selected
identity home. It records only that acceptance minted this key and the identity
has never joined. A definitive refusal releases the invitation selection while
keeping this fact, so another valid conditioned invitation can use the same key
and creator exchange. A successful acceptance removes the marker. It establishes
neither parentage nor registry authority. A malformed or unreadable marker is a
recovery error; it is never treated as a fresh identity or absent state.

### CLI signup recovery

CLI signup keeps `.aw/signup-recovery.json` before submitting anything. The
record uses the common creation-recovery progress header and private atomic
writer, with a signup-specific payload: the original signing key, serialized
request, selected services, and any received response. It is mode 0600 in a
private mode-0700 identity directory. Neither the record nor its credentials
are printed.

Run `aw init` again in that directory to finish the same signup. Recovery keeps
the original signer, username, agent name, identity scope, inbound mode and
request bytes. It precedes username availability checks and ordinary reconnect.
Changing the creation selection refuses without changing the retained record.
Once a response is retained, recovery installs and connects from that response
without submitting another signup. The API key is saved before the connect
request; successful installation leaves it in the workspace before output.

Availability prompting happens before preparation. A 409 from the first local
signup submission clears the recovery record and allows a new username. If
signup created the identity directory just for that request, it removes the
empty directory too. A conflict on a replay or after global DID registration
keeps recovery, as does an unknown result such as a lost response or 500.
Replaying that request requires the service's signup replay contract. An expired
private response must follow the service's account recovery outcome.

`aw doctor --offline` names a leftover signup record and tells the operator to
run `aw init`. To abandon local recovery, first check whether signup created the
account, then remove `.aw/signup-recovery.json`; removing it does not delete the
account. A completed signup removes the record after installing its key,
membership and API key and completing connect.

### Hosted organization setup (including Omarchy)

A person already signed in can create a managed organization without a namespace
controller key in the terminal. Account authorization through the CLI grants the hosted service
permission to create the organization and team; each agent keeps its own signing
key. Device login prints an approval URL and code, and works without opening a
browser on the CLI machine:

```bash
aw auth login --json
aw org list --json
aw org availability alice-laptop --json
aw org create alice-laptop --name "Alice's laptop" --json
aw team create machine --org alice-laptop --json
```

Default login requests `cli.workspace_team cli.org_create`. Existing tokens that
only have `cli.workspace_team` still work for workspace enrollment. Organization
operations require a new `aw auth login` when that scope is missing; the CLI does
not substitute an agent credential or start browser approval on its own.

For automatic setup, propose `<username>-<hostname>` for an existing account and
the hostname for a new account. Default distro hostnames such as `omarchy`,
`archlinux` and `localhost` should go straight to an available suggestion. Use
`org availability` for planning: it creates nothing. Explicit slugs use the
service's existing lowercase handle rules (3–39 characters); the CLI does not
remove punctuation, truncate, or silently append a suffix. A collision returns
`org_slug_taken` and a suggestion. Interactive users confirm it or enter another
slug; JSON and non-interactive invocations exit nonzero with the suggestion.

Choose the same organization when ensuring a workspace team and enrolling its
member. The selector is covered by the enrollment signature; it does not itself
grant an account owner's organization authority:

```bash
aw --identity-home /path/to/principal init --workspace-team \
  --workspace-key aweb.ai/alice/workspace --org alice-laptop \
  --expect-account ACCOUNT_ID --json
```

`aw team create NAME --org ORG` returns a one-use invitation and creates no local
identity or workspace. Keep its `request_id` and parameters for a deliberate
retry. A consumed-invitation replay returns the existing team without a token;
it does not enroll the current caller. `aw id team create --name NAME --org ORG`
is the primitive with the same behavior. Existing controller creation and
certificate-authorized sibling creation keep their own authority paths.

To create a **new** self-custodial global member in an explicitly chosen hosted
team, select a fresh credential root and a Cloud service UUID or canonical team ID:

```bash
aw --identity-home /path/to/worker id create --org alice-laptop \
  --team-id SERVICE_TEAM_UUID --name worker \
  --inbound-mode team-and-contacts --json
```

The CLI registers its local key with public AWID, then asks the hosted service
to authorize the address and ordinary member certificate. It receives no API key
or administrator role. The result names the exact address and canonical team;
the private key stays in the selected root. A lost reply is retried with the
same root and original parameters, retaining the same key. Do not discard that
root or change the organization/team to recover an uncertain result. A name
held by another key refuses with `identity_name_taken`.

Once creation completes, the recovery file is removed. Repeating creation in
that completed root refuses and preserves the installed identity. Use ordinary
commands with that root; another new identity needs a fresh root. This differs
from retrying an incomplete operation after a lost response, which keeps its
original key and exact creation parameters.

This explicit creation differs from joining with an existing global identity:
`aw team join --global` continues to reuse its stored identity and cannot mint
a new address. The selected root can use ordinary mail commands after creation. An explicit
`--inbound-mode contacts-only` requests strict `contacts_only`, which admits
contacts only, including for same-team senders. Before reporting success the CLI
requires the returned mode and a live certificate-authenticated readback to
match the requested mode; a service downgrade is an error. Existing global
creation paths also verify an explicitly selected mode after connecting.
Unspecified modes keep their existing defaults.


A CLI-signup organization's owner principal can authorize this hosted creation
with its existing native key. Select that authority explicitly, separately from
the new member's fresh credential directory:

```bash
aw --identity-home /team-root/.aw inbound-mode --json
aw --identity-home /worker-root/.aw id create \
  --owner-identity-home /team-root/.aw --org alice \
  --team-id TEAM_ID_FROM_INBOUND_MODE --name worker \
  --inbound-mode contacts-only --json
```

Pass the read-only first command's `team_id` unchanged as `--team-id`. It may
be a canonical ID such as `default:alice.aweb.ai` or a service UUID. Cloud
resolves that selector within the authorized organization and returns both
the service UUID and canonical ID. The CLI preserves the exact trimmed input
in its signed intent and recovery state; it does no mapping lookup. `--org`
takes the organization slug (`alice`) or
ID, rather than its namespace domain. A newly created signup flow can retain its
original username as that slug; `whoami.domain` is namespace information rather
than proof of organization ownership.

Both root flags name the credential directory itself: they append no `.aw` and
the directory may have another name. The owner root must differ from the fresh
destination. Its native key signs the authorization request; the hosted service
checks the principal's live owner authority for the selected organization and
team. Ordinary team membership and organization administrator status do not
authorize this path. The service still verifies the new member's separate intent
proof and returns an ordinary self-custodial global certificate.

This owner path uses the Cloud base from the owner's own workspace binding,
leaves that root unchanged, and creates no account device session. It does not use
an API key or grant and does not switch to account login after a refusal. Omitting
`--owner-identity-home` retains the account `cli.org_create` flow above. Signup and
claim-human alone do not mint that account device authorization.

The owner-request DIDKey signature covers canonical JSON with `aud` (the
hosted service's configured public origin, which must equal the owner workspace
binding's `scheme://host[:port]`), `body_sha256` (the exact transmitted request bytes),
`method`, `path` and `timestamp`. The service checks the audience and timestamp
before looking up authority. This is the audience-bound variant for hosted
identity creation; existing signup and claim-human signature bytes remain
unchanged. Recovery pins the original authorizing principal as well as the new
member key, and success still requires the exact mode readback.

`aw connect --bootstrap-token` is retained as an unsupported-command refusal;
use a setup key from the dashboard or `aw init --join-from`.

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

Addressed `aw id create` saves its private signing key and a private
`id-create.json` plan in the target `.aw` before any registry write. A definitive
first-write refusal (401, 403, 409 or 422) clears the plan and its new signing
key when this attempt has no accepted or unresolved write. You can rerun with a
new selection immediately.

If the outcome is uncertain or AWID already accepted an earlier step, keep the
plan and key and repeat the original command. The error names accepted steps,
identifies changed choices on a retry, and prints the original selection to
rerun. A missing original key requires recovery of that same key. Successful
creation removes the plan and keeps the private key.

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

### Provisioned members and encryption discovery

Provisioning through a creator's invitation and creator self-enrollment connect
the accepted member to its aweb service before publishing its E2E key assertion.
A local workspace binding alone does not establish server admission. Provisioning
reports success only after the service confirms publication for that member.

If the accepted certificate is installed but local membership recording fails,
repair the reported file error and use the printed `id team install-cert` command
for that same certificate, followed by `workspace connect`. The outer creation
command retains its home throughout that repair.

A connect failure retains the created home, signing key and accepted certificate
and reports that this attempt did not publish the key. Run the exact
`aw --identity-home <member-home> workspace connect --service <url>` command in
the refusal. If connection completed but publication is unconfirmed, run the
reported `aw --identity-home <member-home> id encryption-key setup` command.
Neither recovery requires a replacement identity or another invitation.
Membership-only joins continue to install their membership before their separate
connection step.

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

## Verified identity attribution

A team controller authorizes membership, alias and team scope. Certificate
`member_did_aw` and `member_address` fields are claims about independent identity
facts; aweb verifies them with AWID before connecting or authenticating a member.
The current DID-log key must equal the request's member signing key. An address
must resolve to that same stable identity and current key. Missing or conflicting
bindings return `403 identity_binding_mismatch`; unavailable registry evidence
returns `503 identity_binding_unavailable`. Provisioning does no registry I/O
inside database locks.

If AWID definitively reports no record for a stable identity, the signing key may
use its own `stable_id_from_did_key` value. This exception does not apply to an
existing registry record, a rotated-out key, or a registry failure. An address
still requires its own positive registry binding.

Successful verification is cached by stable identity, signing key and address
for at most 60 seconds. A connect always rechecks current registry evidence.
Neither older SDK caches nor stale registry results establish this binding.

Embedding hosts obtain an authoritative observation through the public
`aweb.identity_binding.observe_identity_binding(registry_client, *, did_key,
did_aw, address="")` function before opening a provisioning transaction. It
returns a frozen `IdentityBinding` bound to that exact key and fresh AWID facts;
mismatch is 403 and unavailable evidence is 503. Pass the result as
`connect_agent(..., identity_binding=observation)`. Connect requires a fresh,
typed observation exactly matching every certificate identity/address claim,
then writes the projection and marker in its transaction without registry I/O.
The observation cannot add claims absent from the certificate. It is an
in-process Python value, never a header, request body or certificate field.
Hosts must not construct it from claims or rewrite verification flags. The OSS
request verifier returns it as the internal `cert_info["identity_binding"]`
result, and `/v1/connect` obtains that result through its own fresh verification.
Claimless local connects need no observation.
Identity-only and grant authentication apply the same check to their identity
or grant subject; a grant session key does not become the subject's root key.

`agents.did_aw_verified_key` records the key against which a projection was
verified. Historical rows start with a null marker. Stable-DID and global-address
routing, identity expansion and membership checks use a row's global claims only
when the marker equals its `did_key`. A fresh registry observation during
an authenticated request or reconnect refreshes its own projection and clears
markers for other keys of that stable identity in the same transaction.
A cached binding authenticates without writing or clearing markers. This
requires no registry I/O under locks and does not add registry reads to recipient
resolution. Local key-based access remains available
without attributing unverified global metadata. Policy classification still uses
`identity_scope = global` or a raw stable-DID claim: withholding a claim never
relaxes a global recipient's inbound policy. Existing conversation participants
can be looked up by their raw claims solely to enforce policy; this lookup never
selects a new recipient or supplies routing identity. Every matching local policy
row must permit continuation. Lookup errors fail closed. A participant with no
live local row contributes no local delivery or policy check; a retired group
member does not prevent continuation for the remaining members. Single-recipient
mail without a live recipient is not delivered.

After migration 034, operators run `aweb verify-identity-bindings --dry-run`, then
`aweb verify-identity-bindings` before resuming stable-DID/address delivery. The
command reads pending live identity projections, observes current AWID evidence
outside locks, then rechecks the row's key, stable DID and address under a row
lock. It writes only a verified marker; identities and addresses are never
rewritten. It reports only counts (`verified`, `self_derived`, `unbound`,
`awid_error`), is idempotent, and exits nonzero if any row remains unbound or
unavailable. Operators investigate those counts before proceeding. This command
requires the server's database and AWID configuration; it performs no migration.

### Native member projections for embedding hosts

`aweb.member_team_key.member_projection_columns_sql(alias)` supplies the native
member columns for a SELECT or joined host snapshot. Construct its immutable
`MemberProjection.from_row(mapping)` from the complete row; omitted columns are
an error, including authority columns whose value is NULL. PostgreSQL JSON rows
are supported: the constructor normalizes UUID and timestamp strings to their
native types. A host keeps its account and custody overlays separate.

`projection.verified_identity()` applies the existing verified-key rule. Raw
stable-DID and address claims remain available only for policy classification;
a complete projection by itself proves neither identity binding nor membership.
`read_member_projection(db, *, team_id=None, did_key=None, agent_id=None)` reads
the same shape. Select by explicit team plus key, or by agent ID with an optional
team constraint. It retains inactive/deleted rows so an actor resolver can
distinguish a known refused actor from an absent team-level principal.

Hosts pass that typed projection as `cert_info["agent_row"]` only for the exact
certificate team/key it describes. Complete legacy dictionaries are validated;
an incomplete legacy dictionary is replaced by a native read, rather than
manufacturing NULL authority facts. Native scope-aware authentication is exposed
as `aweb.team_auth_deps.resolve_team_identity_with_grant_scope(request, db, *,
grant_scope)`. Hosts apply account-specific fences to its result; they do not
copy its grant or certificate policy.

A host that needs member facts before its route policy can call
`read_team_member_snapshot(db, cert_info, request=request, overlay_sql=...)`
from `aweb.team_auth_deps` after the native certificate verifier succeeds. The
manager executes one statement outside any surrounding transaction, with SHARE
locks on the native team and member. The optional host SELECT receives
`native_member` as a CTE and binds canonical team ID, member DID key and
presented certificate ID as `$1`, `$2` and `$3`. It returns one row of host
facts even when the native member is absent. The native projection and host row
are separate fields of the returned snapshot.

The host then passes that snapshot to `resolve_team_membership` at the normal
native admission point, after host policy. The snapshot is usable for the
same ASGI request and verified credential. The resolver checks the native
member's active status, removal and current team key and returns the admitted
identity and the snapshot. An unchanged certificate and a warm identity
binding require no second SELECT. Reacceptance or a fresh binding uses a
separate UPDATE transaction and rereads the same projection. The optional
synchronous `before_write(snapshot)` checks any host fences on that reread
before a native write. It does no I/O. A verifier-only route can use the
read-only snapshot with its existing policy and no local admission.

## Session grants

A session grant lets a worker process act as an identity until revoked (or for an explicit finite window)
without holding the identity's root keys. The identity mints the grant from
its own `.aw` home:

```
aw id grant mint --bundle normal-agent \
    --ttl never --out /path/to/grant-home
```

When the grant should use local resident custody for signed plaintext or E2EE
operations, pass the preflighted socket explicitly with `--custody-socket
/path/to/custody.sock`, or `--custody-socket auto` for the resident identity
home's default `aw custody serve` socket. This writes only the locator at
`grant.yaml` `custody.socket_path`; it does not copy resident keys.

Short default socket paths remain `<identity-home>/run/custody.sock`. When that
would exceed 103 bytes, custody uses a stable hash of the canonical identity-home
path under an owner-only per-user directory: `/private/tmp/aw-custody-<uid>` on
macOS, `/tmp/aw-custody-<uid>` on other Unix platforms. This does not depend on
`TMPDIR`, so long temporary or OATS paths do not lengthen the socket. Serve,
resident status, and grant mint with `--custody-socket auto` use the same locator;
grant clients use the locator recorded at mint time. Existing short paths and
explicit `--custody-socket` locators remain unchanged. Explicit paths must still
fit the platform's Unix socket limit.

Every custody socket, whether default, configured or shortened, uses a private
directory created with mode 0700. Its ownership, permissions and absence of
symlinks are checked before listening or sending a request. Existing sockets must be
owner-only, owned by the current user, and not symlinks. Unsafe paths are refused
rather than repaired or followed. Restart custody and mint a new grant if an
older grant contains an unusably long explicit locator; resident keys stay in
the identity home, never in the runtime directory.


Minting generates a fresh session Ed25519 keypair, registers its `did:key`
with the server together with the scopes and expiry, and writes a
self-contained grant home (`grant.yaml` plus the session key — never the
identity's `signing.key`). A process pointed at that directory (via
`AWEB_IDENTITY_HOME` or `--identity-home`) runs `aw mail` and `aw chat`
normally; requests are signed per-request with the session key and the server
attributes the results to the identity.

`grant.yaml` also records `team_did_key`: the team key named by the resident's
team certificate when the grant was minted. A grant home holds no team
certificate, and this field is read only to verify the team's owner log-key
record for sealed local logs (see [Local Message Logs](configuration.md#local-message-logs)).
It grants nothing. A grant minted before the field existed cannot verify that
record and stops local logging until it is minted again.

When a grant-backed worker also needs plaintext mail/chat messages to carry the
resident identity's ordinary message signature, run local resident custody from
the resident home with `aw custody serve`. Local API-key workspaces created by
`aw init --alias` are supported even though they intentionally omit
`identity.yaml`: custody uses that workspace's active local team certificate
and matching signing key. The certificate supplies the resident member name;
local identities and newly minted local grants keep their address empty.
Grant-signed mail uses the resident member name, without promoting it to a
namespace address. Run from the resident workspace, not inside `.aw`.
Missing global identity metadata, malformed identity files, and mismatched keys
remain errors; custody does not create identity state or borrow another
workspace's identity when an external home is selected. The grant home records the custody
socket as locator metadata only; each signing request is structured
(`sign_plain_message`) and the service derives the resident sender fields and
constructs the canonical mail/chat envelope itself. It never signs
caller-supplied bytes, digests, identity-auth payloads, certificate-auth
payloads, identity operations, or grant/delegation payloads. `aw custody status
--json` reports safe readiness (signing, encryption, selected team, and
freshness), and `aw custody stop` asks the local service to exit. Custody
does no network I/O at start: it builds its aweb client on the first request
that needs it, so a host that starts custody before its network is up serves
local status at once and reaches the server when a request needs it. A failed
request is logged with its cause, and the status `client` object reports
`connected`, the sanitized `last_error` code and `last_error_at`; nothing
failed is kept, and the next request tries again.

The status `ops` list includes `status.v1`, `sign_plain_message.v1`, and
`sign_app_request.v1`, plus `grant_never_ttl.v1` when the running custody host
supports never-expiring grants. Upgrade and restart custody before using a
never grant; upgrading the binary on disk does not upgrade an existing process. When the encryption assertion and private key are
configured, it also includes `create_e2ee_envelope.v1`,
`unwrap_e2ee_message.v1`, and `mail_reply_continuation.v1`. The last entry is a
capability marker for stored-source mail reply continuation through the existing
envelope operation, not a separate RPC or a grant of permission. Consumers should
require it for grant-seat replies to unlisted senders and still check readiness
and grant scopes. Restart custody after upgrading: an already-running process
keeps its old capabilities. Upgrade with the services stopped, as in
[Upgrading aw under running services](terminal-wake-broker.md#upgrading-aw-under-running-services). The marker is advertised starting with aw 1.36.31.

Before unwrapping, custody independently fetches the stored message as the
resident and compares its encrypted envelope with the requested one. This
readability and message-binding check prevents custody from decrypting arbitrary
caller-supplied ciphertext; a grant seat does not replace it with its own read.
`aw chat history` applies `--limit` and `--unread-only` before decrypting messages,
and recipient lookup does not decrypt unrelated pending-chat previews. HTTP and
custody requests retain their individual timeouts; a history page does not share
one cumulative API timeout. Explicit caller cancellation still stops the work.
`aw mail show` follows the same rule: its page fetch retains the configured
HTTP timeout, then each message is unwrapped independently. The custody RPC
limit remains 10 seconds, with separate 5-second freshness and stored-message
read limits. An explicit caller deadline still bounds the entire operation.

The opt-in real regression is `scripts/e2e/custody_bulk.py`. With locally built
service images and a Linux CLI binary matching Docker's CPU, run:

```sh
python3 scripts/e2e/custody_bulk.py --aw-bin /absolute/path/to/linux/aw \
  --evidence /tmp/custody-bulk-result
```

It provisions disposable identities through the CLI and real owned TXT DNS,
then checks 300 exact verified v2 messages, a delayed page plus unwraps, local
key reads and individually stalled page/header/body/custody/authority steps.
It uses only existing local images, an internal network and fresh private
identity storage, and removes its owned services and volumes on exit. Image
overrides are available with `--help`; older CLI comparisons may supply a
separate current provisioning binary with `--provision-aw-bin`.

Scopes are `mail.read`, `mail.send`, `chat.read`, `chat.send`,
`events.read`, `coord.read`, `coord.write`, `presence.write`,
`contacts.read`, and `contacts.write`. The `normal-agent` bundle expands to
all of those scopes for ordinary worker operation; old grants keep exactly the
scopes they were minted with. Grant requests outside their scopes, and root or
admin surfaces such as team lifecycle, session leases, reservation revoke, and
minting further grants, are refused server-side. A
grant minted with `--ttl never` (the default) does not expire. Explicit finite
TTLs from 60 seconds through 720 hours retain their expiry. Grants can be revoked
idempotently with
`aw id grant revoke <grant-id>`; `aw id grant list` shows each grant as
active, revoked, or expired. Root-authority commands refuse to run from a
grant home, and `aw whoami` there reports the subject identity plus the
grant's status, scopes, and expiry.

The mint API accepts `ttl_seconds: "never"`, null, or omission for no expiry;
existing finite integer requests remain supported. Mint/list/status responses and
`grant.yaml` use `expires_at: "never"` for this case. The server stores a non-null
expiry 100 calendar years after issuance (February 29 maps to February 28 if
needed); an interval of at least 99 calendar years is reserved for never-expiring
grants and is not treated as a clock deadline. No database migration is needed.
Old custody hosts cannot consume the new expiry value and fail closed; both the
worker and running custody host must support the new contract. Malformed expiry
values are not never-expiring grants.

Owner revocation, an inactive/deleted subject, and issuing-certificate revocation
still end delegation. Revocation is enforced on the next authenticated request.
Open never-grant mail/event, status and chat streams recheck within a 30-second
cadence and close with a terminal event; unavailable verification fails closed.
This is bounded rechecking, not instantaneous idle-stream disconnection. Existing
finite notification streams keep their current behavior. Custody's authoritative
status cache remains bounded to 30 seconds. Registry revocation freshness remains
subject to the registry client's existing cache policy.

A grant stays tied to the certificate that issued it. When another certificate
becomes current for the same member, the old grant ends even if the member and
team keys are unchanged. Ask the issuer for a new grant. For an OATS seat, enable
renewal on launch and restart the seat so it receives a new delegation from the
resident's current certificate.

## User-data signatures

`aw id sign` injects its timestamp into the caller's JSON object, canonicalizes
it, then signs the UTF-8 bytes `aweb.user-signature/1\n` followed by that canonical
JSON. The newline is a literal byte. Verifiers of user signatures must prepend
this exact prefix. There is no unprefixed compatibility mode: these signatures
cannot authorize AWID log entries, controller operations or request authentication.
Protocol-specific commands construct and sign their own protocol artifacts.

`aw id request` signs a target-bound v2 request envelope through the same
signer as SDK JSON, raw, streaming and connect requests. It binds the final
external origin, method, raw path and query, actual body hash and timestamp.
Without `--team-auth`, it binds the selected `did_aw` (empty for a local
identity) and refuses caller JSON. With `--team-auth`, it binds the active
certificate's team; optional `--sign` fields cannot replace any authoritative
claim, including `did_aw`. A refusal never triggers a v1 fallback. Publish this
client only after both the OSS server and every embedding host deploy the v2
verifier, following the server-then-Cloud-then-client release order.

## Message verification and trust

Every mail and chat message carries sender identity fields and an Ed25519
signature. Recipients verify the signature against the sender's public key. The
CLI reports verification status on reads such as `aw mail inbox` and
`aw chat open`.

The clients use Trust on First Use (TOFU) pinning for globally addressed peer
continuity. A sender is pinned only after the registry confirms that its
address belongs to it: by `did:aw` when a stable identity is available,
together with its current key and durable DID-log checkpoint, otherwise by
`did:key`. Future changes require verified
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

For CLI folder precedence and the identity/workspace/user trust-store boundary,
see [CLI identity selection](cli-identity-selection.md).
