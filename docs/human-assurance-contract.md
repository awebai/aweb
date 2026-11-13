# Human assurance and protected signing

Status: **frozen implementation contract for aweb-acxy.1**. Juan approved
the architecture on 2026-11-11 at 19:06 UTC; the coordinator directed this
freeze after the settled review decisions. This document and the typed catalog
[`vectors/human-assurance-v1.json`](vectors/human-assurance-v1.json) define the
shared policy boundary for hosted and independent implementations. This is not
a release claim: implementations must pass their positive, refusal and race
cases. Unclassified operations and missing required evidence refuse; they do
not block implementation of the settled groups.

## 1. Independent facts and authorities

Login proves account access. A verified `kind=human` ID certificate records
that its issuer vouches for one person. A passkey assertion with user
verification (UV) proves use of that enrolled credential with its UV factor.
None alone proves that a person understood an act. The current B3 verifier
does not distinguish software from hardware authenticators or establish
hardware attestation. Stronger requirements need explicit policy and tests.

Ancestry answers who is responsible; it grants neither membership nor resource
access. Membership is team-controller authority. An address is
namespace-controller authority. Custody says who can use a private key. A
verified nearest human, account association, team owner, role holder and
credential holder are distinct facts and must not substitute for one another.
For a human leaf, the responsible human is the leaf itself.

One OSS library, embedded in an existing trusted server process, controls
human, namespace-controller and team-controller signing in supported
deployments. Cloud imports the same published package with account/custody
adapters; an independent operator uses its own server and registry. No Cloud
account, Cloud credential or public-registry fallback is required. Worker
agents retain their own **agent** keys and may sign permitted agent operations.

The signer accepts named, typed operations, constructs the artifact itself,
and refuses unknown operations, arbitrary-byte signing and key export. The
fixed minimum below is code, not a configurable exemption. Deployments may
add approvals, tighten scope or shorten time limits. Relaxing such additional
policy requires its current authorized human's live approval; it cannot relax
the minimum. A self-hosting administrator modifying the software is outside
this enforcement claim.

### What a remote verifier can establish

The v1 ID certificate and team certificate formats do not acquire an assurance
field. Their signatures establish issuer authority under their existing
verification rules, not whether the issuer used this signer or a passkey.
Remote consumers trust the issuer's signing policy. A previously token-issued
root cannot be relabelled as gesture-confirmed: its transition requires an
explicit, reviewed revoke/re-endorsement plan. Existing cryptographic
verification, current-head rules, expiry and revocation remain mandatory.

The browser and confirmation display are trusted. A separate trusted device
is deferred. An agent controlling the display can misrepresent the act; a
hardware touch alone does not repair that. Inbox or browser access available
to that same attacker is not an independent recovery factor.

## 2. Typed operation catalog

Each catalog row contains `operation`, `variant`, `key_role`, `enforced_by`,
`origin`, `authorizers`, `payload_binding`, `rule`, `bounds`, `policy_version`
and `audit`. The pair `(operation, variant)` is unique. Variants are disjoint
server-selected classifications, never a caller-selected bypass. The policy
reference is `aweb.human-assurance/1`; each deployment also retains an integer
policy version. Artifact versions such as `aweb.owner-act/1` remain separate.

`enforced_by` distinguishes the protected `signer`, an `app_b3` live-approval
consumer and an `app_verifier` checking already granted authority.
`agent_client` denotes the existing local agent-key implementation, not a
request to import that key into protected custody. The protected signer
executes protected-key rows only; it does not take over ordinary agent
issuance, rotation or revocation. A passkey-only application effect need not manufacture a controller signature.
`key_role=none` means no protected key is needed, not no authorization.

`live_floor` requires a current eligible human, fresh UV bound to the exact
operation, and one consumption. `bounded_unattended` requires the named
existing authority and all listed bounds; it is not anonymous permission.
First enrollment is the explicitly specified bootstrap exception to requiring
an already enrolled passkey; recovery is its own delayed operation. Neither is
an ordinary unattended governance variant.

The exact request binds service/origin, operation and variant, selected key
authority and current key version, subject/key, target, domain/team/holding,
rights, every artifact field, expected current state/head, deployment policy
reference/version and the operation's idempotency identifier. A display is
derived from that frozen request, never a second request rebuilt from labels.
Omitted, unknown or duplicate fields, ambiguous targets and unknown authority
evidence refuse. The catalog references existing artifact encodings; it does
not replace their domain separation with a generic JSON-signing interface.

### Minimum requiring a live exact act

* Human ID issuance, by either a namespace or a verified human; deployment
  root endorsement; root replacement without old-key continuity; changing
  the responsible human or a human-issued parent edge.
* Human, namespace-controller and team-controller key rotation/recovery;
  credential binding/change, recovery-contact change and changes to the set
  of humans authorized for a protected key.
* Human ID revocation and revocation of a human-issued deployment-root
  endorsement, within the existing subject/parent/namespace revocation rules.
* Human membership admission/removal, team/controller ownership changes,
  controller permissions and unattended admission policy changes, event-hook
  activation/change/revocation.
* Human-role designation/removal and credential recovery; log retention,
  explicit erase and legal hold changes; creating or widening resource access;
  policy-required approval of individual resource use.

Human issuance and human team admission are **two independent approvals**.
One tap must not sign both, nor sign a queue of otherwise separate acts.
Recipient acceptance alone never supplies the team's owner authority.

### Permitted unattended neighbors

Agents issue agent children under the existing ID rules; this is identity
creation only. The authorized deployment root may request agent-only team
admission through a bounded controller interface. No raw controller key or
resource grant accompanies that ability. A policy can require approval for
each admission as an additional restriction.

A registered agent, including the root, may rotate using its old key's
continuity proof for the same identity and unchanged rights, with corresponding
membership renewal. Re-signing unchanged child ancestry also remains routine
and requires retained issuance provenance. A local `did:key` cannot rotate in
place. Without the old key, a parent can issue a **new child identity**, never
take over the old stable ID. Replacing the deployment root needs its human.

Agent-to-agent subtree moves may be unattended only when rights are unchanged
and the before/after **verified nearest_human** is identical. An unavailable,
unknown or invalid result cannot qualify. A changed human-issued parent edge
requires live approval even if a loose human label appears unchanged. Existing
child possession, current-head, issuance and registration checks still apply.

An agent may revoke its own agent children within existing revocation rules.
Unregistered local leaves have no portable per-ID revocation; membership
removal is separate. The existing 60-second ID-status bound remains; do not
promise instantaneous worldwide revocation.

Team-controller rotation remains distinct from certificate revocation. It does
not silently revoke existing member certificates. An operator handling a
compromise must explicitly inventory/revoke affected certificates and renew
the intended memberships; rotation alone is not containment of certificates
issued by the old key. Every verifier still applies its existing key/history
and revocation rules; new owner acts require the current controller. This
preserves [the registry's explicit certificate lifecycle](awid-sot.md#certificates)
rather than changing membership as a side effect of key maintenance.

The AWID rule in acxc.69 permits `AWID_SKIP_DNS_VERIFY=1` for first namespace
registration only. PUT replacement requires proof of the new controller key
plus actual DNS evidence for that key or valid parent-controller authorization.
Continuity-preserving rotation retains its previous-/new-key proofs and DNS
requirements; replacement is not that rotation. The signer cannot turn a
bootstrap flag into replacement authority. Source: `docs/awid-sot.md:259-262`
and `docs/self-hosting-guide.md:218-224` at fix `5e7d61ba2` (review head
`ec4eb2a88`); this citation is source evidence, not a claim of release.

Already granted work, authorized reads/export, drafts, authorized access
narrowing and preauthorized containment remain available. Containment may stop
work, disable access or credentials and cancel approvals. It may not install
credentials, replace a human, transfer ownership, erase/redirect audit or remove
a human-role holding through a side door. Last-owner protection still applies.
These restrictions also apply to SCIM-triggered containment. Re-enabling access
requires live approval. Containment must not wait for a ceremony or remote Logs.

### Controller operations and admission policy

Namespace/team creation and deletion, controller permission changes, namespace
routing changes and new/changed team-server records are live floor operations.
The catalog names them explicitly. Exact replay of an already committed signed
publication is receipt recovery, not a new governance act. Unchanged
reconciliation may replay the same retained artifact and idempotency key under
current publication authority; it cannot refresh timestamps, key, destination,
member rights or content without the separately classified operation.

A namespace address for a human, or reassignment/change of an existing address,
requires its namespace-authorized human. A fresh agent address may use a bounded
provisioning policy only when that approved policy names the namespace, name
allocation rule, target agent and permitted route, with no existing-address
replacement or change to human responsibility. No policy means refusal.
Namespace-parented `no_human` agent issuance remains a distinct supported
profile, never a human-endorsed root. Its protected namespace authority requires
a live approval for new issuance; no token exception, manufactured H or agent
parent is allowed. It cannot satisfy the endorsed-root acceptance journey.

Protected provisioning authorizes **one exact default admission policy** under
operator authority. It lists the teams and fixes the root selector to "the
requesting root, verified as endorsed under this service_id by a current
authorizer", agent kind only,
member role only, and an immutable policy version and digest. Endorsing that
root is **one live approval of one act**: its screen discloses the resulting
bounded admission. Endorsement satisfies the existing policy; it neither
creates nor widens it. Later changes require their own
`team.admission-policy.change` approval. A deployment without that provisioned
policy must not silently create one during endorsement.
One policy may list teams across namespaces only when provisioning holds real
authority for every listed controller. A shared account, ancestry or stored key
reference is not that authority. The endorsement discloses the pre-existing
list and never acquires another controller's consent. An unlisted team needs
the separate policy floor act. Hosted .6 supplies the adapter and fresh
protected-test-team fixture; .8 owns existing-team migration/cutover. This
contract authorizes no customer or production provisioning.

A protected admission policy names each canonical team and the authorized root
selector. Admission authenticates the exact root ID named by the request and
verifies that root's current endorsement against the selector, including this
service's retained `identity.root.endorse` result. An ordinary
`identity.agent.issue/human_parent` result never matches it; no new certificate
kind or assurance field is introduced. The service does not search for exactly
one root across the whole service. A second deployment's
endorsed root does not make the first ambiguous. The policy names
permitted agent subject kinds, maximum active admissions and a finite rate
window/count. It specifies the default ordinary member role only, never admin
or a role carrying governance scopes. It grants no new resource access beyond
already applicable team/role policy. Count and rate bounds are per
`(policy, team, root ID)`, enforced under the admission transaction. Rotation of that root's key does not reset the bucket;
an exact replay does not spend the quota twice. An aggregate team ceiling,
if desired, must be separately explicit; per-root limits otherwise add up.
A stolen root agent key can request admissions within those explicit bounds;
subject rotation/revocation and resource permissions remain independent. The
contract does not claim to prevent that use of the root's actual authority.

Local `did:key` and registered agent subjects are both allowed when the policy
permits them. Local membership certificates retain local subject fields and
no invented `did:aw`. For bounded unattended admission the requester is the
explicitly authorized root, not any agent whose chain happens to contain it. The owner-approved
variant uses its separate live controller-human authority under the same
protected policy. Grandchild issuance stays with its actual eligible parent; root-side admission supplies membership separately.
Hosted and independent profiles use this same boundary and command semantics.
Every agent admission **and renewal** on a protected team passes the bounded
policy, including cache/reconciliation and hosted routes. Ordinary member
invites cannot bypass it: legacy invite admission returns HTTP 403
`protected_admission_required`. Clients explain the configured service/root
admission path rather than retrying the invite or reminting an identity.
Legacy teams retain their existing behavior until an explicit operator-approved
migration under section 7; installing a client does not protect a team.

An endorsement target is an ordinary registered agent: a current stable ID/key
mapping in the selected registry, possession of that key, and no conflicting
or revoked ancestry/head. An existing chainless agent is eligible for its first
certificate; absence of its first ID certificate is distinct from an unknown
mapping or failed registry read. Existing matching endorsement is receipt
recovery, not fresh issuance; a different parent/head requires the corresponding
reparent/re-endorsement operation. Team membership is not a prerequisite for
preparing endorsement. A local did:key cannot be the registered root. Setup
submits the root's own proof in both profiles, without a Cloud login token.
Registration of the resulting certificate still requires subject proof and
registry read-back before setup reports an attributed registered root.
When no eligible root exists, setup offers an explicit new-agent choice. Its
new agent key signs its own DID-log mapping registration; that operation gives
no ancestry, namespace address or team membership. The one live root endorsement
then supplies its ID certificate. Address allocation is not required by that
certificate (`id-certificates.md:124-129`); the mapping is subject-authorized
(`cli/go/awid/registry_client.go:309`), not namespace address authority. An
optional address is a separate classified namespace operation, never folded
into the endorsement tap. A local minting root is not silently converted or
replaced. The concrete new-agent CLI composition belongs to .4/.5.

`team.agent.remove` is authorized narrowing: the configured root may remove an
agent membership inside its team/scope, and an agent may leave its own
membership. It uses the protected controller, never a raw worker key. It does
not revoke a human, remove a human-role holding, or acquire resource rights.
Existing last-owner and containment limits apply.

### Owner-approved agent membership removal (catalog addition)

Juan 2026-11-13, via coordinator: `team.agent.remove/owner_approved` is a
`team_controller` / `live_floor` signer operation. It is an additive row;
the frozen base inventory is unchanged. Its policy scenarios are in
[`human-assurance-owner-removal-v1.json`](vectors/human-assurance-owner-removal-v1.json).
This specifies the next implementation; it does not claim the runtime serves
the variant yet.

The current team owner's fresh exact-act passkey approval may remove any
eligible agent or service membership of that team, including one admitted
before cutover, one outside the requesting root's admission bucket, or one
whose admitting root has been replaced or revoked. A working root, membership
certificate or operator credential alone does not authorize this variant.
The default root/self variant keeps its existing narrower authority.

The closed subject is `{team_id, member_id, certificate_id,
expected_membership}`. `member_id` is the certificate's `member_did_aw`, or
its `member_did_key` for a local member. `expected_membership` carries exactly
`{member_did_key, member_did_aw, member_address, alias, identity_scope}` with
explicit nulls for absent optional fields. Prepare binds the exact current
certificate UUID and snapshot, current controller, authority generation and
action policy into B2. Approval displays the target and consequence. A changed
target or snapshot under the same operation UUID conflicts, never silently
selects another certificate.

This is agent/service membership removal, not human membership or human-role
removal. A global target requires positive verified agent kind; unknown kind
or an unenrolled legacy human label establishes no agent eligibility. Local
subjects retain their separate local-member and protected-key exclusions.
Current human/controller/namespace authority and last-owner protections
remain independent checks. An unavailable current fact refuses release.

The existing certificate-revocation encoding and exact registry confirmation
remain the effect boundary. Retain one signed effect and its release claim;
an ambiguous answer reconciles that owned operation without a second mutation
or signature. If the certificate has an admission record, release its capacity
only with fresh confirmation and the atomic receipt/audit transition, keeping
rate history. A pre-cutover or service certificate without an admission record
can still be revoked; removal must not fabricate a quota record or charge.
Original operation, authority-observation and UV deadlines never restart.

Hook retargeting uses the existing owner-act vocabulary: revoke the old
binding and activate the new binding as separate exact acts, with separate
live approvals. There is no hidden multi-act queue behind one gesture.

## 3. Origin, holding and bootstrap

The server exposes the shared ceremony at a configured, pinned HTTPS human
origin. A separate configured request origin accepts request authentication.
These may be mounts of the existing server composition; they are not a new
approval-service product. Origin/registry selection comes from trusted
deployment configuration, never a URL supplied in an approval response.
For non-app governance, an explicit operator-provisioned protected-service
profile binds `service_id`, request origin, human origin/RP and authoritative
registry/key-authority references. No new AWID DNS or team-server discovery
field is introduced here. Existing app scopes retain pinned manifest origins.
The profile is public configuration, not authority. Team-auth headers never
go to the human origin. Browser session protection,
CSRF and WebAuthn origin/RP checks are necessary but do not replace the UV
approval for a floor act.

A holding has a typed authority scope independent of an application owner
installation:

* Application scope: exact service/installation and role, with the human
  principal and identity domain bound to the in-effect holder.
* Protected-key scope: exact signer service, key-authority kind and stable
  authority identifier, with its currently authorized human ID and domain.

Account ID, email, team name or nearest-human inference cannot choose a
holding. One account may hold multiple humans in different domains. Every
ceremony call resolves the explicit scope to its current subject; the effect
adapter locks/rechecks the account/session/human association and authority
through commit. The set of humans allowed to authorize a key is separate from
each human's set of credentials. Credential add never appoints another human.

The shared context extension is versioned and discriminated. Existing
`PasskeyInstallationContext(app_id, team_id, installation_id, generation)` and
its retained-proof encodings remain readable unchanged. A new protected-key
context contains `v=1`, `kind=protected_key`, `service_id` (the configured
signer identifier), `authority={kind,id,domain}`, `human={id,domain}` and
`generation` (the authoritative association generation). Authority kind is
exactly `human_identity`, `namespace_controller` or `team_controller`; its ID
is respectively the human stable ID, namespace domain or canonical team ID.
No private key locator appears in the public context. Application scopes keep
their installation/role/principal binding; a protected context is not coerced
into that type. The context discriminator and all context fields enter the
shared retained-proof commitment. Changing a generation invalidates unused
approval rather than silently rebinding it. Package .2 implements this one
extension; it must preserve existing app proof vectors.

The protected-service scope is admitted before any application role. It binds
an explicit human to existing operator-controlled authority; it is not a
Secrets installation or a team membership fabricated to satisfy B3. Initial
bootstrap can register its pending human under namespace authority after that
human's exact enrollment ceremony, then request the separately approved team
membership. A prior registered human is reused after current evidence checks;
bootstrap must not mint another human because lookup or key access failed.

### First enrollment precedes application roles

The deployment pins the signer origins, registry and initial key authorities
through its existing operator-controlled provisioning boundary, outside worker
access. The initial human association is an explicit bootstrap record under
that boundary, not a worker token or an inferred team member. The enrollment
baseline in the hosted profile is an email-verified browser session and the
existing B3 enrollment and recovery checks. In the independent profile it is
one recorded administrator action on the protected signer host, not a
worker-accessible network endpoint. The action binds the first explicit human,
key authority and credential at the pinned origin, and is consumed once.
Bootstrap establishes only the first authorizer set and the one exact default
agent-admission policy described in section 2. It does not authorize a queue of
later human acts. Later authorizer-set or policy changes are live floor acts.
Every authorizer-set change notifies all current authorizers and preserves at
least one usable authorizer. Adding/removing an authorizer takes effect with
its committed exact act; this build adds no authorizer-removal timer. These proofs establish account/operator authority, not
personhood.
Generate/retain any initial human key only in protected custody. A provisional
bootstrap record permits only that exact enrollment and associated initial
identity registration; it is not a standing general signer unlock.

Complete the first credential's UV registration bound to the selected human,
authority and origin. An operator-supplied or worker-readable bearer token alone
cannot perform this binding. Repeated enrollment resumes the same subject and
key; conflicting or ambiguous existing state refuses. Subsequent human
issuance and team admission consume separate live approvals. Team membership
can therefore be established before installing Secrets or Logs.

The first Secrets owner and Logs reader are then designated by a team-controller
`human-role.designate` act after the current team owner's live approval. The
app verifies the act, the selected human's own kind and current membership.
The signer does not depend on being a Secrets owner to establish that first
owner. Recovery without a working credential uses the separately authenticated
recovery authority and the 72-hour floor; it cannot re-enter initial bootstrap.

## 4. Ordinary human authentication without worker custody

The protected server constructs request authentication for a closed set of
ordinary operations: current membership/certificate reads, connect using an
already issued certificate, authorized status/mail reads, permitted message
send, and a credential handoff start for the same human and explicit scope. It binds the
exact configured destination, method, path/query and body to the selected
principal and team. The consumer still checks its own membership and resource
policy. Private registry member-key reads use the actual member authority and
that team's configured registry, never a public or controller fallback.

Interactive read/connect and credential-handoff signing as the human requires a B3
UV LOGIN session bound to the exact human, holding and credential, at most
900 seconds. Credential retirement ends that session. A cookie, API key or
CLI preparer token is not human-signing authority. This console-session rule
is distinct from the independently authorized linked-channel MAIL path below.
A short authenticated session can browse, draft and stage; it cannot approve
or activate a protected change. The supported path keeps the human key in the
server and uses the one shared handoff with an in-memory ephemeral session key.
It issues no reusable governance approval and installs no background human
signer on the worker. The adapter must classify operations by a closed route
and typed payload table, not by `GET`, an arbitrary installed-tool label or
whether team-auth happens to work. Generic `id request --team-auth` with human
authority is not an arbitrary path/body signing escape.

### App sessions: direct-child preparation, H's own login

For app `session` purpose, use the app's own B3 LOGIN and explicit Allow; there
is no protected-service LOGIN or H-signed intermediary start. The paired wire
delta is [handoff-wire section 1a at 27169df70](https://github.com/awebai/aweb/blob/27169df70f04aae137d214697ffd1155e11a64e2/docs/design/handoff-wire.md).
This changes only session-start admission, not human signing or governance.

A current agent member Q whose freshly verified chain has H as its **direct**
human parent may prepare H's app-session start. Q signs team-auth v2 with Q's
OWN current team certificate, and sends Q's chain in `X-AWID-ID-Chain` using
the existing encoding. The signed start body preserves aw's purpose, scope,
client_key, redirect_uri and verifier_sha256; scope.principal is H. The body
carries no certificate of H: `holder_certificate` is refused with HTTP 400
`handoff_invalid` on every start. The factory loads H's certificate from the
exact holding's retained evidence. It never substitutes for Q's team-auth
admission. A registered non-member laptop is refused; this change adds no
possession-proof app start surface.

Before creating a handoff the app verifies Q's chain for Q's registered did:aw
and the key authenticated by team-auth, with the existing status bound of
60 seconds, current head and no revoked edge. Q's own leaf certificate must
have H as its direct issuer, and that issuer's own verified kind must be human.
A deeper descendant with the same nearest human does not qualify. The app
independently verifies H's retained holding certificate under the current team
key for the installation's team and member_did_aw=H, current published/unrevoked
membership, H's own human
kind and H's exact current holding. Retain H's certificate as session evidence.
Q's ancestry authorizes preparing this request only: it is never H's LOGIN,
membership, holding, session, resource grant or exact-act approval.

A supplied `holder_certificate` is 400 `handoff_invalid`; an ineligible direct
edge is 403 `scope_not_signer`. Missing, renewed, replaced or otherwise unusable
retained membership evidence is `principal_not_member`, and H's failed own-kind
check is `principal_not_human`. Q can neither supply nor refresh that evidence.
aw explains that the app's retained membership record is not current and names
the H-signed credential-start refresh below. Unavailable chain/certificate
status is 503 `principal_status_unavailable`, not a manufactured mismatch.
Other existing handoff refusal rules remain. The page records/displays
`requester: {id,address,key_fingerprint}` separately from H before H's app-RP
UV LOGIN and the separate explicit Allow. Only aw's in-memory ephemeral key,
verifier preimage and single-use loopback code can collect the existing result.
The resulting session is H's, with its exact holding and current membership
checks unchanged. No other purpose, including `credential`, gains this
same-signer exception. A Q-not-H session is **loopback only**:
`return: user_code` refuses with HTTP 400 `handoff_invalid` before any handoff
is created, whether or not the forbidden certificate field is also present.
H's own same-signer fallback is unchanged.

aw derives H from Q's installed direct-parent chain and shows both identities.
No qualifying requester means `requester_missing`. Onboarding is explicit:
`aw id create --human-parent H` prepares `identity.agent.issue/human_parent`,
not `identity.root.endorse`. The new subject key may prove and prepare only
its exact issuance; H supplies one live exact-act approval. The receipt grants
no default deployment-root admission, and no agent is created automatically.
ID registration and team membership remain separate. The configured root
requests `team.agent.admit` for the laptop agent within the protected policy's
subject kinds and bounds. Alternatively the current controller-authorized human
approves `team.agent.admit/owner_approved` as its own live exact act, still
through that protected policy and its explicit root accounting bucket; it may
not bypass bounds or change policy. No raw controller-key path is implied.
Without applicable policy, provision it through the authorized bootstrap or
policy-change route first. Until its OWN membership is issued and current,
the laptop's team-auth session start refuses. Package .8 inventories existing
requester reuse versus deliberate new issuance for the operator's laptop.

### Credential starts retain protected H authentication

`POST /protected-handoff-starts`, through `prepare_handoff_start`, accepts a
restricted requester Q and a closed `purpose=credential` body. It freezes
`return=loopback`, scope.principal=H, aw's in-memory `client_key`, `redirect_uri`,
`verifier_sha256` and pinned target. After H's protected-service UV LOGIN for
that exact human/scope, the server signs those unchanged bytes as H and sends
them to the app's `/handoffs`. No server key/verifier/callback substitution or
local human keychain fallback is permitted. The app's same-signer rule still
sees H. This is LOGIN-bounded authentication for inert credential registration,
not an exact-act approval to bind the new credential.

**Membership evidence refresh happens at start acceptance.** The H-signed
credential start carries H's current certificate in its existing team-auth
header, not a body field. Once the app accepts and verifies that start, it
refreshes the existing holding's retained certificate only when the verified
team and principal match that exact holding. It checks the current team key,
H's current member key, published/unrevoked certificate status and H's own
human kind. The old retained certificate does not block this refresh; the
fresh H-authenticated evidence supplies it. Q's signature, body data or ancestry
cannot do so. A mismatch or failed verification changes no retained evidence.
The refresh and accepted start are committed together, with the holding
rechecked at that effect; no holding is created or rebound.

This refresh does not wait for app credential registration or completion and
requires no new passkey or owner act. It changes only the retained membership
evidence, never a credential, session, approval or holding authority. It
supersedes the older claim that credential handoffs leave no retained state;
credential registration itself remains inert. Same-signer session refresh
keeps its existing successful-login condition. The paired human-confirmation
and handoff documents must carry this credential-start exception when their
implementation lands.

The shared receipt retains `signing=committed` and the known app 201 result
`receiver={handoff_id,expires_at}`. aw constructs the app page from that ID and
its pinned app human origin, never a returned URL. H completes the app-RP UV
registration; aw collects the credential through the unchanged code/verifier/
ephemeral-key result route. Service LOGIN plus new-credential registration is
an enrollment cost, not a two-login cost for each app session. Binding that
credential still needs its separately classified floor act.

The existing app `POST /handoffs` is not idempotent: identical signed starts
can create multiple pending handoffs, although each result remains bound to
the same aw ephemeral key/verifier/loopback. Both session and credential clients
must keep this limitation distinct from signer idempotency. This contract preserves that
receiver behavior. The protected service records the immutable signing result
separately from whether the app returned a handoff ID. If the target response
is lost or ambiguous, report `unknown/external_effect_unresolved`; do not
silently retry POST, generate another key/timestamp/signature, or claim that a
signing receipt proves target creation. The client exits with its operation ID
and the unresolved delivery status. A known response retains the original app
handoff ID/result reference. Reading it never starts another handoff.
Original-handoff recovery using receiver deduplication/tombstones is separate
reliability work, not a security requirement or new store in this build.
Existing authenticated-start timestamp/rate/expiry checks and result
key/verifier/code protections remain. A deliberate new start is a new prepare
with fresh ephemeral material and the purpose's current authorization checks;
it is never automatic recovery from this unresolved operation. A direct-child
session start has no protected H signature receipt: its ambiguous app response
is itself unresolved, and aw must not invent a successful session.

Channel MAIL remains a separate narrow operation: verified retained speaker,
current linked-channel/delivery authorization, recipient and exact retained
mail/chat payload only. It does not require a B3 UV login or periodic
15-minute reauthentication. The authorized channel binding is sufficient for
this named messaging operation, never for a console session or governance.
A CLI token, API key or account cookie is not that channel authority, even
when it asks for a well-typed MAIL/chat payload; it cannot make the signer speak
as the human.
Missing/revoked channel authority refuses under existing ingress rules;
transient infrastructure failure remains distinct. Recovery of an already
committed signature returns the frozen result and nonce without re-signing.
Publication still checks its current delivery authority; an unpublishable
artifact cannot silently turn into a newly signed operation.
Channel login, a mail signature, an
installed-app token or a session signed for reading cannot be presented to
human issuance, owner acts or any governance signer operation.

## 5. One handoff and one operation receipt

The shared page/module gains a governance-approval mode for the typed
protected-key scope. Existing app `session`/`credential` handoffs and
`session_actions` remain their own compatible lane. The governance mode must
not invent an app installation merely to host identity governance. Package .5
owns this single client/browser flow; package .2 owns the shared signer/receipt implementation; .4 and .6 mount adapters.
Pinned request/human origins, no redirects, loopback/fallback binding,
in-memory ephemeral keys and X-Console request protections remain as specified
in [human confirmation](design/human-confirmation-from-aw.md). Scope adaptation
is additive for existing app consumers.

### Shared mounts and requester authentication

These are the shared mounts for .2/.5 and the .4/.6 embeddings, not routes that
already exist in a released server. Extend the existing
`ConsoleHandoffs.api_router()` / `human_router()` and shared page dispatcher.
No adapter implements its own ceremony, request parser or receipt store.

| Origin | Method and path | Authority and effect |
| --- | --- | --- |
| Request | POST `/protected-operations` | Restricted prepare; no signing or human approval. |
| Request | GET `/protected-operations/{operation_id}` | Authorized exact-scope receipt; never re-signs. |
| Request | POST `/protected-operations/{operation_id}/execute` | Bounded unattended operation only, rechecking its catalog authority; live-floor operations refuse here. |
| Request | POST `/protected-handoff-starts` | Restricted preparation of the exact credential-start body; section 4 LOGIN before H signs. |
| Request | GET `/protected-admission-policies?team_id=T` | Nonsecret setup/status read for an authorized requester. |
| Human | GET `/handoff/{handoff_id}` | Existing shared page in its stored governance or LOGIN mode. |
| Human | GET `/handoff/{handoff_id}/governance` | Current authorized human reads the frozen operation/state. |
| Human | POST `/handoff/{handoff_id}/governance/options` | B3 options for this exact act/current human. |
| Human | POST `/handoff/{handoff_id}/governance/execute` | Existing browser/CSRF protections, bound UV and current authority; execute once. |

The request origin accepts one of these mutually exclusive requester proofs:

* An agent/root possession proof using the existing covering-v2 encoding in
  [AWID request binding](awid-controller-requests.md). Headers are
  `Authorization: DIDKey <did:key> <signature>`, `X-AWEB-Timestamp` and
  `X-AWEB-Signed-Payload`. The signature is unpadded standard base64; the
  canonical payload is unpadded base64url. Bind the configured request-origin
  `aud`, exact method, external raw path/query, exact body SHA-256 (empty body
  for GET), timestamp, selected authority domain and operation. The allowed
  operation labels here are `protected_operation_prepare`,
  `protected_operation_receipt`, `protected_operation_execute`,
  `protected_handoff_start` and `protected_admission_policy_read`. Each adds
  exactly `service_id` and `scope_sha256` to the covering-v2 base fields;
  `scope_sha256` is SHA-256 of the canonical typed scope. For an operation it
  is the frozen operation's scope; for policy read it is exactly
  `{service_id, team_id}`. Prepare bodies carry their scope explicitly; receipt
  reads match the retained one before disclosure. An operational team read
  does not fabricate a human holding. Timestamp skew is at
  most 300 seconds. These new receiver labels reuse the encoding, not AWID
  controller privileges. Resolve the selected registered identity's current
  mapping/key; possession alone supplies no human or controller authority.
  Endorsement preparation requires the subject root's key; subsequent bounded
  admission requires the configured root and current policy.
* Existing team-auth v2 from a current agent member, with `aud` equal to the
  request origin and an explicitly permitted requester scope. Its signer is
  the requester, never implicitly the human whose approval is requested.
* A hosted scoped CLI discovery/admission bearer, accepted by that embedding
  only for prepare/read of its exact account-to-H/authority association. It
  cannot execute bounded root authority or sign/approve as H. It is optional;
  independent operation and the root-proof path require no Cloud credential.

A cookie or API key is not a request-origin fallback. Every proof is checked
against the selected service, authority and operation; accepting an envelope
does not authorize its requested effect. Requester scope comes from the
provisioned profile/current policy, not from untrusted scope fields. Remote
evidence failure refuses; no public-registry fallback. Team-auth and the
requester proof do not cross to the human origin. Browser lookup independently
checks the same human/holding or key authority that could prepare the act;
a cookie authenticates that inspection only with the current association,
never a signing approval.

The policy read returns `service_id`, `team_id`, `mode` (`protected` or
`legacy`), and `policy` (the immutable version, digest, listed teams, root
selector and bounds, or null when this service has no policy for the team).
A prospective root is eligible for this read only if its registered identity
is explicitly named by the provisioned profile, or it has an authorized pending
endorsement preparation for this exact service_id. The request must prove that
identity's current key. Merely presenting any registered key is insufficient.
The read is limited to the profile's listed teams before endorsement; already
being endorsed is not a circular prerequisite for setup. It contains no secret key
material and grants no admission. Unknown authority
or unavailable evidence is an error, never `policy:null`. .4/.6 expose this
same read; .5 maps it into setup/status. Under the current root's own proof,
the same read may include its active admitted-member count, remaining rate
window/count and admitted member/certificate references for reconciliation.
Those operational fields are scoped to `(policy, team, root ID)` and are
snapshots, not quota reservations; they reveal no other root's membership.
A prospective-root read returns configuration only. On a protected team with no applicable
policy, setup reports `admission_policy_missing` and directs the operator to
provision or approve the policy rather than creating it itself.

### Frozen operation, display and receipt

For root endorsement, the client prepare input names the exact root/key,
selected H, service and intended teams. The server supplies the existing
default policy's immutable digest/version, complete team list and bounds in
the frozen payload it returns; the client need not discover those before its
first prepare. Missing applicable policy or a legacy target team refuses
`admission_policy_missing` before a pending record or link exists. Prepare never
provisions a policy. The newly authorized pending preparation permits the
scope-limited policy read. Before displaying the link, setup compares that
read's policy digest/version with the frozen payload and checks every intended
team is listed. A failed check stops locally without showing the link; the
unapproved operation expires. Exact prepare retries return the original frozen
policy, never today's replacement. A policy change before execution refuses
explicitly with `policy_changed`; it cannot bind the old approval.

The client chooses and persists an operation UUID before prepare; retries use
the same UUID and exact body. Prepare returns `operation_id`, `handoff_id`,
`digest`, `payload` (the complete frozen request) and `expires_at`, **no URL**.
aw constructs `/handoff/{handoff_id}` on its pinned human origin; any echoed
origin mismatch refuses. The server binds the identifier to its original
requester and exact authority scope. Changed body, key, target, human, policy or
callback under that identifier refuses `operation_conflict`. Pending lifetime
uses the existing shared handoff's bounded expiry (at most 600 seconds), capped
by every frozen artifact/policy deadline. It is never extended by polling or
retry. A new explicit attempt after expiry has a new operation ID; it cannot
silently recover by re-signing the old one.

Use B2's existing covered-request digest, not a second digest engine:
SHA-256 of `aweb.approval-request/1` plus LF plus canonical UTF-8 JSON of
`{"policy":{"ref":POLICY_REF,"version":POLICY_VERSION},"request":REQUEST}`.
REQUEST freezes the typed operation/variant, service/origins, requester, scope,
key authority/generation, every artifact field, expected state/head, operation
ID, protocol nonce/issued/expiry and validated completion binding. Canonical
JSON is the existing B2 safe-integer/no-float form; unknown and duplicate fields
refuse. The `digest` is 64 lowercase hex characters. Both page and CLI display
the full digest and its comparison fingerprint: the first 16 hex characters in
four groups of four separated by a single space. The page displays the selected
identity/key and scope alongside that value; a short fingerprint is a human
comparison aid, never the authentication check. Clients verify the full digest.

Governance prepare accepts an optional `redirect_uri` under the existing
literal-loopback parser. Invalid input is HTTP 400 `redirect_uri_refused`.
Freeze that callback; completion carries only `handoff_id` as a wake hint,
never a code, signature or authority. Without callback, aw polls the authorized
receipt with a bounded interval until final state or expiry. Only a receipt,
never a browser redirect or approval alone, establishes committed.

The closed receipt shape is `pending(reason, expires_at)`,
`refused(code)`, `committed(result)`, or `unknown(code)`. The codes are stable:

| State | Codes |
| --- | --- |
| pending | `awaiting_human`, `awaiting_execute`, `effect_in_progress` |
| refused | `human_refused`, `operation_expired`, `approval_expired`, `proof_invalid`, `approval_spent`, `operation_mismatch`, `authority_changed`, `policy_changed`, `scope_refused`, `stale_binding`, `no_notice_contact`, `cap_reached`, `cap_unavailable`, `last_authorizer_protected`, `last_owner_protected`, `issuer_kind_forbidden`, `subject_ineligible`, `provenance_refused`, `admission_policy_missing`, `admission_limit_reached`, `protected_admission_required`, `live_approval_required`, `operation_refused` |
| unknown | `receipt_unavailable`, `external_effect_unresolved` |

`operation_refused` retains the typed downstream diagnostic for operators;
clients do not parse prose or infer an alternate operation from it. Parsing
failures before prepare use HTTP 400 `request_invalid`/`redirect_uri_refused`.
An unknown or unserved operation/variant uses HTTP 400 `operation_not_served`,
including a defined operation whose required consumer or signing adapter is
not installed in this composition. This creates no pending operation or approval
link. Malformed selectors remain `request_invalid`; a served operation denied
by current policy/authority keeps its specific refusal code. aw preserves
`operation_not_served` and explains that the service needs a version supporting
the operation. A detail-less HTTP failure is not evidence of an unserved
operation and keeps its generic status code. The
[`protected-operation-availability-v1.json`](vectors/protected-operation-availability-v1.json)
controls distinguish these cases from an incorrect request origin.

Invalid authentication is 401 `requester_invalid`, scope denial 403
`scope_refused`, binding conflict 409 `operation_conflict`. Authenticated
lookup with no authorized matching record returns 404 `operation_not_found`,
not proof that a previously sent request never committed. Availability failure
is 503 `receipt_unavailable`. Receipt states themselves use HTTP 200.
No authorization failure discloses another scope's operation.

A running effect is pending, including the gap after assertion verification
commits but before its effect starts. A state reader serializes with execution
and can report spent-uncommitted as `refused/approval_spent` only after a final
failure or expiry prevents a later commit. Unknown is not final success or
refusal: aw prints the operation ID, exits nonzero and never re-prepares on
its own. A lost response after commit returns the exact retained result, not
another signature, nonce or approval. A committed signature is distinct from
remote registry/app delivery; that delivery has its own status/reference.
For a signed credential start, expose `signing=committed` and `receiver=unknown` when
the app committed but its response was dropped. The client must not report a
usable session from that pair; acceptance checks that it sends no second POST.

The typed library ports take trusted adapter evidence explicitly:
`prepare(CatalogOperation, requester=RestrictedRequester)`,
`approval_options(operation_id, human=AdmittedHuman)`,
`execute(operation_id, proof, human=AdmittedHuman)` and
`receipt(operation_id, reader=ReceiptReader)`. The bounded request-origin
execute path supplies its typed catalog authority instead of a human proof;
it cannot select a floor variant. `prepare_handoff_start` (credential purpose only) uses the same store
and receipt with its distinct LOGIN rule. These are closed unions, not raw
bytes, caller-supplied authorization booleans or generic key locators.
The receipt reader is the still-authorized original requester in exact scope,
or a separately authenticated current human for that holding/key authority.
An operation ID is never a capability. A retired credential cannot inspect
through its retired session; an independently authorized reader can still
recover the committed result.

An internal typed custody adapter resolves an existing protected key reference;
missing references refuse, never generate or rotate a replacement. A
current-authorizer adapter supplies original-transaction prepare/check and
synchronous deadline checks. `AuditSink.emit(event, transaction)` remains the
local audit port.

Several explicit domain-authority bindings may refer to the same existing
protected key reference. Each binding must match current authoritative
evidence; sharing a reference grants no authority in another domain. Reference
preparation/import, reader cutover and erasure are separate operator actions.
The adapter must not duplicate ciphertext or silently rotate a controller to
manufacture a one-domain/one-key relationship.

For credential changes, the SQL-only `receipt(tx, change)` hook records the
exact permitted result in the original effect transaction. The consumer must
associate the client-known operation ID with the exact challenge, scope,
subject and verified credential binding before execution. Protected signer
consumers always supply the hook; compatibility optionality for old B3 callers
does not authorize an unreceipted new signing path. Receipt access expires only
under an explicit retention/access policy; retiring a credential must not
erase its committed operation result. Lookup grants no renewed action rights.

Every writer, and every receipt/status reader that also takes authority/B3
locks, serializes the operation **before** those locks. Prepare the operation
association before caller authority acquisition; the receipt hook must not
first acquire it later in inverse order. Credential mutation then uses the
existing consumer order: F6, the typed retirement
gate, role holds, B3 `prepare_credential_change(tx, scope)` with ordered write
locks, then S4. These are the existing authority/effect-fence components, not
a second approval engine. Its mutation fence returns the original-transaction
`PreparedCredentialChange`, which B3 validates and reuses. A shared-lock
usability check followed by a write-lock upgrade is not equivalent. Existing
enrollment/contact fence contracts remain compatible. Retained proof is
historical evidence; it never substitutes for current credential/holding checks.

Approval consumption, local effect and durable local audit/receipt share one
transaction and the existing B2/B3 fences. If a signed artifact is delivered
to a separate registry/app, signing and remote application are separate states:
retain the exact signed artifact before release, reuse its existing nonce/head
and reconcile the remote outcome. Never claim cross-service atomic commit or
blindly re-sign after a timeout. No network call belongs inside the final
effect fence. The ports and mounts above are shared implementation requirements,
not permission for each adapter to create its own store.

For `live_floor` operations, the signer enforces a UV age of at most
**300 seconds at the signing effect**,
bound to one request. Conservatively use the original approval challenge's
issuance time plus 300 seconds, capped by its original expiry and every other
applicable deadline. Do not start at a `verified_at` stamp written after an
awaited counter update. The owner-act verifier independently enforces a lifetime
of at most **600 seconds**, with its existing current-key and prepared-evidence
bounds. A console session of at most **900 seconds** never extends either.
Other existing ID/B2/B3 freshness bounds remain separate. Waiting on a lock
does not restart a deadline. Recheck effect-local deadlines after the final
await, before commit, rolling back a stale effect.

Signing audit starts with the signer, before any Logs installation exists.
Governance requires its durable local record in the effect transaction; an
optional downstream recorder is not the source of authority or an enrollment
prerequisite. Containment remains available during remote logging failure and
records its local outcome. Audit must distinguish bootstrap, live approval,
bounded unattended work and containment; exclude secrets and private keys.

## 6. Working credential changes versus recovery

`human-credential.add` and `human-credential.replace/current_passkey` require a
CURRENT usable credential of the same holding with fresh exact-act UV. Verify
the new credential's UV registration first, retain its exact credential digest,
and bind the current credential's approval to that digest, RP/origin, holding,
human, operation and selected retire target. The new credential cannot approve
itself. Browser `allowCredentials` is not a server-side membership check.

Add retains existing credentials. Replace inserts the new credential and
retires only the selected old credential atomically, never leaving zero usable
credentials. Retired credentials lose their sessions; replacement invalidates
the holder's unused approvals, including approvals made with its other
credentials. It does not undo committed acts or remove the holding. A live
operation racing recovery, subject replacement or retire-target revocation
refuses stale binding and rolls back.

Default maximum active credentials is **5 per holding**. An owner-approved
`human-credential.cap-set` changes the finite bound; stricter bounds may be
lower, never zero. A full set refuses additions without eviction. Replacing
one credential is allowed at or above the cap if the final active count does
not increase and at least one usable credential remains. Zero, negative or
above-ceiling bounds refuse. Lowering
a cap does not evict credentials from an already larger set. No cap-change
delay is added.

For app holdings, `human-credential.cap-set/app` is the existing owner-act/1
encoding with subject exactly `app_id`, `installation_id`, `role`, `cap`;
it names no principal and sets the role's per-holding cap. Its current team
owner supplies live approval, even if that person also holds the app role.
For protected-key holdings, `human-credential.cap-set/protected_key` binds
exactly the versioned protected-key context, `cap`, `old_policy_version` and
`new_policy_version`. Any current member of that key's authorizer set may
approve the exact selected holding/policy. B2's consumed exact approval and B3
retained proof plus current authority fence are the evidence; no fictitious
team-controller `VerifiedOwnerAct` is manufactured. The shared executor mints an opaque `VerifiedProtectedEffect` bound to the
original transaction, operation ID/digest, context/generation, current
authorizer and B3 evidence reference. It is not deserializable from a client
body. The shared cap effect accepts this evidence for protected scopes and
`VerifiedOwnerAct` for app scopes, dispatching to one cap mutation/check.
It writes the cap/receipt/audit in that same transaction. Package .3 owns one
shared typed cap policy store/effect, using .2's trusted evidence and receipt
primitives. B3 remains role-agnostic: its `credential_cap(tx, scope) -> int | None`
resolver reads the applicable policy under the effect's existing write
preparation. `None` means the configured default; a lookup exception refuses,
never defaults. A noninteger or value outside 1..ceiling is `cap_unavailable`,
never clamped. The early options check uses the same resolver, and the effect
rechecks under locks. Cap mutation and credential-count checks serialize in
the shared documented lock order; the operation lock still comes first.

App adapters map each holding to stable `(app_id, installation_id, role)`;
every holding of that role reads the same cap and counts its own credentials.
Protected adapters use stable `(service_id, authority, human)` from the typed
context. Recovery changing the context/subject generation does not reset that
policy; evidence still binds the current generation and policy revision.
The app effect accepts `VerifiedOwnerAct`; the protected effect accepts only
.2's opaque `VerifiedProtectedEffect`, with no stand-in while unavailable.
This specifies a shared implementation requirement, not an already implemented
B3 `set_credential_cap` API. All variants enforce 1..finite deployment ceiling,
default 5, and take effect at commit.

`human-credential.replace/controller_recovery` remains distinct: no usable
credential means separately authenticated recovery, with the **72-hour**
floor and frozen approvals. Security-contact change retains the **24-hour**
delay. A credential act cannot change the contact, and neither waits for nor
cancels a pending contact change. Notify the contact effective immediately
before the act. Notice failure does not reverse a committed result. Notice
delivery and no-contact holding behavior must match the shared B3 decision;
this contract does not create an independent retry subsystem.

For a non-team protected holding, the `protected_recovery` variant of
`human-credential.replace` changes the approval credential only, preserving
the human ID, protected signing key, authority and registry bindings. Its exact
request binds the protected context/generation, existing holder, selected new
credential digest, RP/origin, effective notice-contact digest and recovery
record. The recovery principal is the one explicitly designated for that
authority at provisioning or by a later live policy change. Hosted recovery
requires the existing verified-browser/recovery proof tied to the same current
account/H/domain; independent recovery requires a separately recorded protected-
host administrator recovery action for that exact authority. An ordinary CLI
token, generic cookie, worker call or reusable initial bootstrap is refused.
The adapter supplies a typed `RecoveryAuthority` proof of that existing route,
not a caller boolean and not a synthetic team owner. B3 disables the old
credential/freezes approvals, applies its 72-hour recovery floor and existing
notices/cancellation rules. It never calls initial enrollment to skip the wait.
Changing the protected signing key is `protected-key.recover` separately.
This adapter and its scope checks need their own implementation/security review.

The approved B3 notice behavior is best-effort delivery after commit, with a
structured delivery outcome and contact hash in the committed audit. A crash
between commit and send can lose the notice; no durable notice outbox/retry
has been approved here. A holding with no effective notice contact refuses
current-passkey add and replace with `no_notice_contact`, before any challenge and again under the
effect lock. A pending-only contact counts as none. The unchanged 72-hour
controller-recovery path remains available. No role declaration, mailbox
resolver or delivery subsystem is created to bypass this rule.

A usable stolen passkey plus its UV factor can add a credential. Notices
provide detection, not prevention of that case. The receipt exposes committed
credential changes independently of notification success.

## 7. Custody migration and compatibility

Worker OS users, containers, processes, mounts, backups and keychain access must
not reach protected human/namespace/team-controller private keys or unlock
material. Merely hiding a filename, asking for a passphrase, or checking an
agent-runtime environment marker does not establish isolation. Existing keys
enter protected custody through a separately approved operator-side import,
not through worker request bodies or a key-export endpoint. Preserve the exact
public key, ID, registry/origin bindings and issuance history. No automatic
rotation, remint, global-registry move or production write follows from build
authorization.

Inventory the existing human keychain entries and encrypted backups,
namespace controller stores, team-key stores, hosted DB custody, custody
sockets and worker-visible grants. Include OATS legacy minting roots under `.aweb-roots/<label>/.aw` and configured
`settings.oats.aweb.root`/`roots`, including their referenced team-key stores.
An endorsed root's AGENT key held by the worker is intentional bounded
operational custody, not a human/controller-key isolation finding. Inventory
its admission scope/limits separately; do not confuse it with the old minting
root's controller keys.
A path-only scanner can report known findings but cannot certify isolation:
OS-keychain accessibility, inherited mounts, sockets and backups matter too.
A co-resident protected signer is possible only with an actual separate
protection boundary (for example a different OS security principal without
worker access); a separate process under the worker user is insufficient.
A key for another team is not safe merely because a worker selects a different active team. The isolation finding is
about accessibility and authority, not a directory basename. Package .8 owns
per-installation migration approval, backup/removal and rollback limits.

Released local BYOT owner-act signing continues to produce artifacts that
remote verifiers accept under the unchanged wire rules. It is unsupported in
the protected profile, not cryptographically distinguishable or universally
rejected. Package .8 must name every affected BYOT team/client and its explicit
transition before activation; a documentation change does not perform cutover.
Protecting an existing team is an operator-approved .8 migration, announced to
all affected deployment owners before it takes effect. Inventory even clients
that never opted in but currently use that team's member invites. Their exact
fix is the configured protected-service/root admission path; coordinate their
upgrade/cutover before enforcing the narrowing. No silent automatic opt-in,
identity remint or local invite fallback is permitted. .7 reports findings to
the coordinator/.8 as deployment/team/service identifiers, custody category,
public key/ID references, affected consumer/version, readiness finding and
proposed operator action. Reports contain no private keys or unlock material;
an unavailable inventory result is unknown, not clean.
Legacy artifacts remain verifiable under their original formats. The new
signer removes unsupported human/controller signing entry points rather than
calling them as a fallback. Existing client requests must either use the
compatible restricted operation or return an explicit upgrade/approval-required
refusal. Inventory every affected consumer before activation; do not silently
weaken the signer to preserve a bearer-only governance route.

Agent identity creation remains in the released parent/child exchange. A local
agent can parent a local child; registered children require an eligible
registered issuer under the existing ID contract. A deployment root can issue
a registered descendant when it is that actual issuer; the chain must show the
real parent, never an invented local intermediary. This includes first
certification of an eligible existing chainless registered agent, after subject
possession/current registry checks; a session grant seat retains its resident's
ancestry and does not acquire a new parent of its own. Membership admission is a
separate controller effect and does not mint or endorse an identity itself.


Protected-issuer `identity.ancestry.resign/unchanged_protected_issuer` requires
retained evidence that the original was issued by this signer after live
approval or an explicitly approved re-endorsement. Legacy token-issued artifacts
imported during custody migration refuse; a routine re-sign cannot upgrade
that provenance. Require the unchanged current child ID, key, domain, kind and
parent, its subject-possession proof, current non-revoked head and the same
verified issuer identity/authority. Only the current issuer key (after valid
continuity), issued timestamp and corresponding signature/certificate digest
may change. No child-key change, parent change, rights change, expiry extension
or refresh of a revoked/replaced endorsement qualifies. ID v1 has no new
assurance or expiry field added by this rule. A genuinely new endorsement uses
its own live act.

## 8. Existing entry points and task mapping

The following inventory is source evidence, not evidence that adapters have
already closed these paths. Cloud contributes its hosted route-level trace;
application contributors supply the app rows. A supported composition must
route every key use through its classified operation or refuse it.

| Existing family | Source | Required disposition |
| --- | --- | --- |
| Human creation, keychain signing and backup | `cli/go/cmd/aw/id_human.go`, `cli/go/awid/human_signer.go`, `cli/go/awconfig/human_keychain.go` | Protected enrollment/issuance and operator migration; no worker passphrase fallback. |
| Human/root/agent child exchange and registration | `cli/go/cmd/aw/id_child.go`, `id_parent.go`, `id_create_parent.go` | Human/namespace uses are typed live operations; eligible agent issue/re-sign remains unattended. |
| ID rotation, recovery and revoke | `cli/go/cmd/aw/id_rotate_key.go`, `id_rotate_key_recover.go`, `id_revoke.go` | Classify key type, continuity and target; no human/root replacement under the agent exception. |
| Namespace address, controller, team creation and deletion | `cli/go/cmd/aw/id_namespace_*.go`, `id_team.go`, `id_team_rotate_key.go`, `id_team_server.go` | Enumerate exact controller effects; authority expansion/ownership changes require live policy, unknown operations refuse. |
| Team invite/admission, certificate renewal, member replacement/removal | `cli/go/cmd/aw/id_team.go`, `team_spawn_authority.go`, `team_replace_key.go`, `team_human.go` | Root agent-only bounded admission; human admission separate live act; unchanged agent continuity renewal only. |
| Human reads/connect/team-auth/mail | `cli/go/cmd/aw/human_participation.go`, `id_request.go`, `id_registry_read.go` | Section 4 typed restricted server authentication; no arbitrary installed tool/path signer. |
| Resident custody app/message signing | `cli/go/cmd/aw/custody.go`, `custody_app.go` | Agent resident work remains scoped; never load a protected human/controller key into worker custody. |
| Controller owner/hook acts | `cli/go/cmd/aw/hooks.go`; [owner act](owner-act.md) | Shared signer live approval and existing downstream verification/nonce consumption. |
| Anonymous owner-act delivery | [Owner-act delivery](owner-act-delivery.md) | Allow only the valid controller act; designation checks the human's own kind/current membership, not nearest-human ancestry. |
| Team-auth on the human origin | [Human confirmation](design/human-confirmation-from-aw.md) | Refuse; neither a valid signature nor a typed payload crosses this origin boundary. |
| App-origin handoff starts | Section 4 and [human confirmation](design/human-confirmation-from-aw.md) | Session: current direct-child member may prepare, with H's own app LOGIN and Allow; credential: same-signer H through protected LOGIN. Neither is governance authority. |
| Secrets narrowing through team-auth | [Secrets](design/secrets.md) | Allow only authorized narrowing/containment, with last-owner protection; no holding removal or re-enable. |
| Logs `reader-slot` / `remove-reader` tools and old reader designation route | [Human-role holders](design/human-role-holders.md) | Refuse/remove together in package .9; use protected `human-role.*` owner acts. |
| Token/session-only or browser-only grant completion | [Human confirmation](design/human-confirmation-from-aw.md) | Refuse; exact frozen-request passkey approval and the existing aw confirmation binding remain required. |
| Runner register/claim/result and Logs ingest | [Secrets](design/secrets.md), catalog `runner.execute` / `logs.ingest` | Existing typed operational authority only; not owner designation or governance signing. |

Hosted adapter inventories must cover every browser-session, CLI-token,
installed-tool and linked-channel signer, including cached-member projections,
certificate reconciliation, immediate-connect recovery and namespace/human
re-establishment. Classify each path before minting; a cache or recovery path
is not an exemption. The early hosted `aw id create --org --human-parent`
branch is not made safe by a later local terminal check: its token-only human
issuance authority must be removed. Exact hosted route traces remain with
that implementation's owner; no private application schema governs this OSS
contract.

Existing tasks remain tracked; the build does not discard their delivery scope:

| Prior work | New scope |
| --- | --- |
| acxt deployment-root journey | Attribution/continuity baseline only; not proof of protected controller custody. Preserve the accepted test and add .4/.7 isolation/admission controls. |
| acxv naming cleanup | Preserve its independent landing; no replacement design name restores removed authority. |
| acxu browser file consent | Superseded implementation by .5 shared ceremony and .6 Cloud adapter; retain the frozen historical note, no new file-transport implementation. |
| acwd / C3 / 4.6 and existing human-role handoff | Preserve their shared app API; adapt the signer and typed scope additively in .2/.3/.5. |
| Secrets 16.41, 16.43a+b, 16.44.3 and full provider/runner acceptance | Continue in .9 with catalog compatibility; no restart or dropped scope. |
| Existing deployment roots and team/controller stores | .8 inventory and explicitly approved migration; .7 reports findings, never auto-remints. |

## 9. Acceptance boundary

The vectors pin the policy distinctions, including same/different/unknown
nearest human, old-key continuity versus new-child lost-key recovery, issuer
kind, first enrollment, approver sets versus credential sets and recovery.
Each scenario varies the named inputs with all other row preconditions valid;
its decision reason is distinct from the HTTP receipt code (an unmapped typed
reason remains diagnostic under `operation_refused`). They are policy
scenarios, not new cryptographic test vectors or a duplicate
signer engine. Packages .2–.6 must exercise them against their actual shared
implementation; static catalog validation alone is not runtime acceptance.

The independent profile must use customer registry/service origins with no
Cloud credentials, exercise private member-key reads and wrong-registry
refusal, and prove ordinary request authentication and agent admission while
worker-held human/controller shortcuts fail. Hosted tests must trace all
issuance routes, including cached/recovery certificate paths and channel mail.
Each release names exact package/client/server/registry versions; no version
is claimed by this contract. Fresh setup and supported existing-state
upgrade are separate acceptance journeys.

## 10. Review boundary and evidence

All catalog operation groups, requester/receipt ports and policy cases are
frozen for implementation, including the final loopback-only direct-child
start, retained-certificate source and H-signed credential-start refresh,
laptop admission, and server-frozen endorsement policy. There is no remaining
policy decision blocking these groups. A runtime adapter with no implemented
trusted evidence producer, custody binding or classified route must refuse
that operation until its implementation is available; it must not invent a
fallback or hold the other groups.

Concrete adapter route tables remain .2/.4/.5/.6 deliverables: every
direct/cached/recovery key use maps to a catalog row or explicitly refuses.
Implementation handbacks give an exact SHA and focused positive, refusal and
race evidence, with one independent implementation review and security review
where a boundary changes. No repeated unchanged consumer FIT round is needed.
New credential-change recorder kinds must compose with the installed app's
transactional recorder; a plain local-sink test is not proof of that integration.
No bootstrap depends on remote Logs. Release and install acceptance remain
separate from this contract freeze.

Source contracts are [ID certificates](id-certificates.md),
[AWID](awid-sot.md), [owner acts](owner-act.md),
[owner-act delivery](owner-act-delivery.md),
[human-role holders](design/human-role-holders.md) and
[human confirmation](design/human-confirmation-from-aw.md). The application
catalog/first-role/entry-point cases were contributed by the app-contract lane;
its separate Secrets bootstrap correction is included with original authorship.
The B2/B3 port and lock-order contribution was source-read at
`27fbd08192a1997874da58abff8d151c0e7779ce`, based on the holder stack rather
than older main B3. These sources establish reusable boundaries, not completed
protected-signer integration. The independent reviewer must not ACK their own
contributed portions; security review covers the assembled contract.
