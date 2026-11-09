# Deployment endorsement and swarm admission

Status: **first interface draft**, aweb-acwd.10 (W1). The direction is approved;
this interface is not yet ACKed and grants no implementation authority. W2 is
[aweb-acwd.11, protected human confirmation](human-confirmation-from-aw.md).
The shared admission/proof linkage in section (d) requires agreement with W2
before this contract can be frozen.

Goal 2: support customer-operated agent workflows with an explicit human
endorsement, resource-owner permission for a swarm, and enforceable withdrawal.

## Authority and existing contracts

A deployment identity D is an ordinary **registered, ID-tree-enrolled agent**.
“Deployment” names its use, not a new identity kind, controller or certificate.
A human H endorses D knowing that its descendants may issue further agents.
A swarm here is D and the descendants whose currently valid ancestry contains D;
future descendants qualify by the same rule, not by a copied list of members.

Keep four decisions separate:

| Decision | Authority and evidence |
| --- | --- |
| Identity custody and ancestry | Subject's key possession; parent-signed ID certificates and current public registry evidence |
| Team admission | Current team-controller-signed membership and the team's admission policy |
| Protected endorsement | W2's independently verifiable exact-action confirmation, linked to the accepted endorsement |
| Resource use | Resource owner's current grant for selected operations, under the installation scope ceiling |

The [BYOT contract](../byot-onboarding-contract.md) separates custody,
namespace/team authority and coordination hosting. A directory, hostname or
working service credential does not collapse those authorities. A customer may
operate the registry, coordination server and confirmation-capable component;
Cloud custody is optional. Public registry discovery, bounded freshness and
revocation remain governed by [ID certificates](../id-certificates.md), not
replaced with a new offline-authority claim here.

## (a) Fresh setup and reuse are different journeys

### Fresh setup

1. Select the customer/hosted authority model, target identity domain and team.
   Establish who controls the human signer, namespace and team controllers,
   deployment identity key, and confirmation origin. None is inferred from
   who can write the deployment directory.
2. Create an ordinary agent key, derive its stable ID and establish its public
   current-key registration through existing lifecycle operations. This is key
   registration, **not ID-tree enrollment**: no intermediate namespace-parent
   certificate is implied. If an address is allocated, obtain namespace
   authority separately. Neither operation admits D to a team.
3. Prepare D's first ID-certificate request with H as the intended identity
   parent. Obtain H's protected confirmation of that exact request through W2,
   including: **endorsing this identity endorses everything it spawns**,
   recursively. H's identity signer issues the matching human-parent agent
   certificate only with the matching current confirmation. D registers it at
   the authoritative registry with its own subject-key proof and
   `expected_head=null`. This is D's first ID-tree enrollment. Link the accepted
   certificate revision to the retained proof as (d) requires; a failed or
   pending registration confers no protected authority. If an ID-tree head
   already exists, use the explicit reuse/re-parenting journey instead.
4. Verify D's registered, current H-rooted ancestry. Obtain ordinary team
   membership and any permission needed to admit spawned members separately.
5. The server/app authority selects protected admission for the intended
   operations. A resource owner grants the subtree its selected resource
   operations under (b). No access is inferred from the endorsement alone.
6. D issues carried local child certificates with its identity key. Every
   requester still proves its own key, current membership, current ancestry,
   protected endorsement dependency and applicable resource permission.

This is a contract journey, not a claim that one existing CLI command completes
it. W2 must resolve the existing self-hosted component and first-human/first-owner
bootstrap without requiring secrets merely to endorse an identity.

### Reuse or re-parenting

Inspect an existing identity's registration, actual parentage, current key,
custody, membership and admission authority before reusing it. A registered
agent already under the intended human may retain its identity. Its valid chain
alone does not establish protected confirmation: (d) must still match.

A namespace-root-issued humanless agent does not become human-endorsed through
a role label. Registered re-parenting uses the existing new-parent signature,
subject-key proof and expected-head compare-and-set. It preserves ID/key and
ordinary memberships only where their bindings remain unchanged. Re-parenting
is an explicit change of ancestry, never a silent repair of a failed check.

The existing `aw id parent request/import` exchange issues a first certificate;
it is not a general re-parenting command for an already installed chain. A local
identity is not an independently revocable registered deployment point merely
because its directory is reused. Enrollment/conversion and any membership
changes must be made explicit; this draft promises no automatic local-to-global
migration.

OATS `settings.oats.aweb.root` / `roots[team]` is a **reuse candidate only**.
The selected identity key can issue ancestry. Instance membership minting also
needs the relevant team-controller operation or service-authorized admission
path. Namespace authority may additionally be needed for fresh addresses.
Reusing that context must not grant controllers, expand an admission credential,
or imply that controller custody follows from human endorsement. No new or
mandatory “steward” role is introduced.

## (b) Swarm eligibility belongs in resource permission

The resource owner may grant selected operations to a defined subtree including
future descendants. Ancestry is an eligibility test for that grant, not a grant
by itself. The resource grant must bind the team/resource context, registered
ancestor D, selected operations (including their existing digest/version
constraints), current grant authority, and the applicable endorsement policy.
The exact representation is to be reviewed with the app policy owner; this
paragraph does not freeze new signed bytes or a token family.

For secrets, this extends the subject/eligibility semantics of the existing
[`grant/1` resource permission](secrets.md#43-grants). It does **not** put resource
permissions into `aweb_naapp.runtime.authorization.Grant`, which remains the
installation's team/scope ceiling. All existing secret state, operation digest,
policy, approval, rate, window and dispatch-fence checks still apply.

Shared identity verification establishes the authenticated requester's current
chain and its relationship to D. Shared policy consumes that result together
with the app's authoritative resource grant. The app must not maintain an
independent chain parser/verifier or infer ancestry from aliases, runtime labels,
workspace paths, an arbitrary supplied parent ID or the nearest human alone.

Permissions from matching grants are additive. A narrower individual grant does
not subtract inherited subtree authority. To remove inherited authority, the
owner withdraws/changes the corresponding subtree grant or its required
endorsement. A separately valid individual/role grant remains independent;
none can bypass a server/app requirement that applies to the operation itself.

### Secrets candidate order and containment

Extend secrets decision 46 with a third tier, preserving its whole-candidate
selection and charging rule. The contract remains subject to exact-SHA review:

1. Grants to the requesting principal, in `grant_id` order.
2. Grants to its roles, in `grant_id` order.
3. Eligible subtree grants, in `grant_id` order.

The first candidate that admits is used; charge only that candidate's policy
buckets. Evaluate each candidate whole: operation/digest, open-request and
sensitivity rules, approval, windows, rate, attestation and dispatch fence. Do
not assemble permission from fragments of multiple grants. If candidates exist
but all refuse, return the first candidate's refusal. If none exists, use the
existing no-grant refusal.

A principal grant's rate or window refusal can therefore be followed by a role
or subtree grant that admits and is charged. This is additive permission, not
a deny override. The owner contains subtree use through that grant's own policy.
Existing principal/role grants retain their order and charging behavior.

A subtree grant is eligible only when shared verification establishes current
membership in D's subtree and the currently valid endorsement required by that
grant. A definite wrong subtree, withdrawn endorsement or revoked ancestry
makes it ineligible; secrets parses no chain and reveals no new detail about D
through its no-grant refusal. An operation/team-wide required-endorsement check
in (c) runs before grant evaluation and cannot be bypassed by another candidate.
Unavailable verification is distinct from proven ineligibility; its treatment
when an independently admitting grant exists remains a shared-runtime/policy
interface question, not permission to admit an unverified subtree grant.

The `grant/1` subject gains a subtree variant naming registered D (`did:aw`).
Exact bytes/version remain for the app policy owner at freeze. Existing digest
binding remains: editing an operation cannot silently widen a grant. Sensitive
secrets still admit only named operations; subtree grants do not enable
`open_request` for them.

For a subtree-admitted use, also charge a per-(D, secret) rate bucket in
addition to the existing per-(requesting principal, secret) and per-secret
buckets. A fresh worker does not get a fresh D bucket. This applies to the
selected subtree grant, not an independently admitted individual/role grant.
The app policy schema must freeze the bucket parameters and shared keying across
subtree grants naming the same D and secret; it must not multiply D's budget by
creating another grant ID.

When the selected subtree grant's existing `distinct_approver` condition is
`required`, exclude both the requesting principal and D's verified endorsing
human from eligible approvers. This is scoped to subtree-admitted uses under
that condition, not a universal new four-eyes requirement. The endorser is the
H established by the matched protected binding and current required ancestry
in (d), not an arbitrary nearest-human label. Unknown or mismatched evidence
cannot establish distinctness. Distinct DIDs do not prove distinct people.

These rate, four-eyes and sensitive-secret requirements follow the coordinator's
2026-11-09 disposition of the secrets lane input. Exact app subject/rate encoding
and version remain to be frozen by the policy owner with the vectors.

### Acceptance case: A requests the launch of B

An instance of approved worker definition (soul) A may request the launch of
an instance of B with different permissions. Permission to request that launch
is separate from permission to use B's resources. In this acceptance case,
B-only rights use B's independent principal grant or an owner-authorized app
role designation for B's exact identity. B authenticates as B; A acquires neither
B's role nor its credentials. Neither worker may change its own grants or role
membership. Existing principal/role authorization remains unchanged.

A legitimate designation permits B to use role X. A's own request for X, A
presenting B's soul name, an undesignated child certificate and an edited local
soul file must not acquire X. These protocol cases establish principal/role
enforcement only: refusing A's own key does not prove that A cannot steal or use
B's key. A soul name, local metadata, a locked revision, a merged PR or an
ancestry certificate is not an app-role authorization.

**Assurance boundary.** A deployment is an operational grouping, not
automatically a security boundary. It may contain several isolated execution
environments. Environments where agents can impersonate each other are one
trust boundary for security claims; their effective authority includes all
reachable credentials and privileged interfaces. On a shared-UID host with
accessible minting and member keys, principal/role permissions remain useful
for organization, error prevention and attribution, but do not contain a
compromised worker. A fixed identity-home environment variable is client
behavior, not isolation. Claim narrower per-worker containment only where
execution, credential/signing and privileged-invocation boundaries are enforced
and demonstrated. In particular, A must not be able to read or invoke B's key or
impersonate the authority that provisions B.

Current OATS lane evidence reports per-team deployment roots, local soul/revision
metadata, membership eligibility by soul policy, and no enforced launch
authority against another process on the same UID. This is the OATS owner's
source assessment, not a W1 runtime qualification. Supported provisioning and
support recipes must identify their actual execution/key/signing arrangement,
its limits and evidence, separately from the protocol cases above. Reuse
existing OS, custody and runner controls where they suffice; this contract
prescribes no per-agent container, supervisor service or new attestation family.

For dynamic workers two integration gaps remain unscheduled:

- **G1, approved definition to identity/role binding.** A trusted provisioning
  path must verify the approved soul and revision, and bind the resulting B
  identity to its authorized role. First assess whether an isolated authorized
  launcher can check the pinned definition and use existing owner-controlled
  identity-to-role assignment. No portable soul claim or new certificate field
  is frozen here. A verifier-visible signed claim needs a demonstrated
  cross-boundary requirement. Adding a digest to a disclosure alone does not
  enforce the runtime binding.
- **G2, launch authority.** The authority allowing A to request B's launch must
  be enforced by a provisioning authority A cannot impersonate. Instructions
  to spawn only when asked do not enforce it. This is an OATS integration gap;
  this fit check does not resume paused launch/isolation implementation.

Existing per-instance principal grants and role designations work but require
owner action for each new identity. An optional existing-identity arrangement
for dynamic workers is a separately endorsed D_B rooting B instances, with a
subtree grant covering that branch. D_B is not a required role or a new identity
primitive, and its signing key must not be readable by A. G1 and G2 remain open;
this arrangement does not establish an approved soul binding. A subtree rooted
at B excludes its ancestor A; the real hazards are a COMMON subtree containing
both workers and A controlling B's minting/custody. Never put B-only rights on a
subtree containing A. Subtree grants are actual shared authority, not a ceiling
from which a narrower worker grant subtracts. No deployment-wide permission
object or universal child-permission-subset rule is introduced.

**Restricted invocation.** If A can command B to make arbitrary resource
requests and return arbitrary output, their permission separation is nominal.
For this case B uses named, digest-bound operations and enforced request/output
limits, plus its existing approval and distinct-approver policy where required.
An `open_request` grant cannot establish that restricted-operation boundary;
sensitive secrets never allow it. The provisioning/support evidence must also
qualify the interface through which A invokes B, not only B's authentication.

## (c) Required endorsement is selected by the authority

The server/app policy, not a client flag, selects which operations require
protected deployment endorsement and which deployment ancestors are eligible.
Resolve that requirement from the authenticated team, installation/resource and
operation. Caller-supplied chain bytes are evidence to verify, never permission
to select a weaker admission mode.

The logical shared admission interface consumes:

- the exact authenticated subject ID/key and existing authentication result;
- the authority-selected requirement and applicable current grant;
- current public ID-tree evidence for that subject and selected ancestor;
- W2's matching protected-endorsement binding and retained proof.

After ordinary authentication and installation-ceiling checks, policy selects
the requirement for the exact principal, tool, installation and resource
operation. A typed internal `PreparedDeploymentAdmission` carries a successful
result to the existing effect/dispatch fence. Its semantic fields are:

| Field group | Bound values |
| --- | --- |
| Authenticated operation | Subject ID/key, team, app/installation generation where applicable, audience, canonical operation/target and covered request digest |
| Policy | Authoritative requirement identity/revision; applicable resource grant identity/revision, or explicit absence for coordination without a resource grant |
| Ancestry | Selected D ID/key, matched current certificate revision, verified subject-to-D relationship and required human H |
| Protected endorsement | Authority origin, exact W2 binding/revision and retained-proof/holding references |
| Fence dependencies | Original evidence acquisition/freshness information and mutable local dependency versions/expiry under their existing rules |

This is trusted in-process output, not a request DTO, credential or new signed
artifact. A caller cannot construct authority by supplying these fields.
`ActionPolicy.__call__` currently returns `bool`; the existing `Authorization`
has no endorsement dependencies. Its bool is not a substitute for this typed
handoff. Concrete API placement remains for the runtime lane review.

Acquire remote observations before transaction locks. At the existing effect or
dispatch fence, match the same operation and recheck mutable local grant,
installation and endorsement dependencies and their applicable expiry. A changed
or withdrawn dependency blocks the effect; preparing again cannot restart its
lifetime. Preserve the public ID verifier's original freshness rules, including
its acquisition-time check; do not invent a new post-lock ancestry-age deadline
or imply that a local lock serializes remote registry changes.

Admission requires **all** independent checks. The subject must currently be D
or in D's valid subtree; D must have the required current human ancestry; the
protected endorsement must match; membership, installation scopes and resource
permission must separately pass. `human_required=True` alone is insufficient:
it proves neither membership in the selected subtree nor protected confirmation.

Enforcement is required in both places:

1. OSS coordination's `id_chain_auth` / `team_auth_deps` admission, before the
   protected operation's effect or delivery.
2. Direct naapp endpoints, alongside existing authentication and app policy,
   before the effect and at the app's existing dispatch/effect fence.

A missing chain, foreign subtree, revoked/superseded dependency or mismatched
protected confirmation cannot select ordinary legacy admission for an operation
with this requirement. Enrolled global omission continues to use the existing
public reconstruction rule. A local subject lacking sufficient ancestry is
refused. Unavailable authority is not proof of absence or successful legacy
status. Closed refusal mapping for this lane is:

- `403 deployment_endorsement_required`: definitively absent, mismatched,
  foreign, revoked or otherwise invalid required endorsement evidence.
- `503 deployment_endorsement_unavailable`: required evidence/authority cannot
  be established, including a failed or expired authoritative read.

Existing authentication failures remain earlier, including their existing 401
responses. No approval, dispatch or protected effect is created on these
refusals. An unrelated operation retains its existing disposition.

This opt-in authoritative lane changes no unrelated humanless or legacy team
policy. Existing clients are not silently narrowed globally. Activation must
name affected operations/consumers and their deploy order before enforcement.

## (d) Protected confirmation must be a verifiable dependency

Joint W1/W2 interface, **not settled storage or wire schema**:

A valid H -> D chain contains no user-verification proof. The admission authority
needs a binding to the exact accepted endorsement and W2's retained B2/B3 proof,
not a human label, Cloud session receipt, evidence locator alone or an assertion
that a service saw a click.

The candidate binding must let the verifier establish together:

- the exact CSR/request bytes, target stable ID and key, intended human issuer,
  recursive-scope disclosure and intended endorsement operation;
- the confirmation's audience/context, bound credential/holder authority,
  freshness at authorized consumption and single-use disposition;
- the resulting accepted ID-certificate revision and its correspondence to
  that confirmed request, without making an unaccepted candidate authoritative;
- the current authority record on which protected admission depends, including
  withdrawal/supersession, while retaining the original proof for later audit.

Reuse existing approval proof, credential binding, issuance/registration and
resource-authority records first. Do not add a certificate/token family or a
mandatory approval service. The consumed approval's short lifetime must not
silently become a new identity lifetime: historical confirmation and current
endorsement authority are distinct checks.

**Required acceptance boundary:** an otherwise valid instance of the same ID
created/adopted through session-only Cloud signing, or ordinary human-key
issuance, does not satisfy a policy requiring protected endorsement. Attaching
an unrelated assertion or borrowing another identity's confirmed CSR also
refuses. Fresh confirmation and ancestry signing remain different functions;
there is no passkey-to-Ed25519 conversion.

### Binding authority and assurance

H4 reuse is ruled. The ceremony host is the team server acting as a reserved
first-party human-role host. It reuses B2/B3 and owner-act delivery as libraries;
there is no second WebAuthn or stage-3 verifier. The current team controller
binds H's exact credential with `human-role.designate` and the existing
`human-credential.replace`/`human-role.revoke` lifecycle. A human-key, member,
install-admin or ordinary session signature is not controller authority and
cannot bind a credential. The credential handoff itself authorizes nothing.

The controller-signed `aweb.team-server/1` record selects the human origin; the
owner's client verifies that record and the shipped declaration. The act's
`aud` is that origin and the browser RP ID derives from its hostname. Only the
`team-server` app ID, `endorser` role and fixed per-team installation binding
declared by W2 are accepted. The installation ID is UUIDv5 of
`aweb:team-server:` followed by `team_id`, in the RFC 4122 URL namespace; another app/installation gives
`owner_required`. W2 fixes those
literals, shared-library composition and additive migrations. Non-users of
protected endorsement configure nothing and run no new required service or
startup check. Hosted deployments use the same contract; their chosen origin is
an operator decision, not an OSS dependency.

The retained proof must identify the exact holding current when confirmation
was consumed and retain its authoritative controller-act binding as well as the
original assertion. This includes any `human-credential.replace` act and its
cooling-off transition that established the credential current at consumption;
the original designation alone does not bind a replacement credential. Verifying a hash commitment or trusting an
"approved" row
alone is insufficient. A binding is made once per endorser credential; ordinary
admission reads the local binding/holding history and performs no extra AWID
lookup just for the holding. Public ancestry checks retain their own rules.

The assurance has H4's existing limits:

- A custodian holding H's identity key alone cannot bind a substitute credential.
- A custodian holding both controller and H keys, or controlling the owner's
  signing client, can bind any authenticator; shared custody adds no independent
  protection. The owner = H single-sitting case retains this same client trust.
- A compromised H client can substitute the credential and its displayed
  fingerprint. Comparison protects the channel between clients, not either
  compromised client. A channel controlled by the custodian (including aweb
  mail, a notice or another key under that custodian) is not independent.
- No authenticator attestation or proof that two DIDs are two people is claimed.
  A software authenticator legitimately bound by the controller counts.

Replacing or revoking an endorser credential stops its future confirmations;
it does **not** withdraw endorsements already consumed under the formerly
current holding. Existing endorsements stand until explicit withdrawal or loss
of another required dependency. The customer disclosure must state this, and
the old assertion must still verify against its historical binding. A later
compromise of the authenticator is not automatically detected.

### Candidate direct-consumer read

Extend the existing app-to-team-server read path, not the installation `Grant`
object. `TeamServerDirectory` verifies the controller-signed server record and
current team authority; the existing app read credential machinery authenticates
the app/team. The concrete proposal for review is a read-only
`GET /v1/apps/self/deployment-endorsement` with signed query fields for
`installation_id`, `generation`, `deployment_id` and `certificate_sha256`, using
the existing `app-grant-read` purpose. This is an explicit additional authorized
read, not a claim that today's own-grant endpoint already serves it.

The server derives team/app from the credential, verifies the app's current
installation/generation, and returns only that team's matching endorsement
record and verification material. The response must bind those request fields,
the server's origin, D's exact key/revision, H, CSR/disclosure commitment,
protected binding identity/revision, retained original B3 proof and authoritative
holding evidence. The consumer verifies both original assertion and credential
binding using the shared verifiers, then checks current endorsement status.
No caller URL, arbitrary approval authority or cross-team record is accepted.

The hosting origin must equal the discovered team-server origin. Follow no
redirects; key/record/origin changes invalidate cached observations. Reuse the
existing bounded-freshness read machinery: at most 60 seconds from acquisition
start, no expired fallback and no restarted lifetime. A definitive no-row or
withdrawn answer gives `deployment_endorsement_required`; timeout, malformed or
unavailable authority gives `deployment_endorsement_unavailable`. Cache entries
bind the exact team/app/installation/generation, server authority, D and
certificate revision, not just D's ID.

When the team server's origin changes, its existing endorsement rows stay
valid, because their retained assertions verify under their recorded rp_id;
new confirmations need a credential rebound with `human-credential.replace`. A
move to a different team server carries no rows, and endorsements there are
made afresh.

Admission compares D's current registered key to the row's `subject_key`, as
well as its current certificate to `certificate_sha256`. A registered identity's
key rotation need not change the certificate bytes, so the hash check alone is
insufficient. Both comparisons use the existing ancestry observation.

**Continuity.** A protected endorsement covers one D, one key and one
certificate revision. When D's key rotates, D is re-endorsed. When D is
re-parented or gets a new certificate revision, D is re-endorsed, because no
row matches the new certificate. `resign` does not apply: it is for `did:key`
children, and the covered request names a registered D. An unrelated refresh
of D's ancestry evidence, with the same D, key and certificate, changes
nothing.

W2's [endorsement flow](human-confirmation-from-aw.md)
provides the producer: its consumed record binds `csr_sha256` over request
signing bytes, D's ID/domain/subject key, H, team and server installation,
`disclosure_version`, approval ID, `approval_evidence_sha256` and the holding
current at consumption. Its authenticated certificate-link operation records
`certificate_sha256` over signed certificate bytes idempotently, before D
registers it at AWID. A linked row without the matching current registered
certificate grants nothing. Withdrawal records `withdrawn_at`; it does not
reactivate a row or remove its history.

**Before ACK:** W1 and W2 jointly freeze the read response bytes, authorization
bounds, proof/history references and currentness checks above with the public
corpus. The candidate read is not shipped behavior.

## (e) Withdrawal denies dependent access and keeps history

Ancestry revocation, protected-endorsement withdrawal and resource-grant
withdrawal are separate authority operations. When a required dependency ceases
to be valid, admission and the existing effect fence deny the dependent action.
Membership/permission rows need not be deleted to enforce that denial. Retain
certificates, consumed confirmation proof, grant revisions and decision audit.

Independent grants are not revoked by withdrawing another grant. Their
operations remain subject to any authority-selected endorsement requirement
that applies to them. This distinction must be visible to the operator: removing
one source of permission does not imply that every independent source vanished.

D itself, its current valid parent, or its namespace root may revoke D's ID
ancestry under the existing identity revocation contract. A team-controller
key alone supplies none of that ID authority. If H cannot sign in to withdraw
an endorsement, an authorized ID revoker can revoke D; independently, the team
controller can revoke affected membership certificates and resource owners can
withdraw affected app grants. Those are team/resource-local containment paths,
not portable subtree revocation, and D's membership revocation alone does not
revoke separate descendant memberships. Containment must name each dependency
whose access is being removed.

Revoking registered D can invalidate its descendants' ancestry without revoking
H or H's unrelated branches. Local ordinary admission outside this protected
lane retains its existing semantics. No claim of instantaneous revocation while
disconnected is made; apply existing freshness bounds and fail unavailable when
required evidence cannot be established.

Running jobs, process custody, already delivered values and provider-issued
credentials need their existing containment/expiry/revocation mechanisms.
Denying the next request does not recall an upstream credential or stop a process
by itself. No new TTL for identity certificates, resident grants or upstream
credentials is implied.

## (f) Conformance vectors and real-consumer negatives

Freeze shared decision vectors after (b)/(d)'s interfaces agree. Reuse current
ID-chain and B2/B3 proof fixtures; do not redefine their signed formats. Add
consumer tests at both OSS coordination and direct naapp admission. Each refusal
must precede effects, and effect-fence tests must cover withdrawal after initial
admission. These cases are an acceptance matrix, not a claim of tests run:

| Case | Required result |
| --- | --- |
| H-confirmed registered D, valid local descendant, active membership and matching resource grant | Allow only granted operation |
| Future descendant with the same verified ancestry and grant | Same eligibility, no per-child grant copy |
| Missing local chain on a protected operation | Refuse; no legacy fallback |
| Valid human-rooted but foreign subtree | Refuse despite `nearest_human` |
| Correct chain, absent protected binding; session-only Cloud or plain human-key issuance | Refuse protected admission |
| Grant from a non-owner or confirmation from the wrong bound approver/issuer | Refuse |
| H-key-signed credential binding without controller act | `owner_required`; no holding or endorsement row |
| Assertion from a credential other than the current holding | Refuse; no endorsement row |
| Consumed endorsement predates credential replacement | Verify against historical holding; remains until explicit withdrawal |
| Endorsement consumed after a valid replacement and cooling-off | Verify the replacement binding/history and current credential; admit |
| Old credential used for new confirmation after replacement | Refuse; no new row |
| Required policy with client flag omitted or false | Requirement still applies |
| Changed CSR, target key, parent, audience or recursive disclosure | Refuse mismatched proof |
| D key rotates while certificate bytes remain the same | Refuse; fresh protected endorsement required |
| D re-parented or given a new certificate revision | Refuse; no matching endorsement row |
| Same D, key and certificate after unrelated ancestry-evidence refresh | Admit under unchanged dependencies |
| Same team server changes origin | Retained assertion/history verifies; new confirmations require rebound credential |
| Move to another team server | No transferred endorsement row; fresh endorsement required |
| Replay of consumed proof for another issuance or resource operation | Refuse; exact idempotent receipt replay grants no new effect |
| Revoked D, withdrawn protected endorsement, withdrawn matching resource grant | Deny each dependent path; preserve history |
| Unavailable required registry/proof/authority evidence | Unavailable; no effect or fallback |
| Narrower direct grant plus broader matching subtree grant | Direct grant does not subtract inherited permission |
| Individual rate/window refusal followed by eligible subtree admission | Charge the admitting subtree policy only; no fragment combining |
| Ineligible subtree with no other candidate | Existing no-grant refusal; no D-specific disclosure |
| All eligible candidates refuse | First candidate refusal in principal/role/subtree order |
| Sensitive secret with subtree open request | Refuse; named operations only |
| Newly spawned workers under the same D use one secret | Charge shared D bucket in addition to existing buckets |
| Subtree grant requires distinct approver and candidate is D's endorser | Refuse that approver |
| Same request under policy without distinct-approver requirement | No new universal four-eyes check |
| Read asks another team/app/installation or supplies an approval URL | Refuse; no cross-authority lookup |
| Server origin/key changes, or required response expires | No stale-cache or redirect fallback |
| Withdraw subtree grant with an independent valid grant remaining | Evaluate independent permission under applicable operation policy |
| B uses role X after legitimate owner designation | Permit only B's granted operation |
| A uses its own key for X, claims B's soul, presents an undesignated child certificate or edits local soul files | No B-only role; protocol evidence alone does not qualify custody isolation |
| A can reach B's key, minting authority or unrestricted privileged invocation | No per-worker containment claim, even when principal tests pass |
| Unrelated legacy/humanless operation outside the requirement | Existing disposition unchanged |

Use one public decision corpus consumed by coordination and direct naapp
admission. Every refusal case must assert unchanged approval/dispatch/effect
state, not only its HTTP status. The exact machine-readable vector location,
app grant encoding and protected-binding producer/consumer payload remain open
interface items for this draft. Their resolution, lane review by runtime and secrets
policy owners, and R + Athena ACK at one exact SHA are prerequisites to the
implementation tasks.

## Source anchors for this draft

Current behavior at main `6fd325862`:

- `docs/id-certificates.md`, “What the tree proves”, registration/re-parenting,
  revocation and request disposition: ancestry is not permission; local ordinary
  omission is advisory; registered current ancestry is reconstructible.
- `cli/go/cmd/aw/id_parent.go:242-249`: first-certificate exchange restriction.
- `cli/go/cmd/aw/id_team.go:775-800,1795-1842` and
  `team_invite_attribution.go:89-146`: admission and ancestry are separate.
- `server/src/aweb/id_chain_auth.py:22-48` and
  `awid/src/awid/id_certificates.py:360-369`: current ordinary disposition and
  the existing human-required primitive.
- `naapp-lib/src/aweb_naapp/runtime/team_auth.py:688-754` and
  `runtime/authorization.py:159-192,267-297`: member authentication, installation
  ceiling and application policy seam; no current protected-endorsement switch.
- `naapp-lib/src/aweb_naapp/runtime/passkeys/proof.py:303-355,388-432`:
  retained exact-request confirmation evidence.

The contract direction was authorized on 2026-11-09 by Juan, relayed in the W1
assignment and task aweb-acwd.10. That approval authorizes this contract work;
concrete interfaces above remain draft until reviewed. Existing independently
verifiable approval guarantees are preserved.
