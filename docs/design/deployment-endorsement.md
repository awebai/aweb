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
2. Create an ordinary agent key and establish its registered stable ID through
   existing identity lifecycle operations. If an address is allocated, obtain
   namespace authority separately. ID registration and address allocation are
   distinct operations; neither admits D to a team.
3. Obtain H's protected confirmation of the exact proposed endorsement through
   W2. Its disclosure includes: **endorsing this identity endorses everything
   it spawns**, recursively. The human identity signer signs/issues or registers
   the matching certificate only with the matching current confirmation.
   Preserve the public proof and the authority binding described in (d).
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

**Before freezing:** the secrets owner must specify ordering among individual,
role and subtree candidates, the charged grant/policy and deterministic refusal
when none admits. Preserve existing individual/role outcomes; do not bypass
stricter grant conditions by combining fragments from different grants.

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

It returns an allow/refuse/unavailable decision and the specific matched
ancestry, grant and endorsement dependencies for effect fencing and audit.
These are logical inputs/outputs, not yet a public function signature. Consumers
must preserve the existing public verifier's freshness and refusal semantics.

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
status. Definite denial and unavailable evidence remain distinct (403 versus
503 at HTTP consumers); exact public error names remain to be frozen.

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

**W2 decisions needed before ACK:** which existing component hosts the browser
ceremony and checks issuer authority without circular bootstrap; which existing
record owns the binding and which public API/evidence exposes it to independent
consumers; how successful registration is linked atomically/idempotently; and
what rotation, re-parenting and certificate refresh require. No proof is silently
transferred across a changed target/key/parent. A permitted continuity rule must
be explicit and tested, not inferred from a stable ID alone.

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
| Changed CSR, target key, parent, audience or recursive disclosure | Refuse mismatched proof |
| Replay of consumed proof for another issuance or resource operation | Refuse; exact idempotent receipt replay grants no new effect |
| Revoked D, withdrawn protected endorsement, withdrawn matching resource grant | Deny each dependent path; preserve history |
| Unavailable required registry/proof/authority evidence | Unavailable; no effect or fallback |
| Narrower direct grant plus broader matching subtree grant | Direct grant does not subtract inherited permission |
| Withdraw subtree grant with an independent valid grant remaining | Evaluate independent permission under applicable operation policy |
| Unrelated legacy/humanless operation outside the requirement | Existing disposition unchanged |

The exact machine-readable vector location, semantic error names, grant
candidate order and protected-binding producer/consumer API are open interface
items for this first draft. Their resolution, lane review by runtime and secrets
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
