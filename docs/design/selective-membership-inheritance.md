# Selective membership inheritance

Status: **proposal** (aweb-acwd.13). The product direction is approved; the
semantic choices below are recommendations for R, Athena and Juan to review.
This document commissions no implementation and does not change the currently
supported certificate format. Implementation follows Juan's consideration of
the reviewed contract.

Goal 2: make unattended customer-operated spawning preserve a limited,
understandable membership choice without giving workers unrelated governance
authority.

## Direction and scope

Juan's direction, 2026-11-09:

> Agent A belongs to teams T1 and T2, which gives it access to certain secrets
> etc. When agent A spawns agent B it can chose to let agent B inherit
> membership to T1 for examplee.

The parent chooses a subset of its teams. Each chosen team independently
authorizes admission under its policy. B obtains its own key and membership
evidence; it does not use A's certificate or private key. There is no per-spawn
human ceremony and A need not possess a team-controller key.

Membership inheritance is **new admission**, not copying a certificate. It
does not copy principal or app-role grants, a human classification, an owner
role, controller authority, an address, or a secret. An existing resource
policy that grants access to all current members also applies to B. A policy
that names A's principal or role does not thereby name B.

No isolated launcher, soul attestation, registered deployment identity,
protected endorsement or new steward type is a prerequisite for this
membership-only feature. A team may decline inheritance entirely. A future
policy depending on a verified soul or placement needs separately established
evidence; a caller's soul name is not that evidence.

## Existing boundary being extended

The existing [AWID contract](../awid-sot.md#certificates) requires the team
controller to sign and register team certificates. Registration and revocation
both check the exact team's current key
(`awid/src/awid_service/routes/teams.py:80-101,844-866,1348-1369`). The Python
certificate verifier checks the team signature over canonical certificate
bytes (`awid/src/awid/team_certificate.py:60-75`); the Go equivalent is
`cli/go/awid/certificate.go:98-147`. A member or ID-tree parent is not an
alternative certificate issuer today.

The proposal adds a controller-authorized member-issuance lane. It preserves
direct-controller admission and the separation from
[owner acts](../owner-act.md#who-signs), namespace authority and
[ID certificates](../id-certificates.md). The admission parent described here
is the parent in a **team-membership dependency**, not proof of a particular
OS process or an ID-tree parentage. An ID-parent certificate alone never
enables this lane; this lane never manufactures one.

### Local and global identities

[Identity scope](../identity.md#identity) remains unchanged: a local identity
belongs to one team; an existing global identity may join several teams.

- A global A can select T1 from T1/T2 for a global B using B's existing
  registered identity, or admit a fresh local B to T1 alone.
- An OATS worker using separate local identities for separate teams selects
  the corresponding parent credential for each team. Multiple selected teams
  yield separate local child identities/homes, as the provider does today.
  The logical worker is not thereby one portable identity across those teams.
- One child identity shared across T1/T2 uses the existing global path. This
  proposal grants no address-claim or global-identity creation authority and
  does not silently reuse a local key across teams.

Recommendation: retain this distinction. Allowing one local identity to hold
several teams would be a separate identity-scope change, not an incidental
effect of inheritance. The interface must tell the operator which child
principal was admitted to each team.

## Choices for review

None of these recommendations is an additional ruling attributed to Juan.

| Question | Recommendation | Alternative and consequence |
| --- | --- | --- |
| Who enables inheritance? | The team's current controller publishes a signed, explicit policy; absent policy means disabled. | Treating ordinary membership or ID ancestry as permission would silently widen existing teams. |
| Which parents qualify? | Policy names eligible directly admitted principals, or explicitly all directly admitted members. Current membership is required at issuance and use. | Allowing any former member preserves issuance/access after removal. |
| Can children pass membership onward? | Default one generation. Controller may explicitly select a finite greater depth; every generation remains under the same policy and budget. | Unlimited recursion removes a simple bound; forbidding recursion entirely prevents nested worker spawning. |
| What does withdrawal do? | Parent-certificate revocation, policy withdrawal/expiry or loss of a required dependency denies all memberships depending on that path. | Issued children could instead become independent; then removing A would not contain its existing admissions. |
| What does a policy edit do? | Each signed revision is immutable; replacement withdraws the previous revision and requires re-admission of its dependants. Counters remain under the stable policy ID. | Retaining old revisions requires an explicit parallel-policy lifetime model. |
| What limits are available? | Finite total issuance allowance and rate for the policy, shared across roots and descendants; finite depth and policy expiry. No live-worker count or soul-type claim. | Per-child resettable budgets permit spawning around limits; live counts need lifecycle evidence not present here. |
| Can A revoke memberships? | Preserve controller-only explicit member revocation. A is an admission issuer, not a team administrator. | An issuer-revoke API could be added later but is not required for selective admission. |
| How do several selected teams complete? | Independent per-team transactions, explicit per-team results, resumable idempotently. No distributed transaction. | All-or-nothing across unrelated registries needs a new coordination protocol. |

The remaining sections describe the recommended option consistently, so its
cost and refusal behavior can be reviewed. A different decision updates the
whole dependent contract before implementation.

## Team policy and custody

The policy is a signed admission authorization, verified under the team's
current controller key and published at that team's authoritative AWID
registry. Proposed logical fields are:

- team ID, current team-key DID, policy ID and immutable revision;
- eligible direct-member principals, or an explicit all-direct-members mode;
- activation time, expiry, maximum admission depth, total issuance allowance
  and issuance rate;
- the withdrawal rule stated above, with no implicit legacy fallback.

Exact field names, signing prefix and wire bytes are to be frozen with the
reviewed vectors. Reuse Ed25519 and canonical JSON with a distinct signed
type/domain; do not reinterpret a member signature as an existing controller
request or add this authority to an installation grant. Policy publication,
replacement and withdrawal are controller-authenticated AWID operations, not
new app owner acts or arbitrary coordinator assertions.

Recommend one active policy revision per team initially. A replacement is an
explicit controller action with the dependent-membership consequence shown
before signing. A new revision does not reset the policy's cumulative count
or rate window. A new policy ID and new allowance are explicit controller
authorization, never an action available to a parent member.

The team controller retains its key. AWID, the coordination server and the
parent need no copy of it. A hosted custodian may exercise the same controller
authorization through its approved owner path; this feature does not require
Cloud. Custody and authority are separate: a parent holding only its own key
can exercise only the admission allowed by policy. If workers also hold the
team key, they can change that policy and the rest of team governance.

## Admission and the child's evidence

1. B prepares its own key. A explicitly selects teams; omission selects none,
   never all of A's teams. For each T, A selects its exact current membership
   certificate and the current policy. No caller flag can enable a disabled
   team or substitute a different team certificate.
2. A signs an admission certificate/request binding T, the policy ID/revision,
   the exact parent certificate ID and hash, parent signing key, B's key and
   identity scope, optional verified global DID, alias, a fresh certificate ID,
   issuance time and expiry. B proves possession of its exact key over this
   request. Neither proof authorizes a different child, team or policy.
3. AWID verifies the proofs, policy and complete membership dependency path.
   It checks current direct-root membership, all intervening publications,
   non-revocation, current keys where global continuity is claimed, policy
   eligibility, depth and expiry. It also preserves existing alias/address and
   identity-scope constraints. A child cannot name itself or repeat a parent
   certificate/key along the path; cycles and malformed paths refuse.
4. Under the same registration transaction, AWID checks policy state, parent
   dependency versions and available allowance/rate, records the exact signed
   certificate and provenance, and charges one issuance. A concurrent policy
   withdrawal or parent removal must win before commit or make registration
   fail; there is no check-before-lock authorization gap.
5. Success returns the child's registered evidence. The child installs it in
   the selected home and can authenticate its own requests. Failure creates
   no member publication or runtime membership projection. Preparing a local
   key is not admission and may remain available for an explicit retry.

Recommend a versioned member certificate/proof envelope, rather than a server
that converts these requests into ordinary controller-signed certificates.
The latter requires whole-team key custody and loses the independent admission
provenance. The delegated signature has a new domain-separated signing prefix;
it must not verify as a version-1 team certificate even when a key happens to
serve more than one role.

The carried proof contains the leaf, its parent-membership path and the signed
controller policy. It proves who admitted the child and the authority they
claimed. AWID's accepted publication and recorded dependency history establish
that the parent and policy were current at registration; a backdated issuer
timestamp does not establish that fact. Current admission also checks current
dependency status. A public certificate ID or metadata row is not a substitute
for signed evidence.

Prefer carrying the proof to requiring private parent-certificate blob reads:
the existing raw-blob endpoint requires the member's own signature
(`awid/src/awid_service/routes/teams.py:1292-1346`). The status endpoint needs a
bounded extension to report the leaf's exact proof hash and effective
dependency status without returning private team rosters. It must remain usable
by direct verifiers with the existing public certificate-status access model.
No registry-wide service token becomes mandatory for naapps.

The wire freeze must preserve the existing 8,192-byte encoded header bound
(`awid/src/awid/team_certificate.py:27-48`) or separately justify a versioned
transport change. Recommended first ceiling: four admission edges, additionally
limited by the encoded proof size. Registration refuses an oversized proof
before publication; a configured depth is not a promise that arbitrary-sized
identities fit it. Byte vectors must establish the usable bound. No automatic
truncation, URL-following proof fetch or unbounded recursive verification.

## Registration, replay and limits

New inherited certificates **always require authoritative publication**, even
where legacy direct-controller certificates are accepted without publication.
The direct parent's certificate must also be published before it can serve as
an inheritance root. This is an eligibility condition for this new lane, not a
change to ordinary use of existing unpublished direct-controller certificates.
The current server's optional registered-certificate gate
(`server/src/aweb/team_auth_deps.py:268-270`) must not decide this requirement.
Otherwise A could sign unlimited offline children around registry limits.

One exact request ID/certificate ID and signed content is idempotent: replay
returns the same publication without another charge. Reusing the ID for changed
bytes refuses. A replay after withdrawal returns a revoked/denied result, not
a fresh admission. Concurrent issuers cannot overspend the same remaining
allowance. Failures do not charge or create memberships.

The total counts **successful certificate issuances**, not live workers.
Revoking a certificate does not replenish the allowance. A new certificate
after rotation/re-admission counts again; exact replay does not. The rate and
total are shared across every descendant admitted under that stable policy ID,
so onward delegation does not create fresh buckets. Policy expiry bounds both
issuance and dependent use. Child expiry cannot exceed policy expiry or any
expiring parent dependency. Existing version-1 parents have no expiry field;
their currentness still depends on non-revocation and the current team key.

These limits count admissions, not executions or unique people. One admitted
key can be used by multiple processes. A compromised eligible member can spend
its policy's available allowance on attacker-controlled keys. This is the
authority the controller grants; no unverified soul label narrows it.

## Withdrawal, reissue and currentness

The shared verifier treats the membership proof as a dependency graph, with a
bounded linear path in this revision. Revoking the parent certificate denies
its dependent child certificates and their dependants in this team. Withdrawing
or expiring the policy denies all certificates depending on that revision.
Rows and issuance history remain for audit; authorization denial must not wait
for an asynchronous row-deletion sweep.

This withdraws **that membership path**, not the child's identity or every
permission it could hold. A separately authorized direct certificate or another
independent admission path remains governed by its own authority. T2, unrelated
T1 members, ID ancestry and other teams are unchanged. Local deletion of A's
workspace is not authoritative parent revocation.

Team-key rotation already invalidates old direct certificates; inherited
policies and chains signed under that old key also refuse. Parent-key rotation
does not silently transfer a delegated path: once the referenced parent
membership no longer matches its current global key, dependants refuse until
explicit re-admission with current evidence. Reissuing the parent certificate
does not make an old child reference name the new certificate. Child-key
rotation likewise needs a new membership certificate. Merely refreshing the
same valid evidence changes neither provenance nor expiry.

Registration reads current authority in the registry transaction; it never
uses a client-reported cached approval. At request admission, recommend a
maximum 60-second reuse window for the combined policy/publication/dependency
observation, bounded further by the earliest original expiry of every required
fact. Cache hits cannot restart the window. The existing current-membership
proof has this original-window discipline
(`naapp-lib/src/aweb_naapp/runtime/team_auth.py:212-258`); extend that shared
path rather than add an app-specific cache or verifier.

This is a request-observation bound, not a new claim that DNS, global identity
key resolution or every existing cache has a 60-second end-to-end revocation
SLA. Their governing freshness rules remain required and cannot be weakened.
The byte/interface freeze must show how every dependency's original freshness
is retained. Unavailable required evidence refuses after usable evidence
expires; it never means not enrolled, disabled policy or permission to fall
back to ordinary membership. Mutating app operations retain the verified
dependencies and apply their existing effect-fence expiry checks. Withdrawal
is bounded by those observations, not claimed instantaneous across services.

## Consumers and released-client compatibility

The request still proves possession of B's member key under team-auth. Shared
verification adds the inherited-membership proof, policy and current published
dependency checks. It returns the authenticated principal plus the original
dependency/freshness evidence needed by callers. Installation scopes and app
resource policy run afterward and remain unchanged.

Affected consumers to account for before rollout:

| Surface | Existing entry point | Required treatment |
| --- | --- | --- |
| Python SDK | `awid/src/awid/team_certificate.py:60` | One public version-aware verifier and evidence representation, retaining v1 behavior. |
| Go SDK and CLI | `cli/go/awid/certificate.go:98`; `registry_team.go:417`; CLI fetch/import/doctor | Produce, retain, verify and diagnose the new evidence without reconstructing a controller signature. |
| AWID | `awid/src/awid_service/routes/teams.py:844` | Policy/delegated registration, atomic limits and effective status; controller-only v1 registration stays intact. |
| Coordination HTTP/MCP | `server/src/aweb/team_auth.py:41`; `team_auth_deps.py:268` | No optional-publication bypass, no omitted-proof legacy downgrade, no observation cache that skips dependency expiry. |
| Direct naapp endpoints | `naapp-lib/src/aweb_naapp/runtime/team_auth.py:664` | Same shared verifier and effective membership currentness, before installation/resource authorization. |
| Hook receivers | `naapp-lib/src/aweb_naapp/hooks/delivery.py:243`; `cli/go/hookevent/delivery.go:282` | Explicit version support/refusal; carrying inherited membership never confers app-emission or owner authority. |
| Hosted embedding consumers | Their own team-auth adapters | Inventory and upgrade supported routes; an OSS library pin alone does not prove every host adapter calls it. |

All existing version-1 certificates, deprecated read-compatible fields and
their valid neighbors remain accepted as before. Unsupported new evidence
fails explicitly; it is never flattened into v1, admitted by metadata alone,
or retried using the team key. Old clients cannot be assumed to verify the new
format. The parent and child clients, authoritative registry, accepting server
and direct naapps must advertise support before this lane is enabled for those
uses. An unupgraded consumer remains usable with its existing direct-controller
memberships, not with a silently weakened inherited certificate.

Roll out SDK support and registry storage/status first, then accepting consumers
and client issuance, then opt-in policies. Exact capability negotiation and
wire vectors are a joint freeze prerequisite, not supplied by an HTTP success
from an unrelated route. Existing services need no policy/configuration change
to keep serving version-1 memberships. Add ordered migrations; do not rewrite
old certificates or broaden current owner-act verification.

## Refusals and acceptance corpus

Proposed disposition categories: invalid request/key proof is authentication
failure; definite absent/ineligible/withdrawn inheritance authority is 403;
unavailable required authority is 503; exhausted rate is 429 and exhausted
total/depth is a definite 403. A same-ID/different-content replay is 409.
Exact stable error names and legacy mappings are frozen with wire vectors.
Every refusal leaves publication, allowance, app approvals and effects unchanged.

The public decision corpus must cover both server and direct-naapp consumers:

| Case | Expected result |
| --- | --- |
| A belongs to T1/T2; selects only T1; T1 permits it | B joins T1 with its own key; no request or membership in T2. |
| T1 policy allows a named current A; B proves its key | Registered inherited membership admits ordinary T1 use. |
| B requests a resource granted to all T1 members | Existing resource policy decides normally. |
| B presents only A's principal/role grant or owner authority | Refuse; membership inheritance copied none of those rights. |
| Valid ID-parent certificate, no team inheritance policy | Refuse inherited admission. |
| Parent belongs to another team, or policy names another parent | Refuse without a publication or charge. |
| Parent signs for one child key; another key submits/proves possession | Refuse. |
| Missing child proof, changed team/policy/parent/hash/alias or replay substitution | Refuse. |
| Child attempts onward admission at depth one | Refuse; an explicitly deeper policy admits only within its shared bound. |
| Parent signs unregistered child proof offline | Every inherited-membership consumer refuses, even with legacy publication optional. |
| Parent or policy withdrawn before registration commit | Refuse and preserve allowance. |
| Parent or policy withdrawn after registration | Deny dependent use after the bounded observation expires; unrelated memberships remain valid. |
| Same request retried concurrently | One publication and charge; every successful reply names the same evidence. |
| Concurrent requests compete for the last allowance | At most one new issuance succeeds. |
| Child creates more children to evade root limits | Shared policy count/rate still applies. |
| Authority unavailable with no valid observation, or expired cached evidence | 503; no refresh-on-cache-hit and no legacy fallback. |
| Team, parent or child key rotation / parent certificate reissue | Old dependent proof refuses; explicit valid re-admission is the positive neighbor. |
| Same identity/key/certificate and policy, refreshed observation | Still admits without a new charge or longer certificate lifetime. |
| Circular path, repeated key, excessive depth or oversized header | Refuse before registration/effect. |
| Local B reused across teams | Existing local-scope refusal; distinct local children or existing global B are the valid neighbors. |
| T1 succeeds while T2 refuses in a selected set | Exact per-team receipt; no T2 access, no hidden rollback or silent overall success. |
| Old client receives inherited proof | Unsupported/authentication refusal; existing v1 certificate still works. |
| No policy configured, ordinary direct-controller membership | Behavior unchanged. |

Protocol tests using A's own key establish these admission rules, not that A
cannot steal B's key on a shared UID. Environments with mutually reachable keys
and privileged interfaces remain one compromise boundary. Restricting what B
can be asked to do or return remains resource/invocation policy, not a new
universal child-permission-subset rule.

## Resource-team fit and relationship to option (d)

A human-controlled resource team can directly admit A once and authorize A's
selected descendants through this policy, while keeping its controller key
outside their reach. B becomes a member of that resource team, so its secrets
installation's same-team admission remains intact. This does not introduce a
foreign-team resource grant. It does not by itself make an A-specific grant
apply to B: the resource owner must actually authorize the desired member or
principal/role/subtree use through that resource's supported policy.

Likewise, membership in a separately governed logs team supplies only the
access that installation grants its members. It does not create a cross-team
hook binding or guarantee an independent event feed from a worker-controlled
team. That audit composition remains a distinct gap.

This subsumes the membership-only portion of option (d), admission delegation
to a named provisioner: designate A as an eligible current member, limit its
policy and admit B under A's ordinary key. No raw team key goes to A or the
server, and no new steward principal is necessary. Unlike option (d)'s earlier
launcher-focused discussion, this feature makes no trusted soul/placement claim
and requires no protected launcher for membership alone. Delegation to a
non-member, app-role assignment, verified worker type and live-count limits
are outside this contract; they must not be smuggled into its implementation.

## Implementation cost and freeze boundary

Required future work is substantive: versioned signed policy/certificate
evidence; AWID policy/provenance/accounting storage and status; shared Python/Go
verification; CLI/provider child-key/selection/receipt handling; all accepting
consumer adapters; public bytes and refusal vectors; mixed-version rollout.
No extra service or new cache is justified. Registration must be online and
fails closed when the authority is unavailable. Request admission adds bounded
policy/dependency evidence; its traffic and latency must be measured, not
described as free. No time estimate is established by this proposal.

Before implementation, settle the choices table, freeze exact signed bytes and
status/capability interfaces, prove the size/depth bound with vectors, and
enumerate every accepting consumer. R and Athena review the contract; Juan
sees the reviewed choices before implementation is commissioned. No code,
migration, live policy publication or controller transfer follows from this
document alone.

## Decision record and knowledge checkpoint

This is the single canonical record for acwd.13's product direction and pending
choices. Direction provenance: Juan in the servers conversation on 2026-11-09,
relayed as `f0d7526e-ddb3-4bfe-97cc-ca7527c70d15`; assignment
`7b73ac2a-ee6d-4876-bd46-af1ea0bfd4fe`. The direction is selective,
team-authorized child membership without per-spawn approval or parent custody
of the team key. It does not settle the recommendations above.

Prior accepted knowledge:
`aweb/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md@9a54c7392429`.
That decision expressly deferred member-mediated admission until it became real
scope. This assignment opens that condition; it does not retroactively change
released certificates or mark the proposed delegated lane as shipped.

Checkpoint: the prior controller-only rule remains the current implementation
contract. The approved product direction and proposed extension are recorded
here rather than copied into a competing protocol knowledge note. At decision
acceptance, record which choices were ruled, their review/approval provenance
and the resulting supersession boundary in this section. Knowledge promotion
must point to this canonical decision record; it must not promote unsettled
recommendations as accepted authority. At delivery, record the actual supported
versions separately from the proposal's acceptance.
