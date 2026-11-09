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
| Which parents qualify? | Controller signs a bounded eligibility grant per named directly admitted principal, or policy explicitly enables all directly admitted members. Current membership is required at issuance and use. | Allowing any former member preserves issuance/access after removal. |
| Can children pass membership onward? | Ship depth 1 first; retain a bounded path format for later controller opt-in to greater depth. Every generation shares the policy and budget. | Unlimited recursion removes a simple bound; forbidding recursion entirely prevents nested worker spawning. |
| What does withdrawal do? | Parent-certificate revocation, policy withdrawal/expiry or loss of a required dependency denies all memberships depending on that path. | Issued children could instead become independent; then removing A would not contain its existing admissions. |
| What does a policy edit do? | Each signed revision is immutable; replacement withdraws the previous revision and requires re-admission of its dependants. Counters remain under the stable policy ID. | Preserve dependants for revisions that only increase allowance/rate or extend expiry; other edits withdraw. This needs explicit revision-continuity semantics before freeze. |
| What limits are available? | Finite total issuance allowance and rate for the policy, shared across roots and descendants; finite depth and policy expiry. No live-worker count or soul-type claim. | Per-child resettable budgets permit spawning around limits; live counts need lifecycle evidence not present here. |
| Can A revoke memberships? | Preserve controller-only explicit member revocation. A is an admission issuer, not a team administrator. | An issuer-revoke API could be added later but is not required for selective admission. |
| How do several selected teams complete? | Independent per-team transactions, explicit per-team results, resumable idempotently. No distributed transaction. | All-or-nothing across unrelated registries needs a new coordination protocol. |

The remaining sections describe the recommended option consistently, so its
cost and refusal behavior can be reviewed. A different decision updates the
whole dependent contract before implementation.

### Two choices Juan must settle before freeze

**Depth:** recommend the first release accept only depth 1, including at
registration and every verifier. The bounded path format can accommodate up to
four edges, but a deeper policy is refused until the supported ceiling is
raised. The alternative is enabling nested admission in the first release for
a named customer flow; no such requirement has been established here. Raising
the supported ceiling later requires consumer capability agreement and policy
opt-in, not new wire bytes; maximum-depth vectors belong in the first freeze.

**Policy edits:** recommend strict replacement initially: **no edit keeps
existing dependants**, even increasing allowance/rate or extending expiry.
This can interrupt an unattended swarm and forces explicit re-admission, which
itself consumes allowance. The owner must see that consequence before signing.
It keeps one active revision and avoids an additional continuity mechanism.
The alternative is preserving dependants only when allowance/rate increase or
expiry extends, with every other edit withdrawing them. If Juan chooses it,
the freeze must specify how old signed evidence remains authorized by the new
revision, without rewriting it, resetting counters or growing carried history;
child certificate expiry still cannot be extended by a policy edit alone.
The rest of this draft follows strict replacement pending that choice.

**De-listing one named parent has the same cost:** while retaining A's direct
membership, removing A's inheritance eligibility requires a whole-policy
replacement. That withdraws the other parents' dependants too, not just A's.
The narrower existing action is to revoke A's referenced direct membership
certificate, denying its dependent path while leaving other roots alone; it
is not an eligibility-only removal. If Juan chooses continuity across policy
edits, he should also decide whether removing one parent's eligibility grant
can preserve the other roots' dependants. That selective-removal case must be
specified in the same continuity rule; it is not implied by the allowance,
rate and expiry increases described above.

## Team policy and custody

The policy is a signed admission authorization, verified under the team's
current controller key and published at that team's authoritative AWID
registry. Proposed logical fields are:

- team ID, current team-key DID, policy ID and immutable revision;
- named-parent mode, or an explicit all-direct-members mode (no roster);
- activation time, expiry, maximum admission depth, total issuance allowance
  and issuance rate;
- the withdrawal rule stated above, with no implicit legacy fallback.

In named-parent mode the controller also signs one eligibility grant per
eligible direct member. It contains the team, policy ID/revision and hash,
that parent's exact principal, and the complete bounded policy terms above.
It carries no list of other eligible parents. The proof carries only its
root's grant; that grant's signature covers the policy terms, so no second
copy of the signed policy is carried. The registry checks the terms/hash
against the published revision. In all-direct-members mode the proof instead
carries the compact controller-signed policy itself. Both forms preserve
independently verifiable controller authorization: a registry status alone
cannot confer issuance authority or replace that signature.

The grant binds eligibility to one direct root; onward issuers derive their
authority through that root's bounded path, not additional eligibility grants.
Publishing another parent's grant does not enlarge existing proofs. Removing
eligibility requires a policy replacement or revocation of that root's member
certificate; there is no new independent grant-revocation API in this revision.
Each carried object has a fixed schema and bounded field lengths independent
of team size. Exact length limits and canonical policy-hash derivation are
part of the byte freeze, not left to an implementation's JSON serializer.

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
   request. Neither proof authorizes a different child, team or policy. Before
   submission, the caller durably retains the exact request/certificate ID and
   signed bytes needed to reconcile this per-team operation.
3. AWID verifies the proofs, policy and complete membership dependency path.
   It checks current direct-root membership, all intervening publications,
   non-revocation, current keys where global continuity is claimed, policy
   eligibility, depth and expiry. It also preserves existing alias/address and
   identity-scope constraints. A child cannot name itself or repeat a parent
   certificate/key along the path; cycles and malformed paths refuse.
4. In one team-registry transaction, AWID checks the locally authoritative
   controller/policy revision, published parent chain and revocations, and
   allowance/rate; it records the signed certificate/provenance and charges
   one issuance. Those local dependencies are locked/version-checked through
   commit. Withdrawal serialized first means no publication or charge.
   Issuance serialized first means one publication and charge, made ineffective
   by subsequent withdrawal. Overlap does not give withdrawal priority over a
   committed issuance. External global-key and DNS observations are acquired
   and evaluated under their own freshness rules; this transaction cannot
   serialize mutations at their independent authorities.
5. A confirmed commit returns the child's registered evidence. The child
   installs it in the selected home and can authenticate its own requests.
   A definite pre-commit refusal creates no publication or charge. A lost reply
   or failed local installation is an unresolved or locally incomplete outcome,
   not proof of no membership. Reconcile the same retained operation as below;
   never invent another ID to recover it. Local key preparation grants nothing.

Recommend a versioned member certificate/proof envelope, rather than a server
that converts these requests into ordinary controller-signed certificates.
The latter requires whole-team key custody and loses the independent admission
provenance. The delegated signature has a new domain-separated signing prefix;
it must not verify as a version-1 team certificate even when a key happens to
serve more than one role.

The carried proof contains the leaf, its parent-membership path and exactly
one bounded controller authorization: its root's eligibility grant in named
mode, or the compact signed policy in all-direct-members mode. It proves who
admitted the child and the authority they claimed. AWID's accepted publication and recorded dependency history establish
that the parent and policy were current at registration; a backdated issuer
timestamp does not establish that fact. Current admission also checks current
dependency status. A public certificate ID or metadata row is not a substitute
for signed evidence.

Prefer carrying the proof to requiring private parent-certificate blob reads:
the existing raw-blob endpoint requires the member's own signature
(`awid/src/awid_service/routes/teams.py:1292-1346`). The status endpoint needs a
bounded extension: **one status read per leaf, never per edge or policy**.
One response reports the leaf's effective state over the entire dependency
path (policy revision, root eligibility authorization, every parent and the
current team key), and the exact proof hash it covers. It exposes no roster.
A positive status is useful only alongside the locally verified signed proof;
it is not a registry-issued replacement for controller authorization. Consumers
cache this one fact under the original, at-most-60-second membership window,
with each external dependency's original expiry retained. They do not fan out
into parent/policy status reads. It must remain usable by direct verifiers with the existing public certificate-status access model.
No registry-wide service token becomes mandatory for naapps.

The wire freeze must preserve the existing 8,192-byte encoded header bound
(`awid/src/awid/team_certificate.py:27-48`) or separately justify a versioned
transport change. Freeze a path format bounded to four edges, with the first
release accepting only depth 1 as recommended above. Maximum-depth vectors
must fit the 8,192-byte encoded limit with the largest legal identities and
all maximum-length fields, in both authorization modes. If they cannot fit,
reduce the proposed bounds before freeze; do not ship an advertised legal
combination that cannot be carried. Registration also refuses oversized or
out-of-bound proofs before publication. No automatic truncation, URL-following
proof fetch or unbounded recursive verification.

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
bytes refuses. Reconciliation after withdrawal returns the retained issuance
and its current revoked/denied state, not fresh membership or a refund.
Concurrent issuers cannot overspend the same remaining allowance. Definite
pre-commit refusals do not charge or create memberships.

A transport error does not establish a pre-commit refusal. A committed
publication and charge survive a lost reply or a failure to install the
returned evidence locally. Per-team receipts distinguish confirmed refusal,
confirmed issuance (including local installation pending), and unresolved
outcome. Retain the same ID and signed content and reconcile/replay that exact
operation without another charge. Do not silently retry under a new ID or
report an unresolved team as an uncharged failure. This applies the existing
[BYOT uncertainty rule](../byot-onboarding-contract.md#team-creation) to this
operation; exact receipt field names are a freeze obligation.

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

Registration serializes only the team-local authority and accounting facts
named above; it never uses a client-reported cached approval. A remote identity
key can rotate after it was observed and before local commit. The receipt
must not claim otherwise: the governing external freshness applies, and the
next required observation of the changed key denies the dependent proof.
Local locks do not refresh or extend external evidence. At request admission,
recommend a maximum 60-second reuse window for the combined policy/publication/dependency
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

Affected consumers to inventory at wire freeze, before rollout:

| Surface | Existing entry point | Required treatment |
| --- | --- | --- |
| Python SDK | `awid/src/awid/team_certificate.py:60` | One public version-aware verifier and evidence representation, retaining v1 behavior. |
| Go SDK and CLI | `cli/go/awid/certificate.go:98`; `registry_team.go:417`; CLI fetch/import/doctor | Produce, retain, verify and diagnose the new evidence without reconstructing a controller signature. |
| AWID | `awid/src/awid_service/routes/teams.py:844` | Policy/delegated registration, atomic limits and effective status; controller-only v1 registration stays intact. |
| Coordination HTTP/MCP | `server/src/aweb/team_auth.py:41`; `team_auth_deps.py:268` | No optional-publication bypass, no omitted-proof legacy downgrade, no observation cache that skips dependency expiry. |
| Direct naapp endpoints | `naapp-lib/src/aweb_naapp/runtime/team_auth.py:664` | Same shared verifier and effective membership currentness, before installation/resource authorization. |
| Hook receivers | `naapp-lib/src/aweb_naapp/hooks/delivery.py:243`; `cli/go/hookevent/delivery.go:282` | Explicit version support/refusal; carrying inherited membership never confers app-emission or owner authority. |
| Cloud and other hosted embedding consumers | Their own team-auth adapters | Freeze an exact route/adapter inventory, including middleware, cached identity returns, connect and proxy fallbacks; an OSS library pin alone does not prove every adapter calls it. |

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
to keep serving version-1 memberships. With no policy published, new inherited
verifier paths are inert and existing operation is unchanged. An inherited
proof reaching an unupgraded consumer refuses; no automatic conversion or
configuration requirement is imposed on non-users. Add ordered migrations; do
not rewrite old certificates or broaden current owner-act verification.

## Refusals and acceptance corpus

Proposed disposition categories: invalid request/key proof is authentication
failure; definite absent/ineligible/withdrawn inheritance authority is 403;
unavailable required authority is 503; exhausted rate is 429 and exhausted
total/depth is a definite 403. A same-ID/different-content replay is 409.
Exact stable error names and legacy mappings are frozen with wire vectors.
A definite pre-commit refusal leaves publication and allowance unchanged;
request-admission refusals leave app approvals and effects unchanged. Transport
uncertainty and local installation failure follow reconciliation above and
must not be reported as those definite refusals.

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
| Child attempts onward admission at depth one | Refuse; first release also refuses a deeper policy. A later supported depth admits only within the shared bound. |
| Parent signs unregistered child proof offline | Every inherited-membership consumer refuses, even with legacy publication optional. |
| Local withdrawal serializes before issuance | Refuse; no publication or charge. |
| Local issuance serializes before overlapping withdrawal | One publication/charge, then dependent use denied under bounded observations; no refund. |
| Remote parent key rotates after observation but before local commit | No cross-authority atomicity claim; original external freshness applies, and observing the changed key denies the proof. |
| Parent or policy withdrawn after registration | Deny dependent use after the bounded observation expires; unrelated memberships remain valid. |
| Same request retried concurrently | One publication and charge; every successful reply names the same evidence. |
| Commit succeeds, response is lost | Per-team outcome unresolved; replay retained exact ID/bytes returns the single issuance without another charge. |
| Commit confirmed, local evidence installation fails | Issuance/charge remain; receipt marks installation incomplete; recover same evidence, not a new issuance. |
| Withdrawal occurs before lost-reply reconciliation | Return retained issuance with current denied state; no new membership or refund. |
| Concurrent requests compete for the last allowance | At most one new issuance succeeds. |
| Child creates more children to evade root limits | Shared policy count/rate still applies. |
| Authority unavailable with no valid observation, or expired cached evidence | 503; no refresh-on-cache-hit and no legacy fallback. |
| Team, parent or child key rotation / parent certificate reissue | Old dependent proof refuses; explicit valid re-admission is the positive neighbor. |
| Same identity/key/certificate and policy, refreshed observation | Still admits without a new charge or longer certificate lifetime. |
| Circular path, repeated key, excessive depth or oversized header | Refuse before registration/effect. |
| Maximum-format depth and largest legal fields, both authorization modes | Encoded proof fits 8,192 bytes; first-release depth gate still refuses depths above 1. |
| More named parents receive eligibility grants | Existing carried proof size is unchanged; an unrelated parent's grant cannot authorize this root. |
| Registry claims active status without valid controller authorization | Refuse; status cannot forge membership authority. |
| Currentness checked for a maximum-depth leaf | One effective-status read per leaf/window, no per-edge/policy reads; cache hits keep original expiry. |
| Policy replacement only raises allowance/rate or extends expiry | Under the recommended strict choice, previous dependants still require re-admission; counters do not reset. |
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
fails closed when the authority is unavailable; a lost write reply is reconciled
as an uncertain outcome, not presumed to have failed before commit.

Price: inherited membership currentness costs the same AWID status-read count
as v1: **one read per leaf per original 60-second window**, not one per edge.
The shared verifier adds local Ed25519 verification of bounded evidence: one
controller authorization, one direct-root certificate and one per admission
edge (at most six at the four-edge format bound, three at initial depth 1).
This excludes the ordinary request signature and any separate global-identity
verification. Hundreds of microseconds of local CPU is a review estimate, not
a measured benchmark or latency guarantee. Registration adds one AWID write
operation per selected team per spawn, with publication/provenance writes and
one shared policy counter-row update in that team's transaction. Registry dependency computation is
bounded by the path; it is not pushed into extra consumer network reads.
This is a reasonable proposed cost at spawn frequency, not a new registry
write on every resource use. Measure it and the external evidence acquisition
under realistic load; no implementation-time estimate is established here.

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
and the resulting supersession boundary in this section. Review revision:
Athena `4fafc5c4-4acd-4c76-936e-4669a9d4b8ab` requires bounded carried
eligibility evidence and one effective-status read; independent review
`f7c178b1-6497-4d2b-bb33-31b787eae962` requires uncertain-outcome recovery
and transaction claims limited to serializable local authority. These changes
and the two explicit Juan choices above remain proposals, not an implementation
approval. Knowledge promotion must point to this canonical decision record; it must not promote unsettled
recommendations as accepted authority. At delivery, record the actual supported
versions separately from the proposal's acceptance.
