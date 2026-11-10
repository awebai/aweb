# Selective membership inheritance

Status: **contract revision for review** (aweb-acwd.13). Juan has decided the
local-context, depth, policy-edit and resource-team direction below. The
contract realization and wire freeze still need review. This document changes
no supported certificate format and commissions no implementation; that needs
a separate go after the reviewed contract.

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

### Local children are the primary case

Juan clarified on 2026-11-09 that most spawned deployment instances will be
local. A fresh child therefore needs only its own Ed25519 key (`did:key`),
not a `did:aw`, namespace identity registration, public address or human-kind
classification. Publishing its **team membership** at AWID remains mandatory;
that is not global-identity registration. The inheritance lane must not use a
missing `did:aw` as a reason to refuse or silently promote the child.

[Identity scope](../identity.md#identity) currently makes a local identity
single-team and permits an existing global identity to join multiple teams
(`docs/identity.md:65-77`). An instance is an execution/workspace grouping;
it can use several distinct local identity contexts. One instance with two
local keys is not one local identity with two memberships.

**Existing arrangement, confirmed by Juan:** use one local identity home and
key per selected team, as oats.aweb joined teams already do. This is not a new
product choice or a relaxation of local identity scope. A worker in deployment
team D and resource team H uses B_D and B_H, each a distinct `did:key`, with
separate certificates, publication, status and withdrawal. No global identity
is needed. Cost is one key/context and admission per selected team, explicit
credential selection per request and per-team receipts/recovery.
Inherited-issuance orchestration still needs implementation.

For each selected team, A uses its own membership context and obtains policy
authorization there. A global A in T1/T2 can admit local B_T1 to T1 alone. A
local-only parent instance can hold A_T1 and A_T2 and select the corresponding
key for each admission. Selecting two teams yields two local child principals,
not reuse of one local key across teams. A global identity remains an optional
existing route for stable cross-team identity, not a requirement for spawning.

### Local evidence and the protected-resource flow

Every inheritance mechanism applies to local roots and children:

| Mechanism | Local `did:key` case |
| --- | --- |
| Eligibility and issuer proof | Named eligibility identifies the exact direct member in that team by its `did:key`; all-direct mode uses its verified direct certificate. A signs with that key, B proves possession of its own key. No global lookup or ID-tree proof is required for a local subject. |
| Registration and accounting | The team registry publishes B's signed inherited certificate and its parent/policy dependencies, charges that team's allowance and preserves exact-operation replay. It creates no global ID record or address. |
| Use and status | B signs team-auth with the key named in that team's certificate. The shared verifier checks the signed path and effective leaf status exactly as for a global child; only the optional global-key continuity lookup is absent. |
| Withdrawal and key replacement | Revoking the referenced parent/child certificate or policy denies that team path. A new local key is a new principal and needs new admission; no stable-DID rotation or automatic grant transfer is implied. Another team's separately authorized local context is unaffected. |

For protected secrets, a third, independently governed team H admits A once
as A_H, then its policy authorizes inheritance to B_H. One worker instance
uses B_D for deployment messaging and B_H for H's secrets and audit. The
parent needs eligible membership in H to admit B_H; membership in D cannot
authorize that. H's controller stays outside worker
custody. The app receives B_H's H certificate, not B_D's D certificate and not
an instance-name assertion. Secrets already models a local principal as
`(team_id, member_did_key)` and skips global-key lookup when `member_did_aw` is
absent (`docs/design/secrets.md:238-258`;
`naapp-lib/src/aweb_naapp/runtime/team_auth.py:740-753`).

This solves the membership side without per-worker human admission once H's
policy enables it. **It does not grant secrets use:** the resource owner must
supply a supported policy that actually covers B_H. A grant only to A_H or
its role does not cover B_H, and global-subtree/W1 rules cannot be presumed to
cover a local-only child. If the selected resource policy has no supported
way to cover these newly admitted local members without per-worker grants,
that resource-policy gap remains explicit; inheritance does not invent one.

If the operator insists on one local key/home only, the child can join D or H,
not both under the existing rule. It cannot simultaneously do deployment
messaging and access H's same-team secrets installation with that one local
identity. Use the existing extra local context (or an optional global identity);
this contract does not relax local identity scope.
Several keys under the same worker UID remain one compromise boundary; the
extra homes provide credential selection, not isolation from that worker.

## Decisions and contract model

Juan's decisions are separate from the remaining contract and wire review.
They authorize no implementation by themselves.

| Question | Contract |
| --- | --- |
| Local child needs several teams? | Existing separate local key/home per team; no global registration or identity-scope change. |
| Who enables inheritance? | Current controller publishes a signed explicit policy; absent means disabled. Membership or ID ancestry alone is insufficient. |
| Which parents qualify? | Bounded controller eligibility grant per named direct member, or explicit all-direct-members mode. Current membership is required at issuance and use. |
| Can children pass membership onward? | General bounded paths from the first release, with controller-set maximum depth within the format bound. All generations share the policy and budget; no depth-1 release exception. |
| What does withdrawal do? | Parent revocation, narrowing policy edit, policy withdrawal/expiry or loss of a dependency denies memberships depending on that path. |
| What does a policy edit do? | Widening preserves dependants; narrowing withdraws them. Signed revisions remain immutable; counters remain under the stable policy ID. |
| What limits are available? | Finite total issuance allowance, rate, depth and expiry shared across roots and descendants. No live-worker count or unverified soul-type claim. |
| Can A revoke memberships? | Explicit member revocation remains controller-only; an admission issuer is not a team administrator. |
| How do selected teams complete? | Independent per-team transactions and receipts, resumable idempotently; no distributed transaction. |
| Where are protected resources? | Independently governed H admits A once and B_H by inheritance. Secrets and its audit in H use same-team admission plus resource policy. |

### Policy continuity

A policy has one current revision for **new issuance**. Existing certificates
retain their signed issuance revision and bytes. A pure widening edit raises
allowance or rate, or extends expiry, with no reduction or other authority
change. It preserves dependants without re-admission or another charge. It
does not extend a certificate's signed expiry, restore revoked membership,
reset counters/rate windows, or revive withdrawn paths.

A narrowing edit, including reducing allowance/rate/expiry/depth or removing
parent eligibility, withdraws existing dependants of that policy. Any mixed
edit containing a narrowing has the same result even if another limit rises.
De-listing A while keeping A's direct membership therefore withdraws other
roots' dependants too. Revoking only A's referenced direct certificate is the
narrower existing operation, affecting that path, but removes that membership
path rather than eligibility alone. No selective preservation of other roots
across a narrowing edit is implied. Disclose that before controller signing.

Preservation here covers Juan's named widening edits. Changes to eligibility
mode, added eligibility or increased depth need explicit classification in
the wire freeze; a caller's label is insufficient. Unclassified transitions
refuse publication until specified. Adding another root grant under an unchanged
named policy remains a controller-authorized operation, changing neither
existing proof bytes nor resource grants. Exact policy replay changes nothing.

**Bounded signed continuity (proposed realization for review):** revisions are
ordered under the stable policy ID. The compact controller authorization
includes a continuity floor: the first revision it preserves. Widening retains
that floor; narrowing advances it to the new revision. The controller signature
covers the floor and revision with the policy terms, also in named-root grants.
The registry checks the transition against the published predecessor; caller
fields or registry status cannot invent a compatible revision range. Revisions
and the floor never move backward; replaying an older signed policy cannot
reactivate it. Withdrawal
or expiry ends continuity; re-enabling starts a new range, never reviving old
paths.

An old leaf keeps its original signed authorization and certificate; effective
status confirms its revision remains in the current preserved range and every
other dependency remains effective. Onward issuance after widening uses the
current revision and carries its compact authorization for the same direct
root, explicitly covering earlier revisions in that range, plus the unchanged
signed parent path. Each edge must name that policy ID and a revision in range.
A stale revision cannot authorize a **new** publication; attaching current
authorization cannot repair an edge below the floor. Publication history keeps
the actual issuance terms. This permits mixed-revision paths without a policy
object per revision or edge. Updating carried authorization changes the proof
hash, not the signed certificate or publication/charge; status must cover the
exact proof bytes presented.

The freeze must prove this bounded representation in both modes, including
repeated widening followed by narrowing: constant-size controller evidence,
no revision-history list, no additional consumer status reads and no registry
signing authority. Exact signed fields, transition encoding and status binding
remain review obligations, not implicit implementation choices.

### Mixed laptops and managed servers

Teams may mix agents on managed servers with agents on people's own computers.
Container or host placement is not a condition of membership, inheritance or
this secrets flow. Membership proves neither placement nor host-policy
enforcement; a team label implies neither isolated per-agent custody nor a
common custodian. Laptop callers need not move into a controlled host.

Every caller still needs ordinary membership verification, resource
authorization and applicable custody checks. Reachable keys and privileged
interfaces determine compromise boundaries independently of team labels. No
per-worker isolation follows from a certificate or an identity-home path.

## Team policy and custody

The policy is a signed admission authorization, verified under the team's
current controller key and published at that team's authoritative AWID
registry. Proposed logical fields are:

- team ID, current team-key DID, stable policy ID, immutable revision and
  signed continuity floor;
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

Use one current policy revision per team for new issuance. Earlier revisions
remain usable only for dependencies preserved by signed continuity. Replacement
is an explicit controller action with its preservation or withdrawal consequence
shown before signing. A new revision does not reset the policy's cumulative count
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
   certificate and the current policy revision, including compatible earlier
   parent dependencies under its signed continuity. No caller flag can enable
   a disabled team or substitute a different team certificate.
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
   eligibility, signed revision continuity, depth and expiry. It also preserves
   existing alias/address and identity-scope constraints. A child cannot name itself or repeat a parent
   certificate/key along the path; cycles and malformed paths refuse.
4. In one team-registry transaction, AWID checks the locally authoritative
   controller/current policy revision and continuity floor, published parent
   chain and revocations, and
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
current team key, including current revision/continuity floor), and the exact
proof hash it covers. A revision change alone is not denial: widening preserves
covered older dependencies; narrowing denies them. It exposes no roster.
A positive status is useful only alongside the locally verified signed proof;
it is not a registry-issued replacement for controller authorization. Consumers
cache this one fact under the original, at-most-60-second membership window,
with each external dependency's original expiry retained. They do not fan out
into parent/policy status reads. It must remain usable by direct verifiers with the existing public certificate-status access model.
No registry-wide service token becomes mandatory for naapps.

The wire freeze must preserve the existing 8,192-byte encoded header bound
(`awid/src/awid/team_certificate.py:27-48`) or separately justify a versioned
transport change. Freeze a path format bounded to four edges. From the first
release, the controller sets depth within that supported bound; every registry
and verifier accepts paths within that limit and refuses paths beyond it.
There is no additional depth-1 release gate. Maximum-depth vectors
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
[BYOT uncertainty rule](../byot-onboarding-contract.md#creating-another-hosted-team) to this
operation; exact receipt field names are a freeze obligation.

The total counts **successful certificate issuances**, not live workers.
Revoking a certificate does not replenish the allowance. A new certificate
after rotation/re-admission counts again; exact replay does not. The rate and
total are shared across every descendant admitted under that stable policy ID,
so onward delegation does not create fresh buckets. Policy expiry bounds both
issuance and dependent use, subject to preserved revisions after widening.
Child expiry cannot exceed the policy expiry at issuance or any
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
or expiring the policy, or publishing a narrowing revision, denies certificates
depending on the withdrawn continuity range. Widening preserves dependent
certificates and compatible parent paths; it does not refresh an observation
or extend a signed certificate expiry.
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
dependency/freshness evidence needed by callers. For an inherited leaf it also
returns verified team ID, stable policy ID, direct-root principal, admission
depth and ordered ancestor principals (root first, then each intermediate
parent, ending before the leaf). Depth equals that ancestor count. A principal
key is `(team_id, member_did_aw)` when the verified certificate carries a global
DID, otherwise `(team_id, member_did_key)`. These come only from the verified
path, never request fields. Direct membership returns no inherited-policy
facts. A globally re-admitted root may keep its stable principal key, but old
certificate dependencies never transfer; local key replacement is a new
principal.

Resource decisions consume only verified membership facts. The following rule
follows the converged rule for acwd.16 (Athena `2bc86d1b-8ff1-4063-8686-8bb3633cb6c5`,
settled with R and relayed by secrets `e536012c-0fd4-4feb-86fb-cc4ded970483`):

The shared verifier's original membership dependency deadline (the earliest fresh_until across the verified evidence, retained from admission, never refreshed by a cache hit) is compared LOCALLY against the clock read after the last effect-lock wait in the final fence transaction. That transaction covers approval consumption, credential opening and release, and the dispatch or assignment commit. It applies to direct and inherited members alike and makes no network call. An expired deadline refuses inside that transaction, so the transaction rolls back:

- no approval is newly consumed by the rolled-back transaction;
- no assignment is persisted;
- no bytes are released.

The requester obtains fresh admission with fresh membership evidence. A rollback
cannot undo an approval consumed by an earlier committed admission. Recovery
is determined by that commit boundary, not whether the request is brokered or
runner-based (`secrets.md` §10.5 and §11.1; secrets `103904d4` option (i)):

- Before admission commits, refusal leaves the request and any unconsumed
  approval available for exact re-submission with the same request ID/bytes,
  subject to normal grant, approval expiry and idempotency checks.
- After admission commits, its approval stays consumed. A later fence refusal
  closes the admitted intent `refused` through the existing transition, after
  rolling back the failed effect transaction. No old assignment can be claimed
  again. Recovery is a fresh request and fresh approval where policy requires
  it; nothing refunds or rearms the original approval.

This is an explicit addition to Secrets' existing dispatch fence, not a claim
that its current implementation already checks membership deadlines. The
resource contract adds the local comparison to `secrets.md` §11.3 and owns its
re-submission/idempotency details. No cached hit or retained intent manufactures
a new deadline. The generic path introduces no second verifier or network read.

**Portable deadline (R/A refinement, secrets
`1baed17f-8ad5-49ab-b9ff-12a23e5fdc8e`):** `MembershipProof` uses a process-local
monotonic clock; never persist that value for another worker. In the admission
transaction, sample the database `clock_timestamp()` **first**, then compute
the minimum remaining original monotonic budget, rounded down to the persisted
precision. Add that remaining budget to the earlier database timestamp and
persist the resulting absolute deadline. A non-positive budget refuses.
Adding an earlier budget to a later timestamp would extend authority and is
forbidden. Persisting or queueing may consume that budget; it never extends it.

The final fence compares the persisted deadline against the same database
clock, sampled after its last lock wait. Dequeue, cache hits, retries and lock
acquisition never rebase the deadline. The consumer inventory must cover
admission, persistence, cross-worker queue claim, approval consumption and
credential release using that representation. Expiry is the existing shared
503 `current_membership_unavailable`, not a revocation finding. Recovery is
fresh authenticated re-submission through normal grant, approval and
idempotency checks; it never bypasses them. Grant revocation is an independent
stop. Exact timestamp precision and representation belong in the joint freeze.

Consequences for that consumer:

- A queued runner job claimed after the deadline refuses at its claim fence
  with the shared 503 `current_membership_unavailable`, final for that dispatch.
  This is unavailable evidence, not a claim of revocation. Any approval consumed at admission stays consumed; the intent closes
  `refused`, with no assignment, credential release or send. Recovery requires a
  fresh request and fresh approval where required, never automatic release of
  the old assignment. The remaining deadline can be less than 60 seconds at
  admission. A job queued beyond that deadline requires re-submission and, for
  an approval-gated job, another human approval. This is the availability cost.
- Ordinary brokered requests admit and dispatch in one flow and are unaffected
  in practice; any actual wait beyond the deadline still refuses. One flow does
  not imply one transaction: an approval already consumed at committed admission
  stays consumed after a later broker fence failure, just as for a runner.
- Membership withdrawal exposure is the governing observation window without
  extra queue delay. This retains the earlier qualification for independent
  external-authority freshness. Grant revocation still cuts admitted unsent
  intents at the existing fence.
- Vectors cover expiry during a proven effect-lock wait, during deadline
  persistence and in a queued cross-worker claim. Each asserts no approval
  newly consumed approval in the failed transaction, no assignment row, no
  credential release and no send. A queued job's earlier consumed approval stays
  consumed and its intent closes refused. Short waits with usable evidence
  remain the positive neighbors.

Installation scopes and resource policy remain separate. Acwd.16 owns how the
verified path constrains grants and distinct approvers; these output fields
do not grant those rights.

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

The public decision corpus below is updated with these decisions; exact signed
byte vectors remain a joint freeze prerequisite. It must cover both server and
direct-naapp consumers:

| Case | Expected result |
| --- | --- |
| A belongs to T1/T2; selects only T1; T1 permits it | Local B_T1 joins T1 with its own key and no did:aw; no request or membership in T2. |
| Local parent and child, no global ID records | Signed eligibility/path, publication, effective status and withdrawal work without global identity lookup or creation. |
| One instance selects deployment D and resource H | Distinct local B_D/B_H keys and receipts; each team independently authorizes its parent context. |
| B_D presents D membership to an H installation | Refuse; B_H with H membership is the valid neighbor, subject to H's resource grants. |
| H withdraws B_H's parent path | H use denies under bounded freshness; separately authorized B_D messaging is unchanged. |
| T1 policy allows a named current A; B proves its key | Registered inherited membership admits ordinary T1 use. |
| B requests a resource granted to all T1 members | Existing resource policy decides normally. |
| B presents only A's principal/role grant or owner authority | Refuse; membership inheritance copied none of those rights. |
| Valid ID-parent certificate, no team inheritance policy | Refuse inherited admission. |
| Parent belongs to another team, or policy names another parent | Refuse without a publication or charge. |
| Parent signs for one child key; another key submits/proves possession | Refuse. |
| Missing child proof, changed team/policy/parent/hash/alias or replay substitution | Refuse. |
| Child attempts onward admission | Accept within controller-set depth and shared budget, including depth greater than 1 from the first release; refuse beyond policy or format depth. |
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
| Maximum-format depth and largest legal fields, both authorization modes | Encoded proof including continuity fits 8,192 bytes; admits if controller enables that depth, with no depth-1 exception. |
| More named parents receive eligibility grants | Existing carried proof size is unchanged; an unrelated parent's grant cannot authorize this root. |
| Registry claims active status without valid controller authorization | Refuse; status cannot forge membership authority. |
| Currentness checked for a maximum-depth leaf | One effective-status read per leaf/window, no per-edge/policy reads; cache hits keep original expiry. |
| Policy replacement only raises allowance/rate or extends expiry | Existing dependants still admit without re-admission/charge; counters and original observation deadlines do not reset. |
| Repeated widening then onward admission from an older-revision parent | Current compact authorization covers unchanged parent path; one controller object and one leaf status read, no carried history. |
| Old revision submitted for new issuance after widening | Refuse; existing dependants survive but new issuance names current revision. |
| Narrowing allowance/rate/expiry/depth or removing root eligibility | Prior policy dependants deny under bounded freshness; direct membership does not restore them. |
| Mixed widening/narrowing edit | Narrowing wins; prior dependants withdraw without counter reset or refund. |
| Current authorization attached to an edge below its continuity floor | Refuse even with active status; no controller authorization for that path. |
| Widening or old-policy replay after narrowing, withdrawal or expiry | Old withdrawn paths remain denied; retained issuance history is not revived. |
| Policy expiry extended but old child/parent certificate expires | Refuse expired path; no signed certificate lifetime extension. |
| Unclassified transition, forged floor or changed proof with old status hash | Refuse; transition validation and exact signed/status binding are mandatory. |
| Laptop and managed-server children with equivalent evidence | Same membership/resource decisions; no placement condition or forced host migration. |
| Direct member versus inherited leaf | Only inherited result exposes verified policy/root/ordered ancestors; caller fields cannot substitute. |
| Membership deadline expires during the last effect-lock wait | Local refusal; no newly consumed approval in the failed transaction, no assignment/release/send. Earlier committed admission consumption is not undone. Short wait with unexpired evidence succeeds. |
| Runner claims queued job after membership deadline, including another worker | 503 `current_membership_unavailable`; intent closes refused, admission approval stays consumed; no assignment, credential release or send. Recovery needs a fresh request and fresh approval where required. |
| Evidence expires while its deadline is persisted | DB-first timestamp plus later rounded-down remaining budget does not extend authority; admission refuses before commit with no approval consumed, assignment, credential release or send. |
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

Juan's selected flow uses a **third, independently governed team H**. H admits
A_H once and authorizes inheritance; B_H then uses H membership for H's secrets
and audit. H's controller stays outside worker reach. Deployment membership
supplies no H authority. This uses same-team admission at the resource
installation; the cross-team resource-grant proposal is **withdrawn for this
flow**, not a prerequisite or parallel implementation request.

Membership copies neither A_H's principal nor its role grants. The secrets
owner must have a supported grant covering B_H, including local-only B_H.
That remaining resource-policy fit is assigned to acwd.16 for review with this
contract. The end-to-end gap remains open until the grant and inherited
admission are implemented and qualified; no working-flow claim follows here.

Secrets and its audit governed in H use H's same-team app, hook and membership
authority and ordinary resource policies. Workers cannot change those controls
merely by holding H membership. Audit of apps outside H is separate: this
contract creates no cross-team hook binding or independent event feed from a
deployment-controlled team. Laptop placement changes none of these requirements.

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

Price: inherited membership currentness requires **one effective-status read
per leaf per usable original observation window**, never one per edge. The
window is configurable and at most 60 seconds, bounded by earlier dependency
expiry; cache hits do not restart it. Read-count parity applies only to the
existing token-free naapp per-certificate status path. The service-token path
instead caches team facts and shares a refresh across members
(`naapp-lib/src/aweb_naapp/runtime/team_auth.py:260-278,311-336,393-400`). Moving
that baseline to per-leaf reads increases request cardinality with active
members. The rollout inventory must measure incremental traffic for those
team-shared and other consumer baselines; there is no universal v1 cost-parity
claim and no new caching mechanism proposed here.
The shared verifier adds local Ed25519 verification of bounded evidence: one
controller authorization, one direct-root certificate and one per admission
edge (at most six at the four-edge format bound), on each request. The initial
verifier rechecks these signatures per request; it does not cache a positive
"proof hash verified" result. The effective-status observation retains its
existing bounded cache. Signed continuity remains in the one controller
authorization, so repeated edits add no verifications. Any later signature-cache
optimization needs measurement and must bind exact proof bytes and current
key/authority inputs without extending the observation window.
This excludes the ordinary request signature and any separate global-identity
verification. Hundreds of microseconds of local CPU is a review estimate, not
a measured benchmark or latency guarantee. Registration adds one AWID write
operation per selected team per spawn, with publication/provenance writes and
one shared policy counter-row update in that team's transaction. Registry dependency computation is
bounded by the path; it is not pushed into extra consumer network reads.
This is a reasonable proposed cost at spawn frequency, not a new registry
write on every resource use. Measure it and the external evidence acquisition
under realistic load; no implementation-time estimate is established here.

Before implementation, review the decision realization, freeze signed bytes and
status/capability interfaces, prove the size/depth bound with vectors, and
enumerate every accepting consumer. R and Athena review the contract; Juan
sees the reviewed contract and gives a separate implementation go. No code,
migration, live policy publication or controller transfer follows from this
document alone.

## Decision record and knowledge checkpoint

This is the single canonical record for acwd.13's direction and contract review.
Original direction: Juan in the servers conversation on 2026-11-09, relayed as
`f0d7526e-ddb3-4bfe-97cc-ca7527c70d15`; assignment
`7b73ac2a-ee6d-4876-bd46-af1ea0bfd4fe`. His local-child priority was relayed in
`1500015a-6c61-4153-996a-fb4f8e14fd56`.

Juan's decisions relayed by the coordinator in
`ed0a2bb7-413e-44ac-89fd-b2342a099bdc` (via secrets `2febbda1` and servers
`baec6a1b`) supersede this proposal's depth-1-first and strict-replacement
recommendations. Separate per-team local homes are existing behavior, not an
open identity-scope choice. General controller-bounded depth applies from the
first release; widening preserves dependants and narrowing withdraws them.
Third-team H supplies same-team secrets/audit admission; the cross-team grant
proposal for this flow is withdrawn. Resource grants need their own contract
and implementation. Coordinator `70e101b0-8846-450a-8aa7-230d8b8892d5` records
Juan's mixed laptop/server scope: placement is not admission authority.

Prior accepted knowledge:
`aweb/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md@9a54c7392429`.
Its reopen condition is in scope, but controller-only admission remains the
current implementation contract. These decisions authorize contract revision,
not code, migration, live policy publication or controller transfer. Bounded
continuity realization, signed bytes, status/capabilities and maximum-field
vectors remain subject to review and a separate implementation go. Record
supported versions separately on landing; reviewed design is not shipped behavior.

Review provenance: Athena `4fafc5c4-4acd-4c76-936e-4669a9d4b8ab` required bounded
controller evidence and one effective-status read; independent review
`f7c178b1-6497-4d2b-bb33-31b787eae962` required uncertain-outcome recovery and
local-only transaction claims. Prior head `fa6ff5bcac5b2d6eb63d387abfd6dcb79e47d851`
had proposal ACKs from Athena `a142a526`, identity review `f9810279` and naapp
review `0907b64e`; those do not approve this decision delta.

Checkpoint: keep this record canonical. Knowledge promotion must point here
rather than duplicate a protocol decision or promote an unreviewed realization
as accepted authority. The direction and supersession boundary are recorded;
released v1 authority is unchanged. The later fence convergence
`2bc86d1b-8ff1-4063-8686-8bb3633cb6c5` explicitly adds local original-deadline
checks for both direct and inherited effects; the R/A refinement relayed in
`1baed17f` adds the DB-anchored portable deadline and shared unavailable refusal.
Secrets `103904d4` clarifies that previously committed approval consumption
is not rolled back; the corpus distinguishes pre-admission and queued effects.
This supersedes the provisional
admission-only option and must be qualified with the resource consumer.
