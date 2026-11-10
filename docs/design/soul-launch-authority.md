# Soul, parent and runtime authority at launch

Status: **coordinated proposal for Juan and the OATS product owner** (acwd).
This is the one combined decision record requested in coordinator
`789415b1-804b-4296-9967-d5923008dfb6`. It commissions no implementation,
provisioning, purchase, credential movement or new task family.

Goal 2: connect approved souls to enforced customer-resource access while
preserving optional shared or isolated spawning and mixed laptop/server teams.

## Fit and authority boundaries

The combined model fits if a trusted launcher binds **approved soul revision →
running instance/member identity → authorized permissions**, and the target
actually enforces the claimed boundary. The three inputs are the approved
soul@revision, parent delegation and target runtime policy. Effective inherited
authority is bounded together by the parent's **delegable** authority, the
soul's owner-approved entitlement envelope, the parent's requested reductions
and the target's enforced constraints. An entitlement reference is not a grant.

Delegable authority is not necessarily authority the parent may exercise for
itself. For example, a resource owner can authorize a root's future children
without granting that root direct secret use. The parent cannot invent this
permission. If a requested entitlement falls outside the authorized
intersection, refuse it or obtain separately explicit owner authorization;
neither a local soul edit nor a smaller request silently creates another right.

| Authority | Owner and boundary |
| --- | --- |
| Selected source and soul schema | OATS and the operator's trusted source policy. Select an immutable approved revision; workers cannot substitute files. |
| Placement, co-residency and lifecycle | OATS chooses among operator-authorized targets; provisioning enforces the runtime and custody policy. |
| Identity and team admission | Public aweb contracts and each team's controller policy. [Acwd.13](selective-membership-inheritance.md) remains membership-only. |
| Resource use | The resource owner grants access. Acwd.16's inherited-member subject is separate from an optional soul predicate. |
| Launch claims | A protected issuer whose authority the consumer can verify; a worker's own label or possession of a peer-readable key is insufficient. |

No role, controller power or resource grant follows from ordinary membership.
No universal soul-attestation requirement is added to acwd.13. Its quotas keep
their existing scope across spawning; runtime and resource limits likewise
must not reset merely because a child exists.

## Two approvals and their binding

**Source provenance** means the selected soul@revision passed the operator's
trusted source policy: a protected-branch merge, then an approved locked
revision. The launcher verifies the immutable content selected by that lock
from a location workers cannot change. A branch name or a writable checkout's
HEAD is not equivalent evidence. This establishes source selection, not the
customer resource owner's consent or permission to co-locate.

**Entitlement authorization** is the resource owner's current grant and policy,
including the soul/revision and trusted issuer requirements when the owner
chooses them. Runtime entitlement references similarly need the operator's
placement/network/filesystem authorization. The soul declares references to
these entitlements, never tokens or secrets. A source reviewer cannot grant
another authority's resource merely by merging the declaration.

Bind the two through the exact immutable soul revision, the verified launched
principal and its request-bound launch proof, and the resource owner's current
grant/predicate. For a soul-dependent use, both approvals are required: source
approval without a grant authorizes no resource use, and a grant/predicate
does not authorize launching unapproved source. Ordinary policies that do not
require soul evidence remain ordinary resource policies.

The owner must choose which launch issuer or issuer authority it trusts.
A team-controller registration authenticates an issuer; it must not silently
substitute for resource-owner consent to that issuer's soul claims. Exact
issuer selection and the predicate's signed binding are freeze choices below.

## Existing behavior and evidence limits

| Component | Exists today | Missing for this model |
| --- | --- | --- |
| OATS, reported at 0.69.12 | Locked soul commits, frozen instance homes, same-host and SSH-target spawning. Instance metadata records soul ID/revision under the deployment UID. | Entitlement schema, explicit co-residency enforcement, protected launch mode and trustworthy per-instance caller binding. OATS has no container backend. |
| Aweb identity | Own keys, team certificates, separate local homes per team, ordinary membership and request authentication. | Acwd.13 inherited admission is a reviewed contract, not implemented or qualified here. No soul claim follows from its membership evidence. |
| Secrets | Optional `requires_attestation`, current grants and policy checks; custodial principal-attestation verification. | Acwd.16 inherited-member grants, a launch-provenance predicate and its claim/issuer contract. |
| Provisioning evidence | The contributor reports a lab worker UID denied root administration, sudo and the Docker socket, and denied service-key reads, with privileged positive controls. | That does not prove isolation among workers sharing the UID or protection from administrators. Egress policy, resource limits and protected launcher integration remain proposed. |

OATS facts are contributor evidence (`e2f4c06f`, corrected by `fd251667`), not a
new runtime test by this editor. Provisioning evidence is Hestia's report
relayed in `fda1c1d6`, from ai.aweb `bc4bb2b83e1825bf5fa1d2cd87c5e834cb6ae141`.
It qualifies that lab only, not an interoperable dependency or a general
customer guarantee. Its egress proposal is not evidence of a protected launcher.

## Soul declaration and protected launch

The proposed OATS soul-schema field lists **entitlement references**: resource
identifiers/classes, role references and runtime needs such as egress classes
or mounts. It is an upper bound offered to the relevant authorities. Kernel
validation and `oats inspect` would expose it; those changes are missing.
Neither a role name nor a reference in this field assigns a role or grants use.

The protected launch mode needs these boundaries, owned by OATS with
provisioning:

1. A separate protected launcher principal, local or off-host. Workers cannot
   read or alter its credentials, binary, configuration or source pins, ptrace
   it or use privileged interfaces to bypass it.
2. A narrow authenticated request interface: approved soul name and requested
   reductions, with an optional parent reference. The caller cannot supply
   arbitrary argv, environment, home path, hooks or a subject DID to admit.
3. Launcher-owned source at the approved locked revision, verified by digest.
   A worker-writable workspace, local override or package is not trusted input.
4. Launcher-controlled placement, homes and key preparation. Generate fresh
   child keys at the chosen boundary, bind the public identities to the launch,
   and never admit an arbitrary caller-supplied identity as that launch.
5. Human CLI/Desktop launches use the same checks; they are not a side door.
6. A durable external launch record identifies selected source, parent and
   requester, reductions, target policy/customer scope, placement, member
   identities, lifecycle state and time. It is evidence for the issuer's later
   decision, never a reusable bearer authorization.

A launcher that sees only a worker-generated public key need not hold its
private key. Whether the worker or a protected signer holds that key is a
separate explicit custody choice; the resulting claim must describe the real
arrangement. Publication or admission does not prove process isolation.

## Placement, custody and co-residency

Same-environment spawning is allowed only under an explicit operator-approved
co-residency and customer/data policy. Equal entitlement lists are insufficient:
untrusted code or different customers may require distinct boundaries even
when permissions match. The declaration names which souls may share and within
which customer/data scope. It is not controlled by the spawning worker.

On today's shared UID, peers can use reachable keys, tokens and privileged
interfaces. Selecting fewer certificates for a child does not contain that
child if it can read the parent's or siblings' credentials. The whole reachable
environment is one compromise boundary. Per-instance reductions cannot be
claimed as enforced there merely because local configuration lists fewer rights.

A new environment uses an approved target policy that is equal or more
restrictive for the selected authority, with fresh identities, declared mounts
and credential references. No wholesale HOME/token/controller copy, Docker
socket or unrestricted administrator API is exposed to the parent. The parent
requests attenuation; it does not modify the enforcer. A laptop's ambient
access is not a portable attested runtime policy; unsupported target constraints
cause refusal rather than an assertion of equivalent protection.

The provisioner is a named human or agent principal and includes whoever can
exercise root, Docker administration, provider or DNS authority. Their reachable
credentials and interfaces are inside the trust base. A worker-inaccessible
admin interface on one host does not protect against a shared compromise on
the administrator's own host. State the custodian and that residual explicitly.
Protect source pins and entitlement policy as well as keys; a worker-writable
approved-policy checkout defeats the launch boundary.

A deployment-controlled messaging team may deliberately entrust its entire
team authority to that shared boundary. That is different from H's governance,
namespace authority or credentials intended to resist those workers, which
must remain outside their reach. Acwd.13 does not require moving controller
keys onto a worker or provisioner; a bounded inherited admission needs neither.

Hestia recommends one customer per host/VM as an initial provisioning profile.
That is a proposal, not a universal protocol rule or an approved container
backend. Root-enforced UID/network/storage/resource controls must be qualified
for the selected profile; an egress destination allowlist alone does not prevent
exfiltration through allowed destinations. A bootstrap firewall that can fail
open is not qualified enforcement of a claimed constraint.

## Persistent record and proof for a later request

The persistent launch record establishes what was selected and launched. It is
not accepted by Secrets as a request attestation and cannot be replayed to
obtain use. The missing issuer API has to make a fresh decision for later
requests:

1. Authenticate the asking execution context through a **protected caller
   binding**, not merely a signature made with a key peers can read. A local
   socket's authenticated UID can distinguish instances only where their UIDs
   actually differ; an off-host credential must likewise be protected from
   peers. Shared-UID key possession proves only membership of that trust group.
2. Resolve the issuer-controlled launch record and verify that the exact
   member/team/certificate/key in the team-auth request belongs to that launch.
   The requester cannot substitute a sibling, a chosen soul digest or a record
   ID as evidence. Current membership and key checks remain their own contracts.
3. Check current lifecycle, source approval and still-enforced reductions and
   runtime constraints. Stopped/retired, withdrawn approval, missing binding or
   unavailable required evidence produces no acceptable proof. Exact lifecycle
   transitions and failure semantics still require the product decisions below.
4. Sign a short-lived claim bound to the **exact team-auth signed-payload
   bytes** for that request. Return no proof of unrelated bytes or identity.
5. The consumer verifies the request and proof, then independently checks the
   resource owner's current grant and optional soul predicate at admission and
   its existing policy fence. The launch issuer does not mint resource grants.

If peers can impersonate each other, the issuer may at most claim the whole
compatible trust group. It cannot assert a particular process or soul from
key possession alone. The optional predicate must refuse a group-level claim
when it requires a specific soul/instance. No group claim format is selected
here; support requires its own precise semantics within the same freeze.

The claim establishes launch provenance inside the issuer's stated boundary,
not that a mutable harness has forever executed only its initial source. Later
proof issuance needs current qualification of the claimed constraints; it is
not continuous code attestation. A more privileged parent can still act on its
own or share what it can read; a child's reductions cannot prevent that.

## Attestation reuse and the missing protocol contract

The current [principal-attestation contract](../principal-attestation.md) and
`aweb_naapp.runtime.attestation` already verify signed request-bound evidence.
Secrets' optional policy supports `custodial_via`, `channels` and
`human_principal` ([§4.6](secrets.md#46-custody-and-principal-attestation-contract));
missing required evidence fails closed. Validation/evaluation are in
`naapp/secrets/src/aweb_secrets/policy.py:178-190,278-289`; the admission, run
planner and broker fence consume them (`admission.py:410`,
`run_planner.py:91`, `broker_fence.py:324`, as cited by the consumer owner at
main `38f95eafd`). This is not a shipped soul predicate.

V1 attests **custody**. It requires an actual custodian holding the member key,
a team-controller-signed issuer registration and an immutable member-custody
record for the certificate (`principal-attestation.md:26-38,65-139`). Its only
custody value is `custodial`, and unknown fields refuse (:170-187). A launcher
that sees only the public key is not a v1 custodian. Do not create a false
custody record, add soul fields to frozen v1, or treat inherited admission as
authority to publish custody records. Even a genuine custodial launcher's v1
proof says nothing about the soul it launched.

The proposed minimum extension is a versioned launch-provenance claim and
controller-authorized launch-issuer record, with distinct signed domains. Reuse
canonical JSON, Ed25519, single-encoding transport, request-binding verification
and the existing registration/rotation pattern. The issuer record authorizes
launch claims, not custody; it is not silently the existing custodian record.
Logical claim inputs are the verified team/certificate/member key, immutable
soul revision digest, launch record identity, exact request binding and bounded
issuance/expiry. This list is a proposal, not frozen bytes or a new grant subject.

Secrets would add a predicate evaluated only against this verified claim,
composed by AND with the chosen grant and other policy. Its owner controls
accepted soul/revision and issuer requirements; relaxing them is a widening
owner change. Acwd.16's inherited-member grant subject continues to select a
line of members independently of that optional predicate. No soul-specific
grant subject is selected, and ordinary membership needs no launch proof.

## Freshness, replay and lifecycle

Reuse the existing request/time semantics explicitly:

- V1 attestation binds SHA-256 of the exact decoded team-auth signed-payload
  bytes. `exp > iat`, lifetime at most 300 seconds, `iat` at most 60 seconds
  ahead of verifier time, and expired evidence refuses
  (`principal-attestation.md:180-211`; `runtime/attestation.py:198-214`).
- Issuer authority records have their existing at-most-60-second cache with no
  expired fallback. A new launch-issuer record must specify the same sort of
  freshness and rotation treatment before reuse is claimed.
- [Team-auth v2 replay](../team-auth-envelope-v2.md#replay) expressly permits
  byte-identical replay within its accepted timestamp window. It has no nonce
  mechanism today (:126-134). A request-bound proof is **not single-use**.
- Secrets mutating requests carry signed `request_id` and deduplicate by
  installation/principal/request ID (`secrets.md:259-264`, §11.2). A repeated
  signed request does not thereby authorize a second dispatch. Other endpoint
  owners must state their own deduplication behavior; an attestation creates
  none for them.

Issuer checks run when it signs. A later stop, retirement or source-approval withdrawal
must prevent new issuance once observed, but an already-issued proof can remain
acceptable until its bounded expiry and governing authority observations say
otherwise. Do not claim immediate invalidation, a new universal nonce store or
single-use launch records. A shorter claim lifetime or stronger lifecycle
revocation is an explicit policy/contract decision, with availability cost.
Resource-owner grant/policy withdrawal is checked by the resource consumer at
its own admission and effect fences; proof validity does not override it.
Offline issuers cannot supply fresh evidence to policies that require it;
absence never proves self-custody or bypasses the predicate.

Acwd.13/.16's membership effect deadline remains separate from launch-proof
freshness. Neither cache hits, retries nor a later launch proof refresh the
original membership deadline. The joint consumer freeze must identify which
claim deadlines are checked at each admission/effect boundary and preserve them
through waits, rather than imply that a valid launch record extends authority.

## Laptops and attribution

A laptop without a qualified protected launch binding retains ordinary
membership. A resource owner may refuse it under an optional soul-dependent
policy without forcing all laptop agents into containers or a managed server.
A protected local issuer is a possible product profile, not existing support.
The same rule applies to an unqualified managed-server launch.

Multiple instances may intentionally use one external GitHub or other actor.
Provider-side audit may identify only that shared actor. Internal attribution
is limited by protected caller/key bindings and the accepted compromise
boundary; distinct aweb keys under one shared UID do not prove distinct
processes or souls. Internal records do not manufacture provider-side identity.

The proposed request-proof path costs one issuer signature per protected
request and requires that issuer to be reachable, plus one local consumer
signature verification and a bounded cached issuer-authority read. These are
design costs, not measurements. Policies without the predicate gain none of
this work. Exact cache/freshness and failure behavior are part of the freeze.

## One list of missing work and product choices

| Work / choice | Owner | Required decision or qualification |
| --- | --- | --- |
| Soul entitlement references and presentation | OATS | Kernel schema/validation/inspection; bind immutable source approval separately from resource authorization. |
| Co-residency and customer/data policy | OATS + provisioning | Explicit sharing rules and defaults; decide the initial one-customer-per-host proposal and supported boundaries. Equal permissions alone do not authorize sharing. |
| Protected launch mode and caller binding | OATS + provisioning | Separate protected principal and narrow API; qualify actual UID/signer/remote isolation. Decide whether to open this execution mode and whether to support a laptop profile. No container backend is commissioned. |
| Runtime policy and key custody | Provisioning | Supported target controls, owned pins/mounts/credential references, admin trust base, resource and egress enforcement, fail-closed startup. No worker authority to edit the enforcer. |
| Launch claim, issuer registration and request-proof API | Protocol + OATS | Versioned non-custody authority, exact request/identity/source binding, compatible shared-group semantics if selected, time/replay/failure behavior and maximum-size vectors. Resource owners explicitly select trusted issuer authority. |
| Current launch and resource authorization | OATS + resource owner | Check live lifecycle/source/runtime at proof issuance; current owner grant/predicate at resource admission/fence. No replayable launch record or implicit entitlement grant. |
| Membership and resource composition | Acwd.13 + acwd.16 owners | Finish their separate wire/consumer freeze and qualification; keep membership independent of soul predicates and quotas at their authorized scope. |
| Lifecycle and recovery | OATS + provisioning + protocol | Choose stop/retire/revoke and existing proof validity; disposition of shared/persistent targets and pending work; offline/failure behavior, explicit ownership and teardown. Stopping a process alone revokes no team certificate or resource grant. |
| Cost and evidence | All existing owners | Measure issuer availability/latency and per-request signature cost; qualify source substitution, peer impersonation, stale lifecycle, wrong-request proofs, unauthorized entitlement and incompatible co-residency with valid neighbors. |

## Decision checkpoint and provenance

This is the single combined record requested in coordinator `789415b1`, after
`fcbc209d` superseded the placement/parent-only fit. It complements, rather than
duplicates, the membership decision in acwd.13 and the grant decision in acwd.16.
Contributors: OATS `e2f4c06f` with corrections `fd251667`; provisioning Hestia via
`fda1c1d6` (receipt referenced above); Secrets consumer `3998140b`, source at
`38f95eafd`. Existing source behavior is distinguished from their proposed
work. The editor read the public attestation/request contracts directly; no
new runtime qualification was performed.

Pending product choices and claim bytes are not accepted authority. No
implementation, launcher service, custody transfer or purchase follows. Keep
future approval and supersession here; do not create a competing soul/runtime
architecture record. Acwd.13 stays membership-only throughout.
