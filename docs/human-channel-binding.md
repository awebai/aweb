# Human identity and channel binding

Status: **design candidate, J9 / S6h; no implementation or activation**.
Base: aweb `dba349d5eacae4d792d481ce066834b1f3d25296`.
This contract defines the human authority consumed by channel bindings. It adds
no wire family, endpoint, database, removal store or background job.

## 1. Evidence and authority

**Source facts** below cite repository paths and lines at that base. A statement
labelled **Hypothesis** is a proposed requirement or a reported external design,
not behavior demonstrated in this repository. All requirements and expected
results in sections 2–8 have that Hypothesis status unless
explicitly identified as source facts. Review of this design does not establish
implementation, deployment or enabled delivery.

Source facts:

- An ID certificate identifies a human or agent and its parent; the nearest
  human answers for an agent. A human is one natural person. Namespace admission
  vouches for that fact; it does not prove a mailbox or a fresh human gesture
  ([id-certificates.md:14–21](id-certificates.md#1-what-the-tree-proves)).
- ID issuance, team membership, roles, custody and channel authority are separate.
  A human has a registered `did:aw` and may reuse it across teams and same-domain
  orgs ([id-certificates.md:23–38,53–57](id-certificates.md#1-what-the-tree-proves)).
- The shared verifier returns `outcome`, `human_id`, `identity_valid`, `kind` and
  `reason`. Human-required policy refuses `no_human`, `unknown` and `unavailable`
  ([id-certificates.md:655–689](id-certificates.md#5-presentation-binding-and-verification-result);
  [id_certificates.py:352–360](../awid/src/awid/id_certificates.py)).
- Tree evidence is fresh through 60 seconds inclusive **at acquisition**;
  otherwise refresh or report unavailable. There is no post-lock freshness
  anchor ([id-certificates.md:584–601](id-certificates.md#4-one-batch-and-the-production-cache);
  [id_certificates.py:325–331](../awid/src/awid/id_certificates.py)).
- Org/team removal ends local owner/role authority without revoking a human ID
  shared with other orgs. Current owner mutations recheck membership, session
  and accepted removal, including surviving agent rows
  ([id-certificates.md:482–493](id-certificates.md#revocation-authority-and-cascade)).
- The existing P8 binding family signs exact target, mode, platform/scope,
  blinded commitment, audience, generation and request. Its owner lane verifies
  `BindingOwnershipProof` from an independently pinned authority. It grants no
  custody, team role or message authority
  ([human-channels-contract-v1.md:405–423](human-channels-contract-v1.md#presence-and-native-operation-records)).
- P8 requires a host transaction recheck and generation/request CAS; public actor
  locks stabilize local projections, not remote AWID
  ([human-channels-presence-verification.md:104–145](human-channels-presence-verification.md#applying-a-verified-result)).

**Hypothesis — decision provenance.** The assignment and the approved plan r3,
J9/S6a/S6d/S6g/S6h, require this composition. The coordinator supplied r3 and
Juan's superseding simplifications on 2026-10-29 (aweb mail
`8b94d0e6-a272-4cf0-9288-b5e9de67c142`, clarification `df31a92c-c4b2-4125-8cac-dd910430dd6d`).
The Cloud co-owner supplied source excerpts and its first-hand source survey at
ac `4dcf8ef169e6cbf06869f4cc1a224949e882d568` (mail
`941c53e7-e2fc-4d2f-9011-5da397db7683`) and explicitly unimplemented email design
at ac `ae39546178386f40fcecdb0dd2e5ef390e9c9cc6` (mail
`6f6bf23c-90ba-4e9e-bc12-e57a5d57a89a`). These are provenance for requirements,
not an OSS claim about hosted deployment. Application schema and implementation
remain with that consumer.

## 2. Four distinct relationships

**Hypothesis — proposed model.** Let `U` be the actual signed-in account, `D`
its explicitly selected identity namespace, `H` its associated human `did:aw`,
`S` the exact native subject, `T` the exact selected aweb team and `R` the private
channel resource. Microsoft Teams is a channel platform (`msteams`); it is not
an aweb team. A channel account, bot, room, email address or display name is not
itself an aweb human ID. S is the subject whose binding is being
authorized, not an unrelated sender whose messages it may receive. The human
namespace D need not equal the namespace of team T.

| Relationship | What authorizes it | What it does not establish |
| --- | --- | --- |
| U → H in D | Verified account-association/enrollment operation and current shared human verification | An arbitrary account key row or old registration receipt is not current authority. |
| H → S responsibility | Fully verified current ID tree, bound to S's authenticated current key | No key custody, org role, team admission or consent. |
| U/H → T membership | Host's current org/team policy; ordinary member certificate where that operation requires it | Neither another org's membership nor parent issuance supplies target-team rights. |
| H/S → R binding | Exact human action, resource/intake/consent checks and P8 approval where applicable | Receiving a copy, knowing a token or linking a channel does not make its recipient S's responsible human. |

Source fact: human keys use a human keychain or checked custodial human session;
custom-domain root custody stays with the customer's controller
([id-certificates.md:32–38](id-certificates.md#1-what-the-tree-proves)).
**Hypothesis:** an account association with a self-custodial human confers no
Cloud signing custody. If the operation requires an owner signature that the
host cannot legitimately obtain, it remains pending-external or refuses. A
legacy dashboard actor's key must not silently substitute for H's key. A
message may still be authored by its independently authorized existing actor;
the verified ancestry, rather than an ancestor's signature on every message,
provides responsibility.

## 3. Full current-human predicate for bind and rebind

**Hypothesis — proposed conformance rule.** Bind and rebind through C2-D's human
owner lane succeed only when **all** the following hold for the same operation:

1. **Actual human session.** U has the real, live browser credential, active
   verified account, current session and endpoint's existing exact-origin CSRF
   checks. The endpoint rejects a credential-class substitution. An API key,
   session grant, agent credential or admin role cannot act as this human.
2. **Account association.** The verified U+D association names exactly H, in
   registered state, with H's independently current key and valid human chain.
   No pending enrollment, receipt-only result, email equality, alias,
   `owner_user_id` or API-key account association supplies this fact.
3. **Subject responsibility.** The shared current verifier, bound to S's
   independently authenticated ID/current key and exact required domain, returns
   `nearest_human`, `identity_valid=true`, `human_id=H`. H may be the human leaf
   or an inherited nearest human. No copied ancestor algorithm or caller-supplied
   verified-result object is authority. Omission cannot evade enrolled status;
   revoked, root-replaced, stale, pending or missing evidence cannot grant H.
4. **Current membership.** The host's authoritative decision admits U/H in the
   exact org/team T for this action, with no accepted relevant removal. S's
   ordinary target-team membership, active state and certificate restrictions
   also hold. Surviving agents or cached membership rows cannot override an
   accepted removal. An admin who is a different human fails step 3. A matching
   human who is only a member elsewhere fails this step.
5. **Existing action checks.** Preserve endpoint ownership, connection/link,
   confirmed challenge or approved platform-specific verification basis, explicit
   current consent, org policy, custody and exact subject/resource/scope/mode.
   A platform token establishes neither H nor consent. Independently verify the
   required P8 signed binding intent and owner proof for this exact operation,
   using the configured issuer/pin, current keys and authorization revision.
6. **Atomic application.** Recheck the locally mutable facts in steps 1–5 in
   the binding transaction, serialized against account/session/association,
   membership/removal, consent/resource and subject projection changes. Commit
   only the exact checked operation with its generation/request CAS.

The identity component is shared by S6 and the C2 consumer. Host membership,
resource checks and P8 verification remain their existing authorities. This is
an input/output predicate, not a proposed new persistence API.

Source fact: P8 already has a distinct subject-signed lane and constrained grant
checks ([presence.py:194–211,273–281](../server/src/aweb/human_channels/presence.py)).
**Hypothesis:** the rule above does not remove that released lane or make every
ordinary grant-backed action require a browser. A valid subject operation stays
subject-authorized; it must not be labelled a human-owner action. BYOT owner acts
also keep their controller-key contract; neither an admin role nor a new human
binding rewrites it ([id-certificates.md:1024–1035](id-certificates.md#6-invitations-adoption-and-migration)).

## 4. Transaction and refusal boundary

**Hypothesis — proposed conformance rule.** Resolve registry/key/tree evidence
through the production cached client before host locks, checking freshness once
on acquisition. After a lock wait, re-read local session expiry/revocation,
account association, membership/removal, resources, consent and exact binding
revision on the caller's open transaction. Retain the host locks through commit;
follow the existing host-authority-before-public-actor lock order. Verify the
P8 result's own expiry and exact revision at application; this existing deadline
is distinct from tree-evidence cache age. Do not add a second tree-age test,
post-lock anchor or registry request under locks.

A logout or membership removal that wins serialization makes the pending
bind/rebind refuse without creating/replacing a binding or consuming its proof.
If binding wins, it commits before logout/removal; the later membership removal
then ends its membership-derived eligibility even if retirement is incomplete.
Logout prevents later owner mutations; it is not by itself withdrawal of all
previously committed delivery consent. Remote registry rotation/revocation is
bounded by the tree cache, not serialized by a local database lock.

Refusals preserve the previous binding and generation, leave a new request
unconsumed and create no new delivery, message, wake or charge. An exact retry
recovers its original result; it never reactivates a stopped binding. A different
operation or target under the same request ID conflicts.

Public errors use the existing P8 vocabulary and HTTP map
([human-channels-contract-v1.md:125–137](human-channels-contract-v1.md#capabilities-and-failure-results)).
Log the actual cause at the decision boundary; do not expose raw channel
identifiers, addresses, credentials or private account mappings in public errors.

## 5. Change, stop and removal

**Hypothesis — proposed conformance rule.** These operations have different
powers:

| Operation | Required authority | Effect |
| --- | --- | --- |
| Create or rebind | Full section 3 predicate plus exact P8 approval/resource checks | New authority for the exact target; rebind names its exact old binding and generation. |
| Signed P8 unbind | Existing portable verifier's exact signer/proof/purpose/current-rights policy | No relaxation of that protocol's checks. |
| Account-owned local stop | Actual U session, CSRF and locked exact ownership of the existing private binding | Stops only that binding's delivery; permitted after membership loss or unavailable human evidence. No new owner signature/proof or human association is fabricated. |
| Membership removal / host disable | Existing authorized membership or operator policy | Invalidates eligibility; cannot impersonate H to create/rebind. |

For the Cloud consumer, local stop means its existing `revoke_binding` operation,
not a second stop API (co-owner source survey, §1).

An own local stop is idempotent and retains the existing non-disclosing
not-found response for another account's binding. It does not transfer to a new
human or resource, mint a new P8 proof, restore delivery or grant console/admin
rights. If stop loses a race to an already committed delivery, it does not
unsend it. Signed unbind and local stop remain separate operations.

Bindings never follow an alias, email address or team label to a new identity.
A changed responsible human, lost-key replacement or different account
association invalidates the old binding's authority; a new bind/rebind needs
its own checks and consent. Same-H key rotation uses current verification;
a stale local child cannot confer owner authority until re-signed. Current
registered children retain the tree contract's witnessed issuer history.

Org/team removal closes eligibility in that exact org/team immediately under
the host transaction, independently of delayed agent retirement or the remote
60-second ID-status bound. Another org's binding is unaffected if its own
membership/consent/chain remain valid. ID revocation/root replacement follows
the shared verifier and can affect multiple teams. No historical message is
re-attributed, and no public team-membership directory is created.

Re-admission and re-link require explicit current authorization. They do not
reactivate an old stopped binding or replay its backlog. Preserve existing
cutoffs, generation tombstones and cancellation of pending old routes. This
consumes S6d/S6g/acls membership/removal decisions; it neither reinstates the
superseded email-departure ledger nor creates a competing removal store.

## 6. Email and outsider verification

**Hypothesis — decision and proposed boundary.** Juan's 2026-10-26 decision is:
no public identity/channel record carries an email address; its public email
form, where needed, is `{domain, fingerprint}`. Private delivery/account storage
may retain the address. The human identity is H (`did:aw`), not the email or
fingerprint. Email ↔ H is the host's private verified-account association.

The superseded [member attribution document](member-attribution.md#2-validated-email-and-privacy)
contains a historical team-scoped fingerprint algorithm (lines 78–115); its own
lines 3–6 forbid implementing that record. This contract does not revive it,
freeze a new email fingerprint algorithm or add email to ID certificates/status.
An email descriptor alone is not a signed proof binding that mailbox to H.

An outsider with independently obtained current ID evidence can verify the
responsible H under the ID contract, but not a private mailbox/account mapping,
membership or consent. An email descriptor proves nothing about H, consent or
custody. Knowing the email permits descriptor comparison only under an
independently specified fingerprint profile/context, matching both domain and
fingerprint. A P8 proof binds the signed action and blinded target; it does not
prove the private platform resource or intake ownership.

Fingerprints are not encryption or protection against guessed addresses. Their
profile/context must be specified before publishing a matchable descriptor;
no new profile or publication endpoint is enabled here. Email domain and the
ID certificate's namespace are distinct facts, with no suffix-based authority
inference. No outsider may infer U→H from an address or descriptor, or recover
private org/team membership through status/errors.

Email reception/extra-copy consent is separate from responsibility for the
sending agent. It must not re-parent that agent. An email reply uses its actual
message-author key and existing send authorization; neither the mailbox nor an
SES/service key can issue a human-ID or ownership proof. Address change or
unverification ends the old email link; a new verified address needs consent,
without silently creating a replacement human ID.

Source fact: at this base, `via` accepts open well-formed platform kinds, but
`PresenceIntent`, `OwnershipProof`, `PresenceBindingIntent`,
`BindingOwnershipProof` and verified-presence profiles have closed platform
enums containing telegram/msteams/slack/whatsapp/discord, **not email**
([human-channels-contract-v1.md:83–88](human-channels-contract-v1.md#compatibility-bytes-and-signatures);
[human-channels-profile-v1.json](vectors/human-channels-profile-v1.json)).
**Hypothesis:** email needs a separately reviewed additive platform-profile and
signed-vector extension, publication and consumer pins before activation. No
new email-specific public family or platform impersonation. The decided email
extra-copy role, private uniqueness/selection/dedup extension and verification
basis remain the email consumer's design work; they are not enabled by J9/S6h.

## 7. Membership and the OSS path

Source fact: CSR approval issues an ID certificate, and completion grants no
team membership or contact rebind ([id-certificates.md:838–845,998–1003](id-certificates.md#self-custodial-child-requests-and-re-sign-transport)).
**Hypothesis — proposed composition:** Cloud S6d supplies current org/team
membership. A self-hosted operator admits humans through parent/root issuance
and the CSR path, then separately supplies ordinary team-controller membership
and its action policy. Neither path may derive team admission from parentage.

A same-domain H joining another team/org reuses its human identity; membership
only changes the selected scope. An invitation may complete membership while
human registration stays pending; pending grants no C2 human authority. Removal
from one team does not revoke H globally. A human invited earlier by a departing
human can remain valid under the ID contract; do not revoke it merely because
its inviter left. The exact action's own current membership still must pass.

## 8. Conformance, open questions and release boundary

**Hypothesis — acceptance requirements.** Ordinary tests in the consuming
Cloud C2/S6 implementation must cover independent failure dimensions and valid
neighbors: direct/inherited H, custody independence, wrong H/team/admin,
no-human/pending/unavailable/revoked/root-replaced evidence, accepted removal
with surviving agents, self-custody, scoped membership changes, local stop after
loss, and the preserved ordinary subject-authorized lane.

Real-PostgreSQL tests must exercise both lock orders through commit for logout
and membership/removal versus bind/rebind, including no-write/no-consumption
rollback. Failed-commit and exact-retry cases must exercise the actual P8 ledger
and host binding transaction, including retry after local stop without
reactivation. This design slice does not run that implementation harness or
claim it was shown to fail. No new vectors or matrix are introduced; existing
signed ID/P8/profile vectors remain unchanged.

Open questions and consumer obligations (all **Hypotheses**, not implemented facts;
the activation order is a recorded decision):

1. **S6/C2 interface:** publish the exact verified account→current-human and
   current membership/accepted-removal input plus lock/recheck contract. The
   pending key store/registration receipt and old C2 owner field are insufficient.
   C2's Cloud co-owner validates this against its adapter before activation.
2. **Email profile:** the owning email slice must specify any public fingerprint
   profile/context it actually needs and publish the additive P8 platform
   coverage. A descriptor is not evidence of the private H association. The
   extra-copy decision is already made; it is not a new product fork here.
3. **Custody and owner signing:** configure and test the actual P8 ownership
   issuer/pin and legitimate owner signer, including the self-custodial refusal
   or external-signing path. A verified H does not resolve the custody question.
4. **Decided activation order:** ordinary adoption is available first; then the
   human-owner binding lane is enabled. Unknown and unadopted subjects stay
   refused. The released subject-signed lane and existing account-owned stop
   controls remain unchanged. The coordinator recorded this decision on
   aweb-acmj.19 (mail `31b3bdd8-af75-494a-bd7f-708b44238218`); a legacy
   exception requires Juan's explicit approval. Neither adoption nor enforcement
   is claimed deployed by this design.
5. **Acceptance:** real consumer transaction/race tests and published artifacts
   remain required; no application migration or production activation is part
   of this branch. Genuine product forks go to the coordinator with options and
   a recommendation; none is proposed by this predicate.

## 9. Agent endpoint and email follow-on design

The [agent endpoint model](agent-channel-endpoints.md) and
[email platform profile](email-channel-profile.md) propose the 2026-10-31
follow-on: ONE human ID across teams, human-selected channel sets per agent,
message-ID reply correlation and the additive email profile. Both are design
candidates; they implement no migration or activation and do not change the
current closed platform grammar. Their one-H migration must replace per-team
actors as personal-link keys before the new endpoint model is enabled.
