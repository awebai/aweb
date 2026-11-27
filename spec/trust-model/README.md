# The trust web: a formal model

**Experimental formal model of selected aweb trust rules. Proofs are checked by Lean. Comparison against running implementations is pending.**

Five independent readings of the plain sentences against the Lean statements are worked in.

This is a formal model of who may do what in aweb: organisations, their members, teams, admins, keys, grants and invitations. It is written in Lean 4, and every result in it is proved and checked by Lean. It is licensed under this repository's licence (MIT).

**Read this before relying on anything here.**

- A row is proved only for what its statement says. Each row below states its conditions.
- Lean guarantees that the results follow from the definitions. It does not guarantee that the definitions match the real system. That has been checked by reading the source, twice, and several definitions were corrected afterwards and not yet rechecked.
- The model is not yet run against the real code. Until it is, treat it as a precise description to be tested, not as a guarantee about the software.

## How to check it yourself

Install Lean with [elan](https://github.com/leanprover/elan). In this directory run:

```
lake build
```

If it builds, every proof is correct. The toolchain is pinned to Lean 4.36.0 and no libraries are used. No proof step is left open. The proofs use only Lean's three standard axioms: `propext`, `Classical.choice` and `Quot.sound`.

## What is here

- `TrustWeb/Model.lean`: what exists, the record (`State`), the 21 acts (`Step`), and assumptions 1 to 9.
- `TrustWeb/Properties.lean`: the results below not listed under another file.
- `TrustWeb/Abilities.lean`: results 22 to 26 and 36.
- `TrustWeb/Operations.lean`: the team rule, and results 32 to 35.
- `TrustWeb/Core.lean`: an experiment: six of the acts (`CoreStep`), and five properties stated for them (`core_one` to `core_five`).
- `TrustWeb/Evidence.lean`: planned evidence of how a person was enrolled, results 38 to 40, and assumption 10.

## Who may ask a key holder

Who may ask a key holder is a parameter of the model, `AskRule`. It has three values.

- **As built** (`builtRule`): only adding a person may be asked for. A valid person of the organisation may ask, whatever the policy. Any valid member of it, agent included, may ask when its policy has a rule for adding a person that asks any person's approval; a valid person must then be among the approvals (`Approved`). A rule naming one approver does not let an agent ask. So a held key signs, through `Authorised`, only a person's registration or re-admission directly under the root (`registerByRoot`, `readmitByRoot`), and is never given back (29, `Authorised.not_dns`).
- **Planned** (`adminRule`): an admin of the organisation (`Admin`), person or agent.
- **Planned, general form** (`teamRule`): a valid member of the organisation that holds a certificate of the team the act is assigned to. The admin rule is the team rule with every act assigned to the admin team (32).

The acts with `Authorised` among their premises are the re-admission by the root, having a key given back, registering under the root, revoking by the organisation, admitting to a team, admitting an admin, removing from a team, and issuing an invitation. Two acts change team certificates without it. `leave` removes a team certificate of a team whose key is held, with no ask rule and no policy, and the member need not be registered or valid. `redeem` adds a team certificate on an unused invitation alone.

A result proved for any `AskRule` holds for all three. A row marked **Design** is proved for the planned rule; whether its statement also holds as built is not stated.

Four more parts of the model are planned and not built. They are present under every rule, so the as-built results (15, 29) are proved over acts that include them. The reasons they are not built come from the source.

- `entrust` and `release`: putting a key into a key holder and having it given back. The built holder makes its own keys and has no such commands. Under the built rule, `release` is never accepted (29, `Authorised.not_dns`).
- `KeepsAnAdmin`, a premise of `leave`, and of `remove` when the team's key is held. The registry has no such check.
- `leave`. The built command drops the member's own copy and leaves the certificate standing.
- The premise of `invite` and `redeem` that the team is not the admin team. The registry does not know which team that is.

## The model in plain words

- **An organisation** (`Org`) is a domain. Whoever controls it in DNS creates it (`createOrg`) and, once it exists, can always name a new root key (`replaceRoot`, 27). It has a root key and one key per team (`OrgKey`).
- **A member** holds an identity certificate (`Cert`) naming the organisation, the kind (person or agent) and the issuer: the root or a member. In a record the system can reach, each identity has at most one (14).
- **Who may issue whom** (`MayIssue`): a member registering under itself (`registerByParent`) may issue a person only if it is a person. The root (`registerByRoot`) issues either kind.
- **A valid person** (`Valid`, `Person`) holds a person certificate issued by the root or by a person, and is not revoked. Another identity's revocation, its issuer's included, does not change that (9).
- **A valid agent** (`Valid`) is not revoked, and its issuer is the root or is valid now.
- **Who answers** (`AnswersFor`): a valid person answers for itself, and a person answers for an unrevoked agent whose issuer it answers for. The one who answers is a valid person, and with one certificate each there is at most one (13).
- **A team certificate** (`Membership`) names a member of a team. No premise of `admit` or `redeem` asks the member to have an identity certificate or to be of the organisation; `admitAdmin` asks it to be a valid member of the organisation.
- **Acting in a team** (`InTeam`, `CanAct`) needs the team certificate and, for a key that has an identity certificate, being valid now in some organisation.
- **An admin** (`Admin`) holds a certificate of the organisation's admin team and is a valid member of that organisation, person or agent.
- **Policy** (`Rule`, `Approved`). Each rule names an organisation, a kind of act and whose approval it asks: any valid person of the organisation, or one named member valid in it. Approvals are approved for an act when they satisfy every rule for it.
- **Who can make an organisation's key sign** (`Authorised`). If no key holder holds the key, whoever controls it, with no policy. If a key holder holds it, an identity the rule lets ask, with approvals the policy approves.
- **A grant** (`Grant`). A member that can act in a team gives a grant on itself to a session key no current grant uses (`mintGrant`). While the grant stands and its subject can act in that team (`GrantLive`), whoever holds the session key can send a message attributed to the subject, if the grant may send (`sendGrant`).
- **An invitation** (`Invite`). Issuing it needs the same `Authorised` as admitting to its team (`invite`). Whoever holds its secret joins its team once, as any key it names (`redeem`). Neither is for an admin team.

**The acts (21, `Step`):** create an organisation; replace its root key from DNS; admit again an identity the replacement cut off, by the organisation or by the member that issued it; put a key in a key holder; have a key given back; register an identity under the organisation; register an identity under a member; revoke an identity, by itself, by its issuer, or by the organisation; admit a member to a team; admit an admin; remove a member from a team; leave a team; issue an invitation; use an invitation; give a grant; revoke a grant; send a message with your own key; send a message with a grant.

## What is proved

How to read these rows. Each row first gives its theorem's conditions and conclusion, in the order the theorem states them; anything after that is a reading of it, and says what the statement leaves out. **"In one act"** means the result is about a single accepted act; it is not a claim about any sequence of acts. **"In a record the system can reach"** means the result needs facts that hold after any sequence of accepted acts from a record with nothing in it but a policy (`Reachable`). **"One certificate each"** means the condition that every identity has at most one certificate, which holds in every record the system can reach (14). **Design** means the result is proved for the planned rule; whether its statement also holds as built is not stated. A row with no rule named holds under every rule.

### Identities, admins, revocation

| # | In plain words | Lean name |
|---|---|---|
| 1 | If every identity has one certificate each, no identity is valid as an agent in one organisation and as a person in any organisation | `one_kind` (with 14) |
| 2 | In one act: if after an accepted act someone holds a chain of person certificates in an organisation and did not before, the act added one certificate; it is a person certificate; and its issuer is the root, or a member that was a valid person of the certificate's organisation before the act. The statement does not say whose certificate it is, or that it is of that organisation (15 adds, as built, that it is of that organisation). It looks at certificates only, not at revocation, so admitting an identity again is not covered. It is about who signs, not who asked | `new_person_is_vouched_for` |
| 3 | If every certificate in a list is not issued by the root, and its issuer is not a person of the certificate's organisation in the record, then adding the list to the record makes nobody a person who was not one. (A person certificate of an organisation issued by a person of it does make its subject a person, by the definition of `Person`; what is checked is the rule about issuers, not the registry's admission) | `no_person_from_outside` |
| 4 | If no approver is a valid person of the organisation, the approvals do not satisfy a rule asking for any person | `agents_cannot_approve_as_person` |
| 5 | If an identity is a valid member of an organisation, of either kind, certificates lead from it to the organisation's root; the same if it is an admin. Leading means registered certificates of that organisation, each issued by the next, up to one issued by the root. It says nothing about the kinds, about revocation or about whether the issuers are valid, and nothing about a key with no identity certificate acting in a team | `valid_has_chain_to_root`, `admin_has_chain_to_root` |
| 6 | In one act: if an accepted act adds a team certificate of an admin team, the asker is whoever controls that admin team's key, or an identity the rule lets ask for admitting an admin in that organisation. So it is not an invitation's holder, in that act. Nothing is proved about several acts | `new_admin_needs_controller_or_asker` |
| 7 | If an identity is revoked, it is not valid in any organisation, of either kind. If, besides, only registered identities are revoked (true in every record the system can reach, 14), it is not an admin of any organisation, cannot act in any team, and is not among the identities that can act, which sending with its own key requires | `revoked_not_valid`, `revoked_has_no_authority`, `revoked_cannot_act` |
| 8 | If every identity has one certificate each, an agent certificate is registered, and the member that issued it is revoked, then its subject is not valid in any organisation, of either kind, and cannot act in any team. Its team certificates are not looked at | `revoking_parent_ends_agent`, `orphaned_agent_cannot_act_in_team` |
| 9 | If an identity is a valid person of an organisation, adding any other identity to the revoked leaves it a valid person of that organisation, whoever issued it. This is about the record, not about an act | `person_survives_others` |
| 10 | If the admin team's key is not with a key holder, then for any identity there is an accepted act, asked for by whoever controls that key, after which it is not an admin. If the root key is not with a key holder and an identity is an admin, there is an accepted act, asked for by whoever controls the root key, after which it is not an admin. The asker is the key's controller alone | `controller_can_remove_admin`, `root_can_end_admin` |
| 11 | Design: if the admin team's key is with a key holder, an identity is an admin, some approvals satisfy the policy for a removal, and another identity is given, there is an accepted act under the admin rule, asked for by the admin, after which the other is not an admin. If the policy has a rule for a removal in that organisation naming the other as its approver, those approvals include its own | `admin_can_remove_admin` |
| 11a | A planned check, present under every rule, in one act: if the admin team's key is with a key holder, and an identity holds an admin-team certificate before an accepted act and not after, then some other identity is an admin after it. This is about a team certificate going. A revocation can still leave an organisation with no admin: of the admin, of a member above it, or by a root replacement | `key_holder_keeps_an_admin` |
| 12 | If no rule of the policy is for an organisation, every kind of act is approved for it with no approvals | `no_policy_no_approval` |
| 13 | If a person answers for a member, that person is a valid person of the member's organisation. If every identity has one certificate each and two persons answer for the same member, they are the same | `answerer_is_valid_person`, `answerer_unique` |
| 14 | In every record the system can reach, under any rule: two certificates for the same identity are the same certificate; every revoked identity has a certificate; and two team certificates of the same identity with no certificate are the same | `Reachable.oneCertEach`, `Reachable.revokedAreRegistered`, `Reachable.localInOneTeam` |
| 15 | As built, in one act: if after an accepted act someone holds a chain of person certificates in an organisation and did not before, the act added one person certificate of that organisation, and one of three things holds. Whoever controls its root key asked directly, the key not being with a key holder. Or a valid person of the organisation asked. Or the root key is with a key holder, a valid member of the organisation asked, and approvals exist that satisfy its policy for adding a person and include a valid person of it. The model does not record which approvals an act carried; the act is accepted only with such approvals | `built_person_needs_a_person` |
| 16 | Design: there is a record the system can reach under the admin rule, and an agent valid in an organisation, such that an act the agent asks for is accepted, and afterwards someone holds a chain of person certificates in that organisation who did not before. (In the construction the agent is an admin, the root key is with a key holder, and the root is the new certificate's issuer, so 2 holds.) As built, the built rule also lets an agent ask, where the policy has a rule asking any person's approval for adding a person (`builtRule`); that is not stated as a theorem here | `design_agent_admin_can_ask_for_person` |

### Grants and invitations

| # | In plain words | Lean name |
|---|---|---|
| 17 | In one act: if an act asked for by whoever holds a session key is accepted, there is a grant with that session key that is live and may send, and the record after the act is the record before with one message attributed to the grant's subject added | `session_only_sends` |
| 18 | In one act: if an accepted act changes the messages, it added one message, and either its sender asked as an identity and can act, or the asker holds the session key of a grant on its sender that is live and may send. This covers every message an act adds, not only the first attributed to an identity | `message_from_owner_or_live_grant` |
| 19 | In one act: if an accepted act adds a grant, its subject asked, as an identity | `new_grant_by_subject` |
| 20 | If only registered identities are revoked (true in every record the system can reach, 14), and a grant's subject is revoked or lacks the team certificate the grant came from, the grant is not live. In one act: if an identity holds a team certificate before an accepted act and not after, no grant on it from that team remains after it | `grant_ends_with_subject`, `grant_ends_with_its_certificate` |
| 21 | In one act: if an act asked for by whoever holds an invitation's secret is accepted, the identity certificates, revocations, grants and held keys are as before, and each team certificate it adds is not of an admin team and is for the organisation and team of an unused invitation with that secret. The joiner is whatever key the holder names; that the joiner holds that key is assumed (3) | `bearer_only_joins` |

### DNS, and leaving a key holder

| # | In plain words | Lean name |
|---|---|---|
| 27 | If an organisation exists, there is an accepted act asked for by its domain's owner after which its root key is not with a key holder and no identity is valid in it, of either kind. (The act is the root replacement, whose only premise is that the organisation exists) | `dns_owner_can_always_take_over` |
| 28 | In one act: if a key is with a key holder before an accepted act and not after, the asker is the domain's owner of the key's organisation, or an identity the rule lets ask for giving a key back. When it is the domain's owner, the key is the organisation's root key and no identity of it is valid after the act (37): the holder no longer holds the current root key. Neither the model nor the protocol shows that the holder no longer has the former private key | `key_leaves_holder_only_two_ways` |
| 29 | As built, in one act: under the same conditions, the asker is the domain's owner of the key's organisation | `built_key_leaves_only_by_dns` |
| 30 | Design: if a key is with a key holder, an identity is an admin of the key's organisation, and some approvals satisfy its policy for giving a key back, there is an accepted act under the admin rule, asked for by the admin, after which the key is not with a key holder and the identity certificates, revocations and team certificates are as before | `organisation_can_take_key_back` |
| 31 | If a certificate issued by the root is registered, its subject is cut off by a root replacement, and the root key is not with a key holder, there is an accepted act, asked for by whoever controls the root key, after which the subject is valid in the certificate's organisation, with the certificate's kind | `replaced_organisation_can_readmit` |
| 37 | In one act: if an act asked for by an organisation's domain owner is accepted, and a key is with a key holder before it and not after, the key is that organisation's root key and no identity is valid in it after the act | `dns_takes_out_only_the_root` |

### Each operation belongs to a team

| # | In plain words | Lean name |
|---|---|---|
| 32 | The admin rule is the team rule with every operation of every organisation assigned to the admin team | `adminRule_is_teamRule` |
| 33 | Any assignment: if a key is with a key holder, an identity holds a certificate of the team that giving a key back is assigned to and is valid in the key's organisation, and some approvals satisfy its policy for giving a key back, there is an accepted act under the team rule, asked for by that identity, after which the key is not with a key holder and the identity certificates, revocations and team certificates are as before | `assigned_team_can_take_key_back` |
| 34 | Any assignment, in one act: if a key is with a key holder before an accepted act under the team rule and not after, the asker is the domain's owner of the key's organisation, or an identity that holds a certificate of the assigned team and is valid in that organisation | `only_assigned_team_takes_key_back` |
| 35 | **A warning.** Under a team rule: there is an assignment and three records such that: in the first, an identity holds no team certificate of an organisation and the organisation's root key is with a key holder; an act asked for by the holder of an invitation's secret takes the first record to the second; an act the identity asks for takes the second to the third; and in the third the root key is not with a key holder. (In the construction, giving the root key back is assigned to a named team and the invitation is to that team) | `invitation_reaches_an_assigned_team` |

The protections of the admin team are premises that name it: `admitAdmin` admits only a valid member of the organisation, and `admit`, `invite` and `redeem` exclude it. Under a team rule an act can be assigned to a team they do not name; 35 shows it for giving a key back.

## What must be possible

Two of these rows are limits: the first half of 23, and 25.

| # | In plain words | Lean name |
|---|---|---|
| 22 | Any rule: there is a record the system can reach in which no key is with a key holder; one identity is a valid person of an organisation and two are valid agents of it; the person answers for both agents; and a valid agent of another organisation can act in a named team of the first and is not valid in it. (In the construction the person issues one agent and that agent issues the other, each with its own key; the statement does not say who issued whom) | `runs_without_key_holder` |
| 23 | If an organisation's policy has a rule asking for any person's approval of a kind of act, and no approver is a valid person of it, the approvals are not approved for that act. If an identity is a valid person of an organisation and every rule of it for a kind of act asks for any person, that one identity's approval is approved | `policy_requires_person`, `person_approval_satisfies` |
| 24 | Design: there is a record the system can reach under the admin rule in which nobody is a person of an organisation, and an agent is an admin and a valid agent of it; an act the agent asks for is accepted, after which an identity holds a certificate of a named team of the organisation that it did not hold before | `agent_only_org_runs` |
| 25 | Design, in one act: if the admin team's key is with a key holder, the organisation has no admin, and an accepted act under the admin rule adds a team certificate of an admin team, that certificate is not of this organisation. A re-admission leaves the team certificates as they are (`readmitByRoot`, `readmitByParent`), so it is not covered. Over three acts an admin-team certificate of the organisation can be added (36) | `locked_without_admin` |
| 26 | Design: if a named team's key is with a key holder, an identity is an admin, another is a valid person, a third is registered or holds no team certificate, and every rule for admitting asks for any person, there is an accepted act under the admin rule, asked for by the admin, after which the third holds a certificate of that team | `approved_act_goes_through` |
| 36 | Design: there is a record the system can reach under the admin rule in which the admin team's key is with a key holder and the organisation has no admin; from it two acts asked for by whoever controls the root key and then one act asked for by an identity are accepted, and afterwards another identity holds an admin-team certificate it did not hold in that record. (In the construction a root replacement cut off two agents, the new root admits both again, and the one that still holds its admin-team certificate is an admin again and has the other admitted) | `locked_organisation_unlocks_by_readmission` |

Not stated, because the model has no words for it: an agent whose key a hosting service holds (assumption 7); a person who belongs to several organisations (one certificate each, 14); moving an agent to another parent (a certificate is never removed, `certificate_is_permanent`); an organisation changing its domain (an organisation is its domain, `Org`).

## Evidence of how a person was enrolled (planned)

A planned outcome of the protocol, `controller_asserted_person` (`docs/id-certificates.md`): a verified person, whoever issued its certificate, has enrolment evidence from its own domain's authorised controller, in an assertion bound to that exact enrolment. In the model the evidence is a list of assertions outside the record (`State` has no field for it; assumption 10), so no act and no verdict depends on it. Registering a person directly under the root is one act, `registerByRoot`, whether the controller or a hosted service holds the root key, and `Cert` has no field for how the person was enrolled.

| # | In plain words | Lean name |
|---|---|---|
| 38 | If an identity is a valid person of an organisation, then in that same record: with only the controller's assertion, bound to that enrolment, it is a controller-asserted person and not email-enrolled; with only the hosted service's email assertion it is email-enrolled and not a controller-asserted person; with no assertion its enrolment is unspecified and it is neither. A valid person answering for itself (the shared verdict's `nearest_human`) thus says nothing about an email check | `enrolment_evidence_is_beside_the_chain` |
| 39 | If an identity is a controller-asserted person, it answers for itself | `controller_asserted_person_answers_for_itself` |
| 40 | Under any rule there is a record the system can reach with a valid person for which the three cases of 38 hold | `enrolment_case_is_reachable` |

## What must never happen

| What must never happen | Where it stands |
|---|---|
| An agent passes as a person | Proved: 1 for records with one certificate each, 2 for one act, 3 for added certificates, 4 for every approval |
| Someone has authority with no chain back to a root | **Not true of what is built.** Proved for valid members and admins (5). A key with no identity certificate can act in a team on its team certificate alone (`InTeam`, `CanAct`), and so give a grant (`mintGrant`); in a team or not, it can send a message attributed to itself (`sendOwn`); and it can leave a team whose key is held (`leave`). That the root authorises a team's key is not in the model. The three rules require a valid member to ask a key holder (`builtRule`, `adminRule`, `teamRule`); a rule that let anyone ask would not |
| A revoked member keeps authority | Proved in records the system can reach (7, 8, 20): it is not valid, not an admin, cannot act in a team, cannot send with its own key, and no grant on it is live. The three rules require a valid member to ask a key holder; a rule that let anyone ask would not. Under every rule a revoked identity can still revoke a grant on itself (`revokeGrant`), revoke itself again (`revokeSelf`), leave a team whose key is held (`leave`), and be the key an invitation's holder names (`redeem`) |
| A revocation is undone | Proved for one act: `revocation_is_permanent`. Not proved for several acts. An identity cut off by a root replacement is different: it can be admitted again (31) |
| An identity changes organisation or kind | Proved for one act that no certificate is removed (`certificate_is_permanent`), and in records the system can reach an identity has one certificate (14). Not proved for several acts |
| Controlling one organisation's key changes something in another organisation | Proved for one act, for new identity certificates, new and removed team certificates, and new revocations: `controller_stays_in_its_organisation`. Not stated for invitations, grants, held keys or re-admissions. Revoking an identity ends what it could do in any organisation's teams, in records the system can reach (7) |
| A message is attributed to someone who did not send it and gave no grant | Proved for one act, for every message the act adds: 18. That its subject gave the grant used is proved for the act that adds a grant (19), not for every grant in a record |
| A grant holder does more than send | Proved for one act: 17, its act adds one message and changes nothing else; 19, only the subject gives a grant |
| An invitation's holder becomes a person or an admin | Proved for one act: 21, 6. Not proved for several acts. Under a rule that assigns admitting admins to a named team, an invitation to that team could lead to an admin over several acts; 35 shows that route for another operation, and it is not proved for this one |
| An agent approves where a person is required | Proved for every approval: 4, 23 |
| Being issued an identity gives team membership | Proved for one act: `registering_gives_no_team` |
| A key with no identity certificate is in two teams | Proved in records the system can reach: 14. In the real system it holds on the supported journey; the registry's own route does not enforce it |
| A key leaves its holder except by the domain's owner or an allowed request | Proved for one act: 28 |
| A key holder removes the last admin's team certificate | A planned check, proved for one act: 11a. Whoever controls the team's key directly can still remove anyone (10), and any revocation (of the last admin, of a member above it, or by a root replacement) can still leave no admin |
| An outsider is an admin | True by the definition of an admin (`Admin`) |
| A certificate for one team is accepted for another | True by the definition of a team certificate (`HasTeamCert`) |
| An approval is used for another act, or twice | Assumed (6) |
| A key holder uses a key other than the acts allow, hands it to an admin, or exports it | Assumed (8). Cannot be proved while the holder is assumed honest |
| Whoever holds a member's own key for it speaks as it | Not in the model: nobody holds a member's key in it (7) |
| An identity is re-signed or re-issued as a side effect | Not in the model: it has no key rotation |

## What is assumed

1. **Signatures.** A signature cannot be forged.
2. **Enrolment.** The root issues a person certificate only to a human being who took part themselves.
3. **The subject's key.** Whoever is registered, or joins a team, proved they hold the key.
4. **One current record.** Everyone sees the same record at once. The real system does not: a server caches a team's revocations for 60 seconds, and serves the cached list for 60 seconds more while it refreshes (`docs/aweb-sot.md`, "Caching from awid"). In that window a removed member can still give a grant, and a grant it gave still works.
5. **One act at a time.** Each act happens whole, and acts do not overlap.
6. **Approvals.** An approval comes from the identity it names, for the exact act, and cannot be reused.
7. **Keys.** An identity keeps one key and only its owner uses it.
8. **The key holder.** A key holder uses an organisation's key only as the acts say (`Step`). Nobody outside can check this.
9. **The server.** The server that keeps the grants attributes a message to an identity only as the acts say. Only that server can check a grant.
10. **Enrolment assertions** (planned, `Evidence.lean`). An assertion about how a person was enrolled was signed by the party it names (for the controller, the domain's authorised controller), and is bound to that exact enrolment.

## Where the model does less than the real system

Each item says what the real system does that the model leaves out.

- **Time.** Nothing here is about freshness, crashes, retries or two changes at once (5).
- **Replacing a root key** (`replaceRoot`) cuts off every identity of the organisation at once. Really the cut-off is by time of registration, and a root can also set a backdated cut-off. A rotation signed by both the old and the new root key, which keeps every registration, is not modelled, nor a parent recovering a delegated child organisation.
- **Admitting an identity again** (`readmitByRoot`, `readmitByParent`) puts the same certificate back in force, and only its original issuer can do it. Really it is a new signed certificate for the same identity and key, and the new root can admit anyone it keeps.
- **A key leaves a key holder whole** (`release`). Really the organisation makes a new key and the old and new keys both sign the change.
- **One certificate per identity** (14). Really an identity's organisation and kind are fixed, but it can be moved to another parent.
- **Team keys just exist** (`OrgKey`). Creating, deleting and rotating teams is not modelled, nor the root replacing a team's key: a root replacement leaves the team keys with whoever controlled them (`replaceRoot` takes only the root key out of the key holder).
- **`controller key` is whoever controls that key now** (`Party`). After a root replacement that is whoever controls the new root key. The model cannot name whoever held the old one.
- **The key holder's operator** is not modelled. Whoever controls a key asks directly only while no key holder holds it (`Authorised`). Really the operator acts through the holder's named commands, which are narrower.
- **Policy is given** (`State.policy`), and is checked only when a key holder holds the key (`Authorised`). Who may change it is not modelled. Really servers and applications enforce approval for what they own.
- **A team certificate is one record** (`Membership`). Really the registry revokes a certificate by its id and tells a missing one from a revoked one.
- **A grant can send or not** (`Grant.maySend`). Really it has ten scopes and may expire.
- **Sending with your own key** (`sendOwn`) stands for a send the server accepted. Really it checks that the key is current, the identity valid, and the recipient's rules.
- **An invitation is used once, for one team** (`redeem`). Really it may allow several uses, expire, and name the person its joiner must answer to. A secret is new only among unused invitations (`invite`), and a session key only among current grants (`mintGrant`).
- **"Has an identity certificate"** (`Registered`) is one thing here and three in reality: a local key with no public identity, a public identity with a registered key, and enrolment in the identity tree.
- **Messages go nowhere** (`Message`). The record keeps only who each is attributed to.
- **No answer to "who answers"** (`AnswersFor`) covers both "nobody" and "cannot be established". The protocol tells them apart.
- **Team certificates and invitations need no organisation to exist.** No premise of `admit`, `redeem` or `invite` asks for it.
- **Nobody holds a member's own key for it** (7). A hosting service that holds a person's or an agent's key is not in the model.

## Working on the model

Change a definition, build, and Lean lists the results that no longer hold.

- **Change what a definition says, not its shape.** Making a rule always true leaves every proof's wording valid, so each failure is a proof that used the fact. Removing a premise from an act breaks every proof that lists that act's premises, and most of those errors mean nothing.
- **Read the error.** "Too many variable names", "alternative is not needed" or a wrong number of arguments is a proof naming something that moved. An error that shows a goal Lean could not close is a proof that needed the fact.
- **A result is shown false only by an example.** Write the record in which it fails, as `design_agent_admin_can_ask_for_person` does. Until then it is unproved, not false.
- **Write each row from the theorem's statement, conditions first, and only then make it readable.** Give every other sentence the definition or result that makes it true, or leave it out.

## Not done

- **It does not run yet.** Comparing it with the code needs checker functions proved equal to these definitions, and test cases produced from them.
- **Several definitions were corrected after the last check against the source** and need checking again: the as-built rule for adding a person, root replacement, grants ending with their certificate, the condition for sending, invitations, and the last-admin rule.
