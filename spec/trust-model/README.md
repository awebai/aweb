# The trust web: a formal model

**Experimental formal model of selected aweb trust rules. Proofs are checked by Lean. Comparison against running implementations is pending.**

One independent reading of the plain sentences against the Lean statements is worked in; a second is under way.

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

- `TrustWeb/Model.lean`: what exists, the current record, and the acts that change it.
- `TrustWeb/Properties.lean`: the results. Each has its plain reading above it.
- `TrustWeb/Abilities.lean`: what must be possible, shown by records the system reaches.
- `TrustWeb/Operations.lean`: each operation belongs to a team, the general form of the admin rule.
- `TrustWeb/Core.lean`: an experiment: the fewest acts that still carry five chosen properties.

## What is built and what is planned

The model describes aweb as built, with one exception: **who may ask a key holder to sign**. That is left as a blank the model is given, with three fillings.

- **As built** (`builtRule`): the self-hosted key holder adds a person in two cases. With no approval configured, a valid person of the organisation asks. With a person's approval configured for it, any valid member asks, agent included, and a person approves. Its operator runs everything else.
- **Planned** (`adminRule`): an admin of the organisation asks, person or agent.
- **Planned, general form** (`teamRule`): each kind of operation is assigned to one of the organisation's teams. The admin rule is the case where every operation is assigned to the admin team.

A result proved with the blank open holds for all three, and for any rule chosen later. A row marked **Design** holds for the planned rule only.

Four more things in the model are planned and not built. They are present under every rule, the as-built one included, so the as-built results (15, 29) are proved over acts that include them: putting a key into a key holder and having it given back (the built holder makes its own keys and has no such commands); a key holder refusing to remove the last admin (the registry has no such check); a member leaving a team by asking a key holder (the built command drops the member's own copy and leaves the certificate standing); and invitations never leading into the admin team (the registry does not know which team that is).

## The model in plain words

- **An organisation** is a domain. Whoever controls the domain in DNS names its root key, and can always name a new one. That is the root of trust. It also has one key per team.
- **A member** is a person or an agent, with a key and one identity certificate. The certificate names the organisation, the kind and the issuer: the root, or another member.
- **Who may issue whom.** The root issues either kind. A person issues people and agents. An agent issues only agents.
- **A valid person** holds a person certificate issued by the root or by a person, and is not revoked.
- **A valid agent** is not revoked, and its issuer is the root or is valid now.
- **Who answers for an agent** is the nearest person up its chain. An agent that reaches the root through agents only has nobody.
- **A team certificate** names a member of a team. The member can be from another organisation, or a key with no identity certificate at all.
- **Acting in a team** needs the team certificate and, for a key that has an identity certificate, being valid now.
- **An admin** holds a certificate of the organisation's admin team and is a valid member of that organisation, person or agent.
- **Policy.** Each organisation lists which kinds of act need approval, and whose: any person, or one named member.
- **Who signs.** The root key signs identity certificates and revocations. A team's key signs that team's certificates. A member's own key signs for the identities it creates and revokes.
- **Who can make an organisation's key sign.** If nobody holds the key for the organisation, whoever controls it, directly and with no policy. If a key holder holds it, whoever the rule lets ask, with the approvals the policy names.
- **A grant.** A team member lets a fresh session key act as it, on one server. Whoever holds that key can send messages as the member. Only that server can check the grant.
- **An invitation.** A secret. Whoever holds it joins the team it names, once. Issuing it needs the same authority as admitting a member.

**The acts (21):** create an organisation; replace its root key from DNS; admit again an identity the replacement cut off, by the organisation or by the member that issued it; put a key in a key holder; have a key given back; register an identity under the organisation; register an identity under a member; revoke an identity, by itself, by its issuer, or by the organisation; admit a member to a team; admit an admin; remove a member from a team; leave a team; issue an invitation; use an invitation; give a grant; revoke a grant; send a message with your own key; send a message with a grant.

## What is proved

How to read these rows. Each row says what its theorem says, with its conditions. **"In one act"** means the result is about a single accepted act; it is not a claim about any sequence of acts. **"In a record the system can reach"** means the result needs facts that hold after any sequence of accepted acts from an empty record. **Design** means the result is about the planned rule, not about what is built.

### Identities, admins, revocation

| # | In plain words | Lean name |
|---|---|---|
| 1 | In a record the system can reach, nobody is valid as an agent and as a person | `one_kind` (with 14) |
| 2 | In one act: if someone holds a chain of person certificates after the act and did not before, then the act registered a person certificate whose issuer is the root or a member who is a valid person, never an agent. The statement does not say whose certificate it is. It is about who signs, not who asked (see 16). It looks at certificates only, not at revocation, and does not cover an identity being admitted again | `new_person_is_vouched_for` |
| 3 | Add to the record any certificates that are neither issued by the root nor issued by someone already a person: nobody becomes a person. (A certificate issued by a person does make one; the rule about issuers is what is checked, not the registry's admission) | `no_person_from_outside` |
| 4 | If none of the approvers is a valid person, a rule that asks for a person's approval is not satisfied | `agents_cannot_approve_as_person` |
| 5 | Every valid member, and every admin, has certificates leading from it to its organisation's root. This says the certificates exist. It says nothing about whether the issuers are valid or revoked, and nothing about a key with no identity certificate acting in a team | `valid_has_chain_to_root`, `admin_has_chain_to_root` |
| 6 | In one act: an admin-team certificate is added only when whoever controls the admin team's key asks directly, or someone the rule lets ask does. An invitation does not add one in that act. Nothing is proved about several acts | `new_admin_needs_controller_or_asker` |
| 7 | A revoked identity is not valid. In a record the system can reach it is also not an admin, cannot act in any team, and is not among the identities that can act, which sending with its own key requires | `revoked_not_valid`, `revoked_has_no_authority`, `revoked_cannot_act` |
| 8 | In a record the system can reach: if the member that issued an agent is revoked, the agent is not valid and cannot act in any team, though its team certificates still stand | `revoking_parent_ends_agent`, `orphaned_agent_cannot_act_in_team` |
| 9 | A valid person stays valid when any other identity is revoked, their inviter included | `person_survives_others` |
| 10 | When the admin team's key is not with a key holder, whoever controls it can remove any admin's team certificate, with nobody's cooperation and no approval. When the root key is not with a key holder, whoever controls it can end any admin by revoking that admin's identity | `controller_can_remove_admin`, `root_can_end_admin` |
| 11 | Design: when the admin team's key is with a key holder, an admin can have any other admin's team certificate removed, with the approvals the policy names for a removal. If the policy names the removed admin as an approver, that admin's approval is among them | `admin_can_remove_admin` |
| 11a | Design, in one act: when the admin team's key is with a key holder and an admin's team certificate goes, another admin remains afterwards. This is about team certificates only. An organisation can still be left with no admin by a revocation: of the admin, of a member above it, or by a root replacement | `key_holder_keeps_an_admin` |
| 12 | If an organisation's policy has no rule, every kind of act is approved with no approvals | `no_policy_no_approval` |
| 13 | Whoever answers for a member is a valid person. In a record the system can reach there is at most one | `answerer_is_valid_person`, `answerer_unique` |
| 14 | In every record the system can reach, an identity has one certificate, only registered identities are revoked, and an unregistered identity is in at most one team | `Reachable.oneCertEach`, `Reachable.revokedAreRegistered`, `Reachable.localInOneTeam` |
| 15 | As built, in one act: if someone holds a chain of person certificates after the act and did not before, then whoever controls some organisation key asked directly, or a valid person exists in some organisation. **Under review:** the statement is weaker than intended. It does not say that the person asked or approved, or is of the same organisation | `built_person_needs_a_person` |
| 16 | Design: there is a record in which an agent admin asks the key holder and a person is registered. The root key is the issuer, so 2 holds. (An independent reader showed the record can be reached) | `design_agent_admin_can_ask_for_person` |

### Grants and invitations

| # | In plain words | Lean name |
|---|---|---|
| 17 | In one act, whoever holds a grant's session key changes no identity certificate, revocation, team certificate, grant, held key or invitation | `session_only_sends` |
| 18 | In one act: a new message is attributed to an identity only if that identity asked and can act, or a grant on it that is live and may send was used | `message_from_owner_or_live_grant` |
| 19 | In one act: a new grant on an identity appears only when that identity asks | `new_grant_by_subject` |
| 20 | In a record the system can reach, a grant is not live while its subject is revoked. In any record, it is not live while its subject lacks the team certificate it came from. In one act: when a team certificate goes, no grant from it remains | `grant_ends_with_subject`, `grant_ends_with_its_certificate` |
| 21 | In one act, whoever holds an invitation's secret changes no identity certificate, revocation, grant or held key. The only new team certificate is for the organisation and team of an invitation carrying that secret, and never for an admin team. The joiner is whatever key the holder names; that it holds that key is assumed (assumption 3) | `bearer_only_joins` |

### DNS, and leaving a key holder

| # | In plain words | Lean name |
|---|---|---|
| 27 | For an organisation that exists, the domain's owner can always replace the root; no premise can refuse it. Afterwards no identity of the organisation is valid and the root key is not with a key holder | `dns_owner_can_always_take_over` |
| 28 | In one act: a key leaves its holder only if the domain's owner asked, or an identity the rule lets ask had it given back | `key_leaves_holder_only_two_ways` |
| 29 | As built, in one act: a key leaves its holder only if the domain's owner asked | `built_key_leaves_only_by_dns` |
| 30 | Design: when a key is with a key holder, an admin with the approvals the policy names can have it given back. No identity certificate, revocation or team certificate changes | `organisation_can_take_key_back` |
| 31 | When the root key is not with a key holder, whoever controls it can admit again an identity that was issued by the root and cut off by a replacement. It is valid again with the same key, kind and organisation | `replaced_organisation_can_readmit` |

As built, a key leaves its holder only when the domain's owner replaces the root (29), which cuts off every identity of the organisation (27). The planned design adds a way that changes nothing else (30). In the real protocol the first already has a gentler form that the model does not have: a rotation signed by both the old root key and the new one, which keeps every registration.

### Each operation belongs to a team

| # | In plain words | Lean name |
|---|---|---|
| 32 | The admin rule is this rule with every operation assigned to the admin team | `adminRule_is_teamRule` |
| 33 | Whatever the assignment: when a key is with a key holder, a valid member holding a certificate of the team that giving it back is assigned to can have it given back, with the approvals the policy names. No identity certificate, revocation or team certificate changes | `assigned_team_can_take_key_back` |
| 34 | Whatever the assignment, in one act: a key leaves its holder only by the domain's owner, or at the request of a valid member holding a certificate of the assigned team | `only_assigned_team_takes_key_back` |
| 35 | **A warning.** There is a record in which taking the root key back is assigned to a named team, an agent in no team uses an invitation to that team, and then has the root key given back. The admin team is protected against this; a named team is not | `invitation_reaches_an_assigned_team` |

Result 35 is a warning the model gives about the planned general form, shown for one operation (having a key given back). The protections of the admin team (explicit admission only, members of the organisation only, no invitations) have to apply to every team that an operation is assigned to, not to the admin team by name.

## What must be possible

| # | In plain words | Lean name |
|---|---|---|
| 22 | An organisation runs with no key holder and no hosted service. A person makes an agent, that agent makes an agent, nobody is asked, and the person answers for both. An agent of another organisation joins a team, stays a member of its own organisation, and is not a member of this one | `runs_without_key_holder` |
| 23 | Where a policy rule asks for a person's approval of a kind of act, approvals none of which is a valid person's do not satisfy the policy. Where every rule for that kind of act asks for a person, one valid person's approval satisfies it | `policy_requires_person`, `person_approval_satisfies` |
| 24 | Design: an organisation with no person can run. An agent is its admin and, alone and with no approval, admits a member to a team | `agent_only_org_runs` |
| 25 | Design, in one act: where the admin team's key is with a key holder and the organisation has no admin, no act adds an admin-team certificate. Nothing is proved about several acts | `locked_without_admin` |
| 26 | Design: where a named team's key is with a key holder and every rule for admitting asks for a person, an admin with one valid person's approval admits a member who is registered or in no other team | `approved_act_goes_through` |

Not shown, because the model cannot say it: an agent whose key a hosting service holds; a person who belongs to several organisations and acts as one identity at a time; moving an agent to another parent; an organisation changing its domain.

## What must never happen

| What must never happen | Where it stands |
|---|---|
| An agent passes as a person | Proved: 1 to 4 |
| Someone has authority with no chain back to a root | **Not true of what is built.** Proved for valid members and admins (5). A key with no identity certificate acts in a team, and can give a grant, on its team certificate alone. Its authority is that certificate, signed with the team's key; that the root authorises a team's key is not in the model. The planned design gives every agent its creator's certificate and has a team ask for it at admission; that is not yet in the model |
| A revoked member keeps authority | Proved in records the system can reach: 7, 8, 20, in the sense that it is not valid, not an admin, cannot act in a team and cannot send. Whether it can ask a key holder depends on the rule: the three rules here require a valid member; a rule that let anyone ask would not. A revoked identity can still revoke its own grants and, where the planned leave exists, leave a team |
| A revocation is undone | Proved for one act: `revocation_is_permanent`. An identity cut off by a root replacement is different: it can be admitted again |
| An identity changes organisation or kind | Proved: no act removes an identity certificate (`certificate_is_permanent`, for one act), and in records the system can reach an identity has one certificate (14) |
| Controlling one organisation's key changes something in another organisation | Proved for one act, for new identity certificates, new and removed team certificates, and new revocations: `controller_stays_in_its_organisation`. Not stated for invitations, grants, held keys or re-admissions. Revoking an identity does end what it could do in another organisation's teams |
| A message is attributed to someone who did not send it and gave no grant | Proved for one act: 18 |
| A grant holder does more than send | Proved for one act: 17, 19 |
| An invitation's holder becomes a person or an admin | Proved for one act: 21. Not proved for several acts. Under a rule that assigns admitting admins to a named team, an invitation to that team can lead to an admin in two acts; 35 shows the same route for another operation |
| An agent approves where a person is required | Proved: 4, 23 |
| Being issued an identity gives team membership | Proved for one act: `registering_gives_no_team` |
| A key with no identity certificate is in two teams | Proved in records the system can reach: 14. True on the supported journey; the registry's own route does not enforce it |
| A key leaves its holder except by the domain's owner or an allowed request | Proved for one act: 28 |
| A key holder removes the last admin's team certificate | Design, proved for one act: 11a. Whoever controls the team's key directly can still remove anyone, and the last admin can still revoke its own identity |
| An outsider is an admin | True by the definition of an admin |
| A certificate for one team is accepted for another | True by the definition of a team certificate |
| An approval is used for another act, or twice | Assumed (6) |
| A key holder signs outside its rule, hands a key to an admin, or exports it | Assumed (8). Cannot be proved while the holder is assumed honest |
| Whoever holds a member's own key for it speaks as it | Not in the model: nobody holds a member's key in it |
| An identity is re-signed or re-issued as a side effect | Not in the model: it has no key rotation |

## What is assumed

1. **Signatures.** A signature cannot be forged.
2. **Enrolment.** The root issues a person certificate only to a human being who took part themselves.
3. **The subject's key.** Whoever is registered, or joins a team, proved they hold the key.
4. **One current record.** Everyone sees the same record at once. The real system lets a verifier go on accepting for a bounded time after a revocation.
5. **One act at a time.** No crashes, retries or overlapping changes.
6. **Approvals.** An approval comes from the identity it names, for the exact act, and cannot be reused.
7. **Keys.** An identity keeps one key and only its owner uses it.
8. **The key holder.** A key holder uses an organisation's key only as the model says. Nobody outside can check this.
9. **The server.** The server that keeps the grants attributes a message to an identity only as the model says. Only that server can check a grant.

## Where the model does less than the real system

- **Time.** Nothing here is about freshness, two changes at once, or retries. The hard bugs of a real system live there.
- **Replacing a root key cuts off every identity at once.** Really the cut-off is by time of registration, and a root can also set a backdated cut-off. A rotation signed by both the old and the new root key, which keeps everything, is not modelled.
- **Admitting an identity again** is, really, a new signed certificate for the same identity and key. Here the same certificate stands again, and only its original issuer can admit it; really the new root can admit anyone it keeps.
- **One certificate per identity.** Really an identity's organisation and kind are fixed, but it can be moved to another parent.
- **Team keys just exist.** Creating, deleting and rotating teams is not modelled, nor the root replacing a team's key. So after a root replacement, whoever controlled a team key still does.
- **`controller key` means whoever controls that key now.** After a root replacement that is whoever controls the new root key. The model cannot name whoever held the old one.
- **The key holder's operator** is modelled as whoever controls the key directly. Really the operator has narrower, named commands.
- **Policy is given, and applies only at the key holder.** Who may change it is not modelled. Really servers and applications enforce approval for what they own.
- **A grant can send or not.** Really it has ten scopes and may expire. The model claims only that a grant never gives control of identities, keys, teams or grants.
- **An invitation is used once.** Really it may allow several uses, expire, and name the person its joiner must answer to. A secret is new only among unused invitations, and a grant's session key only among current grants.
- **"Has an identity certificate" is one thing here and three in reality:** a local key with no public identity, a public identity with a registered key, and enrolment in the identity tree.
- **Messages go nowhere.** The record keeps only who each is attributed to.
- **No answer to "who answers"** covers both "nobody" and "cannot be established". The protocol tells them apart.
- **Team certificates and invitations can exist for an organisation that was never created.** Nothing checks it.
- **Nobody holds a member's own key for it.** A hosting service that holds a person's or an agent's key is not in the model.

## Working on the model

Change a definition, build, and Lean lists the results that no longer hold.

- **Change what a definition says, not its shape.** Making a rule always true leaves every proof's wording valid, so each failure is a proof that used the fact. Removing a premise from an act breaks every proof that lists that act's premises, and most of those errors mean nothing.
- **Read the error.** "Too many variable names", "alternative is not needed" or a wrong number of arguments is a proof naming something that moved. An error that shows a goal Lean could not close is a proof that needed the fact.
- **A result is shown false only by an example.** Write the record in which it fails, as `design_agent_admin_can_ask_for_person` does. Until then it is unproved, not false.
- **Write each plain sentence from the theorem's statement, conditions first.** In the first independent reading every one of 21 findings was a sentence that claimed more than its theorem. No proof was wrong.

## Not done

- **It does not run yet.** Comparing it with the code needs checker functions proved equal to these definitions, and test cases produced from them.
- **A second independent reading** of the sentences against the statements is under way.
- **Several definitions were corrected after the last check against the source** and need checking again: the as-built rule for adding a person, root replacement, grants ending with their certificate, the condition for sending, invitations, and the last-admin rule.
