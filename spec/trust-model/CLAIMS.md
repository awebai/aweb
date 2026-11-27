# Claims ledger

One line for every sentence that says something about the model, apart from a theorem's own restatement. That covers the README's prose, every cell of "What must never happen", every reading inside a result row, every module, definition, field and constructor doc comment, and every reading inside a theorem's doc comment. Each line gives where the sentence is, the sentence in short, and what makes it true.

- **Restatements.** A row of the README's result tables, and a theorem's doc comment, first restate the theorem's statement. A restatement is checked against the statement and is not listed here. What follows it in the row or the doc comment is listed: a reading, with what makes it true, or a construction note ("In the construction ..."), which describes the proof's witnesses.
- **Names.** The build's name check, as the README's "How to check it yourself" describes it, reads this file too.
- **Kinds of line.**
  - A *definition* or *act* line names the definition or `Step` constructor that the sentence reads off.
  - A *result* line names the theorem or row.
  - A *source* line is about the real system or the protocol, not the model, and names where it was read.
  - A *process* line is about how the model was made or is checked.
  - An *assumption* line is taken as given, not proved.
  - A *construction* line is a construction note: it describes the witnesses a proof uses, which the statement does not fix.

A sentence about the model that is not on this list should not be in the README or in a doc comment.

## README.md

### Header and "Read this"

| Sentence | Kind | What makes it true |
|---|---|---|
| Experimental formal model ... comparison against running implementations is pending | process | No checker or emitter exists (see "Not done") |
| Independent readings ... are worked in, one round at a time | process | PR 263's history |
| Every sentence ..., apart from a theorem's own restatement, has a line in `CLAIMS.md` | process | This file |
| This is a formal model of who may do what in aweb ... | process | The files listed under "What is here" |
| Every result in it is proved and checked by Lean | process | `lake build` with no warning; no `sorry`, `axiom`, `native_decide`, `opaque` or `implemented_by` in the sources |
| A row is proved only for what its statement says | process | Reading convention |
| Lean guarantees the results follow from the definitions, not that the definitions match the real system | process | What a proof checker checks |
| Checked by reading the source, twice; several definitions corrected afterwards and not yet rechecked | process | The two source readings; the list under "Not done" |
| The model is not yet run against the real code | process | "Not done" |

### How to check it yourself

| Sentence | Kind | What makes it true |
|---|---|---|
| With no warning, no proof is left open; `sorry` builds with a warning | process | Lean's behaviour |
| An `axiom` or `native_decide` builds with no warning; the sources use none of `axiom`, `native_decide`, `opaque`, `implemented_by` | process | A grep of the sources (each reading ran it); the words occur only as strings in `DocNames.lean`'s skipped list |
| `#print axioms` shows only `propext`, `Classical.choice`, `Quot.sound` | process | `#print axioms` on every theorem (each reading ran it) |
| Pinned to Lean 4.36.0; no package beyond Lean | process | `lean-toolchain`; `lake-manifest.json` lists no packages |
| The build runs a name check: what it reads and skips, and how an identifier passes; it finds a misspelled or removed name, not a wrong one | process | `TrustWeb/DocNames.lean`: the `#doc_names_resolve` file list, `isPathOrCommand`, `skipped`, `passes`, `resolvesInModel`, `isConstructorOfModel`; built as the `DocCheck` library in `lakefile.toml`, with `README.md` and `CLAIMS.md` as its inputs, so it reruns when either changes |

### What is here

| Sentence | Kind | What makes it true |
|---|---|---|
| `Model.lean`: what exists, `State`, the 22 acts, assumptions 1 to 9 | definition | `State`; `Step` has 22 constructors; the module doc lists A1 to A9 |
| `Properties.lean`: the results not listed under another file | process | File contents |
| `Abilities.lean`: results 22 to 26, 36 and 41 to 47 | process | File contents |
| `DocNames.lean`: the build's name check | process | File contents |
| `Operations.lean`: the team rule, results 32 to 35 and 48 | process | File contents |
| `Core.lean`: six acts (`CoreStep`), `core_one` to `core_five`, `core_two_design` | definition | `CoreStep` has 6 constructors; file contents |
| `Evidence.lean`: results 38 to 40, assumption 10 | process | File contents |

### Who may ask a key holder

| Sentence | Kind | What makes it true |
|---|---|---|
| Who may ask is a parameter, `AskRule`, any rule of that type | definition | `AskRule`; `Step` and `Reachable` take `ask` |
| The model names three, the last a family with one rule per assignment | definition | `builtRule`, `adminRule`, `teamRule (assign)` |
| As built, only adding a person may be asked for | definition | `builtRule`'s first conjunct `act = .registerPerson` |
| A valid person of the organisation may ask, whatever the policy | definition | `builtRule`'s first disjunct |
| Any valid member may ask when the policy has an anyPerson rule for adding a person | definition | `builtRule`'s second disjunct |
| A valid person must then be among the approvals | definition | `Authorised` requires `Approved`; `Approved` with that rule needs `Satisfies .anyPerson` |
| A rule naming one approver does not let an agent ask | definition | `builtRule`'s second disjunct needs `r.approver = .anyPerson` |
| So a held key signs, through `Authorised`, only a person's registration or re-admission under the root | definition | `Authorised`'s held branch needs `builtRule`, so the act is `.registerPerson`; only `registerByRoot` and `readmitByRoot` ask for `registerOf .person` |
| A held key is never given back as built | definition | `release` needs `key ∈ s.held`, so `Authorised`'s held branch, and `builtRule` never allows `.release` |
| Planned: `adminRule` is an admin, person or agent | definition | `adminRule`; `Admin` allows either kind |
| Planned: `teamRule` is a valid member with a certificate of the assigned team | definition | `teamRule` |
| The admin rule is the team rule with every act assigned to the admin team | result | Row 32 |
| The acts with `Authorised` among their premises are these nine | act | Premises of `readmitByRoot`, `release`, `rekeyTeam`, `registerByRoot`, `revokeByOrg`, `admit`, `admitAdmin`, `remove`, `invite` |
| Two acts change team certificates without it | act | Of the acts that change `members` (`admit`, `admitAdmin`, `remove`, `leave`, `redeem`), only `leave` and `redeem` lack `Authorised` |
| `leave` removes a held team's certificate with no rule or policy; the member need not be registered or valid | act | `leave`'s premises |
| `redeem` adds a team certificate on an unused invitation, with no `Authorised` | act | `redeem`'s premises |
| A result proved for any `AskRule` holds for all three | definition | Universal quantification over `ask` |
| A Design row is proved for the admin rule and claims nothing about the built rule | process | Reading convention |
| Row 30's statement is false as built, by 29 | result | Row 29: under `builtRule` a key leaves its holder only at `.dns` or `.controller (.root _)`, never `.id a` |
| Four more parts are planned and not built | source | See each item |
| They are present under every rule, so 15 and 29 are proved over acts that include them | definition | They are constructors or premises of `Step`, which takes any `ask` |
| `entrust` and `release`: the built holder makes its own keys and has no such commands | source | the source readings (sources listed in `Model.lean`) |
| Under the built rule, `release` is never accepted | definition | As above |
| `KeepsAnAdmin` is a premise of `leave`, and of `remove` when the key is held | act | `leave`, `remove` |
| The registry has no such check | source | the source readings (sources listed in `Model.lean`) |
| The built leave command drops the member's own copy and leaves the certificate standing | source | the source readings (sources listed in `Model.lean`) |
| `invite` and `redeem` require a team other than the admin team | act | `i.team ≠ .admin` in both |
| The registry does not know which team is the admin team | source | the source readings (sources listed in `Model.lean`) |

### The model in plain words

| Sentence | Kind | What makes it true |
|---|---|---|
| An organisation is a domain | definition | `Org` |
| Whoever controls it in DNS creates it | act | `createOrg` is asked by `.dns o` |
| Once it exists, it can always name a new root key | result | Row 27 (`replaceRoot` needs only `o ∈ s.orgs`) |
| It has a root key and one key per team | definition | `OrgKey` |
| A member holds an identity certificate naming organisation, kind and issuer | definition | `Cert`, `Issuer`, `Kind` |
| In a reachable record each identity has at most one | result | Row 14, `Reachable.oneCertEach` |
| A member registering under itself may issue a person only if it is a person | definition | `registerByParent`'s `MayIssue pk c.kind` |
| The root issues either kind | act | `registerByRoot` has no kind premise |
| A valid person holds a person certificate issued by the root or a person, and is not revoked | definition | `Valid.person`, `Person` |
| Another identity's revocation, its issuer's included, does not change that | result | Row 9 |
| A valid agent is not revoked, and its issuer is the root or valid now | definition | `Valid.agentOfRoot`, `Valid.agentOf` |
| A valid person answers for itself; a person answers for an unrevoked agent whose issuer it answers for | definition | `AnswersFor.self`, `AnswersFor.up` |
| The one who answers is a valid person, and with one certificate each there is at most one | result | Row 13 |
| A team certificate names a member of a team | definition | `Membership` |
| No premise of `admit` or `redeem` asks the member to be registered or of the organisation | act | Premises of `admit`, `redeem` |
| `admitAdmin` asks it to be a valid member of the organisation | act | `admitAdmin`'s `Valid s m.org m.member kind` |
| Acting in a team needs the certificate and, if registered, being valid now | definition | `InTeam`, `CanAct` |
| An admin holds an admin-team certificate and is a valid member, of either kind | definition | `Admin` |
| Each rule names an organisation, a kind of act and whose approval | definition | `Rule`, `Approver` |
| Any valid person of the organisation, or one named member valid in it | definition | `Satisfies` |
| Approvals are approved when they satisfy every rule for the act | definition | `Approved` |
| `Authorised`: if not held, whoever controls the key, no policy; if held, an identity the rule lets ask, with approved approvals | definition | `Authorised` |
| In the nine acts that go through it; `leave` and `redeem` change team certificates without it | act | As in "Who may ask" |
| A member that can act in a team gives a grant on itself to a session key no current grant uses | act | `mintGrant` |
| While the grant stands and its subject can act in the team, the session key's holder can send as the subject, if it may send | act | `GrantLive`, `sendGrant` |
| Issuing an invitation needs the same `Authorised` as admitting to its team | act | `invite` asks `Authorised ... (.team i.org i.team) .admit` |
| Whoever holds the secret joins once, as a key that is registered or holds no team certificate | act | `redeem`: `OneTeamIfLocal`; the invitation is removed |
| Neither is for an admin team | act | `i.team ≠ .admin` in `invite` and `redeem` |
| The acts (22) and their list | definition | The 22 constructors of `Step` |

### What is proved: how to read the rows

| Sentence | Kind | What makes it true |
|---|---|---|
| Each row gives its theorem's conditions and conclusion first | process | Reading convention |
| "In one act" is about a single accepted act | process | Such theorems take one `Step` |
| "In a record the system can reach" is after any sequence of acts from a record with only a policy | definition | `Reachable`, `Reachable.start` |
| One certificate each holds in every reachable record | result | Row 14 |
| A row with no rule named holds under every rule | process | Such theorems quantify over `ask` |

### Between the tables

| Sentence | Kind | What makes it true |
|---|---|---|
| Rows 25, 42, 43, 44, 46 and 47 state limits, and so does the first half of 23 | process | Their statements are negative or show a gap |
| An agent whose key a hosting service holds is not in the model | assumption | A7 |
| Moving an agent to another parent is not in the model | result | `certificate_is_permanent`; row 14 |
| An organisation changing its domain is not in the model | definition | `Org` is the domain |
| A person of several organisations can be stated, and there is none in reachable records | result | `Person.cert` with row 14: it would need two certificates |
| `controller_asserted_person` is described in `Evidence.lean` | process | File contents |
| In the model the evidence is a list outside the record | definition | `State` has no field for it; the definitions in `Evidence.lean` take `as : List Assertion` |
| Assumption 10 is about who signs an assertion | assumption | A10 |

### What must never happen

One block per cell, in the table's order.

| Cell | Sentence | Kind | What makes it true |
|---|---|---|---|
| An agent passes as a person | Proved by 1 for records with one certificate each, 2 for one act, 3 for added certificates, 4 for every approval | result | Rows 1 to 4 and their conditions |
| No chain back to a root | Not true of what is built | result | The lines below |
| | Proved for valid members and admins (5) | result | Row 5 |
| | A key with no identity certificate can act in a team on its team certificate alone | definition | `InTeam`; `CanAct`'s first disjunct |
| | And so give a grant | act | `mintGrant` needs `InTeam` and a session key no current grant uses; some key is always unused, since `grants` is a finite list |
| | In a team or not, it can send attributed to itself | act | `sendOwn` needs only `CanAct` |
| | It can leave a team whose key is held | act | `leave` has no validity or registration premise |
| | A team certificate counts without the root having set the team's key | definition | `InTeam`, `GrantLive` and `admit` have no premise about the root or `rekeyTeam` |
| | The three rules require a valid member to ask; a rule letting anyone ask would not | definition | `builtRule`, `adminRule` (`Admin` needs `Valid`), `teamRule` |
| A revoked member keeps authority | Proved in reachable records: not valid, not an admin, cannot act in a team, cannot send with its own key, no live grant | result | Rows 7, 8, 20; `sendOwn` needs `CanAct` |
| | The three rules require a valid member to ask; a rule letting anyone ask would not | definition | As above |
| | Under every rule it can still revoke a grant on itself, revoke itself, leave a held team unless it is the admin team and no other admin remains, be the key `redeem` names | act, result | `revokeGrant`, `revokeSelf` have no validity premise; `leave` has none but `KeepsAnAdmin`; `redeem` needs `OneTeamIfLocal`, which a revoked identity meets because in reachable records it is registered (row 14) |
| A revocation is undone | Proved for one act | result | `revocation_is_permanent` |
| | Not proved for several acts | process | No theorem states it |
| | A root-issued cut-off identity can be admitted again while the root key is not held | result | Row 31 |
| | With one certificate each, a member-issued one is admitted again only by that member, while valid | act | `readmitByRoot` needs `c.issuer = .root`; `readmitByParent` is asked by `.id p` with `c.issuer = .member p` and `Valid s c.org p pk`; with row 14, `c` is the identity's only certificate; only these two acts take an identity out of `revoked` |
| An identity changes organisation or kind | Proved for one act that no certificate is removed; in reachable records one certificate | result | `certificate_is_permanent`; row 14 |
| | Not proved for several acts | process | No theorem states it |
| Controlling one organisation's key changes something in another | Not true of what is built: one organisation's root controller can stop an identity acting in another's team and make its grant there not live | result | Row 46 |
| | It can revoke its own identity | act | `revokeByOrg` |
| | A revoked identity cannot act in any team, in reachable records | result | Row 7 |
| | Proved for one act: new identity and new or removed team certificates are of the key's organisation; a newly revoked identity has a certificate of it | result | `controller_stays_in_its_organisation` |
| | With one certificate each, of no other | result | Same theorem's last conjunct; row 14 |
| | Not stated for invitations, grants, held keys or re-admissions | result | The theorem's statement |
| A message attributed to someone who did not send it | Proved for one act, for every message the act adds | result | Row 18 |
| | That the subject gave the grant is proved for the act that adds it, not for every grant | result | Row 19; no theorem about every grant |
| A grant holder does more than send | Proved for one act | result | Rows 17, 19 |
| An invitation's holder becomes a person or an admin | Proved for one act, under every rule | result | Rows 21, 6 quantify over every `AskRule` |
| | Not proved for several acts | process | No theorem states it |
| | Under a team rule that gives admitting admins to a named team, it happens in two acts | result | Row 48 |
| | As 35 shows for giving a key back | result | Row 35 |
| An agent approves where a person is required | Proved for every approval | result | Rows 4, 23 |
| Being issued an identity gives team membership | Proved for one act | result | `registering_gives_no_team` |
| An unregistered key in two teams | Proved in reachable records | result | Row 14 |
| | It holds on the supported journey; the registry's own route does not enforce it | source | the source readings (sources listed in `Model.lean`) |
| A key leaves its holder except ... | Proved for one act | result | Row 28 |
| The last admin's team certificate | A planned check, proved for one act | result | Row 11a |
| | The team key's controller can still remove anyone | result | Row 10 |
| | A revocation can still leave no admin: of the last admin, of an agent admin's issuer, or by a root replacement | result | Rows 44, 47; row 27 applied to 44's record |
| An outsider is an admin | True by the definition | definition | `Admin` needs `Valid s o k kind` |
| A certificate for one team accepted for another | True by the definition | definition | `HasTeamCert` matches organisation and team |
| An approval reused | Assumed | assumption | A6 |
| A key holder uses a key other than the acts allow | Assumed; cannot be proved while the holder is assumed honest | assumption | A8 |
| Whoever holds a member's key speaks as it | Not in the model | assumption | A7 |
| Re-signed or re-issued as a side effect | Not in the model | act | `Fresh` premises of `registerByRoot` and `registerByParent`; `certificate_is_permanent`; A7 |

### Readings inside result rows

| Row | Reading | Kind | What makes it true |
|---|---|---|---|
| 1 | (with 14) | result | Row 14 gives the condition in reachable records |
| 2 | The statement does not say whose certificate it is, or that it is of that organisation | result | The statement's conclusion |
| 2 | 15 adds, as built, that it is of that organisation | result | Row 15 |
| 2 | It looks at certificates only, so admitting again is not covered | definition | `Person` reads only `certs`; re-admissions change no `certs` |
| 2 | It is about who signs, not who asked | result | The conclusion says nothing about the asker |
| 3 | A person certificate of an organisation issued by a person of it makes its subject a person | definition | `Person.byPerson` |
| 3 | What is checked is the rule about issuers, not the registry's admission | result | The hypothesis is about issuers only |
| 5 | What leading means, and what it says nothing about | definition | `ChainToRoot` |
| 5 | Nothing about a key with no identity certificate acting in a team | result | The statements are about valid members and admins |
| 6 | So it is not an invitation's holder, in that act | result | `.bearer` is neither disjunct |
| 6 | Nothing is proved about several acts | process | No theorem states it |
| 7 | (true in every reachable record, 14) | result | Row 14 |
| 7 | Sending with its own key requires being able to act | act | `sendOwn` |
| 8 | Its team certificates are not looked at | result | The statement |
| 9 | Whoever issued it; about the record, not an act | result | The statement quantifies over the issuer and has no `Step` |
| 10 | The asker is the key's controller alone | definition | `Authorised`'s first branch: no policy |
| 11 | A rule naming the other as approver means the approvals include its own | definition | `Satisfies` for `.exactly` |
| 11a | This is about a team certificate going | result | The hypothesis |
| 11a | A revocation can still leave no admin: three cases | result | Rows 44, 47; row 27 applied to 44's record |
| 15 | The model does not record which approvals an act carried; the act is accepted only with such approvals | definition | `approvals` is an implicit argument of the constructor, not part of `State` |
| 16 | Construction note; so 2 holds | construction, result | The proof; row 2 holds for any act |
| 16 | As built, an agent may ask where the policy has an anyPerson rule for adding a person; not stated as a theorem | definition | `builtRule`'s second disjunct |
| 18 | This covers every message an act adds | result | The hypothesis is that the act changes `sent` |
| 20 | (true in every reachable record, 14) | result | Row 14 |
| 21 | The joiner is whatever key the holder names | act | `redeem`'s `k` is any key meeting `OneTeamIfLocal` |
| 21 | That the joiner holds that key is assumed | assumption | A3 |
| 22, 35, 36, 41, 43, 44, 45, 46, 47, 48 | Construction notes | construction | The proofs |
| 22 | The statement does not say who issued whom | result | The statement |
| 25 | Re-admissions change no team certificate | act | `readmitByRoot`, `readmitByParent` |
| 26 | The three need not differ | result | The statement has no inequality |
| 27 | The act is the root replacement, whose only premise is that the organisation exists | construction, act | The proof; `replaceRoot` |
| 28 | When it is the domain's owner, the key is the root key and no identity is valid after (37) | result | Row 37 |
| 28 | The holder no longer holds the current root key | act | `replaceRoot` takes the root key out of `held` |
| 28 | The model does not show the holder no longer has the former private key | definition | `held` records only which keys are held, not copies |
| 28 | Nor does the protocol | source | the source readings (sources listed in `Model.lean`) |
| 35, 48 | A warning | process | A label |
| 38 | A valid person answering for itself (`nearest_human`) says nothing about an email check | result, source | `AnswersFor.self` needs only `Valid`; row 38; the verdict's name is the protocol's (`docs/id-certificates.md`) |
| 40 | The rest of 38's three cases follows from 38 | result | Row 38 applies to any valid person |
| 41 | In every record such a key exists | result | `exists_fresh_key` |
| 42 | Locked means ...; then the organisation has no admin | definition, result | `AdminTeamLocked`; `AdminTeamLocked.no_admin` |
| 43 | A re-key leaves the team certificates and grants as they are | act | `rekeyTeam` changes only `held` |
| 43 | 45 ends a membership and its grants | result | Row 45 |

### What is assumed

Assumptions 1 to 10 are assumptions: taken as given, not proved. Two sentences in them are about the real system.

| Sentence | Kind | What makes it true |
|---|---|---|
| A server caches a team's revocations for 60 s and serves them stale for 60 s more | source | `docs/aweb-sot.md`, "Caching from awid" |
| In that window a removed member can still give a grant, and its grant still works | source | Same |

### Where the model does less than the real system

Each item pairs a sentence about the model with one about the real system.

| Sentence | Kind | What makes it true |
|---|---|---|
| Nothing here is about time, crashes, retries or concurrent changes | assumption | A5 |
| `replaceRoot` cuts off every unrevoked identity of the organisation at once | act | `replaceRoot` |
| Really by time of registration, with a backdated option; dual-signed rotation and parent recovery exist | source | the source readings (sources listed in `Model.lean`) |
| Re-admission puts the same certificate back in force | act | `readmitByRoot`, `readmitByParent` take the subject out of `revoked` and `cutOff` and change no certificate |
| Really a new signed certificate, and the new root can admit anyone it keeps | source | the source readings (sources listed in `Model.lean`) |
| `release` gives a key back whole | act | `release` changes only `held` |
| Really a new key, signed by old and new | source | the source readings (sources listed in `Model.lean`) |
| One certificate per identity | result | Row 14 |
| Really an identity can be moved to another parent | source | the source readings (sources listed in `Model.lean`) |
| Creating and deleting teams is not modelled | definition | `OrgKey` and `Team` are fixed; no act creates a team |
| A root replacement leaves the team keys where they were | act | `replaceRoot` filters only `.root o` from `held` |
| The root re-keys a team by a separate act | act | `rekeyTeam` |
| A re-key only changes which key is the team's | act | `rekeyTeam` changes only `held` |
| Really the rotation also re-signs the member certificates it is given | source | awid `rotate_team_key` at 5c2ee7bad3 |
| `controller key` is whoever controls that key now; the old one cannot be named | definition | `Party.controller` names a key, not a holder |
| The operator is not modelled; whoever controls a key asks directly only while it is not held | definition | `Authorised`'s first branch needs `key ∉ s.held`; `entrust` needs `key ∉ s.held` |
| Really the operator has narrower named commands | source | the source readings (sources listed in `Model.lean`) |
| Policy is given and checked only when a key holder holds the key | definition | No act changes `policy`; `Approved` is only in `Authorised`'s held branch |
| Really servers and applications enforce approval | source | the source readings (sources listed in `Model.lean`) |
| A team certificate is one record | definition | `Membership` has no id |
| Really revoked by id, missing told from revoked | source | the source readings (sources listed in `Model.lean`) |
| A grant can send or not | definition | `Grant.maySend` |
| Really ten scopes and expiry | source | the source readings (sources listed in `Model.lean`) |
| `sendOwn` stands for an accepted send | act | `sendOwn` |
| Really the server checks key, identity and recipient rules | source | the source readings (sources listed in `Model.lean`) |
| An invitation is used once, for one team | act | `redeem` removes it; `Invite` names one team |
| Really several uses, expiry, a named answerer | source | the source readings (sources listed in `Model.lean`) |
| A secret is new only among unused invitations; a session key only among current grants | act | `invite`'s and `mintGrant`'s freshness premises |
| "Has an identity certificate" is one thing here | definition | `Registered` |
| Really three things | source | the source readings (sources listed in `Model.lean`) |
| The record keeps only who each message is attributed to | definition | `Message` |
| No answer covers both "nobody" and "cannot be established" | definition | `AnswersFor` is a `Prop` with no reason |
| The protocol tells them apart | source | the source readings (sources listed in `Model.lean`) |
| Team certificates and invitations need no organisation to exist | act | No premise of `admit`, `redeem` or `invite` mentions `orgs` |
| Nobody holds a member's own key for it | assumption | A7 |

### Working on the model; Not done

These are method and process. They make no claim about the model beyond what is listed here.

| Sentence | Kind | What makes it true |
|---|---|---|
| `design_agent_admin_can_ask_for_person` writes a record in which something fails | result | That theorem is an existential with a construction |
| It does not run yet | process | No checker functions exist |
| Several definitions were corrected after the last source check | process | The list given there |

## TrustWeb/Model.lean

### Module doc

| Sentence | Kind | What makes it true |
|---|---|---|
| What exists, what is true, and the acts; the results are in the other files | process | File contents |
| Sources: docs/id-certificates.md, teams.md, human-approval-architecture.md, trust-model.md, identity.md, grant code, key holder | process | The source readings |
| The protocol's word for a person is "human" | source | the source readings (sources listed in `Model.lean`) |
| Read against the source, not yet run | process | As in the README |
| Who may ask is a parameter; two values here, `teamRule` in Operations | definition | `AskRule`, `builtRule`, `adminRule`; `Operations.lean` |
| A result for any `AskRule` holds for each | definition | Universal quantification |
| The four planned parts, and the source reasons | source | As in the README's list |
| A1 to A9 | assumption | Taken as given |
| A4: a verifier may go on accepting for a bounded time | source | `docs/aweb-sot.md`, "Caching from awid" |

### Definitions

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| `Key` | Whoever holds it can sign as it; an identity is its key | assumption | A1, A7 |
| `Org` | An organisation is a domain | definition | Naming |
| `Issuer`, `Team`, `Kind` | The cases | definition | The constructors |
| `OrgKey` | Root key and one key per team | definition | Constructors |
| `OrgKey` | Which key each `Authorised` act names | act | The `Authorised` premise of each of the nine acts |
| `OrgKey` | `leave` and `redeem` change a team's certificates without `Authorised` | act | Their premises |
| `Party` | The five kinds of asker | definition | Constructors |
| `Party` | `controller key` is whoever controls the key now; after a replacement, the new root | definition | `Party.controller` names a key; `replaceRoot` takes the root key out of `held` |
| `Party` | The model cannot name the old controller | definition | No `Party` names a past holder |
| `Party` | A root replacement does not replace a team's key; a re-key does | act | `replaceRoot` leaves team keys in `held`; `rekeyTeam` takes one out |
| `Cert` | Fields | definition | Fields |
| `Membership` | The member can be an outsider or unregistered | act | No premise of `admit` or `redeem` restricts it |
| `ActKind`, `Approver`, `Rule` | Their cases and fields | definition | Constructors, fields |
| `Grant` | The session key's holder sends attributed to the subject, if `maySend` | act | `sendGrant` |
| `Grant` | When given, no current grant uses `session` | act | `mintGrant` |
| `Invite` | Whoever holds `token` may join `team` of `org` | act | `redeem` |
| `Message` | As the server attributes it | assumption | A9 |
| `State.revoked` | `replaceRoot` adds cut-off identities here and to `cutOff` | act | `replaceRoot` |
| `State.revoked` | In every reachable record every cut-off identity is here | result | `Reachable.cutOffAreRevoked` |
| `State.cutOff` | `replaceRoot` adds; re-admission or revocation takes out | act | `replaceRoot`; `readmitByRoot`, `readmitByParent`, `revokeSelf`, `revokeChild`, `revokeByOrg` filter it |
| `State.cutOff` | The re-admission acts take an identity in it | act | Their `c.subject ∈ s.cutOff` premise |
| other fields | What each list holds | definition | Field types and the acts that change them |
| `MayIssue` | A person issues either kind; an agent only agents | definition | `MayIssue` |
| `Person` | Person certificate by root or person; revocation not looked at | definition | `Person`'s constructors |
| `Valid` | A person: chain and not revoked | definition | `Valid.person` |
| `Valid` | Their issuer was checked when they were registered | act | `registerByParent`'s `Valid s c.org p pk` |
| `Valid` | Its later revocation does not undo them | result | Row 9 |
| `Valid` | An agent: not revoked, issuer root or valid now | definition | `Valid.agentOfRoot`, `Valid.agentOf` |
| `ChainToRoot` | Certificates lead from `k` to the root | definition | Constructors |
| `AnswersFor` | `self` and `up` | definition | Constructors |
| `AnswersFor` | Every agent on the way is unrevoked; the person is valid | definition, result | `up`'s `a ∉ s.revoked`; `answerer_is_valid_person` |
| `AnswersFor` | With one certificate each, at most one answers | result | `answerer_unique` |
| `Registered`, `HasTeamCert` | Their meaning | definition | Their bodies |
| `Fresh` | `k` has no identity certificate in this record | definition | Body |
| `CanAct` | Unregistered, or valid somewhere | definition | Body |
| `CanAct` | With one certificate each, its own organisation | result | `Valid.cert` with `OneCertEach` |
| `CanAct` | In reachable records revoked and cut-off identities cannot act | result | `revoked_cannot_act`, `Reachable.revokedAreRegistered`, `Reachable.cutOffAreRevoked` |
| `InTeam` | Team certificate and can act | definition | Body |
| `InTeam` | An unregistered member has no chain | definition | `ChainToRoot` needs a certificate with that subject |
| `Admin` | Admin-team certificate and valid member; an outsider never is | definition | Body |
| `Satisfies`, `Approved`, `OrgKey.org`, `AskRule`, `registerOf` | Their meaning | definition | Bodies |
| `builtRule` | Each sentence | definition | As in the README's "Who may ask" |
| `adminRule` | An admin may ask for any act | definition | Body |
| `Authorised` | Not held: the controller, no policy; held: the rule's identity, with approvals | definition | Body |
| `GrantLive` | Stands and its subject can act in the team | definition | Body |
| `GrantLive` | Removing the certificate removes the grant, so a later certificate does not bring it back | act | `remove` and `leave` filter `grants` |
| `OneTeamIfLocal` | `k` is registered, or holds no team certificate | definition | Body |
| `KeepsAnAdmin` | For an admin-team certificate, another identity is an admin | definition | Body |
| `Step` | `Step ask s who s'`: under `ask`, `who` asks for one act, accepted, from `s` to `s'` | definition | Its signature and constructors |
| `Step` | Each constructor's premises are what is checked | definition | Naming |
| `createOrg` | Asked for by whoever controls the domain in DNS | act | Its asker is `.dns o` |
| `replaceRoot` | Whoever controls the domain in DNS replaces the root key | act | Its asker is `.dns o`; it takes the root key out of `held`. The model has no value for a root key |
| `replaceRoot` | Cuts off every current identity of the organisation | act | Its `revoked` and `cutOff` update |
| `replaceRoot` | The new root key is not held | act | Its `held` filter |
| `replaceRoot` | Team certificates, invitations and team keys are not touched | act | It changes only `revoked`, `cutOff`, `held` (root only) |
| `replaceRoot` | In a reachable record a cut-off member cannot act in a team | result | `revoked_has_no_authority` with `Reachable.cutOffAreRevoked` and `Reachable.revokedAreRegistered` |
| `replaceRoot` | Nothing can refuse this | act | Its only premise is `o ∈ s.orgs` |
| `readmitByRoot` | The root key signs; the identity keeps its key | act | `Authorised ... (.root c.org)`; the act puts the same certificate, with the same subject, back in force |
| `readmitByParent` | A valid member re-admits one it issued | act | Premises |
| `release` | Nothing else changes | act | It changes only `held` |
| `rekeyTeam` | Replaces a team's key; no key holder holds the new one | act | It filters `.team o t` from `held` |
| `rekeyTeam` | The root key signs; no team key, member or admin signs | act, source | `Authorised ... (.root o) .rekey`; awid `rotate_team_key` needs only the namespace controller |
| `rekeyTeam` | The old key is no longer the team's key | act | Same filter |
| `rekeyTeam` | Certificates, grants and invitations are not touched | act | It changes only `held` |
| `rekeyTeam` | Admitting and removing are separate acts | definition | `admit`, `admitAdmin` and `remove` are other constructors of `Step` |
| `entrust` | Whoever controls a key puts it in a key holder | act | `.controller key`, `key ∉ s.held` |
| `registerByRoot` | Either kind, root key signs | act, assumption | Premises; A2 for a person |
| `registerByParent` | Within R1, its own key signs | act | `MayIssue` premise; asked by `.id p` |
| `revokeSelf` | Need not be valid | act | Only premise `c ∈ s.certs` |
| `revokeChild`, `revokeByOrg` | Who signs | act | `.id p` with `Valid`; `Authorised ... (.root c.org)` |
| `admit` | Named team; the member can be an outsider; the team key signs | act | Premises |
| `admitAdmin` | A valid member of the organisation; the admin team key signs | act | Premises |
| `remove` | The removed member need not take part; the policy may name it | act | Premises; `Approved` with an `.exactly` rule |
| `remove` | A key holder does not remove the last admin | act | `KeepsAnAdmin` premise when held |
| `remove` | Grants from this certificate end with it | act | `grants` filter |
| `leave` | Held team, by asking the key holder; no rule or policy; need not be registered or valid | act | Premises |
| `invite` | Same authority as admitting | act | `Authorised ... .admit` |
| `redeem` | Team not admin; unregistered key holds no team certificate; who holds the secret not checked | act, assumption | Premises; A3 |
| `mintGrant`, `revokeGrant`, `sendOwn`, `sendGrant` | Their askers and effects | act | Constructors |
| `Reachable` | From nothing but a policy | definition | `Reachable.start` |
| `OneCertEach` | Every identity has at most one certificate, so organisation, kind and issuer are fixed | definition | Body: two certificates with one subject are equal |
| `OneCertEach` | R2 fixes organisation and kind; the fixed issuer is this model's restriction | source | the source readings (sources listed in `Model.lean`) |
| `LocalInOneTeam`, `RevokedAreRegistered` | Their meaning | definition | Bodies |

## TrustWeb/Properties.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | Each result has a doc comment that restates it; the lemmas with none are helpers | process | File contents |
| `new_person_is_vouched_for` | The statement does not say the certificate is `k`'s; it looks at certificates only | result | The statement |
| `valid_has_chain_to_root` | Leading means ...; kind, revocation, issuers' validity not part of it | definition | `ChainToRoot` |
| `new_admin_needs_controller_or_asker` | So it is not an invitation's holder | result | `.bearer` is neither disjunct |
| `revoked_has_no_authority`, `revoked_cannot_act`, `grant_ends_with_subject` | In reachable records only registered identities are revoked | result | `Reachable.revokedAreRegistered` |
| `revoked_cannot_act` | Sending, acting in a team and a live grant need `CanAct` | act, definition | `sendOwn`, `InTeam`, `GrantLive` |
| `grant_ends_with_subject` | The revoking acts leave the grants as they are | act | `revokeSelf`, `revokeChild`, `revokeByOrg` change no `grants` |
| `person_survives_others` | About the record, not an act | result | The statement has no `Step` |
| `orphaned_agent_cannot_act_in_team` | Its team certificates are not looked at | result | The statement |
| `admin_can_remove_admin` | A rule naming `b` as approver means the approvals include `b`'s | definition | `Satisfies .exactly` |
| `key_holder_keeps_an_admin` | A planned check | source | `KeepsAnAdmin` is one of the planned parts; the registry has no such check (the source readings) |
| `key_holder_keeps_an_admin` | A revocation can still leave no admin | result | `revocation_can_leave_no_admin` |
| `built_person_needs_a_person` | The model does not record which approvals an act carried | definition | `approvals` is an implicit argument of the constructor, not part of `State` |
| `controller_stays_in_its_organisation` | Nothing stated about invitations, grants, held keys, re-admissions | result | The statement |
| `design_agent_admin_can_ask_for_person` | Construction note | construction | The proof |

## TrustWeb/Abilities.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | Records reached, acts that go through, and the limits it names | process | File contents; the names are checked by `DocNames.lean` |
| `approved_act_goes_through` | `a`, `p`, `k` need not differ | result | The statement |
| `runs_without_key_holder` | The statement does not say who issued whom | result | The statement |
| `no_admin_no_new_admin_certificate` | Re-admissions change no team certificate | act | `readmitByRoot`, `readmitByParent` |
| `AdminTeamLocked` | Its meaning | definition | Body |
| several | Construction notes | construction | The proofs |

## TrustWeb/Operations.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | An `Assignment` names a team for each organisation and kind of act | definition | `Assignment` |
| module doc | Under `teamRule` a valid member with a certificate of the assigned team may ask | definition | `teamRule` |
| module doc | `adminRule` is the team rule with every act assigned to the admin team | result | `adminRule_is_teamRule` |
| module doc | How an assignment is chosen is not modelled | definition | `assign` is a parameter |
| `invitation_reaches_an_assigned_team` | `admit`, `invite`, `redeem` exclude the admin team; no premise excludes an assigned team | act | Their premises |
| `invitation_reaches_an_assigned_team` | Not proved for every assignment and team | result | The statement is one example |
| `invitation_reaches_an_assigned_team`, `invitation_then_own_request_makes_an_admin` | Construction notes | construction | The proofs |

## TrustWeb/Core.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | Six of the 22 acts, each exactly as in `Step` | definition | `CoreStep`; compare with `Step` |
| `CoreStep` | The six acts of the core, each exactly as in `Step` | definition | Its constructors |
| `CoreReachable` | The records the core can reach | definition | Its constructors mirror `Reachable` over `CoreStep`; `CoreReachable.toReachable` |
| module doc | `CoreStep.toStep` proves each is an act of the model | result | `CoreStep.toStep` |
| module doc | Some parts, `core_five` among them, are about any record | result | `core_five` and `core_three`'s first conjunct take no core hypothesis |
| module doc | An experiment, not a proposal | process | The author's intent |
| `core_one` | `agents_cannot_approve_as_person` holds in any record | result | That theorem takes any `s` |
| `core_three` | The three rules let only valid members ask; a rule letting anyone ask would not | definition | `builtRule`, `adminRule`, `teamRule` |

## TrustWeb/Evidence.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | The planned outcome, what it records and carries, and that it is reported beside the shared verdict | source | `docs/id-certificates.md`; the protocol seat's wording |
| module doc | The evidence is kept outside the record | definition | `State` has no field for it |
| module doc | So no act's premise and no verdict depends on it | definition | No `Step` premise and no definition in `Model.lean` mentions `Assertion` |
| module doc | The results hold the record fixed and vary the assertions | result | 38's statement |
| module doc | Both routes are `registerByRoot` of a person; `Cert` has no field for how | definition | `registerByRoot`; `Cert` |
| A10 | The assertions are signed by the party they name and bound to the enrolment | assumption | A10 |
| `Enrolment`, `Assertion` | Their cases and fields | definition | Constructors, fields |
| `ControllerAssertedPerson`, `HostedEmailEnrolled`, `EnrolmentUnspecified` | Their meaning | definition | Bodies |

## TrustWeb/DocNames.lean

Its doc comments are about the build, not the model.

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | What the build reads, what it skips, and how an identifier passes | process | `isPathOrCommand`, `runs`, `passes`, `failures` |
| `skipped`, `leanNames`, `modelTypes`, `inductives` | What each list is for | process | Their use in `passes`, `resolvesInModel`, `isConstructorOfModel` |
| `#doc_names_resolve` | Fails if a file cites an identifier that does not pass | process | Its body |
