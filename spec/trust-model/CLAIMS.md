# Claims ledger

One line for every sentence that says something about the model, apart from a theorem's own restatement: the README's prose, every cell of "What must never happen", every reading inside a result row, every module, definition, field and constructor doc comment, and every reading inside a theorem's doc comment. Each line gives where the sentence is, the sentence in short, and what makes it true.

- **Restatements.** A row of the README's result tables, and a theorem's doc comment, first restate the theorem's statement. A restatement is checked against the statement and is not listed here. What follows it is listed: a reading, or a construction note.
- **Names.** The build's name check, as the README's "How to check it yourself" describes it, reads this file too.
- **Kinds of line.**
  - A *definition* or *act* line names the definition or `Step` constructor that the sentence reads off.
  - A *result* line names the theorem or row.
  - A *source* line is about the real system or the protocol, not the model. "The source readings" are the readings of `docs/id-certificates.md` (sections 1 to 3 and 6), `docs/teams.md`, `docs/human-approval-architecture.md`, `docs/trust-model.md`, `docs/identity.md` ("Session grants"), the server's grant code and the key holder.
  - A *process* line is about how the model was made or is checked.
  - An *assumption* line is taken as given, not proved.
  - A *construction* line is a construction note: it describes the witnesses a proof uses, which the statement does not fix.

## README.md

### Opening

| Sentence | Kind | What makes it true |
|---|---|---|
| Experimental; proofs checked by Lean; comparison with running implementations pending | process | The generated cases have not yet been run against the code (see "Not done") |
| A formal model, in Lean 4, of who may do what in aweb | process | The files in `TrustWeb/` |
| Lean checks that each result follows from the definitions | process | `lake build`; see "How to check it yourself" |
| The definitions were checked against aweb by reading the source; not yet run against the code | process | The source readings; "Not done" |
| A row is proved only for what its statement says | process | Reading convention |

### How to check it yourself

| Sentence | Kind | What makes it true |
|---|---|---|
| With no warning, no proof is left open; `sorry` builds with a warning | process | Lean's behaviour |
| An `axiom` or `native_decide` builds with no warning; the sources use none of `axiom`, `native_decide`, `opaque`, `implemented_by` | process | A grep of the sources (each reading ran it); the words occur only as strings in `DocNames.lean`'s skipped list |
| `#print axioms` shows only `propext`, `Classical.choice`, `Quot.sound` | process | `#print axioms` on every theorem (each reading ran it) |
| Pinned to Lean 4.36.0; no package beyond Lean | process | `lean-toolchain`; `lake-manifest.json` lists no packages |
| The build runs a name check: what it reads and skips, and how an identifier passes; it finds a misspelled or removed name, not a wrong one | process | `TrustWeb/DocNames.lean`: the `#doc_names_resolve` file list, `isPathOrCommand`, `skipped`, `passes`, `resolvesInModel`, `isConstructorOfModel`; built as the `DocCheck` library in `lakefile.toml`, with `README.md` and `CLAIMS.md` as its inputs, so it reruns when either changes |

### What is proved: how to read the rows

| Sentence | Kind | What makes it true |
|---|---|---|
| A row restates its theorem first; anything after is a reading or a construction note | process | Reading convention |
| "In one act" is about a single accepted act | process | Such theorems take one `Step` |
| "In a record the system can reach": after any sequence of acts from a record with only a policy | definition | `Reachable`, `Reachable.start` |
| One certificate each holds in every reachable record | result | Row 14 |
| A row with no rule named holds for every `AskRule` | process | Such theorems quantify over `ask`, or take no `ask` and state no rule |
| As built is `builtRule`, Design is `adminRule` (row 52: the planned root replacement), a team rule is `teamRule`; a Design row claims nothing about `builtRule` | process | Reading convention |
| A row under a team rule claims nothing about `builtRule` | result | `no_teamRule_is_builtRule` |
| Five parts of `Step` are planned, not built | source | The source readings: the built key holder has no command to take a key in or give one back; the registry has no last-admin check and does not know the admin team; the built leave command leaves the certificate standing; the registry's certificate route registers a certificate for any team with the same checks, so nothing in it excludes the admin team (`awid/src/awid_service/routes/teams.py`, the function register_certificate, lines 1219 to 1246, at 5c2ee7bad3); the same route checks the member's address ownership (the function _require_member_address_owned_by_did_aw, line 1235), not its validity in the organisation |
| They are present under every rule, `builtRule` included; under `builtRule` `release` is never accepted | definition | `entrust`, `release`, `leave` are constructors of `Step`; `KeepsAnAdmin`, `rekeyTeam`'s premise on `keep`, `m.team ≠ .admin`, `i.team ≠ .admin` and `admitAdmin`'s `Valid` are premises of its constructors; `Step` takes any `ask`; `release` needs `key ∈ s.held`, so `Authorised`'s held branch, and `builtRule` never allows `.release` |
| The Design rule, the team rule, the planned root replacement and the evidence are planned too, named in their rows | source, definition | `adminRule`; `plannedReplaceRoot` is a definition, not a `Step` constructor; `Evidence.lean`'s module doc |
| Every reachable record with a held key is reached through `entrust`, so every row whose reachable record or act has a held key rests on it, and a row about any record with a held key applies among reachable records only to ones reached through `entrust` | result | `held_key_reached_through_entrust`, `only_entrust_puts_a_key_with_a_holder` |
| Every row whose act is `release` rests on the planned `release` | act | `release` is a planned part |
| A row that rests on another planned premise says so | process | The labels on rows 6, 11a, 14, 21, 25 and 42, and the cells that cite them |

### Evidence of how a person was enrolled

| Sentence | Kind | What makes it true |
|---|---|---|
| The evidence is a list of assertions outside the record | definition | The definitions in `Evidence.lean` take `as : List Assertion`; `State` has no field for it |


### Readings inside result rows

| Row | Reading | Kind | What makes it true |
|---|---|---|---|
| 1 | (with 14) | result | Row 14 gives the condition in reachable records |
| 2 | The statement does not say whose certificate it is, or that it is of that organisation | result | The statement's conclusion |
| 2 | Under every rule, the certificate is of that organisation | result | `Person.added_cert_org` |
| 2 | It looks at certificates only, so admitting again is not covered | definition | `Person` reads only `certs`; re-admissions change no `certs` |
| 2 | It is about who signs, not who asked | result | The conclusion says nothing about the asker |
| 3 | A person certificate of an organisation issued by a person of it makes its subject a person | definition | `Person.byPerson` |
| 3 | What is checked is the rule about issuers, not the registry's admission | result | The hypothesis is about issuers only |
| 5 | What leading means, and what it says nothing about | definition | `ChainToRoot` |
| 5 | Nothing about a key with no identity certificate acting in a team | result | The statements are about valid members and admins |
| 6 | So it is not an invitation's holder, in that act | result | `.bearer` is neither disjunct |
| 6 | An invitation can still lead to an admin a step later, under a team rule | result | Row 48 |
| 14 | Its clause on identities with no certificate rests on the planned premise of `admitAdmin` | result, source | `Step.localInOneTeam`'s proof uses `admitAdmin`'s `Valid` premise; that premise is planned |
| 7 | (true in every reachable record, 14) | result | Row 14 |
| 7 | Sending with its own key requires being able to act | act | `sendOwn` |
| 8 | Its team certificates are not looked at | result | The statement |
| 9 | Whoever issued it; about the record, not an act | result | The statement quantifies over the other identity and over `k`'s validity, whatever its issuer, and has no `Step` |
| 10 | The asker is the key's controller alone | definition | `Authorised`'s first branch: no policy |
| 11 | A rule naming the other as approver means the approvals include its own | definition | `Satisfies` for `.exactly` |
| 11a | A planned check, present under every rule | source, definition | `KeepsAnAdmin` is one of the planned parts (the source readings); it is a premise of `Step` constructors, and `Step` takes any `ask` |
| 11a | This is about a team certificate going | result | The hypothesis |
| 11a | A revocation can still leave no admin: three cases | result | Rows 44, 47; `root_replacement_can_leave_no_admin` |
| 15 | The model does not record which approvals an act carried; the act is accepted only with such approvals | definition | `approvals` is an implicit argument of the constructor, not part of `State` |
| 16 | Construction note; so 2 holds | construction, result | The proof; row 2 holds for any act |
| 16 | As built, an agent valid in the organisation may ask where the policy has an anyPerson rule for adding a person; not stated as a theorem | definition | `builtRule`'s second disjunct |
| 18 | This covers every message an act adds | result | The hypothesis is that the act changes `sent` |
| 20 | (true in every reachable record, 14) | result | Row 14 |
| 21 | The joiner is whatever key the holder names | act | `redeem`'s `k` is any key meeting `OneTeamIfLocal` |
| 21 | That the joiner holds that key is assumed | assumption | A3 |
| 22, 35, 36, 41, 43, 44, 45, 46, 47, 48, 49 | Construction notes | construction | The proofs |
| 22 | The statement does not say who issued whom | result | The statement |
| 25 | Re-admissions change no team certificate | act | `readmitByRoot`, `readmitByParent` |
| 26 | The three need not differ | result | The statement has no inequality |
| 27 | The act is the root replacement, whose only premise is that the organisation exists | construction, act | The proof; `replaceRoot` |
| 28 | When it is the domain's owner, the key is the root key and no identity is valid after (37) | result | Row 37 |
| 28 | The holder no longer holds the current root key | act | `replaceRoot` takes the root key out of `held` |
| 28 | The model does not show the holder no longer has the former private key | definition | `held` records only which keys are held, not copies |
| 28 | Nor does the protocol | source | the source readings |
| 35, 48, 49 | A warning | process | A label |
| 25, 42 | Resting on the planned premise that `redeem`'s team is not the admin team | definition, source | The proofs close the `redeem` case with `i.team ≠ .admin`, a planned part |
| 28, 34 | Giving a key back is the planned `release` | act | `release` is a planned part |
| 50 | Resting, for the admin team through a held root key, on the planned keep-an-admin premise | act, source | `rekeyTeam`'s premise on `keep`, a planned part |
| 11a | Before and after the act | result | The hypothesis that the admin team's key is held after the act; a re-key removes it |
| 21 | Admission asked for by an invitation's bearer; a native invitation is accepted with the team controller's own key, that controller's act | source, act | `cli/go/cmd/aw/id_team.go` line 1764 at 5c2ee7bad3; the security owner's note; `admit` asked by the team key's controller |
| 50 | A grant is added only by its subject, so a grant from the team does not come back unless its subject gives it again | result | Row 19 |
| 51 | Construction note | construction | The proof |
| 51 | This is how aweb behaves as built | source | `server/src/aweb/identity_grant_auth.py` lines 196 to 217, `server/src/aweb/member_team_key.py` lines 745 to 757, at 5c2ee7bad3; the protocol seat's check (mail f8b91c44) |
| 51 | The statement does not say the grant is from that organisation | result | The statement has no `g.org` conjunct |
| 52 | Design, aweb-adzf.9, a planned effect that is not an act of the model | source, definition | The seat's ruling (mail e1749dfc); `plannedReplaceRoot` is a definition, not a `Step` constructor |
| 52 | A re-admission changes no grant, so it brings none back; a fresh grant is given under the usual premises | act | `readmitByRoot`, `readmitByParent` change no `grants`; `mintGrant` |
| 6 | Resting on the planned premises that `admit`'s and `redeem`'s team is not the admin team | definition, source | `admit`'s premise `m.team ≠ .admin` and `redeem`'s premise `i.team ≠ .admin`, planned parts |
| 21 | Resting on the planned premise that `redeem`'s team is not the admin team | definition, source | `redeem`'s premise `i.team ≠ .admin`, a planned part |
| 38 | A valid person answering for itself (`nearest_human`) says nothing about an email check | result, source | `AnswersFor.self` needs only `Valid`; row 38; the verdict's name is the protocol's (`docs/id-certificates.md`) |
| 40 | The rest of 38's three cases follows from 38 | result | Row 38 applies to any valid person |
| 41 | In every record such a key exists | result | `exists_fresh_key` |
| 42 | Locked means ...; then the organisation has no admin | definition, result | `AdminTeamLocked`; `AdminTeamLocked.no_admin` |
| 43 | A re-key keeps standing only the certificates of the members it keeps, and removes the grants from the team | result | Row 50 |

### What must never happen

One block per cell, in the table's order.

| Cell | Sentence | Kind | What makes it true |
|---|---|---|---|
| An agent passes as a person | Proved by 1 for records with one certificate each, 2 for one act, 3 for added certificates, 4 for every approval | result | Rows 1 to 4 and their conditions |
| No chain back to a root | Not true of what is built | result | The lines below |
| | Proved for valid members and admins (5) | result | Row 5 |
| | A key with no identity certificate can act in a team on its team certificate alone | definition | `InTeam`; `CanAct`'s first disjunct |
| | And so give a grant | act | `mintGrant` needs `InTeam` and a session key no current grant uses; some key is always unused (`unused_session_key`) |
| | In a team or not, it can send attributed to itself | act | `sendOwn` needs only `CanAct` |
| | In a record the system can reach, by the planned `leave` and resting on the planned premises of `admitAdmin`, `admit` and `redeem`, it can leave a team whose key is held | act, result | `leave` needs the certificate, the held key and `KeepsAnAdmin`, and no validity or registration; `KeepsAnAdmin` is vacuous outside the admin team, and a key with no identity certificate never holds an admin-team certificate in a reachable record (`admin_certificate_member_is_registered`, which rests on `new_admin_certificate_needs_valid_member`, so on the planned premises of `admitAdmin`, `admit` and `redeem`, and on `certificate_is_permanent`) |
| | A team certificate counts without the root having set the team's key | definition | `InTeam`, `GrantLive` and `admit` have no premise about the root or `rekeyTeam` |
| | The three rules require a valid member to ask; a rule letting anyone ask would not | definition | `builtRule`, `adminRule` (`Admin` needs `Valid`), `teamRule` |
| A revoked member keeps authority | Proved in reachable records: not valid, not an admin, cannot act in a team, cannot send with its own key, no live grant | result | Rows 7, 20; `sendOwn` needs `CanAct` |
| | The three rules require a valid member to ask; a rule letting anyone ask would not | definition | As above |
| | Under every rule it can still revoke a grant on itself, revoke itself, by the planned `leave` leave a held team unless it is the admin team and no other admin remains, be the key `redeem` names | act, result | `revokeGrant`, `revokeSelf` have no validity premise; `leave` has none but `KeepsAnAdmin`; `redeem` needs `OneTeamIfLocal`, which a revoked identity meets because in reachable records it is registered (row 14) |
| A revocation is undone | Proved for one act | result | `revocation_is_permanent` |
| | Not proved for several acts | process | No theorem states it |
| | A root-issued cut-off identity can be admitted again while the root key is not held | result | Row 31 |
| | With one certificate each, a member-issued one is admitted again only by that member, while valid | act | `readmitByRoot` needs `c.issuer = .root`; `readmitByParent` is asked by `.id p` with `c.issuer = .member p` and `Valid s c.org p pk`; with row 14, `c` is the identity's only certificate; only these two acts take an identity out of `revoked` |
| An identity changes organisation or kind | Proved for one act that no certificate is removed; in reachable records one certificate | result | `certificate_is_permanent`; row 14 |
| | Not proved for several acts | process | No theorem states it |
| Controlling one organisation's key changes something in another | Not true of what is built: while no key holder holds an organisation's root key, its controller can stop an identity acting in another's team and make its grant there not live | result | Row 46 |
| | It can revoke its own identity | act | `revokeByOrg`; while the root key is held, no act its controller asks for is accepted (`root_controller_cannot_act_while_held`) |
| | A revoked identity cannot act in any team, in reachable records | result | Row 7 |
| | Proved for one act: new identity and new or removed team certificates are of the key's organisation; a newly revoked identity has a certificate of it | result | `controller_stays_in_its_organisation` |
| | With one certificate each, of no other | result | Same theorem's last conjunct; row 14 |
| | Not stated for invitations, grants, held keys, cut-offs or re-admissions | result | The theorem's statement |
| A message attributed to someone who did not send it | Proved for one act, for every message the act adds | result | Row 18 |
| | That the subject gave the grant is proved for the act that adds it, not for every grant | result | Row 19; no theorem about every grant |
| A grant holder does more than send | Proved for one act | result | Rows 17, 19 |
| An invitation's holder becomes a person or an admin | Proved for one act, under every rule | result | Rows 21, 6 quantify over every `AskRule` |
| | Resting on the planned premises that `admit`'s and `redeem`'s team is not the admin team | definition, source | Rows 6 and 21; `admit`'s and `redeem`'s premises, planned parts |
| | Not proved for several acts under the built or the admin rule | process | No theorem states it |
| | Under such a team rule, the identity an invitation's holder names can become an admin in three acts, the middle one asked for by a valid agent of the organisation, which registers the joiner | result | Row 49's statement (a valid agent of the organisation asks the second act) and its construction note |
| | And in two if it is already a valid member | result | Row 48 with `invitation_route_starts_from_a_member` |
| | As 35 shows for giving a key back | result | Row 35 |
| An agent approves where a person is required | Proved for every approval | result | Rows 4, 23 |
| Being issued an identity gives team membership | Proved for one act | result | `registering_gives_no_team` |
| An unregistered key in two teams | Proved in reachable records, resting on the planned premise of `admitAdmin` | result | Row 14 and its label |
| | It holds on the supported journey; the registry's own route does not enforce it | source | the source readings |
| A key leaves its holder except ... | Proved for one act | result | Row 28 |
| The last admin's team certificate | A planned check, proved for one act | result | Row 11a |
| | The team key's controller can still remove anyone | result | Row 10 |
| | A revocation can still leave no admin: of the last admin, of an agent admin's issuer, or by a root replacement | result | Rows 44, 47; `root_replacement_can_leave_no_admin` |
| | So can a re-key of the admin team by the root's controller while the root key is not held; through a held root key it must keep an admin, a planned premise | result, act | `rekey_can_leave_no_admin`; `rekeyTeam`'s premise |
| An outsider is an admin | True by the definition | definition | `Admin` needs `Valid s o k kind` |
| A certificate for one team accepted for another | True by the definition | definition | `HasTeamCert` matches organisation and team |
| An approval reused | Assumed | assumption | A6 |
| A key holder uses a key other than the acts allow | Assumed; cannot be proved while the holder is assumed honest | assumption | A8 |
| Whoever holds a member's key speaks as it | Not in the model | assumption | A7 |
| Re-signed or re-issued as a side effect | Not in the model | act | `Fresh` premises of `registerByRoot` and `registerByParent`; `certificate_is_permanent`; A7 |

### What is assumed

Assumptions 1 to 10 are taken as given, not proved. Two sentences in them are about the real system.

| Sentence | Kind | What makes it true |
|---|---|---|
| A server caches a team's revocations for 60 s and serves them stale for 60 s more | source | `docs/aweb-sot.md`, "Caching from awid" |
| In that window a removed member can still give a grant, and its grant still works | source | Same |

### Where the model does less than the real system

Each item pairs a sentence about the model with one about the real system.

| Sentence | Kind | What makes it true |
|---|---|---|
| Nothing here is about time, crashes, retries or concurrent changes | assumption | A4, A5 |
| `replaceRoot` cuts off every unrevoked identity of the organisation at once | act | `replaceRoot` |
| Really the cut-off is derived at verification from replacement epochs; the open epoch's own key cuts nothing off | source | `awid/src/awid_service/routes/dns_namespaces.py` lines 705 to 712, `awid/src/awid/id_certificates.py` lines 855 and 856, at 5c2ee7bad3 |
| `createOrg` is fresh creation; the registry returns an existing namespace without creating or replacing it | act, source | `createOrg`'s premise `o ∉ s.orgs`; `awid/src/awid_service/routes/dns_namespaces.py` lines 391 to 418 |
| Really by time of registration, with a backdated option; dual-signed rotation and parent recovery exist | source | the source readings |
| Neither a dual-signed root rotation nor a parent's recovery of a child organisation is modelled | definition | No `Step` constructor does either |
| Re-admission puts the same certificate back in force | act | `readmitByRoot`, `readmitByParent` take the subject out of `revoked` and `cutOff` and change no certificate |
| Really a new signed certificate, through the one registration route that serves every supersession, and the new root can admit anyone it keeps; the route does not check "cut off" | source | `awid/src/awid_service/id_registration.py` at 5c2ee7bad3, line 95 |
| Having a key given back is planned, and under `builtRule` its premises are never met | result, source | `no_release_premises_as_built`, `built_never_authorises_release`; `release` is a planned part |
| The built key holder has no command to give a key back | source | the source readings |
| In the model the key comes back whole | act | `release` changes only `held` |
| The protocol documents describe leaving a key holder by a new key that the old and the new both sign | source | the source readings |
| One certificate per identity | result | Row 14 |
| Really one current certificate per identity, earlier revisions kept; naming the expected head supersedes it, which re-parents | source | `awid/src/awid_service/id_registration.py` at 5c2ee7bad3, lines 89 to 106 and 155 to 170 |
| Creating and deleting teams is not modelled | definition | `OrgKey` and `Team` are fixed; no act creates a team |
| A root replacement leaves the team keys where they were | act | `replaceRoot` filters only `.root o` from `held` |
| The root re-keys a team by a separate act | act | `rekeyTeam` |
| A re-key takes the team's key out of `held`, keeps standing only the given members' certificates, and ends every grant from the team | act | `rekeyTeam` filters `held`, `members` (keeping `keep`) and `grants` |
| Asked through a held root key for the admin team, it must keep an admin | act | `rekeyTeam`'s premise on `keep` |
| As `remove` must when the admin team's key is held, and `leave` always must | act | `remove`'s `KeepsAnAdmin` premise applies when the team's key is held; `leave`'s always |
| These keep-an-admin checks are planned; the registry has none | source | `KeepsAnAdmin` and `rekeyTeam`'s premise on `keep` are planned parts; the source readings (the registry has no last-admin check) |
| Really the rotation re-signs the members it is given with new certificates in the same act | source | awid `rotate_team_key` at 5c2ee7bad3; the protocol seat's E7.3 disposition |
| A legacy grant with no stored issuing certificate stays eligible once its subject is a member again | source | `server/src/aweb/identity_grant_status.py` lines 125 to 130 at 5c2ee7bad3 |
| The model's grants have no such case | definition, act | `Grant` stores no issuing certificate; `remove`, `leave` and `rekeyTeam` remove the grants on a team certificate that goes |
| `controller key` is whoever controls that key now; the old one cannot be named | definition | `Party.controller` names a key, not a holder |
| The operator is not modelled; whoever controls a key asks directly only while it is not held | definition | `Authorised`'s first branch needs `key ∉ s.held`; `entrust` needs `key ∉ s.held` |
| Really a generic allowlisted routine signer that checks the exact controller and refuses person issuance, beside named person commands | source | The security owner's note, via the protocol seat (mail 5ff1d5fb) |
| `builtRule` is the public requester path; the operator is trusted and outside it | source | The protocol seat's E7.3 disposition (mail b3dd950b) |
| Policy is given and checked only when a key holder holds the key | definition | No act changes `policy`; `Approved` is only in `Authorised`'s held branch |
| Really servers and applications enforce approval | source | the source readings |
| A team certificate is one record | definition | `Membership` has no id |
| Really revoked by id, missing told from revoked | source | the source readings |
| A grant can send or not | definition | `Grant.maySend` |
| Really ten scopes and expiry | source | the source readings |
| `sendOwn` stands for an accepted send | act | `sendOwn` |
| Really the server checks key, identity and recipient rules | source | the source readings |
| An invitation is an ordinary invitation; a privileged admin admission is planned at the grantor (aweb-adyx.8) | source | The protocol seat's E7.3 disposition |
| An invitation is used once, for one team | act | `redeem` removes it; `Invite` names one team |
| Really several uses, expiry, a named answerer | source | the source readings |
| A secret is new only among unused invitations; a session key only among current grants | act | `invite`'s and `mintGrant`'s freshness premises |
| "Has an identity certificate" is one thing here | definition | `Registered` |
| Really three things | source | the source readings |
| The record keeps only who each message is attributed to | definition | `Message` |
| No answer covers both "nobody" and "cannot be established" | definition | `AnswersFor` is a `Prop` with no reason |
| The protocol tells them apart | source | the source readings |
| Named-team certificates and invitations need no organisation to exist | act | No premise of `admit`, `redeem` or `invite` mentions `orgs` |
| Nobody holds a member's own key for it | assumption | A7 |
| Premises of built acts that the registry does not check: `OneTeamIfLocal`, and an invitation's authority, unique secret and being unused | source | aweb 5c2ee7bad3 at the files and lines the item cites |
| So one certificate each holds of the model, not of the registry | result, source | Row 14 rests on the `Fresh` premises; the registry gives superseding certificates |

### Not done

| Sentence | Kind | What makes it true |
|---|---|---|
| It is not yet run against the code; the model runs and generates its first batch | process | `run` and the generator exist (rows 91 to 93); the runner has not run the file |
| Several definitions were corrected after the last source check | process | The list given there |

## TrustWeb/Model.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | What the file holds | process | File contents |
| every definition, field and `Step` constructor doc | A near-literal reading of its body: for a constructor, its asker, premises and effect | definition, act | Each body |
| `builtRule` | "As built" | source | The source readings: the self-hosted key holder |
| `adminRule` | "Planned" | source | The design documents among the source readings |

## TrustWeb/Properties.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | What the file holds | process | File contents |
| `Steps` | A sequence of accepted acts under `ask` takes `s` to `s'` | definition | Its constructors |
| `new_person_is_vouched_for` | The statement does not say the certificate is `k`'s; it looks at certificates only | result | The statement |
| `valid_has_chain_to_root` | Leading means ...; kind, revocation, issuers' validity not part of it | definition | `ChainToRoot` |
| `new_admin_needs_controller_or_asker` | So it is not an invitation's holder | result | `.bearer` is neither disjunct |
| `revoked_has_no_authority`, `revoked_cannot_act`, `grant_ends_with_subject` | In reachable records only registered identities are revoked | result | `Reachable.revokedAreRegistered` |
| `revoked_cannot_act` | Sending, acting in a team and a live grant need `CanAct` | act, definition | `sendOwn`, `InTeam`, `GrantLive` |
| `grant_ends_with_subject` | `revokeSelf`, `revokeChild`, `revokeByOrg` and `replaceRoot` leave the grants as they are | act | Their effects |
| `person_survives_others` | About the record, not an act | result | The statement has no `Step` |
| `orphaned_agent_cannot_act_in_team` | Its team certificates are not looked at | result | The statement |
| `admin_can_remove_admin` | A rule naming `b` as approver means the approvals include `b`'s | definition | `Satisfies .exactly` |
| `key_holder_keeps_an_admin` | A planned check | source | `KeepsAnAdmin` is one of the planned parts; the registry has no such check (the source readings) |
| `key_holder_keeps_an_admin` | A revocation can still leave no admin | result | `revocation_can_leave_no_admin` |
| `built_person_needs_a_person` | The model does not record which approvals an act carried | definition | `approvals` is an implicit argument of the constructor, not part of `State` |
| `controller_stays_in_its_organisation` | Nothing stated about invitations, grants, held keys, cut-offs, re-admissions | result | The statement |
| `design_agent_admin_can_ask_for_person` | Construction note | construction | The proof |

## TrustWeb/Abilities.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | What the file holds | process | File contents |
| `approved_act_goes_through` | `a`, `p`, `k` need not differ | result | The statement |
| `runs_without_key_holder` | The statement does not say who issued whom | result | The statement |
| `no_admin_no_new_admin_certificate` | Re-admissions change no team certificate | act | `readmitByRoot`, `readmitByParent` |
| `AdminTeamLocked` | Its body, read literally | definition | Body |
| `plannedReplaceRoot` | The record `replaceRoot` gives, with the grants on the identities it cuts off removed | definition | Its body |
| `plannedReplaceRoot`, `planned_replacement_ends_cut_off_grants` | Planned, aweb-adzf.9; Design | source | The protocol seat's ruling (mail e1749dfc) |
| several | Construction notes | construction | The proofs |

## TrustWeb/Operations.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | What the file holds | process | File contents |
| `Assignment`, `teamRule` | Their bodies, read literally | definition | Bodies |
| `assigned_team_can_take_key_back`, `only_assigned_team_takes_key_back`, rows 33 and 34 | "Any assignment" | result | Both quantify over `assign` |
| `invitation_reaches_an_assigned_team` | `admit`, `invite`, `redeem` exclude the admin team; no premise excludes an assigned team | act | Their premises |
| `invitation_reaches_an_assigned_team` | Not proved for every assignment and team | result | The statement is one example |
| `invitation_reaches_an_assigned_team`, `invitation_then_own_request_makes_an_admin`, `outsider_becomes_admin_in_three_acts` | Construction notes | construction | The proofs |

## TrustWeb/Core.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | An experiment: six of the acts, and results proved for them | definition, process | `CoreStep` has six constructors; the author's intent |
| `CoreStep` | The six acts of the core, each exactly as in `Step` | definition | Its constructors |
| `CoreReachable` | The records the core can reach | definition | Its constructors mirror `Reachable` over `CoreStep`; `CoreReachable.toReachable` |
| title, section heading | "Six acts and five properties"; "The five, in the core" | process | The theorems `core_one` to `core_five`, with `core_two_design` beside `core_two` |
| `core_one` | `agents_cannot_approve_as_person` holds in any record | result | That theorem takes any `s` |
| `core_three` | The three rules let only valid members ask; a rule letting anyone ask would not | definition | `builtRule`, `adminRule`, `teamRule` |

## TrustWeb/Evidence.lean

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | Planned evidence, kept as a list of assertions outside the record | source, definition | `docs/id-certificates.md`; `State` has no field for it |
| `Enrolment`, `Assertion` and the three definitions | Near-literal readings of their bodies | definition | Bodies |
| `Enrolment.controller`, `Enrolment.hostedEmail` | What each tag names: an assertion by the organisation's domain controller; one by a hosted service, for an email enrolment | source | `docs/id-certificates.md`; the protocol seat's wording |

## TrustWeb/Spheres.lean and the README's trust spheres section

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| README, module doc | `Spheres.lean` adds where secrets sit and changes nothing in the model | process | The file imports the model and declares only new names; no other model file changes |
| README | A sphere is any place whose secrets are reachable together; the layer does not say what a sphere is | definition | `Sphere` is a number; nothing else is said of it |
| README, `Party.secret` | Each party asks with one secret, of five kinds | definition | `Secret`, `Party.secret` |
| README, `Secret.approval` | A person also holds the credential it enrolled to approve with, in aweb a key of its own, not its identity key | definition, source | `Secret.approval`; `docs/human-approval-architecture.md` (the enrolled key signs the challenge); the key holder's enrolment binds credentials beside the identity key; the approval service verifies a receipt with the enrolled credential's key |
| README, `World` | A world is a record, the secrets each sphere holds, and the secrets each sphere got from acts | definition | `World` |
| README, `WStep` | A step is an act asked from a sphere holding the asker's secret, after which that sphere holds and has got every secret the act gives, or a leak from a persuadable sphere to one it talks to | definition | `WStep.act`, `WStep.leak` |
| README, `SphereActs.lean` | `SphereActs.lean` gives the secrets and the acts that give them | definition | `Secret`, `Party.secret`, `StepVia` |
| README, `StepVia` | Creating an organisation and replacing its root give the root key they make, a re-key the team's new key, an invitation its secret, a grant its session key, and having a key given back that key; no other act gives a secret | definition, source | `StepVia`'s `received` lists; awid's namespace registration and controller rotation require the caller's signature with the new controller key (awid routes, dns namespaces); `rotate_team_key` installs the caller's new team key, which the CLI makes; the CLI makes a grant's session key; an invitation's token is returned to whoever asks for it |
| README | Who talks to whom and who is persuadable are parameters | definition | `WStep`'s and `WReachable`'s arguments |
| README, three defs | The three worlds | definition | `noneSwayed`, `agentsSwayed`, `agentsAndPersonsSwayed` |
| `WReachable`, `Flows`, `Occupant` | Their meaning | definition | Their bodies |
| 60 | Construction note | construction | The proof |
| README | In `WStep` an approval is not tied to a sphere, so approvals there rest on assumption 6 | definition, assumption | `Step`'s constructors take `approvals` as an implicit argument that `WStep` does not see; A6 |
| README | An identity key, an approval credential and a DNS credential are never given by an act; the initial placement may give a sphere identity keys no record names yet | definition | `Secret.Givable`; `WReachable.start` takes any `init` |
| README | Such a key already lets its holder send | act | `sendOwn` needs only `CanAct`, which an unregistered key meets |
| README | An invitation secret or a session key held before its record exists gives nothing | act | `redeem` needs the invitation unused; `sendGrant` needs the grant live |
| README | A team's first key is placed too, since the model does not create teams | definition | No `Step` constructor creates a team |
| README | After a re-key or a root replacement the asking sphere holds the new key; copies of the old one still count, which can only overstate their holders | definition | `WStep.act` adds the received secrets to the asking sphere and keeps `holds`; `Party.secret` maps a key's controller to the key's name, not to a version of it |
| README | A key given back goes to the sphere that asked for it; `release` does not say to whom, and the asker is the most it can overstate | definition | `StepVia.release` gives `[.orgKey key]`; `release`'s effect only removes the key from `held` |

## TrustWeb/SphereApprovals.lean and the README's approvals section

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| README | `SphereApprovals.lean` changes nothing in the model | process | The file imports the model and declares only new names |
| README, 61 | `StepVia` is the model's acts with their approvals and the secrets each gives the asker; an act with no `Authorised` premise carries no approvals | definition | `StepVia`'s constructors; each passes `approvals` only where `Authorised` takes them, else `[]` |
| 61 | Generated from `Step` | process | Its text was generated from `Step`'s |
| README, `Available`, `AStep` | An adversarial sphere's act counts an approval only when available to it: it holds the approval credential or the identity key, or a persuadable holder of one talks to it | definition | `Available`, `Secret.ApprovesAs`; `AStep.act`'s third premise |
| README | aweb's approvals are signed with the approval credential; counting the identity key too can only overstate its holder | source, definition | `docs/human-approval-architecture.md`; `Available` is a disjunction over both |
| README | Which spheres are adversarial is a parameter; an honest sphere that is not persuadable never approves an adversarial request | definition | `AStep`'s `Adv`; `Available` has no case for such a sphere |
| README, `NamedStep` | Redeeming adds a certificate for the key the invitation names | definition | `NamedStep.redeem` |
| README, `NamedStep` | Planned | source | A proposed design; aweb's invitations do not name an identity |
| 65 | "Whoever asks" | result | The theorem quantifies over `who` |
| 68 | Resting on the planned premises of `admit` and `redeem` | result | It uses `new_admin_needs_controller_or_asker`, row 6 |
| README | These results do not say a persuaded person's approval can be refused | definition | No result above has such a conclusion |
| README | Row 68 joins the layer to one act; rows 69 to 74 bound a chain | result | Row 68's theorems take one `Step`; rows 69 to 71 take an `Attack`; row 74 builds one |

## TrustWeb/SphereAdmins.lean and the README's chain section

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| README, `Attack` | Only the attacker acts, with any secret it holds and no approval beyond the model's premises; it holds every secret its acts give | definition | `Attack.act` takes the attacker's held secret and a `StepVia`, whose approvals are not checked, and adds its received secrets to the attacker |
| README | Which can only overstate it | definition | An `Attack` act has no premise beyond `StepVia`'s and the held secret |
| README, `Attack` | Persuadable spheres give secrets to the spheres they talk to | definition | `Attack.leak` |
| README | What a persuaded agent could do with its keys, the attacker can do once they reach it | definition | Every act needs only `who.secret` held by the attacker; leaks move secrets one at a time along `Flows` |
| README, `CanReach` | Its meaning | definition | Its body |
| 70 | Resting on the planned premises of `admit` and `redeem` | result | It uses `new_admin_needs_controller_or_asker`, row 6 |
| 72 | The Design rule is planned | source | `adminRule`, row 72 names it |
| 73, 74 | Construction notes | construction | The proofs |
| README | Row 70 says the attacker never gains an admin's key; an attack that begins with one within its reach is outside it | result | Its premises are about the world when the attack begins |
| README | It does not bound what honest spheres do | definition | Only the attacker acts in `Attack` |
| README | Rows 73's and 74's starting worlds are any record; row 48 reaches one of row 73's kind | result, construction | Both theorems build their record without `Reachable`; `invitation_then_own_request_makes_an_admin` |
| README | The DNS credential is in row 70's premises for the same reason as the root key | act, result | `replaceRoot` gives the root key (`StepVia.given_root`); a root key then re-keys the admin team as in row 74 |
| README | Having a key given back is in row 70's rule premise for the same reason | act | `StepVia.release` gives the key to the asker (`StepVia.given_root`, `StepVia.given_team`) |

## TrustWeb/Decide.lean, Run.lean, Emit.lean and the README's running section

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| README, module docs | `Decide.lean` decides every condition the acts check, each proved to agree with its definition | result | Each decision is a `Decidable` instance built by `decidable_of_iff` from a proved equivalence, or derived from instances that are |
| README, `CertChain`, `chainB` | Chains of certificates, and the search over them | definition | Their bodies |
| README, `Act`, `Act.checks`, `Act.effect`, `run`, `Check`, `firstFailing` | A request, its named checks in the constructor's order, its effect, and what `run` returns | definition | Their bodies; each act's checks list the premises of its `Step` constructor in order |
| `AskedByIssuer`, `IssuerValid`, `ByMember`, `rootCut`, `AskDecidable`, `Act.Accepted` | Their meaning | definition | Their bodies |
| README | `lake exe trust-web-cases` followed by the model commit prints the cases, written to the vectors file | process | The entry point at the end of `Emit.lean`, and the lakefile's executable entry |
| README | The first batch: the acts, no held key, an allowed case per act and a refusal per premise the batch can make fail | definition | `Emit.cases` |
| README | Each refusal fails exactly one premise, the one it names, so it agrees with the code in any check order | definition | The count of false checks in `Emit.Case.json` |
| README | Each refusal's neighbour is allowed and differs in exactly one of setup, party and arguments; a party the arguments fix in both changes with them | definition | `Emit.changes`, `Emit.followingParty`, `Emit.partyFollows`, `Emit.checkNeighbours`, called by `Emit.document` |
| README | Checks that depend on another premise hold vacuously when it fails; all the checks together are the constructor's premises, and each fails alone | definition, result | `ByMember`, `AskedByIssuer`, `IssuerValid` and the MayIssue check's form in `Act.checks`; `step_iff_run` |
| README | A refusal is written only if no act on its route allows the same request; which acts share a route | definition, source | `Emit.routeMates` and its use in `Emit.Case.json`; AWID's one identity-revocation route names the subject and the signer, not the constructor |
| README | `remove`'s last-admin premise can fail only when the team's key is held | act | The premise of `remove` |
| README | Every request goes through `run`; the generator refuses on a refused setup request, an unintended outcome, a refusal not failing exactly its named premise, a bad neighbour or a route mate that allows the request | definition | `Emit.Case.json`, `Emit.checkNeighbours` |
| README | So every verdict and premise in the file is the model's by rows 92 and 93 | result | `step_iff_run`, `run_error_premise` |
| README | What the cases observe | definition | `Emit.Obs`, `Emit.Obs.json` |
| README | Propagation: after an identity or team-certificate revocation, except a refused grant mint for a subject not in the team, judged at once because creating authority reads revocation fresh under the planned E7 rule; revoking a grant has no wait, since the server reads its own grant record directly | definition, source | `Emit.revokes` and `Emit.Case.json`; the runner invalidates the server's cached team revocations and reads identity status uncached; the planned E7 fresh read at grant mint, which the runner's seeds pin as immediate |
| README, `CasesCheck.lean` | The build fails unless the committed file's format, emitter and cases are the generator's output | process | `#cases_file_current` in the `DocCheck` library, which the default build runs |
| README | The cases are not proved to cover every premise; the code passing them shows agreement on these cases only | definition | No theorem is about coverage |
| README | Running them against the code is the runner's | source | The runner in the aweb server's tests |
| `Emit.keyName`, `Emit.orgName` and the other renderers | The runner's names and forms | source | The runner's seed cases |

## TrustWeb/DocNames.lean

Its doc comments are about the build, not the model.

| Where | Sentence | Kind | What makes it true |
|---|---|---|---|
| module doc | What the check is | process | `#doc_names_resolve` and its file list |
| `skipped`, `leanNames`, `modelTypes`, `inductives` | What each list is for | process | Their use in `passes`, `resolvesInModel`, `isConstructorOfModel` |
| `backquote`, `runs`, `passes`, `isPathOrCommand`, `quoted`, `failures` | Each reads its body | process | Their bodies |
| `#doc_names_resolve` | Fails if a file cites an identifier that does not pass | process | Its body |
