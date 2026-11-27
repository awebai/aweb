/-!
# The trust web: the model

What exists, what is currently true, and the acts that change it. The proofs
are in `Properties.lean`.

Sources, all in this repository: `docs/id-certificates.md` (sections 1 to 3
and 6), `docs/teams.md`, `docs/human-approval-architecture.md`,
`docs/trust-model.md`, `docs/identity.md` ("Session grants"), the server's
grant code and the key holder. The protocol's word for a person is "human".

Experimental. Not yet checked against the code. See the README for what has
been checked.

## What is built and what is design

Everything here describes aweb as built, except the rule for who may ask a
key holder and the four things listed below. That rule is a parameter, `AskRule`. Two values are
here; `Operations.lean` adds a third, `teamRule`, the general form of the
second.

* `builtRule`: what the self-hosted key holder does today.
* `adminRule`: the planned design, in which an organisation's members are
  people and agents alike: an admin asks.

Four more things are planned design, kept in the model because the design
needs them. They are acts and checks under every rule, `builtRule` included:

* `entrust` and `release`. The built key holder makes its keys inside itself
  and has no command to take a key in or give one back.
* `KeepsAnAdmin`: a key holder not removing the last admin. The registry has
  no such check.
* `leave`: a member leaving by asking a key holder. The built command drops
  the member's own copy and does not end the certificate.
* An invitation never leading into the admin team. The registry does not
  know which team is the admin team.

A result stated for any rule holds for each of them, and for any rule chosen
later. Results under `builtRule` are proved over acts that include the four
planned things.

## Assumptions (taken as given, not proved)

* **A1. Signatures.** A signature cannot be forged. A statement signed by a
  key exists only because whoever holds that key signed it.
* **A2. Enrolment.** The root issues a person certificate only to a human
  being who took part themselves. How an organisation checks that is its own
  process.
* **A3. The subject's key.** Whoever is registered, or joins a team, proved
  they hold the key.
* **A4. One current record.** Everyone sees the same record at once. In the
  real system a verifier may go on accepting for a bounded time after a
  revocation.
* **A5. One act at a time.** Each act happens whole, and acts do not overlap.
  Crashes, retries and two changes at once are not modelled.
* **A6. Approvals.** An approval is given by the identity it names, for the
  exact act, and cannot be reused.
* **A7. Keys.** An identity keeps one key, and only its owner uses it. Key
  rotation, and anyone holding an identity's key for it, are not modelled.
* **A8. The key holder.** A key holder that holds an organisation's key uses
  it only as `Authorised` says. Nobody outside can check this.
* **A9. The server.** The server that keeps the grants attributes a message to
  an identity only as `Step` says. Only that server can check a grant.

## Restrictions (the real system does more)

* **Replacing a root key cuts off every identity at once.** Really the
  cut-off is by time of registration, and a root can also set a backdated
  cut-off. Admitting an identity again is, really, a new signed certificate
  for the same identity and key; here the same certificate stands again, and
  only its original issuer can admit it, where really the new root can admit
  anyone it keeps. A delegated child organisation can also be recovered by
  its parent; that path is not modelled.
* **A key leaves a key holder whole.** Really the organisation makes a new key
  and the old and new keys both sign the change. The effect is the same:
  everything issued before stays valid.
* **One certificate per identity.** In the real system an identity's
  organisation and kind are fixed, but it can be moved to another parent.
* **Every team has a key.** Creating, deleting and rotating teams and their
  keys are not modelled. Nor is the root replacing a team's key.
* **Policy is given.** Who may change an organisation's policy is not modelled.
* **A team certificate is one record.** The registry revokes a certificate by
  its id and tells a missing one from a revoked one.
* **`AnswersFor` with no answer** covers both "no person answers" and "cannot
  be established". The protocol tells them apart.
* **A grant here can send or not.** Really it has ten scopes (reading,
  subscribing, contacts, presence, coordination) and may expire. What the
  model claims is only that a grant never gives control of identities, keys,
  teams or grants.
* **Sending with your own key** stands for a send the server accepted. Really
  it checks the key is current, the identity valid, and the recipient's rules.
* **The key holder's operator** is modelled as whoever controls the key
  directly. Really the operator acts through the holder's named commands,
  which are narrower.
* **Registered** stands for three real things: a local key with no public
  identity, a public identity with a registered key, and enrolment in the
  identity tree. The one-team rule is about the first. It holds on the
  supported journey; the registry's own route does not enforce it.
* **An invitation here is used once, for one team.** Really it may allow
  several uses, expire, and name the person its joiner must answer to.
* **Messages go nowhere.** The record keeps who each message is attributed to.
  Delivery, reading and encryption are not modelled.
-/

namespace TrustWeb

/-- A key. Whoever holds it can sign as it. An identity is its key (A7). -/
abbrev Key := Nat

/-- An organisation: a domain. -/
abbrev Org := Nat

/-- The two kinds of member. -/
inductive Kind where
  | person
  | agent
  deriving DecidableEq, Repr

/-- Who issued an identity certificate: the organisation's root, or one of its members. -/
inductive Issuer where
  | root
  | member (k : Key)
  deriving DecidableEq, Repr

/-- A team of an organisation: its admin team, or a named team. -/
inductive Team where
  | admin
  | named (n : Nat)
  deriving DecidableEq, Repr

/-- An organisation's keys: its root key, and one key per team. The root key
signs identity certificates and revocations. A team's key signs that team's
certificates. -/
inductive OrgKey where
  | root (o : Org)
  | team (o : Org) (t : Team)
  deriving DecidableEq, Repr

/-- Who can ask for an act: whoever controls an organisation's domain in DNS;
whoever controls one of its keys directly; an identity; whoever holds a
grant's session key; or whoever holds an invitation's secret.

`controller key` means whoever controls that key **now**. After the domain's
owner replaces a root, `controller (.root o)` is whoever controls the new root
key. The model cannot name whoever controlled the old one, and says nothing
about them. A team's key is not replaced by a root replacement: whoever
controlled it before still does. -/
inductive Party where
  | dns (o : Org)
  | controller (key : OrgKey)
  | id (k : Key)
  | session (k : Key)
  | bearer (token : Nat)
  deriving DecidableEq, Repr

/-- An identity certificate: in organisation `org`, `issuer` says that
`subject` is a member of this `kind`. -/
structure Cert where
  org : Org
  subject : Key
  kind : Kind
  issuer : Issuer
  deriving DecidableEq, Repr

/-- A team certificate: `member` is in `team` of `org`. The member can be an
outsider, with an identity in another organisation or none registered. -/
structure Membership where
  org : Org
  team : Team
  member : Key
  deriving DecidableEq, Repr

/-- The acts an organisation's keys are used for. -/
inductive ActKind where
  | registerPerson
  | registerAgent
  | revoke
  | admit
  | admitAdmin
  | remove
  | release
  deriving DecidableEq, Repr

/-- Whose approval a rule asks for: any person of the organisation, or one named member. -/
inductive Approver where
  | anyPerson
  | exactly (k : Key)
  deriving DecidableEq, Repr

/-- One line of an organisation's policy: this kind of act needs this approval. -/
structure Rule where
  org : Org
  act : ActKind
  approver : Approver
  deriving DecidableEq, Repr

/-- A grant: `subject` lets whoever holds the fresh key `session` act as it,
on the server of team `team` of `org`. -/
structure Grant where
  session : Key
  subject : Key
  org : Org
  team : Team
  maySend : Bool
  deriving DecidableEq, Repr

/-- An invitation: whoever holds the secret `token` may join team `team` of `org`. -/
structure Invite where
  token : Nat
  org : Org
  team : Team
  deriving DecidableEq, Repr

/-- A message, as the server attributes it. -/
structure Message where
  sender : Key
  deriving DecidableEq, Repr

/-- The current record. -/
structure State where
  /-- The organisations that exist. -/
  orgs : List Org
  /-- The registered identity certificates. -/
  certs : List Cert
  /-- The identities that are not current: revoked, or cut off by a root replacement. -/
  revoked : List Key
  /-- Those among them that a root replacement cut off. They can be admitted again. -/
  cutOff : List Key
  /-- The team certificates that stand. -/
  members : List Membership
  /-- Every organisation's policy. -/
  policy : List Rule
  /-- The organisation keys that a key holder holds. -/
  held : List OrgKey
  /-- The grants that stand, at the server that keeps them. -/
  grants : List Grant
  /-- The invitations not yet used. -/
  invites : List Invite
  /-- The messages sent. -/
  sent : List Message

/-! ## What a verifier concludes -/

/-- Rule R1. A person can issue people and agents. An agent can issue only agents. -/
def MayIssue (issuer child : Kind) : Prop :=
  issuer = .person ∨ child = .agent

/-- `Person s o k`: in organisation `o`, `k` holds a person certificate issued
by the root or by a person. Revocation is not looked at here; `Valid` does that. -/
inductive Person (s : State) (o : Org) : Key → Prop where
  | byRoot {c : Cert} {k : Key} :
      c ∈ s.certs → c.org = o → c.kind = .person → c.issuer = .root → c.subject = k →
      Person s o k
  | byPerson {c : Cert} {k p : Key} :
      c ∈ s.certs → c.org = o → c.kind = .person → c.issuer = .member p → c.subject = k →
      Person s o p → Person s o k

/-- `Valid s o k kind`: `k` is now a member of organisation `o`, of this kind.

* A person is valid if their chain holds and they are not revoked. Their issuer
  was checked when they were registered; its later revocation does not undo them.
* An agent is valid if it is not revoked and its issuer is the root or is valid now. -/
inductive Valid (s : State) (o : Org) : Key → Kind → Prop where
  | person {k : Key} :
      Person s o k → k ∉ s.revoked → Valid s o k .person
  | agentOfRoot {c : Cert} {k : Key} :
      c ∈ s.certs → c.org = o → c.kind = .agent → c.issuer = .root → c.subject = k →
      k ∉ s.revoked → Valid s o k .agent
  | agentOf {c : Cert} {k p : Key} {pk : Kind} :
      c ∈ s.certs → c.org = o → c.kind = .agent → c.issuer = .member p → c.subject = k →
      k ∉ s.revoked → Valid s o p pk → Valid s o k .agent

/-- `ChainToRoot s o k`: certificates lead from `k` up to the root of `o`. -/
inductive ChainToRoot (s : State) (o : Org) : Key → Prop where
  | root {c : Cert} {k : Key} :
      c ∈ s.certs → c.org = o → c.issuer = .root → c.subject = k → ChainToRoot s o k
  | link {c : Cert} {k p : Key} :
      c ∈ s.certs → c.org = o → c.issuer = .member p → c.subject = k →
      ChainToRoot s o p → ChainToRoot s o k

/-- `AnswersFor s o a h`: person `h` answers for `a`. A person answers for
themselves. For an agent it is the nearest person up its chain; with one
certificate each, the only one (`answerer_unique`). An agent whose
chain reaches the root through agents only has nobody. -/
inductive AnswersFor (s : State) (o : Org) : Key → Key → Prop where
  | self {h : Key} : Valid s o h .person → AnswersFor s o h h
  | up {c : Cert} {a p h : Key} :
      c ∈ s.certs → c.org = o → c.kind = .agent → c.issuer = .member p → c.subject = a →
      a ∉ s.revoked → AnswersFor s o p h → AnswersFor s o a h

/-- `k` has an identity certificate, revoked or not. -/
def Registered (s : State) (k : Key) : Prop :=
  ∃ c, c ∈ s.certs ∧ c.subject = k

/-- `HasTeamCert s o t k`: a team certificate for `k` in team `t` of `o` stands. -/
def HasTeamCert (s : State) (o : Org) (t : Team) (k : Key) : Prop :=
  ⟨o, t, k⟩ ∈ s.members

/-- `CanAct s k`: `k` is not a registered identity, or it is one and is valid
now in some organisation (with one certificate each, its own). Where only
registered identities are revoked, as in every reachable record, a revoked or
cut-off identity cannot act (`revoked_cannot_act`). -/
def CanAct (s : State) (k : Key) : Prop :=
  ¬ Registered s k ∨ ∃ o' kind, Valid s o' k kind

/-- `InTeam s o t k`: `k` can act in team `t` of `o`. It holds the team
certificate and can act. An unregistered member has only its team
certificate: no certificate leads from it to a root. -/
def InTeam (s : State) (o : Org) (t : Team) (k : Key) : Prop :=
  HasTeamCert s o t k ∧ CanAct s k

/-- `Admin s o k`: `k` is in the admin team of `o` and is a valid member of `o`,
of either kind. An outsider is never an admin. -/
def Admin (s : State) (o : Org) (k : Key) : Prop :=
  ⟨o, .admin, k⟩ ∈ s.members ∧ ∃ kind, Valid s o k kind

/-! ## Approval -/

/-- The approvals given satisfy what a rule asks for. -/
def Satisfies (s : State) (o : Org) (approvals : List Key) : Approver → Prop
  | .anyPerson => ∃ k, k ∈ approvals ∧ Valid s o k .person
  | .exactly k => k ∈ approvals ∧ ∃ kind, Valid s o k kind

/-- The approvals given satisfy every rule the organisation has for this kind of act. -/
def Approved (s : State) (o : Org) (act : ActKind) (approvals : List Key) : Prop :=
  ∀ r, r ∈ s.policy → r.org = o → r.act = act → Satisfies s o approvals r.approver

/-- The organisation a key belongs to. -/
def OrgKey.org : OrgKey → Org
  | .root o => o
  | .team o _ => o

/-- A rule for who may ask a key holder: in this record, for this
organisation and this kind of act, may identity `k` ask? -/
abbrev AskRule := State → Org → ActKind → Key → Prop

/-- As built. The self-hosted key holder adds a person in two cases. With no
approval configured, a valid person of the organisation asks. With a person's
approval configured for adding a person, any valid member of the organisation
asks, agent included, and `Approved` then requires a person's approval. The
same request re-admits a cut-off person directly under the root
(`readmitByRoot`, which asks for `registerOf .person`). It signs nothing else
on a member's request, and never gives a key back. -/
def builtRule : AskRule :=
  fun s o act k => act = .registerPerson ∧
    (Valid s o k .person ∨
      ((∃ r, r ∈ s.policy ∧ r.org = o ∧ r.act = .registerPerson ∧ r.approver = .anyPerson) ∧
        ∃ kind, Valid s o k kind))

/-- The design. An admin of the organisation may ask for any of these acts. -/
def adminRule : AskRule :=
  fun s o _ k => Admin s o k

/-- `Authorised ask s key act who approvals`: `key` signs this act when `who` asks.

* If nobody holds the key for the organisation, whoever controls it signs
  directly. No policy applies: nothing stands between them and the key.
* If a key holder holds it, an identity the rule `ask` allows asks, with the
  approvals the organisation's policy names (A8). -/
def Authorised (ask : AskRule) (s : State) (key : OrgKey) (act : ActKind) (who : Party)
    (approvals : List Key) : Prop :=
  (key ∉ s.held ∧ who = .controller key) ∨
  (key ∈ s.held ∧ ∃ k, who = .id k ∧ ask s key.org act k ∧ Approved s key.org act approvals)

/-- The kind of act that registers a member of this kind. -/
def ActKind.registerOf : Kind → ActKind
  | .person => .registerPerson
  | .agent => .registerAgent

/-- `GrantLive s g`: the grant stands and its subject can still act in the
team it was issued from. A grant is tied to the team certificate it came
from: removing that certificate removes the grant (see `remove`, `leave`), so
a later certificate for the same member does not bring it back. -/
def GrantLive (s : State) (g : Grant) : Prop :=
  g ∈ s.grants ∧ InTeam s g.org g.team g.subject

/-! ## The acts -/

/-- An identity that is not registered can be in one team only. -/
def OneTeamIfLocal (s : State) (k : Key) : Prop :=
  Registered s k ∨ ∀ m, m ∈ s.members → m.member ≠ k

/-- Removing this team certificate leaves the organisation an admin: either it
is not an admin team certificate, or another admin remains. -/
def KeepsAnAdmin (s : State) (m : Membership) : Prop :=
  m.team = .admin → ∃ k, k ≠ m.member ∧ Admin s m.org k

/-- `k` has never been registered. -/
def Fresh (s : State) (k : Key) : Prop :=
  ∀ c, c ∈ s.certs → c.subject ≠ k

/-- `Step s who s'`: `who` asks for one act, it is accepted, and the record
changes from `s` to `s'`. Each constructor's premises are what is checked. -/
inductive Step (ask : AskRule) : State → Party → State → Prop where
  /-- Create an organisation. Whoever controls the domain in DNS names its root key there. -/
  | createOrg {s : State} {o : Org} :
      o ∉ s.orgs →
      Step ask s (.dns o) { s with orgs := o :: s.orgs }
  /-- Whoever controls the domain in DNS names a new root key and proves it
  holds it. Every identity of the organisation that was current is cut off.
  The new root key is not with a key holder. Team certificates, invitations
  and the teams' keys are not touched: a cut-off member simply cannot use its
  team certificate. Nothing can refuse this. -/
  | replaceRoot {s : State} {o : Org} :
      o ∈ s.orgs →
      Step ask s (.dns o)
        { s with
          revoked := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.revoked,
          cutOff := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.cutOff,
          held := s.held.filter (fun k => decide (k ≠ .root o)) }
  /-- The organisation admits again an identity directly under it that a root
  replacement cut off. The root key signs; the identity keeps its key (A3). -/
  | readmitByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → c.issuer = .root → c.subject ∈ s.cutOff →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      Step ask s who
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- A valid member admits again an identity it issued that a root replacement cut off. -/
  | readmitByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → c.subject ∈ s.cutOff → Valid s c.org p pk →
      Step ask s (.id p)
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- A key holder gives a key back to the organisation. Nothing else changes. -/
  | release {s : State} {key : OrgKey} {who : Party} {approvals : List Key} :
      key ∈ s.held → Authorised ask s key .release who approvals →
      Step ask s who { s with held := s.held.filter (fun k => decide (k ≠ key)) }
  /-- Whoever controls a key puts it in a key holder. -/
  | entrust {s : State} {key : OrgKey} :
      key ∉ s.held →
      Step ask s (.controller key) { s with held := key :: s.held }
  /-- Register a new identity directly under the organisation, of either kind.
  The root key signs (A2 for a person). -/
  | registerByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c.issuer = .root → c.org ∈ s.orgs → Fresh s c.subject →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      Step ask s who { s with certs := c :: s.certs }
  /-- A valid member registers a new identity under itself, within R1. Its own key signs. -/
  | registerByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c.issuer = .member p → Fresh s c.subject → Valid s c.org p pk → MayIssue pk c.kind →
      Step ask s (.id p) { s with certs := c :: s.certs }
  /-- An identity revokes itself. Its own key signs; it need not be valid. -/
  | revokeSelf {s : State} {c : Cert} :
      c ∈ s.certs →
      Step ask s (.id c.subject)
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- A valid member revokes an identity it issued. Its own key signs. -/
  | revokeChild {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → Valid s c.org p pk →
      Step ask s (.id p)
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- The organisation revokes one of its identities. The root key signs. -/
  | revokeByOrg {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → Authorised ask s (.root c.org) .revoke who approvals →
      Step ask s who
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- Admit a member to a named team. The member can be an outsider. The team's key signs. -/
  | admit {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      m.team ≠ .admin → Authorised ask s (.team m.org m.team) .admit who approvals →
      OneTeamIfLocal s m.member →
      Step ask s who { s with members := m :: s.members }
  /-- Admit a valid member of the organisation to its admin team. The admin team's key signs. -/
  | admitAdmin {s : State} {m : Membership} {kind : Kind} {who : Party} {approvals : List Key} :
      m.team = .admin → Valid s m.org m.member kind →
      Authorised ask s (.team m.org m.team) .admitAdmin who approvals →
      Step ask s who { s with members := m :: s.members }
  /-- Remove a member from a team, the admin team included. The team's key signs.
  The removed member need not take part, though the policy may name it as an
  approver. A key holder does not remove the last admin.
  Grants given from this team certificate end with it. -/
  | remove {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      Authorised ask s (.team m.org m.team) .remove who approvals →
      (.team m.org m.team ∈ s.held → KeepsAnAdmin s m) →
      Step ask s who
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  /-- A member leaves a team whose key a key holder holds, by asking it. The
  last admin cannot leave. -/
  | leave {s : State} {m : Membership} :
      m ∈ s.members → .team m.org m.team ∈ s.held → KeepsAnAdmin s m →
      Step ask s (.id m.member)
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  /-- Issue an invitation to a named team. It needs the same authority as admitting. -/
  | invite {s : State} {i : Invite} {who : Party} {approvals : List Key} :
      i.team ≠ .admin → Authorised ask s (.team i.org i.team) .admit who approvals →
      (∀ j, j ∈ s.invites → j.token ≠ i.token) →
      Step ask s who { s with invites := i :: s.invites }
  /-- Whoever holds an invitation's secret joins its team as `k`, a key the
  joiner holds (A3). Also checked: the team is not an admin team, and an
  unregistered `k` is in no other team. Who holds the secret is not checked. -/
  | redeem {s : State} {i : Invite} {k : Key} :
      i ∈ s.invites → i.team ≠ .admin → OneTeamIfLocal s k →
      Step ask s (.bearer i.token)
        { s with members := ⟨i.org, i.team, k⟩ :: s.members,
                 invites := s.invites.filter (fun x => decide (x ≠ i)) }
  /-- A team member gives a grant on itself to a fresh session key. -/
  | mintGrant {s : State} {g : Grant} :
      InTeam s g.org g.team g.subject → (∀ g', g' ∈ s.grants → g'.session ≠ g.session) →
      Step ask s (.id g.subject) { s with grants := g :: s.grants }
  /-- An identity revokes a grant on itself. -/
  | revokeGrant {s : State} {g : Grant} :
      g ∈ s.grants →
      Step ask s (.id g.subject) { s with grants := s.grants.filter (fun x => decide (x ≠ g)) }
  /-- An identity that can act sends a message with its own key. -/
  | sendOwn {s : State} {k : Key} :
      CanAct s k →
      Step ask s (.id k) { s with sent := ⟨k⟩ :: s.sent }
  /-- The holder of a live grant's session key sends a message. The server
  attributes it to the grant's subject. -/
  | sendGrant {s : State} {g : Grant} :
      GrantLive s g → g.maySend = true →
      Step ask s (.session g.session) { s with sent := ⟨g.subject⟩ :: s.sent }

/-- The records that can be reached by accepted acts, starting with nothing but a policy. -/
inductive Reachable (ask : AskRule) : State → Prop where
  | start (policy : List Rule) : Reachable ask ⟨[], [], [], [], [], policy, [], [], [], []⟩
  | step {s s' : State} {who : Party} :
      Reachable ask s → Step ask s who s' → Reachable ask s'

/-- An identity has one certificate, so its organisation, kind and issuer are
fixed. The protocol's rule R2 fixes organisation and kind; the fixed issuer is
this model's restriction. -/
def OneCertEach (s : State) : Prop :=
  ∀ c, c ∈ s.certs → ∀ d, d ∈ s.certs → c.subject = d.subject → c = d

/-- An identity that is not registered holds at most one team certificate. -/
def LocalInOneTeam (s : State) : Prop :=
  ∀ m1, m1 ∈ s.members → ∀ m2, m2 ∈ s.members → m1.member = m2.member →
    ¬ Registered s m1.member → m1 = m2

/-- Only registered identities are revoked. -/
def RevokedAreRegistered (s : State) : Prop :=
  ∀ k, k ∈ s.revoked → Registered s k

end TrustWeb
