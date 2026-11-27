/-!
# The trust web: the model

What exists, the current record (`State`), and the acts that change it (`Step`).
-/

namespace TrustWeb

/-- A key; identities are keys. -/
abbrev Key := Nat

/-- An organisation. -/
abbrev Org := Nat

/-- The two kinds of member. -/
inductive Kind where
  | person
  | agent
  deriving DecidableEq, Repr

/-- Who issued an identity certificate: the organisation's root, or the key `k`. -/
inductive Issuer where
  | root
  | member (k : Key)
  deriving DecidableEq, Repr

/-- A team of an organisation: its admin team, or a named team. -/
inductive Team where
  | admin
  | named (n : Nat)
  deriving DecidableEq, Repr

/-- An organisation's keys: its root key, and one key per team. -/
inductive OrgKey where
  | root (o : Org)
  | team (o : Org) (t : Team)
  deriving DecidableEq, Repr

/-- Who asks for an act: `dns o`, whoever controls `o`'s domain; `controller
key`, whoever controls `key`; `id k`, the identity `k`; `session k`, whoever
holds session key `k`; `bearer token`, whoever holds an invitation's secret. -/
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

/-- A team certificate: `member` is in `team` of `org`. -/
structure Membership where
  org : Org
  team : Team
  member : Key
  deriving DecidableEq, Repr

/-- The kinds of act that `Authorised` and `AskRule` take. -/
inductive ActKind where
  | registerPerson
  | registerAgent
  | revoke
  | admit
  | admitAdmin
  | remove
  | release
  | rekey
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

/-- A grant on `subject`, with session key `session`, from team `team` of
`org`; `maySend` says whether it may send. -/
structure Grant where
  session : Key
  subject : Key
  org : Org
  team : Team
  maySend : Bool
  deriving DecidableEq, Repr

/-- An invitation with secret `token` to team `team` of `org`. -/
structure Invite where
  token : Nat
  org : Org
  team : Team
  deriving DecidableEq, Repr

/-- A message, with the identity it is attributed to. -/
structure Message where
  sender : Key
  deriving DecidableEq, Repr

/-- The current record. -/
structure State where
  /-- The organisations that exist. -/
  orgs : List Org
  /-- The registered identity certificates. -/
  certs : List Cert
  /-- The revoked identities. -/
  revoked : List Key
  /-- The identities that are cut off. -/
  cutOff : List Key
  /-- The team certificates that stand. -/
  members : List Membership
  /-- Every organisation's policy. -/
  policy : List Rule
  /-- The organisation keys that a key holder holds. -/
  held : List OrgKey
  /-- The grants that stand. -/
  grants : List Grant
  /-- The invitations not yet used. -/
  invites : List Invite
  /-- The messages sent. -/
  sent : List Message

/-! ## What a verifier concludes -/

/-- A person may issue either kind of member; an agent may issue only agents. -/
def MayIssue (issuer child : Kind) : Prop :=
  issuer = .person ∨ child = .agent

/-- `Person s o k`: `k` holds a person certificate of `o` issued by the root,
or by a member that is itself a person of `o`. -/
inductive Person (s : State) (o : Org) : Key → Prop where
  | byRoot {c : Cert} {k : Key} :
      c ∈ s.certs → c.org = o → c.kind = .person → c.issuer = .root → c.subject = k →
      Person s o k
  | byPerson {c : Cert} {k p : Key} :
      c ∈ s.certs → c.org = o → c.kind = .person → c.issuer = .member p → c.subject = k →
      Person s o p → Person s o k

/-- `Valid s o k kind`: for a person, `k` is a person of `o` and not revoked;
for an agent, `k` holds an agent certificate of `o`, is not revoked, and its
issuer is the root or a member valid in `o`. -/
inductive Valid (s : State) (o : Org) : Key → Kind → Prop where
  | person {k : Key} :
      Person s o k → k ∉ s.revoked → Valid s o k .person
  | agentOfRoot {c : Cert} {k : Key} :
      c ∈ s.certs → c.org = o → c.kind = .agent → c.issuer = .root → c.subject = k →
      k ∉ s.revoked → Valid s o k .agent
  | agentOf {c : Cert} {k p : Key} {pk : Kind} :
      c ∈ s.certs → c.org = o → c.kind = .agent → c.issuer = .member p → c.subject = k →
      k ∉ s.revoked → Valid s o p pk → Valid s o k .agent

/-- `ChainToRoot s o k`: `k` holds a certificate of `o` issued by the root, or
by a member with a chain to `o`'s root. -/
inductive ChainToRoot (s : State) (o : Org) : Key → Prop where
  | root {c : Cert} {k : Key} :
      c ∈ s.certs → c.org = o → c.issuer = .root → c.subject = k → ChainToRoot s o k
  | link {c : Cert} {k p : Key} :
      c ∈ s.certs → c.org = o → c.issuer = .member p → c.subject = k →
      ChainToRoot s o p → ChainToRoot s o k

/-- `AnswersFor s o a h`: `a` is `h` and a valid person of `o` (`self`), or
`a` is not revoked and holds an agent certificate of `o` issued by a member
that `h` answers for (`up`). -/
inductive AnswersFor (s : State) (o : Org) : Key → Key → Prop where
  | self {h : Key} : Valid s o h .person → AnswersFor s o h h
  | up {c : Cert} {a p h : Key} :
      c ∈ s.certs → c.org = o → c.kind = .agent → c.issuer = .member p → c.subject = a →
      a ∉ s.revoked → AnswersFor s o p h → AnswersFor s o a h

/-- `k` has an identity certificate. -/
def Registered (s : State) (k : Key) : Prop :=
  ∃ c, c ∈ s.certs ∧ c.subject = k

/-- `HasTeamCert s o t k`: a team certificate for `k` in team `t` of `o` stands. -/
def HasTeamCert (s : State) (o : Org) (t : Team) (k : Key) : Prop :=
  ⟨o, t, k⟩ ∈ s.members

/-- `CanAct s k`: `k` has no identity certificate, or is valid in some
organisation, of some kind. -/
def CanAct (s : State) (k : Key) : Prop :=
  ¬ Registered s k ∨ ∃ o' kind, Valid s o' k kind

/-- `InTeam s o t k`: `k` holds a certificate of team `t` of `o` and can act. -/
def InTeam (s : State) (o : Org) (t : Team) (k : Key) : Prop :=
  HasTeamCert s o t k ∧ CanAct s k

/-- `Admin s o k`: `k` holds a certificate of `o`'s admin team and is valid in
`o`, of some kind. -/
def Admin (s : State) (o : Org) (k : Key) : Prop :=
  ⟨o, .admin, k⟩ ∈ s.members ∧ ∃ kind, Valid s o k kind

/-! ## Approval -/

/-- Approvals satisfy `.anyPerson` if one of them is a valid person of `o`,
and `.exactly k` if `k` is one of them and is valid in `o`. -/
def Satisfies (s : State) (o : Org) (approvals : List Key) : Approver → Prop
  | .anyPerson => ∃ k, k ∈ approvals ∧ Valid s o k .person
  | .exactly k => k ∈ approvals ∧ ∃ kind, Valid s o k kind

/-- The approvals satisfy every rule of the policy for `o` and this kind of
act. -/
def Approved (s : State) (o : Org) (act : ActKind) (approvals : List Key) : Prop :=
  ∀ r, r ∈ s.policy → r.org = o → r.act = act → Satisfies s o approvals r.approver

/-- The organisation a key belongs to. -/
def OrgKey.org : OrgKey → Org
  | .root o => o
  | .team o _ => o

/-- A rule for who may ask a key holder: given the record, the organisation,
the kind of act and an identity, whether that identity may ask. -/
abbrev AskRule := State → Org → ActKind → Key → Prop

/-- As built: the act is adding a person, and either the identity is a valid
person of the organisation, or the policy has a rule for adding a person in it
that asks any person's approval and the identity is valid in it. -/
def builtRule : AskRule :=
  fun s o act k => act = .registerPerson ∧
    (Valid s o k .person ∨
      ((∃ r, r ∈ s.policy ∧ r.org = o ∧ r.act = .registerPerson ∧ r.approver = .anyPerson) ∧
        ∃ kind, Valid s o k kind))

/-- Planned: the identity is an admin of the organisation. -/
def adminRule : AskRule :=
  fun s o _ k => Admin s o k

/-- `Authorised ask s key act who approvals`: either `key` is not held and
`who` controls it, or `key` is held, `who` is an identity that `ask` lets ask
for `act` in `key`'s organisation, and the approvals are approved for `act`
there. -/
def Authorised (ask : AskRule) (s : State) (key : OrgKey) (act : ActKind) (who : Party)
    (approvals : List Key) : Prop :=
  (key ∉ s.held ∧ who = .controller key) ∨
  (key ∈ s.held ∧ ∃ k, who = .id k ∧ ask s key.org act k ∧ Approved s key.org act approvals)

/-- The kind of act that registers a member of this kind. -/
def ActKind.registerOf : Kind → ActKind
  | .person => .registerPerson
  | .agent => .registerAgent

/-- `GrantLive s g`: `g` stands and its subject can act in its team. -/
def GrantLive (s : State) (g : Grant) : Prop :=
  g ∈ s.grants ∧ InTeam s g.org g.team g.subject

/-! ## The acts -/

/-- `k` is registered, or holds no team certificate. -/
def OneTeamIfLocal (s : State) (k : Key) : Prop :=
  Registered s k ∨ ∀ m, m ∈ s.members → m.member ≠ k

/-- If `m` is a certificate of an admin team, some identity other than
`m.member` is an admin of `m.org`. -/
def KeepsAnAdmin (s : State) (m : Membership) : Prop :=
  m.team = .admin → ∃ k, k ≠ m.member ∧ Admin s m.org k

/-- `k` has no identity certificate in this record. -/
def Fresh (s : State) (k : Key) : Prop :=
  ∀ c, c ∈ s.certs → c.subject ≠ k

/-- `Step ask s who s'`: under the rule `ask`, `who` asks for an act that is
accepted and takes `s` to `s'`. -/
inductive Step (ask : AskRule) : State → Party → State → Prop where
  /-- Asked for by `dns o`, if `o` does not exist: `o` exists. -/
  | createOrg {s : State} {o : Org} :
      o ∉ s.orgs →
      Step ask s (.dns o) { s with orgs := o :: s.orgs }
  /-- Asked for by `dns o`, if `o` exists: every unrevoked identity with a
  certificate of `o` is revoked and cut off, no grant on any of them stands,
  and `o`'s root key is not held. -/
  | replaceRoot {s : State} {o : Org} :
      o ∈ s.orgs →
      Step ask s (.dns o)
        { s with
          revoked := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.revoked,
          cutOff := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.cutOff,
          held := s.held.filter (fun k => decide (k ≠ .root o)),
          grants := s.grants.filter (fun g => decide (g.subject ∉
            (s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
              (·.subject))) }
  /-- If `c` is registered and issued by the root, its subject is cut off, and
  `Authorised` holds for the root key of `c`'s organisation and registering
  `c`'s kind: the subject is neither revoked nor cut off. -/
  | readmitByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → c.issuer = .root → c.subject ∈ s.cutOff →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      Step ask s who
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- Asked for by `id p`, if `c` is registered and issued by `p`, its subject
  is cut off, and `p` is valid in `c`'s organisation: the subject is neither
  revoked nor cut off. -/
  | readmitByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → c.subject ∈ s.cutOff → Valid s c.org p pk →
      Step ask s (.id p)
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- If `key` is held and `Authorised` holds for it and giving a key back:
  `key` is not held. -/
  | release {s : State} {key : OrgKey} {who : Party} {approvals : List Key} :
      key ∈ s.held → Authorised ask s key .release who approvals →
      Step ask s who { s with held := s.held.filter (fun k => decide (k ≠ key)) }
  /-- If `Authorised` holds for `o`'s root key and a re-key: the key of team
  `t` of `o` is not held, and no certificate of that team stands, nor any grant
  from it. -/
  | rekeyTeam {s : State} {o : Org} {t : Team} {who : Party} {approvals : List Key} :
      Authorised ask s (.root o) .rekey who approvals →
      Step ask s who
        { s with held := s.held.filter (fun k => decide (k ≠ .team o t)),
                 members := s.members.filter (fun m => decide (¬ (m.org = o ∧ m.team = t))),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = o ∧ g.team = t))) }
  /-- Asked for by `controller key`, if `key` is not held: `key` is held. -/
  | entrust {s : State} {key : OrgKey} :
      key ∉ s.held →
      Step ask s (.controller key) { s with held := key :: s.held }
  /-- If `c` is issued by the root, its organisation exists, its subject has
  no certificate, and `Authorised` holds for the root key and registering
  `c`'s kind: `c` is registered. -/
  | registerByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c.issuer = .root → c.org ∈ s.orgs → Fresh s c.subject →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      Step ask s who { s with certs := c :: s.certs }
  /-- Asked for by `id p`, if `c` is issued by `p`, its subject has no
  certificate, `p` is valid in `c`'s organisation, and `p`'s kind may issue
  `c`'s: `c` is registered. -/
  | registerByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c.issuer = .member p → Fresh s c.subject → Valid s c.org p pk → MayIssue pk c.kind →
      Step ask s (.id p) { s with certs := c :: s.certs }
  /-- Asked for by `c`'s subject, if `c` is registered: the subject is revoked
  and not cut off. -/
  | revokeSelf {s : State} {c : Cert} :
      c ∈ s.certs →
      Step ask s (.id c.subject)
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- Asked for by `id p`, if `c` is registered and issued by `p`, and `p` is
  valid in `c`'s organisation: `c`'s subject is revoked and not cut off. -/
  | revokeChild {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → Valid s c.org p pk →
      Step ask s (.id p)
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- If `c` is registered and `Authorised` holds for the root key of `c`'s
  organisation and revoking: `c`'s subject is revoked and not cut off. -/
  | revokeByOrg {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → Authorised ask s (.root c.org) .revoke who approvals →
      Step ask s who
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  /-- If `m` is not of an admin team, `Authorised` holds for its team's key
  and admitting, and `OneTeamIfLocal` holds for its member: `m` stands. -/
  | admit {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      m.team ≠ .admin → Authorised ask s (.team m.org m.team) .admit who approvals →
      OneTeamIfLocal s m.member →
      Step ask s who { s with members := m :: s.members }
  /-- If `m` is of an admin team, its member is valid in its organisation, and
  `Authorised` holds for that team's key and admitting an admin: `m` stands. -/
  | admitAdmin {s : State} {m : Membership} {kind : Kind} {who : Party} {approvals : List Key} :
      m.team = .admin → Valid s m.org m.member kind →
      Authorised ask s (.team m.org m.team) .admitAdmin who approvals →
      Step ask s who { s with members := m :: s.members }
  /-- If `Authorised` holds for `m`'s team's key and removing, and
  `KeepsAnAdmin` holds when that key is held: `m` no longer stands, nor any
  grant on its member from its team. -/
  | remove {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      Authorised ask s (.team m.org m.team) .remove who approvals →
      (.team m.org m.team ∈ s.held → KeepsAnAdmin s m) →
      Step ask s who
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  /-- Asked for by `m`'s member, if `m` stands, its team's key is held, and
  `KeepsAnAdmin` holds: `m` no longer stands, nor any grant on its member from
  its team. -/
  | leave {s : State} {m : Membership} :
      m ∈ s.members → .team m.org m.team ∈ s.held → KeepsAnAdmin s m →
      Step ask s (.id m.member)
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  /-- If the invitation is not to an admin team, `Authorised` holds for its
  team's key and admitting, and no unused invitation has its secret: the
  invitation is unused. -/
  | invite {s : State} {i : Invite} {who : Party} {approvals : List Key} :
      i.team ≠ .admin → Authorised ask s (.team i.org i.team) .admit who approvals →
      (∀ j, j ∈ s.invites → j.token ≠ i.token) →
      Step ask s who { s with invites := i :: s.invites }
  /-- Asked for by the holder of `i`'s secret, if `i` is unused and not to an
  admin team and `OneTeamIfLocal` holds for `k`: `k` holds a certificate of
  `i`'s team, and `i` is used. -/
  | redeem {s : State} {i : Invite} {k : Key} :
      i ∈ s.invites → i.team ≠ .admin → OneTeamIfLocal s k →
      Step ask s (.bearer i.token)
        { s with members := ⟨i.org, i.team, k⟩ :: s.members,
                 invites := s.invites.filter (fun x => decide (x ≠ i)) }
  /-- Asked for by `g`'s subject, if it can act in `g`'s team and no current
  grant uses `g`'s session key: `g` stands. -/
  | mintGrant {s : State} {g : Grant} :
      InTeam s g.org g.team g.subject → (∀ g', g' ∈ s.grants → g'.session ≠ g.session) →
      Step ask s (.id g.subject) { s with grants := g :: s.grants }
  /-- Asked for by `g`'s subject, if `g` stands: `g` no longer stands. -/
  | revokeGrant {s : State} {g : Grant} :
      g ∈ s.grants →
      Step ask s (.id g.subject) { s with grants := s.grants.filter (fun x => decide (x ≠ g)) }
  /-- Asked for by `id k`, if `k` can act: a message attributed to `k` is
  sent. -/
  | sendOwn {s : State} {k : Key} :
      CanAct s k →
      Step ask s (.id k) { s with sent := ⟨k⟩ :: s.sent }
  /-- Asked for by the holder of `g`'s session key, if `g` is live and may
  send: a message attributed to `g`'s subject is sent. -/
  | sendGrant {s : State} {g : Grant} :
      GrantLive s g → g.maySend = true →
      Step ask s (.session g.session) { s with sent := ⟨g.subject⟩ :: s.sent }

/-- The records reached by accepted acts from a record with nothing in it but
a policy. -/
inductive Reachable (ask : AskRule) : State → Prop where
  | start (policy : List Rule) : Reachable ask ⟨[], [], [], [], [], policy, [], [], [], []⟩
  | step {s s' : State} {who : Party} :
      Reachable ask s → Step ask s who s' → Reachable ask s'

/-- Every identity has at most one certificate. -/
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
