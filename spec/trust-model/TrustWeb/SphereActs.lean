import TrustWeb.Operations

/-!
# Trust spheres: secrets, and the acts that make them

The secrets a sphere can hold, and the model's acts with the approvals each is
accepted with and the secrets each makes, proved to agree with `Step`.
-/

namespace TrustWeb

/-- A secret: what lets its holder ask as one party. -/
inductive Secret where
  | dns (o : Org)
  | orgKey (key : OrgKey)
  | idKey (k : Key)
  | session (k : Key)
  | invite (token : Nat)
  deriving DecidableEq, Repr

/-- The secret a party asks with. -/
def Party.secret : Party → Secret
  | .dns o => .dns o
  | .controller key => .orgKey key
  | .id k => .idKey k
  | .session k => .session k
  | .bearer t => .invite t

/-- The secrets an act can make: organisation keys, invitation secrets and
session keys. A domain's DNS credential and an identity key are never made by
an act. -/
def Secret.Makeable : Secret → Prop
  | .orgKey _ => True
  | .invite _ => True
  | .session _ => True
  | .dns _ => False
  | .idKey _ => False

/-- `StepVia ask s who approvals made s'`: the acts of `Step`, each with the
approvals it is accepted with and the secrets it makes. An act with no
`Authorised` premise carries no approvals. Creating an organisation and
replacing its root make the root key, a re-key makes the team's key, an
invitation makes its secret, and a grant makes its session key; no other act
makes a secret. -/
inductive StepVia (ask : AskRule) : State → Party → List Key → List Secret → State → Prop where
  | createOrg {s : State} {o : Org} :
      o ∉ s.orgs →
      StepVia ask s (.dns o) [] [.orgKey (.root o)] { s with orgs := o :: s.orgs }
  | replaceRoot {s : State} {o : Org} :
      o ∈ s.orgs →
      StepVia ask s (.dns o) [] [.orgKey (.root o)]
        { s with
          revoked := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.revoked,
          cutOff := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.cutOff,
          held := s.held.filter (fun k => decide (k ≠ .root o)) }
  | readmitByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → c.issuer = .root → c.subject ∈ s.cutOff →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      StepVia ask s who approvals []
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | readmitByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → c.subject ∈ s.cutOff → Valid s c.org p pk →
      StepVia ask s (.id p) [] []
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | release {s : State} {key : OrgKey} {who : Party} {approvals : List Key} :
      key ∈ s.held → Authorised ask s key .release who approvals →
      StepVia ask s who approvals [] { s with held := s.held.filter (fun k => decide (k ≠ key)) }
  | rekeyTeam {s : State} {o : Org} {t : Team} {keep : List Key} {who : Party}
      {approvals : List Key} :
      Authorised ask s (.root o) .rekey who approvals →
      (.root o ∈ s.held → t = .admin → ∃ k, k ∈ keep ∧ Admin s o k) →
      StepVia ask s who approvals [.orgKey (.team o t)]
        { s with held := s.held.filter (fun k => decide (k ≠ .team o t)),
                 members := s.members.filter
                   (fun m => decide (¬ (m.org = o ∧ m.team = t) ∨ m.member ∈ keep)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = o ∧ g.team = t))) }
  | entrust {s : State} {key : OrgKey} :
      key ∉ s.held →
      StepVia ask s (.controller key) [] [] { s with held := key :: s.held }
  | registerByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c.issuer = .root → c.org ∈ s.orgs → Fresh s c.subject →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      StepVia ask s who approvals [] { s with certs := c :: s.certs }
  | registerByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c.issuer = .member p → Fresh s c.subject → Valid s c.org p pk → MayIssue pk c.kind →
      StepVia ask s (.id p) [] [] { s with certs := c :: s.certs }
  | revokeSelf {s : State} {c : Cert} :
      c ∈ s.certs →
      StepVia ask s (.id c.subject) [] []
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | revokeChild {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → Valid s c.org p pk →
      StepVia ask s (.id p) [] []
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | revokeByOrg {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → Authorised ask s (.root c.org) .revoke who approvals →
      StepVia ask s who approvals []
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | admit {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      m.team ≠ .admin → Authorised ask s (.team m.org m.team) .admit who approvals →
      OneTeamIfLocal s m.member →
      StepVia ask s who approvals [] { s with members := m :: s.members }
  | admitAdmin {s : State} {m : Membership} {kind : Kind} {who : Party} {approvals : List Key} :
      m.team = .admin → Valid s m.org m.member kind →
      Authorised ask s (.team m.org m.team) .admitAdmin who approvals →
      StepVia ask s who approvals [] { s with members := m :: s.members }
  | remove {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      Authorised ask s (.team m.org m.team) .remove who approvals →
      (.team m.org m.team ∈ s.held → KeepsAnAdmin s m) →
      StepVia ask s who approvals []
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  | leave {s : State} {m : Membership} :
      m ∈ s.members → .team m.org m.team ∈ s.held → KeepsAnAdmin s m →
      StepVia ask s (.id m.member) [] []
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  | invite {s : State} {i : Invite} {who : Party} {approvals : List Key} :
      i.team ≠ .admin → Authorised ask s (.team i.org i.team) .admit who approvals →
      (∀ j, j ∈ s.invites → j.token ≠ i.token) →
      StepVia ask s who approvals [.invite i.token] { s with invites := i :: s.invites }
  | redeem {s : State} {i : Invite} {k : Key} :
      i ∈ s.invites → i.team ≠ .admin → OneTeamIfLocal s k →
      StepVia ask s (.bearer i.token) [] []
        { s with members := ⟨i.org, i.team, k⟩ :: s.members,
                 invites := s.invites.filter (fun x => decide (x ≠ i)) }
  | mintGrant {s : State} {g : Grant} :
      InTeam s g.org g.team g.subject → (∀ g', g' ∈ s.grants → g'.session ≠ g.session) →
      StepVia ask s (.id g.subject) [] [.session g.session] { s with grants := g :: s.grants }
  | revokeGrant {s : State} {g : Grant} :
      g ∈ s.grants →
      StepVia ask s (.id g.subject) [] [] { s with grants := s.grants.filter (fun x => decide (x ≠ g)) }
  | sendOwn {s : State} {k : Key} :
      CanAct s k →
      StepVia ask s (.id k) [] [] { s with sent := ⟨k⟩ :: s.sent }
  | sendGrant {s : State} {g : Grant} :
      GrantLive s g → g.maySend = true →
      StepVia ask s (.session g.session) [] [] { s with sent := ⟨g.subject⟩ :: s.sent }

/-- Every act of `StepVia` is an act of `Step`. -/
theorem StepVia.toStep {ask : AskRule} {s s' : State} {who : Party} {approvals : List Key}
    {made : List Secret} (h : StepVia ask s who approvals made s') : Step ask s who s' := by
  cases h with
  | createOrg h0 => exact .createOrg h0
  | replaceRoot h0 => exact .replaceRoot h0
  | readmitByRoot h0 h1 h2 h3 => exact .readmitByRoot h0 h1 h2 h3
  | readmitByParent h0 h1 h2 h3 => exact .readmitByParent h0 h1 h2 h3
  | release h0 h1 => exact .release h0 h1
  | rekeyTeam h0 h1 => exact .rekeyTeam h0 h1
  | entrust h0 => exact .entrust h0
  | registerByRoot h0 h1 h2 h3 => exact .registerByRoot h0 h1 h2 h3
  | registerByParent h0 h1 h2 h3 => exact .registerByParent h0 h1 h2 h3
  | revokeSelf h0 => exact .revokeSelf h0
  | revokeChild h0 h1 h2 => exact .revokeChild h0 h1 h2
  | revokeByOrg h0 h1 => exact .revokeByOrg h0 h1
  | admit h0 h1 h2 => exact .admit h0 h1 h2
  | admitAdmin h0 h1 h2 => exact .admitAdmin h0 h1 h2
  | remove h0 h1 => exact .remove h0 h1
  | leave h0 h1 h2 => exact .leave h0 h1 h2
  | invite h0 h1 h2 => exact .invite h0 h1 h2
  | redeem h0 h1 h2 => exact .redeem h0 h1 h2
  | mintGrant h0 h1 => exact .mintGrant h0 h1
  | revokeGrant h0 => exact .revokeGrant h0
  | sendOwn h0 => exact .sendOwn h0
  | sendGrant h0 h1 => exact .sendGrant h0 h1

/-- Every act of `Step` is an act of `StepVia` with some approvals and made
secrets. -/
theorem Step.toVia {ask : AskRule} {s s' : State} {who : Party}
    (h : Step ask s who s') : ∃ approvals made, StepVia ask s who approvals made s' := by
  cases h with
  | createOrg h0 => exact ⟨_, _, .createOrg h0⟩
  | replaceRoot h0 => exact ⟨_, _, .replaceRoot h0⟩
  | readmitByRoot h0 h1 h2 h3 => exact ⟨_, _, .readmitByRoot h0 h1 h2 h3⟩
  | readmitByParent h0 h1 h2 h3 => exact ⟨_, _, .readmitByParent h0 h1 h2 h3⟩
  | release h0 h1 => exact ⟨_, _, .release h0 h1⟩
  | rekeyTeam h0 h1 => exact ⟨_, _, .rekeyTeam h0 h1⟩
  | entrust h0 => exact ⟨_, _, .entrust h0⟩
  | registerByRoot h0 h1 h2 h3 => exact ⟨_, _, .registerByRoot h0 h1 h2 h3⟩
  | registerByParent h0 h1 h2 h3 => exact ⟨_, _, .registerByParent h0 h1 h2 h3⟩
  | revokeSelf h0 => exact ⟨_, _, .revokeSelf h0⟩
  | revokeChild h0 h1 h2 => exact ⟨_, _, .revokeChild h0 h1 h2⟩
  | revokeByOrg h0 h1 => exact ⟨_, _, .revokeByOrg h0 h1⟩
  | admit h0 h1 h2 => exact ⟨_, _, .admit h0 h1 h2⟩
  | admitAdmin h0 h1 h2 => exact ⟨_, _, .admitAdmin h0 h1 h2⟩
  | remove h0 h1 => exact ⟨_, _, .remove h0 h1⟩
  | leave h0 h1 h2 => exact ⟨_, _, .leave h0 h1 h2⟩
  | invite h0 h1 h2 => exact ⟨_, _, .invite h0 h1 h2⟩
  | redeem h0 h1 h2 => exact ⟨_, _, .redeem h0 h1 h2⟩
  | mintGrant h0 h1 => exact ⟨_, _, .mintGrant h0 h1⟩
  | revokeGrant h0 => exact ⟨_, _, .revokeGrant h0⟩
  | sendOwn h0 => exact ⟨_, _, .sendOwn h0⟩
  | sendGrant h0 h1 => exact ⟨_, _, .sendGrant h0 h1⟩

/-- An act makes only organisation keys, invitation secrets and session keys. -/
theorem StepVia.made_makeable {ask : AskRule} {s s' : State} {who : Party}
    {approvals : List Key} {made : List Secret} (h : StepVia ask s who approvals made s')
    {x : Secret} (hx : x ∈ made) : x.Makeable := by
  cases h <;> simp at hx <;> subst hx <;> trivial

/-- An act that makes organisation `o`'s root key is asked for by `o`'s
domain. -/
theorem StepVia.made_root {ask : AskRule} {s s' : State} {who : Party}
    {approvals : List Key} {made : List Secret} (h : StepVia ask s who approvals made s')
    {o : Org} (hx : .orgKey (.root o) ∈ made) : who = .dns o := by
  cases h <;> simp at hx <;> subst hx <;> rfl

/-- An act that makes the key of team `t` of organisation `o` is one for
which `Authorised` holds for `o`'s root key and a re-key. -/
theorem StepVia.made_team {ask : AskRule} {s s' : State} {who : Party}
    {approvals : List Key} {made : List Secret} (h : StepVia ask s who approvals made s')
    {o : Org} {t : Team} (hx : .orgKey (.team o t) ∈ made) :
    Authorised ask s (.root o) .rekey who approvals := by
  cases h with
  | rekeyTeam h0 _ =>
      simp at hx
      obtain ⟨rfl, rfl⟩ := hx
      exact h0
  | _ => simp at hx

end TrustWeb
