import TrustWeb.Decide

/-!
# The executable step

`run` takes a request (who asks, with which approvals, for which act) and
returns the record after the act, or the name of the first premise that fails.
Each act is a list of named checks, in the order its `Step` constructor states
them, and an effect. `step_iff_run` proves that `run` accepts exactly the steps
`Step` allows, with the same record after, and `run_error_premise` that a
refusal names a premise that is false while every premise before it holds.
-/

namespace TrustWeb

/-- A named premise with a decision. -/
structure Check where
  name : String
  prop : Prop
  [dec : Decidable prop]

attribute [instance] Check.dec

/-- The name of the first check that fails, if any. -/
def firstFailing : List Check → Option String
  | [] => none
  | c :: cs => if c.prop then firstFailing cs else some c.name

theorem firstFailing_none {l : List Check} : firstFailing l = none ↔ ∀ c, c ∈ l → c.prop := by
  induction l with
  | nil => simp [firstFailing]
  | cons c cs ih =>
    simp only [firstFailing, List.mem_cons, forall_eq_or_imp]
    by_cases h : c.prop <;> simp [h, ih]

theorem firstFailing_some {l : List Check} {n : String} (h : firstFailing l = some n) :
    ∃ pre c post, l = pre ++ c :: post ∧ c.name = n ∧ ¬ c.prop ∧ ∀ c', c' ∈ pre → c'.prop := by
  induction l with
  | nil => simp [firstFailing] at h
  | cons c cs ih =>
    simp only [firstFailing] at h
    by_cases hc : c.prop
    · simp only [hc] at h
      obtain ⟨pre, c', post, rfl, hn, hf, hpre⟩ := ih h
      refine ⟨c :: pre, c', post, rfl, hn, hf, ?_⟩
      intro x hx
      simp at hx
      rcases hx with rfl | hx
      · exact hc
      · exact hpre x hx
    · simp [hc] at h
      exact ⟨[], c, cs, rfl, h, hc, by simp⟩

/-- An act, with what the request gives beyond who asks and the approvals. -/
inductive Act where
  | createOrg (o : Org)
  | replaceRoot (o : Org)
  | readmitByRoot (c : Cert)
  | readmitByParent (c : Cert)
  | release (key : OrgKey)
  | rekeyTeam (o : Org) (t : Team) (keep : List Key)
  | entrust (key : OrgKey)
  | registerByRoot (c : Cert)
  | registerByParent (c : Cert)
  | revokeSelf (c : Cert)
  | revokeChild (c : Cert)
  | revokeByOrg (c : Cert)
  | admit (m : Membership)
  | admitAdmin (m : Membership)
  | remove (m : Membership)
  | leave (m : Membership)
  | invite (i : Invite)
  | redeem (i : Invite) (k : Key)
  | mintGrant (g : Grant)
  | revokeGrant (g : Grant)
  | sendOwn (k : Key)
  | sendGrant (g : Grant)
  deriving DecidableEq, Repr

/-- `who` is `id p` for the member `p` that issued `c`. -/
def AskedByIssuer (c : Cert) (who : Party) : Prop :=
  match c.issuer with
  | .root => False
  | .member p => who = .id p

instance AskedByIssuer.decidable (c : Cert) (who : Party) : Decidable (AskedByIssuer c who) := by
  unfold AskedByIssuer
  cases c.issuer <;> infer_instance

/-- The member that issued `c` is valid in `c`'s organisation, of some kind
for which `ok` holds. -/
def IssuerValid (s : State) (c : Cert) (ok : Kind → Prop) : Prop :=
  match c.issuer with
  | .root => False
  | .member p => ∃ pk, Valid s c.org p pk ∧ ok pk

instance IssuerValid.decidable (s : State) (c : Cert) (ok : Kind → Prop) [DecidablePred ok] :
    Decidable (IssuerValid s c ok) := by
  unfold IssuerValid
  cases c.issuer <;> infer_instance

/-- `c` is issued by a member. -/
def ByMember (c : Cert) : Prop :=
  match c.issuer with
  | .root => False
  | .member _ => True

instance ByMember.decidable (c : Cert) : Decidable (ByMember c) := by
  unfold ByMember
  cases c.issuer <;> infer_instance

/-- The checks of an act, in the order its `Step` constructor states them. -/
def Act.checks (ask : AskRule) [AskDecidable ask] (s : State) (who : Party)
    (approvals : List Key) : Act → List Check
  | .createOrg o =>
    [⟨"createOrg.Asker", who = .dns o⟩, ⟨"createOrg.New", o ∉ s.orgs⟩]
  | .replaceRoot o =>
    [⟨"replaceRoot.Asker", who = .dns o⟩, ⟨"replaceRoot.Exists", o ∈ s.orgs⟩]
  | .readmitByRoot c =>
    [⟨"readmitByRoot.Registered", c ∈ s.certs⟩, ⟨"readmitByRoot.Issuer", c.issuer = .root⟩,
     ⟨"readmitByRoot.CutOff", c.subject ∈ s.cutOff⟩,
     ⟨"readmitByRoot.Authorised", Authorised ask s (.root c.org) (.registerOf c.kind) who approvals⟩]
  | .readmitByParent c =>
    [⟨"readmitByParent.Registered", c ∈ s.certs⟩, ⟨"readmitByParent.Issuer", ByMember c⟩,
     ⟨"readmitByParent.Asker", AskedByIssuer c who⟩,
     ⟨"readmitByParent.CutOff", c.subject ∈ s.cutOff⟩,
     ⟨"readmitByParent.Valid", IssuerValid s c (fun _ => True)⟩]
  | .release key =>
    [⟨"release.Held", key ∈ s.held⟩,
     ⟨"release.Authorised", Authorised ask s key .release who approvals⟩]
  | .rekeyTeam o t keep =>
    [⟨"rekeyTeam.Authorised", Authorised ask s (.root o) .rekey who approvals⟩,
     ⟨"rekeyTeam.KeepsAnAdmin", OrgKey.root o ∈ s.held → t = .admin → ∃ k, k ∈ keep ∧ Admin s o k⟩]
  | .entrust key =>
    [⟨"entrust.Asker", who = .controller key⟩, ⟨"entrust.NotHeld", key ∉ s.held⟩]
  | .registerByRoot c =>
    [⟨"registerByRoot.Issuer", c.issuer = .root⟩, ⟨"registerByRoot.OrgExists", c.org ∈ s.orgs⟩,
     ⟨"registerByRoot.Fresh", Fresh s c.subject⟩,
     ⟨"registerByRoot.Authorised", Authorised ask s (.root c.org) (.registerOf c.kind) who approvals⟩]
  | .registerByParent c =>
    [⟨"registerByParent.Issuer", ByMember c⟩, ⟨"registerByParent.Asker", AskedByIssuer c who⟩,
     ⟨"registerByParent.Fresh", Fresh s c.subject⟩,
     ⟨"registerByParent.Valid", IssuerValid s c (fun _ => True)⟩,
     ⟨"registerByParent.MayIssue", IssuerValid s c (fun pk => MayIssue pk c.kind)⟩]
  | .revokeSelf c =>
    [⟨"revokeSelf.Registered", c ∈ s.certs⟩, ⟨"revokeSelf.Asker", who = .id c.subject⟩]
  | .revokeChild c =>
    [⟨"revokeChild.Registered", c ∈ s.certs⟩, ⟨"revokeChild.Issuer", ByMember c⟩,
     ⟨"revokeChild.Asker", AskedByIssuer c who⟩,
     ⟨"revokeChild.Valid", IssuerValid s c (fun _ => True)⟩]
  | .revokeByOrg c =>
    [⟨"revokeByOrg.Registered", c ∈ s.certs⟩,
     ⟨"revokeByOrg.Authorised", Authorised ask s (.root c.org) .revoke who approvals⟩]
  | .admit m =>
    [⟨"admit.NotAdminTeam", m.team ≠ .admin⟩,
     ⟨"admit.Authorised", Authorised ask s (.team m.org m.team) .admit who approvals⟩,
     ⟨"admit.OneTeamIfLocal", OneTeamIfLocal s m.member⟩]
  | .admitAdmin m =>
    [⟨"admitAdmin.AdminTeam", m.team = .admin⟩,
     ⟨"admitAdmin.Valid", ∃ kind, Valid s m.org m.member kind⟩,
     ⟨"admitAdmin.Authorised", Authorised ask s (.team m.org m.team) .admitAdmin who approvals⟩]
  | .remove m =>
    [⟨"remove.Authorised", Authorised ask s (.team m.org m.team) .remove who approvals⟩,
     ⟨"remove.KeepsAnAdmin", OrgKey.team m.org m.team ∈ s.held → KeepsAnAdmin s m⟩]
  | .leave m =>
    [⟨"leave.Asker", who = .id m.member⟩, ⟨"leave.Stands", m ∈ s.members⟩,
     ⟨"leave.Held", OrgKey.team m.org m.team ∈ s.held⟩, ⟨"leave.KeepsAnAdmin", KeepsAnAdmin s m⟩]
  | .invite i =>
    [⟨"invite.NotAdminTeam", i.team ≠ .admin⟩,
     ⟨"invite.Authorised", Authorised ask s (.team i.org i.team) .admit who approvals⟩,
     ⟨"invite.FreshToken", ∀ j, j ∈ s.invites → j.token ≠ i.token⟩]
  | .redeem i k =>
    [⟨"redeem.Asker", who = .bearer i.token⟩, ⟨"redeem.Unused", i ∈ s.invites⟩,
     ⟨"redeem.NotAdminTeam", i.team ≠ .admin⟩, ⟨"redeem.OneTeamIfLocal", OneTeamIfLocal s k⟩]
  | .mintGrant g =>
    [⟨"mintGrant.Asker", who = .id g.subject⟩, ⟨"mintGrant.InTeam", InTeam s g.org g.team g.subject⟩,
     ⟨"mintGrant.FreshSession", ∀ g', g' ∈ s.grants → g'.session ≠ g.session⟩]
  | .revokeGrant g =>
    [⟨"revokeGrant.Asker", who = .id g.subject⟩, ⟨"revokeGrant.Stands", g ∈ s.grants⟩]
  | .sendOwn k =>
    [⟨"sendOwn.Asker", who = .id k⟩, ⟨"sendOwn.CanAct", CanAct s k⟩]
  | .sendGrant g =>
    [⟨"sendGrant.Asker", who = .session g.session⟩, ⟨"sendGrant.Live", GrantLive s g⟩,
     ⟨"sendGrant.MaySend", g.maySend = true⟩]

/-- The subjects `replaceRoot o` revokes and cuts off. -/
def rootCut (s : State) (o : Org) : List Key :=
  (s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map (·.subject)

/-- The record after an act, as its `Step` constructor states it. -/
def Act.effect (s : State) : Act → State
  | .createOrg o => { s with orgs := o :: s.orgs }
  | .replaceRoot o =>
    { s with revoked := rootCut s o ++ s.revoked, cutOff := rootCut s o ++ s.cutOff,
             held := s.held.filter (fun k => decide (k ≠ .root o)) }
  | .readmitByRoot c | .readmitByParent c =>
    { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
             cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | .release key => { s with held := s.held.filter (fun k => decide (k ≠ key)) }
  | .rekeyTeam o t keep =>
    { s with held := s.held.filter (fun k => decide (k ≠ .team o t)),
             members := s.members.filter
               (fun m => decide (¬ (m.org = o ∧ m.team = t) ∨ m.member ∈ keep)),
             grants := s.grants.filter (fun g => decide (¬ (g.org = o ∧ g.team = t))) }
  | .entrust key => { s with held := key :: s.held }
  | .registerByRoot c | .registerByParent c => { s with certs := c :: s.certs }
  | .revokeSelf c | .revokeChild c | .revokeByOrg c =>
    { s with revoked := c.subject :: s.revoked,
             cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | .admit m | .admitAdmin m => { s with members := m :: s.members }
  | .remove m | .leave m =>
    { s with members := s.members.filter (fun x => decide (x ≠ m)),
             grants := s.grants.filter
               (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  | .invite i => { s with invites := i :: s.invites }
  | .redeem i k =>
    { s with members := ⟨i.org, i.team, k⟩ :: s.members,
             invites := s.invites.filter (fun x => decide (x ≠ i)) }
  | .mintGrant g => { s with grants := g :: s.grants }
  | .revokeGrant g => { s with grants := s.grants.filter (fun x => decide (x ≠ g)) }
  | .sendOwn k => { s with sent := ⟨k⟩ :: s.sent }
  | .sendGrant g => { s with sent := ⟨g.subject⟩ :: s.sent }

/-- Every check of the act holds. -/
def Act.Accepted (ask : AskRule) [AskDecidable ask] (s : State) (who : Party)
    (approvals : List Key) (a : Act) : Prop :=
  ∀ c, c ∈ a.checks ask s who approvals → c.prop

/-- The executable step: the record after the act, or the first premise that
fails. -/
def run (ask : AskRule) [AskDecidable ask] (s : State) (who : Party) (approvals : List Key)
    (a : Act) : Except String State :=
  match firstFailing (a.checks ask s who approvals) with
  | none => .ok (a.effect s)
  | some n => .error n

theorem run_ok_iff {ask : AskRule} [AskDecidable ask] {s s' : State} {who : Party}
    {approvals : List Key} {a : Act} :
    run ask s who approvals a = .ok s' ↔ a.Accepted ask s who approvals ∧ s' = a.effect s := by
  unfold run Act.Accepted
  cases h : firstFailing (a.checks ask s who approvals) with
  | none =>
    simp only [Except.ok.injEq]
    exact ⟨fun he => ⟨firstFailing_none.1 h, he.symm⟩, fun ⟨_, he⟩ => he.symm⟩
  | some n =>
    simp only [reduceCtorEq, false_iff, not_and]
    intro hall
    obtain ⟨pre, c, post, hl, -, hf, -⟩ := firstFailing_some h
    exact absurd (hall c (by rw [hl]; simp)) hf

/-- A refusal names a premise of the act that is false, and every premise
before it holds. -/
theorem run_error_premise {ask : AskRule} [AskDecidable ask] {s : State} {who : Party}
    {approvals : List Key} {a : Act} {n : String} (h : run ask s who approvals a = .error n) :
    ∃ pre c post, a.checks ask s who approvals = pre ++ c :: post ∧ c.name = n ∧ ¬ c.prop ∧
      ∀ c', c' ∈ pre → c'.prop := by
  unfold run at h
  cases hf : firstFailing (a.checks ask s who approvals) with
  | none => rw [hf] at h; simp at h
  | some m =>
    rw [hf] at h
    simp at h
    subst h
    exact firstFailing_some hf

/-- An accepted act is a step of the model, to the act's effect. -/
theorem Act.Accepted.step {ask : AskRule} [AskDecidable ask] {s : State} {who : Party}
    {approvals : List Key} {a : Act} (h : a.Accepted ask s who approvals) :
    Step ask s who (a.effect s) := by
  simp only [Act.Accepted] at h
  cases a with
  | createOrg o =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2⟩ := h
    exact .createOrg h2
  | replaceRoot o =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2⟩ := h
    exact .replaceRoot h2
  | readmitByRoot c =>
    simp [Act.checks] at h
    obtain ⟨h1, h2, h3, h4⟩ := h
    exact .readmitByRoot h1 h2 h3 h4
  | readmitByParent c =>
    simp [Act.checks] at h
    obtain ⟨h1, h2, h3, h4, h5⟩ := h
    cases hi : c.issuer with
    | root => simp [ByMember, hi] at h2
    | member p =>
      simp [AskedByIssuer, IssuerValid, hi] at h3 h5
      obtain ⟨pk, hv⟩ := h5
      subst h3
      exact .readmitByParent h1 hi h4 hv
  | release key =>
    simp [Act.checks] at h
    exact .release h.1 h.2
  | rekeyTeam o t keep =>
    simp [Act.checks] at h
    exact .rekeyTeam h.1 h.2
  | entrust key =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2⟩ := h
    exact .entrust h2
  | registerByRoot c =>
    simp [Act.checks] at h
    obtain ⟨h1, h2, h3, h4⟩ := h
    exact .registerByRoot h1 h2 h3 h4
  | registerByParent c =>
    simp [Act.checks] at h
    obtain ⟨h1, h2, h3, h4, h5⟩ := h
    cases hi : c.issuer with
    | root => simp [ByMember, hi] at h1
    | member p =>
      simp [AskedByIssuer, IssuerValid, hi] at h2 h5
      obtain ⟨pk, hv, hm⟩ := h5
      subst h2
      exact .registerByParent hi h3 hv hm
  | revokeSelf c =>
    simp [Act.checks] at h
    obtain ⟨h1, rfl⟩ := h
    exact .revokeSelf h1
  | revokeChild c =>
    simp [Act.checks] at h
    obtain ⟨h1, h2, h3, h4⟩ := h
    cases hi : c.issuer with
    | root => simp [ByMember, hi] at h2
    | member p =>
      simp [AskedByIssuer, IssuerValid, hi] at h3 h4
      obtain ⟨pk, hv⟩ := h4
      subst h3
      exact .revokeChild h1 hi hv
  | revokeByOrg c =>
    simp [Act.checks] at h
    exact .revokeByOrg h.1 h.2
  | admit m =>
    simp [Act.checks] at h
    exact .admit h.1 h.2.1 h.2.2
  | admitAdmin m =>
    simp [Act.checks] at h
    obtain ⟨h1, ⟨kind, h2⟩, h3⟩ := h
    exact .admitAdmin h1 h2 h3
  | remove m =>
    simp [Act.checks] at h
    exact .remove h.1 h.2
  | leave m =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2, h3, h4⟩ := h
    exact .leave h2 h3 h4
  | invite i =>
    simp [Act.checks] at h
    exact .invite h.1 h.2.1 h.2.2
  | redeem i k =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2, h3, h4⟩ := h
    exact .redeem h2 h3 h4
  | mintGrant g =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2, h3⟩ := h
    exact .mintGrant h2 h3
  | revokeGrant g =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2⟩ := h
    exact .revokeGrant h2
  | sendOwn k =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2⟩ := h
    exact .sendOwn h2
  | sendGrant g =>
    simp [Act.checks] at h
    obtain ⟨rfl, h2, h3⟩ := h
    exact .sendGrant h2 h3

/-- Every step of the model is an accepted act, with its effect. -/
theorem Step.accepted {ask : AskRule} [AskDecidable ask] {s s' : State} {who : Party}
    (h : Step ask s who s') :
    ∃ (a : Act) (approvals : List Key), a.Accepted ask s who approvals ∧ s' = a.effect s := by
  cases h with
  | createOrg h1 =>
    exact ⟨.createOrg _, [], by simp [Act.Accepted, Act.checks, h1], rfl⟩
  | replaceRoot h1 =>
    exact ⟨.replaceRoot _, [], by simp [Act.Accepted, Act.checks, h1], rfl⟩
  | readmitByRoot h1 h2 h3 h4 =>
    rename_i _ ap
    exact ⟨.readmitByRoot _, ap, by simp [Act.Accepted, Act.checks, h1, h2, h3, h4], rfl⟩
  | readmitByParent h1 h2 h3 h4 =>
    exact ⟨.readmitByParent _, [], by
      simp [Act.Accepted, Act.checks, ByMember, AskedByIssuer, IssuerValid, h1, h2, h3]
      exact ⟨_, h4⟩, rfl⟩
  | release h1 h2 =>
    rename_i _ ap
    exact ⟨.release _, ap, by simp [Act.Accepted, Act.checks, h1, h2], rfl⟩
  | rekeyTeam h1 h2 =>
    rename_i _ _ _ ap
    exact ⟨.rekeyTeam _ _ _, ap, by simp [Act.Accepted, Act.checks]; exact ⟨h1, h2⟩, rfl⟩
  | entrust h1 =>
    exact ⟨.entrust _, [], by simp [Act.Accepted, Act.checks, h1], rfl⟩
  | registerByRoot h1 h2 h3 h4 =>
    rename_i _ ap
    exact ⟨.registerByRoot _, ap, by simp [Act.Accepted, Act.checks, h1, h2, h3, h4], rfl⟩
  | registerByParent h1 h2 h3 h4 =>
    exact ⟨.registerByParent _, [], by
      simp [Act.Accepted, Act.checks, ByMember, AskedByIssuer, IssuerValid, h1, h2]
      exact ⟨⟨_, h3⟩, _, h3, h4⟩, rfl⟩
  | revokeSelf h1 =>
    exact ⟨.revokeSelf _, [], by simp [Act.Accepted, Act.checks, h1], rfl⟩
  | revokeChild h1 h2 h3 =>
    exact ⟨.revokeChild _, [], by
      simp [Act.Accepted, Act.checks, ByMember, AskedByIssuer, IssuerValid, h1, h2]
      exact ⟨_, h3⟩, rfl⟩
  | revokeByOrg h1 h2 =>
    rename_i _ ap
    exact ⟨.revokeByOrg _, ap, by simp [Act.Accepted, Act.checks, h1, h2], rfl⟩
  | admit h1 h2 h3 =>
    rename_i _ ap
    exact ⟨.admit _, ap, by simp [Act.Accepted, Act.checks, h1, h2, h3], rfl⟩
  | admitAdmin h1 h2 h3 =>
    rename_i _ _ ap
    exact ⟨.admitAdmin _, ap, by simp [Act.Accepted, Act.checks, h1]; exact ⟨⟨_, h2⟩, h1 ▸ h3⟩, rfl⟩
  | remove h1 h2 =>
    rename_i _ ap
    exact ⟨.remove _, ap, by simp [Act.Accepted, Act.checks]; exact ⟨h1, h2⟩, rfl⟩
  | leave h1 h2 h3 =>
    exact ⟨.leave _, [], by simp [Act.Accepted, Act.checks, h1, h2, h3], rfl⟩
  | invite h1 h2 h3 =>
    rename_i _ ap
    exact ⟨.invite _, ap, by simp [Act.Accepted, Act.checks, h1]; exact ⟨h2, h3⟩, rfl⟩
  | redeem h1 h2 h3 =>
    exact ⟨.redeem _ _, [], by simp [Act.Accepted, Act.checks, h1, h2, h3], rfl⟩
  | mintGrant h1 h2 =>
    exact ⟨.mintGrant _, [], by simp [Act.Accepted, Act.checks, h1]; exact h2, rfl⟩
  | revokeGrant h1 =>
    exact ⟨.revokeGrant _, [], by simp [Act.Accepted, Act.checks, h1], rfl⟩
  | sendOwn h1 =>
    exact ⟨.sendOwn _, [], by simp [Act.Accepted, Act.checks, h1], rfl⟩
  | sendGrant h1 h2 =>
    exact ⟨.sendGrant _, [], by simp [Act.Accepted, Act.checks, h1, h2], rfl⟩

/-- `run` accepts exactly the steps of the model: a step from `s` by `who` to
`s'` exists if and only if some act and approvals make `run` return `s'`. -/
theorem step_iff_run {ask : AskRule} [AskDecidable ask] {s s' : State} {who : Party} :
    Step ask s who s' ↔ ∃ (a : Act) (approvals : List Key), run ask s who approvals a = .ok s' := by
  constructor
  · intro h
    obtain ⟨a, approvals, ha, he⟩ := h.accepted
    exact ⟨a, approvals, run_ok_iff.2 ⟨ha, he⟩⟩
  · rintro ⟨a, approvals, h⟩
    obtain ⟨ha, rfl⟩ := run_ok_iff.1 h
    exact ha.step

end TrustWeb
