import TrustWeb.Properties

/-!
# What must be possible

Records the system reaches in which something works, acts that go through
when their conditions hold, and limits: `policy_requires_person`,
`locked_without_admin`, `takeover_can_leave_admin_team_locked`,
`takeover_leaves_outsiders_acting` and `revocation_can_leave_no_admin`. Each
theorem's doc comment says what it states.
-/

namespace TrustWeb

/-- **A record with no key holder in which a person, its agents and an outsider
act.** Under
any rule, there is a record the system reaches in which:

* no key is with a key holder;
* 1 is a valid person of organisation 0, and 2 and 3 are valid agents of it;
* 1 answers for 2 and for 3;
* 9 is a valid agent of organisation 1, can act in team 7 of organisation 0,
  and is not valid in organisation 0.

In the construction 1 issues 2 and 2 issues 3, each with its own key; the
statement does not say who issued whom. -/
theorem runs_without_key_holder (ask : AskRule) :
    ∃ s, Reachable ask s ∧ s.held = [] ∧
      Valid s 0 1 .person ∧ Valid s 0 2 .agent ∧ Valid s 0 3 .agent ∧
      AnswersFor s 0 2 1 ∧ AnswersFor s 0 3 1 ∧
      Valid s 1 9 .agent ∧ InTeam s 0 (.named 7) 9 ∧ (∀ kind, ¬ Valid s 0 9 kind) := by
  let c1 : Cert := ⟨0, 1, .person, .root⟩
  let c2 : Cert := ⟨0, 2, .agent, .member 1⟩
  let c3 : Cert := ⟨0, 3, .agent, .member 2⟩
  let c9 : Cert := ⟨1, 9, .agent, .root⟩
  let m : Membership := ⟨0, .named 7, 9⟩
  let s0 : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let s1 : State := { s0 with orgs := [0] }
  let s2 : State := { s1 with certs := [c1] }
  let s3 : State := { s2 with certs := [c2, c1] }
  let s4 : State := { s3 with certs := [c3, c2, c1] }
  let s5 : State := { s4 with orgs := [1, 0] }
  let s6 : State := { s5 with certs := [c9, c3, c2, c1] }
  let s7 : State := { s6 with members := [m] }
  have r0 : Reachable ask s0 := .start []
  have r1 : Reachable ask s1 := .step r0 (Step.createOrg (o := 0) (by simp [s0]))
  have r2 : Reachable ask s2 :=
    .step r1 (Step.registerByRoot (c := c1) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s1, c1]) (by intro d hd; simp [s1, s0] at hd)
      (.inl ⟨by simp [s1, s0], rfl⟩))
  have v1 : Valid s2 0 1 .person :=
    .person (.byRoot (c := c1) (by simp [s2]) rfl rfl rfl rfl) (by simp [s2, s1, s0])
  have r3 : Reachable ask s3 :=
    .step r2 (Step.registerByParent (c := c2) (p := 1) (pk := .person) rfl
      (by intro d hd; simp [s2] at hd; subst hd; simp [c1, c2]) v1 (.inl rfl))
  have v2 : Valid s3 0 2 .agent :=
    .agentOf (c := c2) (by simp [s3]) rfl rfl rfl rfl (by simp [s3, s2, s1, s0])
      (v1.mono (by intro c hc; simp [s2] at hc; simp [s3, hc]) (by intro k hk; exact hk))
  have r4 : Reachable ask s4 :=
    .step r3 (Step.registerByParent (c := c3) (p := 2) (pk := .agent) rfl
      (by intro d hd; simp [s3] at hd; rcases hd with rfl | rfl <;> simp [c1, c2, c3])
      v2 (.inr rfl))
  have r5 : Reachable ask s5 :=
    .step r4 (Step.createOrg (o := 1) (by simp [s4, s3, s2, s1]))
  have r6 : Reachable ask s6 :=
    .step r5 (Step.registerByRoot (c := c9) (who := .controller (.root 1)) (approvals := [])
      rfl (by simp [s5, c9])
      (by intro d hd; simp [s5, s4] at hd; rcases hd with rfl | rfl | rfl <;> simp [c1, c2, c3, c9])
      (.inl ⟨by simp [s5, s4, s3, s2, s1, s0], rfl⟩))
  have r7 : Reachable ask s7 :=
    .step r6 (Step.admit (m := m) (who := .controller (.team 0 (.named 7))) (approvals := [])
      (by simp [m]) (.inl ⟨by simp [s6, s5, s4, s3, s2, s1, s0], rfl⟩)
      (.inl ⟨c9, by simp [s6], rfl⟩))
  have norev : ∀ k, k ∉ s7.revoked := by
    intro k hk; simp [s7, s6, s5, s4, s3, s2, s1, s0] at hk
  have w1 : Valid s7 0 1 .person :=
    v1.mono (by intro c hc; simp [s2] at hc; simp [s7, s6, hc]) (fun k hk => absurd hk (norev k))
  have w2 : Valid s7 0 2 .agent :=
    .agentOf (c := c2) (by simp [s7, s6]) rfl rfl rfl rfl (norev 2) w1
  have w3 : Valid s7 0 3 .agent :=
    .agentOf (c := c3) (by simp [s7, s6]) rfl rfl rfl rfl (norev 3) w2
  have w9 : Valid s7 1 9 .agent :=
    .agentOfRoot (c := c9) (by simp [s7, s6]) rfl rfl rfl rfl (norev 9)
  have a2 : AnswersFor s7 0 2 1 :=
    .up (c := c2) (by simp [s7, s6]) rfl rfl rfl rfl (norev 2) (.self w1)
  refine ⟨s7, r7, by simp [s7, s6, s5, s4, s3, s2, s1, s0], w1, w2, w3, a2,
    .up (c := c3) (by simp [s7, s6]) rfl rfl rfl rfl (norev 3) a2, w9,
    ⟨by simp [HasTeamCert, s7, m], .inr ⟨1, .agent, w9⟩⟩, ?_⟩
  intro kind hv
  obtain ⟨d, hd, hds, _, hdo⟩ := hv.cert
  simp [s7, s6] at hd
  rcases hd with rfl | rfl | rfl | rfl <;> simp [c1, c2, c3, c9] at hds hdo

/-- **A rule asking for any person's approval refuses approvals with no valid
person.** If `o`'s policy has a
rule asking for any person's approval of a kind of act, and no approver is a
valid person of `o`, the approvals are not approved for that act. -/
theorem policy_requires_person {s : State} {o : Org} {act : ActKind} {r : Rule}
    (hr : r ∈ s.policy) (ho : r.org = o) (ha : r.act = act) (hp : r.approver = .anyPerson)
    {approvals : List Key} (hnone : ∀ k, k ∈ approvals → ¬ Valid s o k .person) :
    ¬ Approved s o act approvals := by
  intro happ
  have h := happ r hr ho ha
  rw [hp] at h
  exact agents_cannot_approve_as_person hnone h

/-- **One valid person's approval satisfies rules that ask for any person.** If `p` is a valid person of `o`
and every rule of `o` for a kind of act asks for any person, `p`'s approval
alone is approved for that act. -/
theorem person_approval_satisfies {s : State} {o : Org} {act : ActKind} {p : Key}
    (hv : Valid s o p .person)
    (hrules : ∀ r, r ∈ s.policy → r.org = o → r.act = act → r.approver = .anyPerson) :
    Approved s o act [p] := by
  intro r hr ho ha
  rw [hrules r hr ho ha]
  exact ⟨p, List.mem_cons_self, hv⟩

/-- **Design. With a valid person's approval, an admin's admission to a named
team goes through.** If a named team's key is with a key holder, `a` is an admin, `p` is
a valid person, `k` is registered or holds no team certificate, and every rule
for admitting asks for any person, there is an accepted act under the admin
rule that `a` asks for, after which `k` holds a certificate of that team. -/
theorem approved_act_goes_through {s : State} {o : Org} {n : Nat} {a p k : Key}
    (hheld : OrgKey.team o (.named n) ∈ s.held) (ha : Admin s o a)
    (hv : Valid s o p .person) (hk : OneTeamIfLocal s k)
    (hrules : ∀ r, r ∈ s.policy → r.org = o → r.act = .admit → r.approver = .anyPerson) :
    ∃ s', Step adminRule s (.id a) s' ∧ HasTeamCert s' o (.named n) k := by
  refine ⟨_, Step.admit (m := ⟨o, .named n, k⟩) (approvals := [p]) (by simp)
    (.inr ⟨hheld, a, rfl, ha, person_approval_satisfies hv hrules⟩) hk, ?_⟩
  exact List.mem_cons_self

/-- **Design, in one act. Where the admin team's key is with a key holder and
the organisation has no admin, no accepted act adds an admin-team
certificate of it.** It says nothing about re-admission, which leaves the
team certificates as they are (`readmitByRoot`, `readmitByParent`). Over three acts an admin-team certificate
of it can be added (`locked_organisation_unlocks_by_readmission`). -/
theorem locked_without_admin {s s' : State} {who : Party} {o : Org}
    (hheld : OrgKey.team o .admin ∈ s.held) (hnone : ∀ k, ¬ Admin s o k)
    (hstep : Step adminRule s who s') {m : Membership}
    (hnew : m ∈ s'.members) (hold : m ∉ s.members) (hteam : m.team = .admin) : m.org ≠ o := by
  intro ho
  cases hstep with
  | createOrg _ => exact absurd hnew hold
  | entrust _ => exact absurd hnew hold
  | registerByRoot _ _ _ _ => exact absurd hnew hold
  | registerByParent _ _ _ _ => exact absurd hnew hold
  | revokeSelf _ => exact absurd hnew hold
  | revokeChild _ _ _ => exact absurd hnew hold
  | revokeByOrg _ _ => exact absurd hnew hold
  | invite _ _ _ => exact absurd hnew hold
  | mintGrant _ _ => exact absurd hnew hold
  | revokeGrant _ => exact absurd hnew hold
  | release _ _ => exact absurd hnew hold
  | rekeyTeam _ => exact absurd hnew hold
  | replaceRoot _ => exact absurd hnew hold
  | readmitByRoot _ _ _ _ => exact absurd hnew hold
  | readmitByParent _ _ _ _ => exact absurd hnew hold
  | sendOwn _ => exact absurd hnew hold
  | sendGrant _ _ => exact absurd hnew hold
  | remove _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
  | leave _ _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
  | admit hne _ _ =>
      rcases List.mem_cons.mp hnew with rfl | h
      · exact absurd hteam hne
      · exact absurd h hold
  | redeem _ hne _ =>
      rcases List.mem_cons.mp hnew with rfl | h
      · exact absurd hteam hne
      · exact absurd h hold
  | admitAdmin _ _ hauth =>
      rcases List.mem_cons.mp hnew with rfl | h
      · rcases hauth with ⟨hnot, _⟩ | ⟨_, a, _, hask, _⟩
        · rw [hteam, ho] at hnot; exact hnot hheld
        · have ha : Admin s o a := by
            simpa [adminRule, OrgKey.org, ho] using hask
          exact hnone a ha
      · exact absurd h hold

/-- **Design. An organisation with no admin, its admin team's key held, can
gain an admin-team certificate after the root's acts.** There is a record `L` the system reaches under the admin rule
in which the admin team's key of organisation 0 is with a key holder and 0
has no admin; from `L`, two acts asked by whoever controls 0's root key and
then one act asked by identity 1 are accepted, and afterwards 2 holds an
admin-team certificate of 0 that it did not hold in `L`. In the construction
a root replacement cut off agents 1 and 2, the new root admits both again,
and 1, which still holds its admin-team certificate, is an admin again and
has 2 admitted through the key holder. -/
theorem locked_organisation_unlocks_by_readmission :
    ∃ L R1 R2 R3, Reachable adminRule L ∧ OrgKey.team 0 .admin ∈ L.held ∧
      (∀ k, ¬ Admin L 0 k) ∧
      Step adminRule L (.controller (.root 0)) R1 ∧
      Step adminRule R1 (.controller (.root 0)) R2 ∧
      Step adminRule R2 (.id 1) R3 ∧
      (⟨0, .admin, 2⟩ : Membership) ∈ R3.members ∧ (⟨0, .admin, 2⟩ : Membership) ∉ L.members := by
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let c1 : Cert := ⟨0, 1, .agent, .root⟩
  let c2 : Cert := ⟨0, 2, .agent, .root⟩
  let ma : Membership := ⟨0, .admin, 1⟩
  let s1 : State := { e with orgs := [0] }
  let s2 : State := { s1 with certs := [c1] }
  let s3 : State := { s2 with certs := [c2, c1] }
  let s4 : State := { s3 with members := [ma] }
  let s5 : State := { s4 with held := [.team 0 .admin] }
  let L : State :=
    { s5 with
      revoked := ((s5.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s5.revoked))).map
        (·.subject)) ++ s5.revoked,
      cutOff := ((s5.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s5.revoked))).map
        (·.subject)) ++ s5.cutOff,
      held := s5.held.filter (fun k => decide (k ≠ .root 0)) }
  let R1 : State :=
    { L with revoked := L.revoked.filter (fun k => decide (k ≠ c1.subject)),
             cutOff := L.cutOff.filter (fun k => decide (k ≠ c1.subject)) }
  let R2 : State :=
    { R1 with revoked := R1.revoked.filter (fun k => decide (k ≠ c2.subject)),
              cutOff := R1.cutOff.filter (fun k => decide (k ≠ c2.subject)) }
  let m2 : Membership := ⟨0, .admin, 2⟩
  have r1 : Reachable adminRule s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable adminRule s2 :=
    .step r1 (Step.registerByRoot (c := c1) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s1, c1]) (by intro d hd; simp [s1, e] at hd) (.inl ⟨by simp [s1, e], rfl⟩))
  have r3 : Reachable adminRule s3 :=
    .step r2 (Step.registerByRoot (c := c2) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s2, s1, c2]) (by intro d hd; simp [s2] at hd; subst hd; simp [c1, c2])
      (.inl ⟨by simp [s2, s1, e], rfl⟩))
  have v3 : Valid s3 0 1 .agent :=
    .agentOfRoot (c := c1) (by simp [s3]) rfl rfl rfl rfl (by simp [s3, s2, s1, e])
  have r4 : Reachable adminRule s4 :=
    .step r3 (Step.admitAdmin (m := ma) (kind := .agent) (who := .controller (.team 0 .admin))
      (approvals := []) rfl v3 (.inl ⟨by simp [s3, s2, s1, e], rfl⟩))
  have r5 : Reachable adminRule s5 :=
    .step r4 (Step.entrust (key := .team 0 .admin) (by simp [s4, s3, s2, s1, e]))
  have rL : Reachable adminRule L := .step r5 (Step.replaceRoot (o := 0) (by simp [s5, s4, s3, s2, s1]))
  have hR1 : Step adminRule L (.controller (.root 0)) R1 :=
    Step.readmitByRoot (c := c1) (approvals := []) (by simp [L, s5, s4, s3])
      rfl (by simp [L, s5, s4, s3, s2, s1, e, c1, c2])
      (.inl ⟨by simp [L, s5], rfl⟩)
  have hR2 : Step adminRule R1 (.controller (.root 0)) R2 :=
    Step.readmitByRoot (c := c2) (approvals := []) (by simp [R1, L, s5, s4, s3])
      rfl (by simp [R1, L, s5, s4, s3, s2, s1, e, c1, c2])
      (.inl ⟨by simp [R1, L, s5], rfl⟩)
  have norev : ∀ k, k ∉ R2.revoked := by
    intro k hk; simp [R2, R1, L, s5, s4, s3, s2, s1, e, c1, c2] at hk
  have w1 : Valid R2 0 1 .agent :=
    .agentOfRoot (c := c1) (by simp [R2, R1, L, s5, s4, s3]) rfl rfl rfl rfl (norev 1)
  have w2 : Valid R2 0 2 .agent :=
    .agentOfRoot (c := c2) (by simp [R2, R1, L, s5, s4, s3]) rfl rfl rfl rfl (norev 2)
  have a1 : Admin R2 0 1 := ⟨by simp [R2, R1, L, s5, s4, ma], .agent, w1⟩
  refine ⟨L, R1, R2, { R2 with members := m2 :: R2.members }, rL, by simp [L, s5], ?_, hR1, hR2,
    ?_, List.mem_cons_self, by simp [L, s5, s4, ma]⟩
  · intro k ⟨hm, kind, hv⟩
    simp [L, s5, s4, ma] at hm
    subst hm
    exact revoked_not_valid (by simp [L, s5, s4, s3, s2, s1, e, c1, c2]) hv
  · refine Step.admitAdmin (m := m2) (kind := .agent) (approvals := []) rfl w2
      (.inr ⟨by simp [R2, R1, L, s5, m2], 1, rfl, a1, ?_⟩)
    intro r hr; simp [R2, R1, L, s5, s4, s3, s2, s1, e] at hr

/-- **Design. With no person, an agent admin can admit to a named team.** There is a
record the system reaches under the admin rule in which nobody is a person of
organisation 0, and 1 is an admin and a valid agent of it; an act that 1 asks
for is accepted, after which 2 holds a certificate of team 7 of 0 that it did
not hold before. -/
theorem agent_only_org_runs :
    ∃ s s', Reachable adminRule s ∧ (∀ k, ¬ Person s 0 k) ∧ Admin s 0 1 ∧
      Valid s 0 1 .agent ∧ Step adminRule s (.id 1) s' ∧
      (⟨0, .named 7, 2⟩ : Membership) ∈ s'.members ∧
      (⟨0, .named 7, 2⟩ : Membership) ∉ s.members := by
  let c : Cert := ⟨0, 1, .agent, .root⟩
  let ma : Membership := ⟨0, .admin, 1⟩
  let tk : OrgKey := .team 0 (.named 7)
  let s0 : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let s1 : State := { s0 with orgs := [0] }
  let s2 : State := { s1 with certs := [c] }
  let s3 : State := { s2 with members := [ma] }
  let s4 : State := { s3 with held := [tk] }
  have r0 : Reachable adminRule s0 := .start []
  have r1 : Reachable adminRule s1 :=
    .step r0 (Step.createOrg (o := 0) (by simp [s0]))
  have r2 : Reachable adminRule s2 :=
    .step r1 (Step.registerByRoot (c := c) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s1, c]) (by intro d hd; simp [s1, s0] at hd)
      (.inl ⟨by simp [s1, s0], rfl⟩))
  have v2 : Valid s2 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s2]) rfl rfl rfl rfl (by simp [s2, s1, s0])
  have r3 : Reachable adminRule s3 :=
    .step r2 (Step.admitAdmin (m := ma) (kind := .agent) (who := .controller (.team 0 .admin))
      (approvals := []) rfl v2 (.inl ⟨by simp [s2, s1, s0], rfl⟩))
  have r4 : Reachable adminRule s4 :=
    .step r3 (Step.entrust (key := tk) (by simp [s3, s2, s1, s0]))
  have v4 : Valid s4 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s4, s3, s2]) rfl rfl rfl rfl (by simp [s4, s3, s2, s1, s0])
  have a4 : Admin s4 0 1 := ⟨by simp [s4, s3, ma], .agent, v4⟩
  refine ⟨s4, _, r4, ?_, a4, v4,
    Step.admit (m := ⟨0, .named 7, 2⟩) (who := .id 1) (approvals := []) (by simp)
      (.inr ⟨by simp [s4, tk], 1, rfl, a4, ?_⟩)
      (.inr (by intro m' hm'; simp [s4, s3, ma] at hm'; subst hm'; simp)), by simp,
    by simp [s4, s3, ma]⟩
  · intro k hp
    obtain ⟨d, hd, _, hk, _⟩ := hp.cert
    simp [s4, s3, s2, c] at hd
    subst hd
    simp at hk
  · intro r hr
    simp [s4, s3, s2, s1, s0] at hr

/-- `AdminTeamLocked s o`: the admin team's key of `o` is with a key holder,
and no team certificate of `o`'s admin team stands. -/
def AdminTeamLocked (s : State) (o : Org) : Prop :=
  OrgKey.team o .admin ∈ s.held ∧ ∀ m, m ∈ s.members → m.org = o → m.team ≠ .admin

/-- A locked admin team leaves its organisation with no admin. -/
theorem AdminTeamLocked.no_admin {s : State} {o : Org} (h : AdminTeamLocked s o) (k : Key) :
    ¬ Admin s o k := by
  intro ⟨hm, _⟩
  exact h.2 _ hm rfl rfl

/-- **Replacing the root can leave the admin team locked.** Under any rule
there is a record the system reaches and an act asked for by organisation
0's domain owner, after which the record is reachable, 0's root key is not
with a key holder, no identity is valid in 0, and 0's admin team is locked.
-/
theorem takeover_can_leave_admin_team_locked (ask : AskRule) :
    ∃ s s', Reachable ask s ∧ Step ask s (.dns 0) s' ∧ Reachable ask s' ∧
      OrgKey.root 0 ∉ s'.held ∧ (∀ k kind, ¬ Valid s' 0 k kind) ∧ AdminTeamLocked s' 0 := by
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let s1 : State := { e with orgs := [0] }
  let s2 : State := { s1 with held := [.team 0 .admin] }
  have r1 : Reachable ask s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable ask s2 := .step r1 (Step.entrust (key := .team 0 .admin) (by simp [s1, e]))
  have hstep : Step ask s2 (.dns 0) _ := Step.replaceRoot (o := 0) (by simp [s2, s1])
  refine ⟨s2, _, r2, hstep, .step r2 hstep, ?_, ?_, ?_⟩
  · simp [s2]
  · intro k kind hv
    obtain ⟨c, hc, _⟩ := hv.cert
    simp [s2, s1, e] at hc
  · refine ⟨by simp [s2], ?_⟩
    intro m hm
    simp [s2, s1, e] at hm

/-- **Replacing the root leaves outsiders acting in the organisation's
teams.** Under any rule there is a record the system reaches, an act asked
for by organisation 0's domain owner, and a grant `g`, such that after the act
0's root key is not with a key holder, no identity is valid in 0, identity 9
can act in team 7 of 0, `g`'s subject is 9, and `g` is live. -/
theorem takeover_leaves_outsiders_acting (ask : AskRule) :
    ∃ (s s' : State) (g : Grant), Reachable ask s ∧ Step ask s (.dns 0) s' ∧
      OrgKey.root 0 ∉ s'.held ∧ (∀ k kind, ¬ Valid s' 0 k kind) ∧
      InTeam s' 0 (.named 7) 9 ∧ g.subject = 9 ∧ GrantLive s' g := by
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let c9 : Cert := ⟨1, 9, .agent, .root⟩
  let m : Membership := ⟨0, .named 7, 9⟩
  let g : Grant := ⟨5, 9, 0, .named 7, true⟩
  let s1 : State := { e with orgs := [0] }
  let s2 : State := { s1 with orgs := [1, 0] }
  let s3 : State := { s2 with certs := [c9] }
  let s4 : State := { s3 with members := [m] }
  let s5 : State := { s4 with grants := [g] }
  have r1 : Reachable ask s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable ask s2 := .step r1 (Step.createOrg (o := 1) (by simp [s1]))
  have r3 : Reachable ask s3 :=
    .step r2 (Step.registerByRoot (c := c9) (who := .controller (.root 1)) (approvals := [])
      rfl (by simp [s2, c9]) (by intro d hd; simp [s2, s1, e] at hd) (.inl ⟨by simp [s2, s1, e], rfl⟩))
  have v3 : Valid s3 1 9 .agent :=
    .agentOfRoot (c := c9) (by simp [s3]) rfl rfl rfl rfl (by simp [s3, s2, s1, e])
  have r4 : Reachable ask s4 :=
    .step r3 (Step.admit (m := m) (who := .controller (.team 0 (.named 7))) (approvals := [])
      (by simp [m]) (.inl ⟨by simp [s3, s2, s1, e], rfl⟩) (.inl ⟨c9, by simp [s3], rfl⟩))
  have v4 : Valid s4 1 9 .agent :=
    .agentOfRoot (c := c9) (by simp [s4, s3]) rfl rfl rfl rfl (by simp [s4, s3, s2, s1, e])
  have r5 : Reachable ask s5 :=
    .step r4 (Step.mintGrant (g := g) ⟨by simp [HasTeamCert, s4, m, g], .inr ⟨1, .agent, v4⟩⟩
      (by intro g' hg'; simp [s4, s3, s2, s1, e] at hg'))
  have hstep : Step ask s5 (.dns 0) _ := Step.replaceRoot (o := 0) (by simp [s5, s4, s3, s2])
  have v' : Valid { s5 with
      revoked := ((s5.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s5.revoked))).map
        (·.subject)) ++ s5.revoked,
      cutOff := ((s5.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s5.revoked))).map
        (·.subject)) ++ s5.cutOff,
      held := s5.held.filter (fun k => decide (k ≠ .root 0)) } 1 9 .agent :=
    .agentOfRoot (c := c9) (by simp [s5, s4, s3]) rfl rfl rfl rfl
      (by simp [s5, s4, s3, s2, s1, e, c9])
  have hin : InTeam { s5 with
      revoked := ((s5.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s5.revoked))).map
        (·.subject)) ++ s5.revoked,
      cutOff := ((s5.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s5.revoked))).map
        (·.subject)) ++ s5.cutOff,
      held := s5.held.filter (fun k => decide (k ≠ .root 0)) } 0 (.named 7) 9 :=
    ⟨by simp [HasTeamCert, s5, s4, m], .inr ⟨1, .agent, v'⟩⟩
  refine ⟨s5, _, g, r5, hstep, by simp [s5, s4, s3, s2, s1, e], ?_, hin, rfl,
    ⟨by simp [s5], hin⟩⟩
  intro k kind hv
  obtain ⟨c, hc, _, _, hco⟩ := hv.cert
  simp [s5, s4, s3] at hc
  subst hc
  simp [c9] at hco

/-- **A revocation can leave an organisation with no admin.** Under any rule
there is a record the system reaches in which the admin team's key of 0 is
with a key holder and 1 is an admin of 0, and an accepted act 1 asks for
after which 0 has no admin. In the construction the act is 1 revoking itself. -/
theorem revocation_can_leave_no_admin (ask : AskRule) :
    ∃ s s', Reachable ask s ∧ OrgKey.team 0 .admin ∈ s.held ∧ Admin s 0 1 ∧
      Step ask s (.id 1) s' ∧ ∀ k, ¬ Admin s' 0 k := by
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let c : Cert := ⟨0, 1, .agent, .root⟩
  let ma : Membership := ⟨0, .admin, 1⟩
  let s1 : State := { e with orgs := [0] }
  let s2 : State := { s1 with certs := [c] }
  let s3 : State := { s2 with members := [ma] }
  let s4 : State := { s3 with held := [.team 0 .admin] }
  have r1 : Reachable ask s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable ask s2 :=
    .step r1 (Step.registerByRoot (c := c) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s1, c]) (by intro d hd; simp [s1, e] at hd) (.inl ⟨by simp [s1, e], rfl⟩))
  have v2 : Valid s2 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s2]) rfl rfl rfl rfl (by simp [s2, s1, e])
  have r3 : Reachable ask s3 :=
    .step r2 (Step.admitAdmin (m := ma) (kind := .agent) (who := .controller (.team 0 .admin))
      (approvals := []) rfl v2 (.inl ⟨by simp [s2, s1, e], rfl⟩))
  have r4 : Reachable ask s4 :=
    .step r3 (Step.entrust (key := .team 0 .admin) (by simp [s3, s2, s1, e]))
  have v4 : Valid s4 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s4, s3, s2]) rfl rfl rfl rfl (by simp [s4, s3, s2, s1, e])
  refine ⟨s4, _, r4, by simp [s4], ⟨by simp [s4, s3, ma], .agent, v4⟩,
    Step.revokeSelf (c := c) (by simp [s4, s3, s2]), ?_⟩
  intro k ⟨hm, kind, hv⟩
  simp [s4, s3, ma] at hm
  subst hm
  exact revoked_not_valid List.mem_cons_self hv

/-- Some key has no certificate and is not revoked. -/
theorem exists_fresh_key (s : State) : ∃ k, Fresh s k ∧ k ∉ s.revoked := by
  let n := (s.certs.map (·.subject) ++ s.revoked).foldr max 0 + 1
  have big : ∀ x, x ∈ s.certs.map (·.subject) ++ s.revoked → x < n := by
    intro x hx
    have : ∀ (l : List Key) (y : Key), y ∈ l → y ≤ l.foldr max 0 := by
      intro l
      induction l with
      | nil => intro y hy; cases hy
      | cons a l ih =>
          intro y hy
          rcases List.mem_cons.mp hy with rfl | hy
          · exact Nat.le_max_left _ _
          · exact Nat.le_trans (ih y hy) (Nat.le_max_right _ _)
    exact Nat.lt_succ_of_le (this _ x hx)
  refine ⟨n, ?_, ?_⟩
  · intro c hc hs
    have := big c.subject (List.mem_append_left _ (List.mem_map.mpr ⟨c, hc, rfl⟩))
    rw [hs] at this
    exact Nat.lt_irrefl _ this
  · intro hr
    exact Nat.lt_irrefl _ (big n (List.mem_append_right _ hr))

/-- **An organisation gets an admin back from its domain alone.** If `o`
exists and `k` has no certificate and is not revoked, then under any rule
there are four accepted acts: `o`'s domain owner replaces the root; whoever
controls the new root key re-keys the admin team; it registers `k` as a
person under the root; and whoever controls the admin team's new key admits
`k` to it. Afterwards `k` is an admin of `o`. This holds in any record, a
locked admin team's included, and such a `k` always exists
(`exists_fresh_key`). -/
theorem domain_owner_recovers_an_admin {ask : AskRule} {s : State} {o : Org} {k : Key}
    (ho : o ∈ s.orgs) (hk : Fresh s k) (hkr : k ∉ s.revoked) :
    ∃ s1 s2 s3 s4, Step ask s (.dns o) s1 ∧ Step ask s1 (.controller (.root o)) s2 ∧
      Step ask s2 (.controller (.root o)) s3 ∧ Step ask s3 (.controller (.team o .admin)) s4 ∧
      Admin s4 o k := by
  let s1 : State :=
    { s with
      revoked := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
        (·.subject)) ++ s.revoked,
      cutOff := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
        (·.subject)) ++ s.cutOff,
      held := s.held.filter (fun x => decide (x ≠ .root o)) }
  let s2 : State := { s1 with held := s1.held.filter (fun x => decide (x ≠ .team o .admin)) }
  let c : Cert := ⟨o, k, .person, .root⟩
  let s3 : State := { s2 with certs := c :: s2.certs }
  let s4 : State := { s3 with members := ⟨o, .admin, k⟩ :: s3.members }
  have hroot1 : OrgKey.root o ∉ s1.held := by simp [s1]
  have hroot2 : OrgKey.root o ∉ s2.held := fun h => hroot1 (List.mem_filter.mp h).1
  have hteam3 : OrgKey.team o .admin ∉ s3.held := by simp [s3, s2]
  have hrev3 : k ∉ s3.revoked := by
    intro h
    simp only [s3, s2, s1, List.mem_append, List.mem_map, List.mem_filter] at h
    rcases h with ⟨d, ⟨hd, _⟩, hds⟩ | h
    · exact hk d hd hds
    · exact hkr h
  have hv3 : Valid s3 o k .person :=
    .person (.byRoot (c := c) List.mem_cons_self rfl rfl rfl rfl) hrev3
  refine ⟨s1, s2, s3, s4, Step.replaceRoot ho,
    Step.rekeyTeam (t := .admin) (approvals := []) (.inl ⟨hroot1, rfl⟩),
    Step.registerByRoot (c := c) (approvals := []) rfl ho hk (.inl ⟨hroot2, rfl⟩),
    Step.admitAdmin (m := ⟨o, .admin, k⟩) (kind := .person) (approvals := []) rfl hv3
      (.inl ⟨hteam3, rfl⟩), List.mem_cons_self, .person, ?_⟩
  exact Valid.mono (s := s3) (t := s4) (fun _ h => h) (fun _ h => h) hv3

/-- **The root can end any team membership in two acts.** If `o`'s root key
is not with a key holder, then for any team `t` of `o` and any key `k` there
are two accepted acts: whoever controls the root key re-keys `t`, and whoever
controls `t`'s new key removes `k`'s certificate of `t`. Afterwards `k` holds
no certificate of `t`, and no grant on `k` from `t` stands. -/
theorem root_can_end_team_membership {ask : AskRule} {s : State} {o : Org} {t : Team}
    {k : Key} (hroot : OrgKey.root o ∉ s.held) :
    ∃ s1 s2, Step ask s (.controller (.root o)) s1 ∧ Step ask s1 (.controller (.team o t)) s2 ∧
      ¬ HasTeamCert s2 o t k ∧ ∀ g, g ∈ s2.grants → ¬ (g.org = o ∧ g.team = t ∧ g.subject = k) := by
  let s1 : State := { s with held := s.held.filter (fun x => decide (x ≠ .team o t)) }
  have hteam : OrgKey.team o t ∉ s1.held := by simp [s1]
  refine ⟨s1, _, Step.rekeyTeam (approvals := []) (.inl ⟨hroot, rfl⟩),
    Step.remove (m := ⟨o, t, k⟩) (approvals := []) (.inl ⟨hteam, rfl⟩)
      (fun h => absurd h hteam), ?_, ?_⟩
  · exact not_mem_filter_ne
  · intro g hg hc
    have := (List.mem_filter.mp hg).2
    simp only [decide_eq_true_eq] at this
    exact this hc

end TrustWeb
