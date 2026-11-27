import TrustWeb.Properties

/-!
# What must be possible

The other results say what never happens. These say what can happen: each
shows a record the system reaches in which something works.
-/

namespace TrustWeb

/-- **An organisation runs with no key holder and no hosted service.** There
is a record the system reaches, under any rule, with no key held by anyone
else, in which:

* a person made an agent, and that agent made an agent, with nobody asked;
* the person answers for both;
* an agent of another organisation is in one of the first organisation's
  teams, is still a member of its own organisation, and is not a member of
  the first. -/
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

/-- **An organisation can require a person's approval.** Where its policy asks
for a person's approval of a kind of act, approvals from anyone else do not
satisfy it. -/
theorem policy_requires_person {s : State} {o : Org} {act : ActKind} {r : Rule}
    (hr : r ∈ s.policy) (ho : r.org = o) (ha : r.act = act) (hp : r.approver = .anyPerson)
    {approvals : List Key} (hnone : ∀ k, k ∈ approvals → ¬ Valid s o k .person) :
    ¬ Approved s o act approvals := by
  intro happ
  have h := happ r hr ho ha
  rw [hp] at h
  exact agents_cannot_approve_as_person hnone h

/-- **And a person's approval satisfies it.** Where the only rule for a kind
of act asks for a person, one valid person's approval is enough. -/
theorem person_approval_satisfies {s : State} {o : Org} {act : ActKind} {p : Key}
    (hv : Valid s o p .person)
    (hrules : ∀ r, r ∈ s.policy → r.org = o → r.act = act → r.approver = .anyPerson) :
    Approved s o act [p] := by
  intro r hr ho ha
  rw [hrules r hr ho ha]
  exact ⟨p, List.mem_cons_self, hv⟩

/-- **Design. A required approval can be given, and then the act goes
through.** Where a key holder holds a team's key and the policy asks for a
person's approval to admit, an admin with one valid person's approval admits
a member. -/
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
certificate.** Nothing is proved here about several acts. -/
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

/-- **Design. An organisation with no person at all can run.** There is a
record the system reaches in which organisation 0 has no person, agent 1 is
its admin, and agent 1 alone, with no approval, admits a member to a team. -/
theorem agent_only_org_runs :
    ∃ s s', Reachable adminRule s ∧ (∀ k, ¬ Person s 0 k) ∧ Admin s 0 1 ∧
      Valid s 0 1 .agent ∧ Step adminRule s (.id 1) s' ∧
      (⟨0, .named 7, 2⟩ : Membership) ∈ s'.members := by
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
      (.inr (by intro m' hm'; simp [s4, s3, ma] at hm'; subst hm'; simp)), by simp⟩
  · intro k hp
    obtain ⟨d, hd, _, hk, _⟩ := hp.cert
    simp [s4, s3, s2, c] at hd
    subst hd
    simp at hk
  · intro r hr
    simp [s4, s3, s2, s1, s0] at hr

end TrustWeb
