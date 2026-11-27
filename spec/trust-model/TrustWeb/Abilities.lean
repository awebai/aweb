import TrustWeb.Properties

/-!
# What must be possible

Results that something can happen, and limits on what can.
-/

namespace TrustWeb

/-- Under any rule, there is a record the system reaches in which: no key is
with a key holder; 1 is a valid person of organisation 0, and 2 and 3 are
valid agents of it; 1 answers for 2 and for 3; and 9 is a valid agent of
organisation 1, can act in team 7 of organisation 0, and is not valid in
organisation 0. In the construction 1 issues 2 and 2 issues 3, each with its
own key; the statement does not say who issued whom. -/
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

/-- If `o`'s policy has a rule asking for any person's approval of a kind of
act, and no approver is a valid person of `o`, the approvals are not approved
for that act. -/
theorem policy_requires_person {s : State} {o : Org} {act : ActKind} {r : Rule}
    (hr : r ∈ s.policy) (ho : r.org = o) (ha : r.act = act) (hp : r.approver = .anyPerson)
    {approvals : List Key} (hnone : ∀ k, k ∈ approvals → ¬ Valid s o k .person) :
    ¬ Approved s o act approvals := by
  intro happ
  have h := happ r hr ho ha
  rw [hp] at h
  exact agents_cannot_approve_as_person hnone h

/-- If `p` is a valid person of `o` and every rule of `o` for a kind of act
asks for any person, `p`'s approval alone is approved for that act. -/
theorem person_approval_satisfies {s : State} {o : Org} {act : ActKind} {p : Key}
    (hv : Valid s o p .person)
    (hrules : ∀ r, r ∈ s.policy → r.org = o → r.act = act → r.approver = .anyPerson) :
    Approved s o act [p] := by
  intro r hr ho ha
  rw [hrules r hr ho ha]
  exact ⟨p, List.mem_cons_self, hv⟩

/-- Design. If a named team `n` of `o` has its key with a key holder, `a` is
an admin of `o`, `p` is a valid person of `o`, `k` is registered or holds no
team certificate, and every rule of `o` for admitting asks for any person,
there is an accepted act under the admin rule that `a` asks for, after which
`k` holds a certificate of team `n` of `o`. The statement does not require
`a`, `p` and `k` to differ. -/
theorem approved_act_goes_through {s : State} {o : Org} {n : Nat} {a p k : Key}
    (hheld : OrgKey.team o (.named n) ∈ s.held) (ha : Admin s o a)
    (hv : Valid s o p .person) (hk : OneTeamIfLocal s k)
    (hrules : ∀ r, r ∈ s.policy → r.org = o → r.act = .admit → r.approver = .anyPerson) :
    ∃ s', Step adminRule s (.id a) s' ∧ HasTeamCert s' o (.named n) k := by
  refine ⟨_, Step.admit (m := ⟨o, .named n, k⟩) (approvals := [p]) (by simp)
    (.inr ⟨hheld, a, rfl, ha, person_approval_satisfies hv hrules⟩) hk, ?_⟩
  exact List.mem_cons_self

/-- Design, in one act. If the admin team's key of `o` is with a key holder
and `o` has no admin, no accepted act under the admin rule adds a team
certificate of `o`'s admin team. Re-admissions (`readmitByRoot`,
`readmitByParent`) change no team certificate. -/
theorem no_admin_no_new_admin_certificate {s s' : State} {who : Party} {o : Org}
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
  | rekeyTeam _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
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

/-- Design. There is a record `L` the system reaches under the admin rule in
which the admin team's key of organisation 0 is with a key holder and 0 has no
admin; from `L`, two acts asked for by whoever controls 0's root key and then
one act asked for by identity 1 are accepted, and afterwards 2 holds an
admin-team certificate of 0 that it did not hold in `L`. In the construction a
root replacement cut off agents 1 and 2, the new root admits both again, and
1, which still holds its admin-team certificate, is an admin again and has 2
admitted through the key holder. -/
theorem no_admin_organisation_gains_admin_certificate :
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

/-- Design. There is a record the system reaches under the admin rule in which
nobody is a person of organisation 0, 2 holds no certificate of team 7 of 0,
and 1 is an admin and a valid agent of 0; an act that 1 asks for is accepted,
after which 2 holds a certificate of team 7 of 0. -/
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

/-- If `o`'s admin team is locked, no identity is an admin of `o`. -/
theorem AdminTeamLocked.no_admin {s : State} {o : Org} (h : AdminTeamLocked s o) (k : Key) :
    ¬ Admin s o k := by
  intro ⟨hm, _⟩
  exact h.2 _ hm rfl rfl

/-- Design, in one act. If `o`'s admin team is locked before an accepted act
under the admin rule and the asker is not whoever controls `o`'s root key, it
is locked after it. -/
theorem locked_admin_team_opens_only_by_root {s s' : State} {who : Party} {o : Org}
    (hstep : Step adminRule s who s') (hl : AdminTeamLocked s o)
    (hwho : who ≠ .controller (.root o)) : AdminTeamLocked s' o := by
  have noAdmin := hl.no_admin
  obtain ⟨hheld, hnone⟩ := hl
  cases hstep with
  | createOrg _ => exact ⟨hheld, hnone⟩
  | replaceRoot _ => exact ⟨List.mem_filter.mpr ⟨hheld, by simp⟩, hnone⟩
  | readmitByRoot _ _ _ _ => exact ⟨hheld, hnone⟩
  | readmitByParent _ _ _ _ => exact ⟨hheld, hnone⟩
  | release hk hauth =>
      rename_i key approvals
      refine ⟨List.mem_filter.mpr ⟨hheld, ?_⟩, hnone⟩
      rcases hauth with ⟨hn, _⟩ | ⟨_, k, _, hask, _⟩
      · exact absurd hk hn
      · by_cases he : OrgKey.team o .admin = key
        · subst he
          exact absurd hask (noAdmin k)
        · simp only [ne_eq, decide_eq_true_eq]; exact he
  | @rekeyTeam o' t _ _ _ hauth _ =>
      refine ⟨List.mem_filter.mpr ⟨hheld, ?_⟩, fun x hx => hnone x (List.mem_filter.mp hx).1⟩
      by_cases he : OrgKey.team o .admin = OrgKey.team o' t
      · cases he
        rcases hauth with ⟨_, hw⟩ | ⟨_, k, _, hask, _⟩
        · exact absurd hw hwho
        · exact absurd hask (noAdmin k)
      · simp only [ne_eq, decide_eq_true_eq]; exact he
  | entrust _ => exact ⟨List.mem_cons_of_mem _ hheld, hnone⟩
  | registerByRoot _ _ _ _ => exact ⟨hheld, hnone⟩
  | registerByParent _ _ _ _ => exact ⟨hheld, hnone⟩
  | revokeSelf _ => exact ⟨hheld, hnone⟩
  | revokeChild _ _ _ => exact ⟨hheld, hnone⟩
  | revokeByOrg _ _ => exact ⟨hheld, hnone⟩
  | admit hne _ _ =>
      refine ⟨hheld, ?_⟩
      intro x hx hxo
      rcases List.mem_cons.mp hx with rfl | hx
      · exact hne
      · exact hnone x hx hxo
  | admitAdmin ht _ hauth =>
      refine ⟨hheld, ?_⟩
      intro x hx hxo
      rcases List.mem_cons.mp hx with rfl | hx
      · exfalso
        rcases hauth with ⟨hn, _⟩ | ⟨_, k, _, hask, _⟩
        · rw [ht, hxo] at hn; exact hn hheld
        · have : Admin s o k := by simpa [adminRule, OrgKey.org, hxo] using hask
          exact noAdmin k this
      · exact hnone x hx hxo
  | remove _ _ => exact ⟨hheld, fun x hx => hnone x (List.mem_filter.mp hx).1⟩
  | leave _ _ _ => exact ⟨hheld, fun x hx => hnone x (List.mem_filter.mp hx).1⟩
  | invite _ _ _ => exact ⟨hheld, hnone⟩
  | redeem _ hne _ =>
      refine ⟨hheld, ?_⟩
      intro x hx hxo
      rcases List.mem_cons.mp hx with rfl | hx
      · exact hne
      · exact hnone x hx hxo
  | mintGrant _ _ => exact ⟨hheld, hnone⟩
  | revokeGrant _ => exact ⟨hheld, hnone⟩
  | sendOwn _ => exact ⟨hheld, hnone⟩
  | sendGrant _ _ => exact ⟨hheld, hnone⟩

/-- Under any rule there is a record the system reaches, an act asked for by
organisation 0's domain owner, and a grant `g`, such that after the act 0's
root key is not with a key holder, no identity is valid in 0, identity 9 can
act in team 7 of 0, `g`'s subject is 9, and `g` is live. In the construction 9
is an agent of organisation 1. -/
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
    ⟨by simp [s5, s4, s3, s2, s1, e, g, c9], hin⟩⟩
  intro k kind hv
  obtain ⟨c, hc, _, _, hco⟩ := hv.cert
  simp [s5, s4, s3] at hc
  subst hc
  simp [c9] at hco

/-- Under any rule there is a record the system reaches in which the admin
team's key of 0 is with a key holder and 1 is an admin of 0, and an accepted
act 1 asks for after which 0 has no admin. In the construction the act is 1
revoking itself. -/
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

/-- In every record some key has no certificate and is not revoked. -/
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

/-- If `o` exists and `k` has no certificate and is not revoked, then under
any rule there are four accepted acts, asked for in turn by `o`'s domain
owner, by whoever controls `o`'s root key, by whoever controls it again, and
by whoever controls `o`'s admin team's key, after which `k` is an admin of
`o`. In the construction the four acts are a root replacement, a re-key of the
admin team, a registration of `k` as a person under the root, and an admission
of `k` to the admin team. -/
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
  let s2 : State :=
    { s1 with held := s1.held.filter (fun x => decide (x ≠ .team o .admin)),
              members := s1.members.filter
                (fun m => decide (¬ (m.org = o ∧ m.team = .admin) ∨ m.member ∈ ([] : List Key))),
              grants := s1.grants.filter (fun g => decide (¬ (g.org = o ∧ g.team = .admin))) }
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
    Step.rekeyTeam (t := .admin) (keep := []) (approvals := []) (.inl ⟨hroot1, rfl⟩)
      (fun h => absurd h hroot1),
    Step.registerByRoot (c := c) (approvals := []) rfl ho hk (.inl ⟨hroot2, rfl⟩),
    Step.admitAdmin (m := ⟨o, .admin, k⟩) (kind := .person) (approvals := []) rfl hv3
      (.inl ⟨hteam3, rfl⟩), List.mem_cons_self, .person, ?_⟩
  exact Valid.mono (s := s3) (t := s4) (fun _ h => h) (fun _ h => h) hv3

/-- If `o`'s root key is not with a key holder, then for any team `t` of `o`
and any key `k` there is an accepted act asked for by whoever controls `o`'s
root key, after which `k` holds no certificate of `t` and no grant on `k` from
team `t` of `o` stands. In the construction the act is a re-key of `t` that
keeps no member. -/
theorem root_can_end_team_membership {ask : AskRule} {s : State} {o : Org} {t : Team}
    {k : Key} (hroot : OrgKey.root o ∉ s.held) :
    ∃ s1, Step ask s (.controller (.root o)) s1 ∧
      ¬ HasTeamCert s1 o t k ∧ ∀ g, g ∈ s1.grants → ¬ (g.org = o ∧ g.team = t ∧ g.subject = k) := by
  refine ⟨_, Step.rekeyTeam (t := t) (keep := []) (approvals := []) (.inl ⟨hroot, rfl⟩)
    (fun h => absurd h hroot), ?_, ?_⟩
  · intro h
    have := (List.mem_filter.mp h).2
    simp at this
  · intro g hg ⟨h1, h2, _⟩
    have := (List.mem_filter.mp hg).2
    simp [h1, h2] at this

/-- Under any rule there is a record the system reaches, an act asked for by
whoever controls organisation 1's root key, and a grant `g` of organisation 0,
such that before the act 9 can act in team 7 of 0 and `g` is live, and after
it 9 cannot act in that team and `g` is not live. In the construction 9 is an
agent of 1, and the act is 1's root revoking it. -/
theorem root_controller_ends_access_in_another_organisation (ask : AskRule) :
    ∃ (s s' : State) (g : Grant), Reachable ask s ∧
      Step ask s (.controller (.root 1)) s' ∧
      InTeam s 0 (.named 7) 9 ∧ ¬ InTeam s' 0 (.named 7) 9 ∧
      g.org = 0 ∧ GrantLive s g ∧ ¬ GrantLive s' g := by
  let c9 : Cert := ⟨1, 9, .agent, .root⟩
  let m : Membership := ⟨0, .named 7, 9⟩
  let g : Grant := ⟨5, 9, 0, .named 7, true⟩
  let s1 : State := ⟨[0], [], [], [], [], [], [], [], [], []⟩
  let s2 : State := ⟨[1, 0], [], [], [], [], [], [], [], [], []⟩
  let s3 : State := ⟨[1, 0], [c9], [], [], [], [], [], [], [], []⟩
  let s4 : State := ⟨[1, 0], [c9], [], [], [m], [], [], [], [], []⟩
  let s5 : State := ⟨[1, 0], [c9], [], [], [m], [], [], [g], [], []⟩
  let s6 : State := ⟨[1, 0], [c9], [9], [], [m], [], [], [g], [], []⟩
  have r1 : Reachable ask s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable ask s2 := .step r1 (Step.createOrg (o := 1) (by simp [s1]))
  have r3 : Reachable ask s3 :=
    .step r2 (Step.registerByRoot (c := c9) (who := .controller (.root 1)) (approvals := [])
      rfl (by simp [s2, c9]) (by intro d hd; simp [s2] at hd) (.inl ⟨by simp [s2], rfl⟩))
  have r4 : Reachable ask s4 :=
    .step r3 (Step.admit (m := m) (who := .controller (.team 0 (.named 7))) (approvals := [])
      (by simp [m]) (.inl ⟨by simp [s3], rfl⟩) (.inl ⟨c9, by simp [s3], rfl⟩))
  have v4 : Valid s4 1 9 .agent :=
    .agentOfRoot (c := c9) (by simp [s4]) rfl rfl rfl rfl (by simp [s4])
  have r5 : Reachable ask s5 :=
    .step r4 (Step.mintGrant (g := g) ⟨by simp [HasTeamCert, s4, m, g], .inr ⟨1, .agent, v4⟩⟩
      (by intro g' hg'; simp [s4] at hg'))
  have v5 : Valid s5 1 9 .agent :=
    .agentOfRoot (c := c9) (by simp [s5]) rfl rfl rfl rfl (by simp [s5])
  have hin : InTeam s5 0 (.named 7) 9 := ⟨by simp [HasTeamCert, s5, m], .inr ⟨1, .agent, v5⟩⟩
  have hstep : Step ask s5 (.controller (.root 1)) s6 :=
    Step.revokeByOrg (c := c9) (approvals := []) (by simp [s5]) (.inl ⟨by simp [s5], rfl⟩)
  have hrr : RevokedAreRegistered s6 := (Reachable.step r5 hstep).revokedAreRegistered
  have hout : ¬ InTeam s6 0 (.named 7) 9 :=
    (revoked_has_no_authority hrr (k := 9) (by simp [s6])).2 0 (.named 7)
  refine ⟨s5, s6, g, r5, hstep, hin, hout, rfl, ⟨by simp [s5], hin⟩, ?_⟩
  exact grant_ends_with_subject hrr (.inl (by simp [s6, g]))

/-- Under any rule there is a record the system reaches in which the admin
team's key of 0 is with a key holder and 2 is the only admin of 0, and an act
1 asks for, after which 2 is not revoked and 0 has no admin. In the
construction 2 is an agent issued by person 1, and the act is 1 revoking
itself. -/
theorem issuer_revocation_can_leave_no_admin (ask : AskRule) :
    ∃ s s', Reachable ask s ∧ OrgKey.team 0 .admin ∈ s.held ∧ Admin s 0 2 ∧
      (∀ k, Admin s 0 k → k = 2) ∧ Step ask s (.id 1) s' ∧ 2 ∉ s'.revoked ∧
      ∀ k, ¬ Admin s' 0 k := by
  let c1 : Cert := ⟨0, 1, .person, .root⟩
  let c2 : Cert := ⟨0, 2, .agent, .member 1⟩
  let ma : Membership := ⟨0, .admin, 2⟩
  let s1 : State := ⟨[0], [], [], [], [], [], [], [], [], []⟩
  let s2 : State := ⟨[0], [c1], [], [], [], [], [], [], [], []⟩
  let s3 : State := ⟨[0], [c2, c1], [], [], [], [], [], [], [], []⟩
  let s4 : State := ⟨[0], [c2, c1], [], [], [ma], [], [], [], [], []⟩
  let s5 : State := ⟨[0], [c2, c1], [], [], [ma], [], [.team 0 .admin], [], [], []⟩
  let s6 : State := ⟨[0], [c2, c1], [1], [], [ma], [], [.team 0 .admin], [], [], []⟩
  have r1 : Reachable ask s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable ask s2 :=
    .step r1 (Step.registerByRoot (c := c1) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s1, c1]) (by intro d hd; simp [s1] at hd) (.inl ⟨by simp [s1], rfl⟩))
  have v1 : Valid s2 0 1 .person :=
    .person (.byRoot (c := c1) (by simp [s2]) rfl rfl rfl rfl) (by simp [s2])
  have r3 : Reachable ask s3 :=
    .step r2 (Step.registerByParent (c := c2) (p := 1) (pk := .person) rfl
      (by intro d hd; simp [s2] at hd; subst hd; simp [c1, c2]) v1 (.inl rfl))
  have valid2 : ∀ t : State, t.certs = [c2, c1] → t.revoked = [] → Valid t 0 2 .agent := by
    intro t hc hr
    exact .agentOf (c := c2) (by simp [hc]) rfl rfl rfl rfl (by simp [hr])
      (.person (.byRoot (c := c1) (by simp [hc]) rfl rfl rfl rfl) (by simp [hr]))
  have r4 : Reachable ask s4 :=
    .step r3 (Step.admitAdmin (m := ma) (kind := .agent) (who := .controller (.team 0 .admin))
      (approvals := []) rfl (valid2 s3 rfl rfl) (.inl ⟨by simp [s3], rfl⟩))
  have r5 : Reachable ask s5 :=
    .step r4 (Step.entrust (key := .team 0 .admin) (by simp [s4]))
  have hstep : Step ask s5 (.id 1) s6 := Step.revokeSelf (c := c1) (by simp [s5])
  have h1 : OneCertEach s6 := (Reachable.step r5 hstep).oneCertEach
  refine ⟨s5, s6, r5, by simp [s5], ⟨by simp [s5, ma], .agent, valid2 s5 rfl rfl⟩, ?_, hstep,
    by simp [s6], ?_⟩
  · intro k ⟨hm, _⟩
    simp [s5, ma] at hm
    exact hm
  · intro k ⟨hm, kind, hv⟩
    simp [s6, ma] at hm
    subst hm
    exact revoking_parent_ends_agent h1 (c := c2) (p := 1) (by simp [s6]) rfl rfl
      (by simp [s6]) 0 kind hv

/-- In one act. If an act asked for by an invitation's holder adds a team
certificate, it is not of an admin team. -/
theorem bearer_adds_no_admin_certificate {ask : AskRule} {s s' : State} {t : Nat}
    {m : Membership} (hstep : Step ask s (.bearer t) s') (hnew : m ∈ s'.members)
    (hold : m ∉ s.members) : m.team ≠ .admin :=
  ((bearer_only_joins hstep).2.2.2.2 m hnew hold).1

/-- In one act. If an accepted act adds a certificate of an admin team, its
member is valid in its organisation before the act. -/
theorem new_admin_certificate_needs_valid_member {ask : AskRule} {s s' : State}
    {who : Party} {m : Membership} (hstep : Step ask s who s') (hnew : m ∈ s'.members)
    (hold : m ∉ s.members) (hteam : m.team = .admin) : ∃ kind, Valid s m.org m.member kind := by
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
  | rekeyTeam _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
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
  | admitAdmin _ hv _ =>
      rcases List.mem_cons.mp hnew with rfl | h
      · exact ⟨_, hv⟩
      · exact absurd h hold

/-- If `k` holds no team certificate of `o` in `s`, an act asked for by an
invitation's holder takes `s` to `s1`, an act `k` asks for takes `s1` to `s2`,
and `k` is an admin of `o` in `s2`, then `k` is valid in `o` in `s`. -/
theorem invitation_route_starts_from_a_member {ask : AskRule} {s s1 s2 : State}
    {t : Nat} {o : Org} {k : Key} (hnone : ∀ tm, ¬ HasTeamCert s o tm k)
    (h1 : Step ask s (.bearer t) s1) (h2 : Step ask s1 (.id k) s2) (hadm : Admin s2 o k) :
    ∃ kind, Valid s o k kind := by
  obtain ⟨hm2, _⟩ := hadm
  have hnot1 : (⟨o, .admin, k⟩ : Membership) ∉ s1.members := by
    intro hm1
    by_cases hm0 : (⟨o, .admin, k⟩ : Membership) ∈ s.members
    · exact hnone .admin hm0
    · exact bearer_adds_no_admin_certificate h1 hm1 hm0 rfl
  obtain ⟨kind, hv⟩ := new_admin_certificate_needs_valid_member h2 hm2 hnot1 rfl
  obtain ⟨hc, hr, _⟩ := bearer_only_joins h1
  exact ⟨kind, Valid.mono (by intro c h; rw [hc] at h; exact h)
    (by intro j h; rw [hr]; exact h) hv⟩

/-- In every reachable record the member of every admin-team certificate is
registered. -/
theorem admin_certificate_member_is_registered {ask : AskRule} {s : State}
    (hr : Reachable ask s) : ∀ m, m ∈ s.members → m.team = .admin → Registered s m.member := by
  induction hr with
  | start _ => intro m hm; cases hm
  | step _ hstep ih =>
      rename_i t t' _ _
      intro m hm hteam
      by_cases hold : m ∈ t.members
      · obtain ⟨c, hc, hcs⟩ := ih m hold hteam
        exact ⟨c, certificate_is_permanent hstep hc, hcs⟩
      · obtain ⟨kind, hv⟩ := new_admin_certificate_needs_valid_member hstep hm hold hteam
        obtain ⟨c, hc, hcs, _, _⟩ := hv.cert
        exact ⟨c, certificate_is_permanent hstep hc, hcs⟩

/-- In every record some session key is used by no grant. -/
theorem unused_session_key (s : State) : ∃ x : Key, ∀ g, g ∈ s.grants → g.session ≠ x := by
  let t : State := { s with certs := s.grants.map (fun g => ⟨0, g.session, .person, .root⟩) }
  obtain ⟨x, hx, _⟩ := exists_fresh_key t
  refine ⟨x, fun g hg => ?_⟩
  exact hx ⟨0, g.session, .person, .root⟩ (List.mem_map.mpr ⟨g, hg, rfl⟩)

/-- If `o`'s root key is with a key holder, no act asked for by whoever
controls it is accepted. -/
theorem root_controller_cannot_act_while_held {ask : AskRule} {s s' : State} {o : Org}
    (hheld : OrgKey.root o ∈ s.held) : ¬ Step ask s (.controller (.root o)) s' := by
  intro hstep
  have ctrl : ∀ {key : OrgKey} {act : ActKind} {approvals : List Key},
      Authorised ask s key act (.controller (.root o)) approvals → key = .root o ∧ key ∉ s.held := by
    intro key act approvals h
    rcases h with ⟨hn, hw⟩ | ⟨_, _, hw, _⟩
    · cases hw; exact ⟨rfl, hn⟩
    · cases hw
  cases hstep with
  | entrust hn => exact hn hheld
  | readmitByRoot _ _ _ h => exact (ctrl h).2 ((ctrl h).1 ▸ hheld)
  | release hk h => exact (ctrl h).2 hk
  | rekeyTeam h _ => exact (ctrl h).2 ((ctrl h).1 ▸ hheld)
  | registerByRoot _ _ _ h => exact (ctrl h).2 ((ctrl h).1 ▸ hheld)
  | revokeByOrg _ h => exact (ctrl h).2 ((ctrl h).1 ▸ hheld)
  | admit _ h _ => cases (ctrl h).1
  | admitAdmin _ _ h => cases (ctrl h).1
  | remove h _ => cases (ctrl h).1
  | invite _ h _ => cases (ctrl h).1

/-- In every reachable record, every registered certificate issued by the root
is of an organisation that exists. -/
theorem root_cert_org_exists {ask : AskRule} {s : State} (hr : Reachable ask s) :
    ∀ c, c ∈ s.certs → c.issuer = .root → c.org ∈ s.orgs := by
  induction hr with
  | start _ => intro c hc; cases hc
  | step _ hstep ih =>
      rename_i t t' _ _
      have keep : ∀ c, c ∈ t.certs → c.issuer = .root → c.org ∈ t.orgs := ih
      cases hstep with
      | createOrg _ => intro c hc hi; exact List.mem_cons_of_mem _ (keep c hc hi)
      | registerByRoot _ ho _ _ =>
          intro c hc hi
          rcases List.mem_cons.mp hc with rfl | hc
          · exact ho
          · exact keep c hc hi
      | registerByParent hi' _ _ _ =>
          intro c hc hi
          rcases List.mem_cons.mp hc with rfl | hc
          · rw [hi'] at hi; cases hi
          · exact keep c hc hi
      | replaceRoot _ => exact keep
      | readmitByRoot _ _ _ _ => exact keep
      | readmitByParent _ _ _ _ => exact keep
      | release _ _ => exact keep
      | rekeyTeam _ _ => exact keep
      | entrust _ => exact keep
      | revokeSelf _ => exact keep
      | revokeChild _ _ _ => exact keep
      | revokeByOrg _ _ => exact keep
      | admit _ _ _ => exact keep
      | admitAdmin _ _ _ => exact keep
      | remove _ _ => exact keep
      | leave _ _ _ => exact keep
      | invite _ _ _ => exact keep
      | redeem _ _ _ => exact keep
      | mintGrant _ _ => exact keep
      | revokeGrant _ => exact keep
      | sendOwn _ => exact keep
      | sendGrant _ _ => exact keep

/-- If certificates lead from `k` to `o`'s root, a registered certificate of
`o` is issued by the root. -/
theorem chain_has_root_cert {s : State} {o : Org} {k : Key} (h : ChainToRoot s o k) :
    ∃ c, c ∈ s.certs ∧ c.org = o ∧ c.issuer = .root := by
  induction h with
  | root hc ho hi _ => exact ⟨_, hc, ho, hi⟩
  | link _ _ _ _ _ ih => exact ih

/-- In every reachable record, an organisation with an admin exists. -/
theorem admin_org_exists {ask : AskRule} {s : State} (hr : Reachable ask s) {o : Org} {k : Key}
    (ha : Admin s o k) : o ∈ s.orgs := by
  obtain ⟨c, hc, ho, hi⟩ := chain_has_root_cert (admin_has_chain_to_root ha)
  exact ho ▸ root_cert_org_exists hr c hc hi

/-- Under any rule there is a record the system reaches in which the admin
team's key of 0 is with a key holder and 1 is an admin of 0, and an act asked
for by 0's domain owner after which 0 has no admin. -/
theorem root_replacement_can_leave_no_admin (ask : AskRule) :
    ∃ s s', Reachable ask s ∧ OrgKey.team 0 .admin ∈ s.held ∧ Admin s 0 1 ∧
      Step ask s (.dns 0) s' ∧ ∀ k, ¬ Admin s' 0 k := by
  obtain ⟨s, _, hr, hheld, ha, _, _⟩ := revocation_can_leave_no_admin ask
  obtain ⟨s', hstep, _, hnone⟩ := dns_owner_can_always_take_over (admin_org_exists hr ha)
  exact ⟨s, s', hr, hheld, ha, hstep, fun k ⟨_, kind, hv⟩ => hnone k kind hv⟩

/-- As built. Under any rule there is a record the system reaches in which a
grant `g` stands, its subject is revoked, and `g` is not live; and an act
asked for by whoever controls organisation 0's root key, after which the
grants are as before, `g` is live, and `g` may send. In the construction the
subject was cut off by a root replacement and the act re-admits it. -/
theorem grant_revives_with_readmission (ask : AskRule) :
    ∃ (s s' : State) (g : Grant), Reachable ask s ∧ g ∈ s.grants ∧ g.subject ∈ s.revoked ∧
      ¬ GrantLive s g ∧ Step ask s (.controller (.root 0)) s' ∧ s'.grants = s.grants ∧
      GrantLive s' g ∧ g.maySend = true := by
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let c : Cert := ⟨0, 1, .agent, .root⟩
  let m : Membership := ⟨0, .named 7, 1⟩
  let g : Grant := ⟨5, 1, 0, .named 7, true⟩
  let s1 : State := { e with orgs := [0] }
  let s2 : State := { s1 with certs := [c] }
  let s3 : State := { s2 with members := [m] }
  let s4 : State := { s3 with grants := [g] }
  let s5 : State := { s4 with
      revoked := ((s4.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s4.revoked))).map
        (·.subject)) ++ s4.revoked,
      cutOff := ((s4.certs.filter (fun c => decide (c.org = 0 ∧ c.subject ∉ s4.revoked))).map
        (·.subject)) ++ s4.cutOff,
      held := s4.held.filter (fun k => decide (k ≠ .root 0)) }
  let s6 : State := { s5 with revoked := s5.revoked.filter (fun k => decide (k ≠ c.subject)),
                              cutOff := s5.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  have r1 : Reachable ask s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
  have r2 : Reachable ask s2 :=
    .step r1 (Step.registerByRoot (c := c) (who := .controller (.root 0)) (approvals := [])
      rfl (by simp [s1, c]) (by intro d hd; simp [s1, e] at hd) (.inl ⟨by simp [s1, e], rfl⟩))
  have v2 : Valid s2 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s2]) rfl rfl rfl rfl (by simp [s2, s1, e])
  have r3 : Reachable ask s3 :=
    .step r2 (Step.admit (m := m) (who := .controller (.team 0 (.named 7))) (approvals := [])
      (by simp [m]) (.inl ⟨by simp [s2, s1, e], rfl⟩) (.inl ⟨c, by simp [s2], rfl⟩))
  have v3 : Valid s3 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s3, s2]) rfl rfl rfl rfl (by simp [s3, s2, s1, e])
  have r4 : Reachable ask s4 :=
    .step r3 (Step.mintGrant (g := g) ⟨by simp [HasTeamCert, s3, m, g], .inr ⟨0, .agent, v3⟩⟩
      (by intro g' hg'; simp [s3, s2, s1, e] at hg'))
  have r5 : Reachable ask s5 := .step r4 (Step.replaceRoot (o := 0) (by simp [s4, s3, s2, s1]))
  have hrev : g.subject ∈ s5.revoked := by simp [s5, s4, s3, s2, s1, e, c, g]
  have hstep : Step ask s5 (.controller (.root 0)) s6 :=
    Step.readmitByRoot (c := c) (approvals := []) (by simp [s5, s4, s3, s2])
      rfl (by simp [s5, s4, s3, s2, s1, e, c]) (.inl ⟨by simp [s5, c], rfl⟩)
  have v6 : Valid s6 0 1 .agent :=
    .agentOfRoot (c := c) (by simp [s6, s5, s4, s3, s2]) rfl rfl rfl rfl
      (by simp [s6, s5, s4, s3, s2, s1, e, c])
  refine ⟨s5, s6, g, r5, by simp [s5, s4], hrev, ?_, hstep, rfl,
    ⟨by simp [s6, s5, s4], by simp [HasTeamCert, s6, s5, s4, s3, m, g], .inr ⟨0, .agent, v6⟩⟩, rfl⟩
  exact grant_ends_with_subject r5.revokedAreRegistered (.inl hrev)

/-- The planned root replacement (aweb-adzf.9): the record `replaceRoot` gives,
with the grants on the identities it cuts off removed. -/
def plannedReplaceRoot (s : State) (o : Org) : State :=
  let cut := (s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map (·.subject)
  { s with revoked := cut ++ s.revoked, cutOff := cut ++ s.cutOff,
           held := s.held.filter (fun k => decide (k ≠ .root o)),
           grants := s.grants.filter (fun g => decide (g.subject ∉ cut)) }

/-- Design, aweb-adzf.9. After the planned root replacement of `o`, no grant
stands on an unrevoked identity with a certificate of `o`; and every grant on
any other identity still stands. -/
theorem planned_replacement_ends_cut_off_grants (s : State) (o : Org) :
    (∀ g, g ∈ (plannedReplaceRoot s o).grants → ∀ c, c ∈ s.certs → c.org = o →
      c.subject ∉ s.revoked → g.subject ≠ c.subject) ∧
    (∀ g, g ∈ s.grants → (∀ c, c ∈ s.certs → c.org = o → c.subject ∉ s.revoked →
      g.subject ≠ c.subject) → g ∈ (plannedReplaceRoot s o).grants) := by
  refine ⟨?_, ?_⟩
  · intro g hg c hc ho hr he
    have h := (List.mem_filter.mp hg).2
    simp only [decide_eq_true_eq] at h
    exact h (List.mem_map.mpr ⟨c, List.mem_filter.mpr ⟨hc, by simp [ho, hr]⟩, he.symm⟩)
  · intro g hg hno
    refine List.mem_filter.mpr ⟨hg, ?_⟩
    simp only [decide_eq_true_eq]
    intro hm
    obtain ⟨c, hc, hcs⟩ := List.mem_map.mp hm
    have hc' := List.mem_filter.mp hc
    simp only [decide_eq_true_eq] at hc'
    exact hno c hc'.1 hc'.2.1 hc'.2.2 hcs.symm

/-- If `Authorised` holds for `o`'s root key and a re-key, and, when `o`'s root
key is held and `t` is the admin team, some identity in `keep` is an admin of
`o`, there is an accepted act that `who` asks for, after which the key of team
`t` of `o` is not held, every certificate of that team that stands is of a
member in `keep`, and no grant from that team stands. -/
theorem rekey_ends_team_grants {ask : AskRule} {s : State} {o : Org} {t : Team}
    {keep : List Key} {who : Party} {approvals : List Key}
    (hauth : Authorised ask s (.root o) .rekey who approvals)
    (hkeep : OrgKey.root o ∈ s.held → t = .admin → ∃ k, k ∈ keep ∧ Admin s o k) :
    ∃ s', Step ask s who s' ∧ OrgKey.team o t ∉ s'.held ∧
      (∀ m, m ∈ s'.members → m.org = o → m.team = t → m.member ∈ keep) ∧
      ∀ g, g ∈ s'.grants → ¬ (g.org = o ∧ g.team = t) := by
  refine ⟨_, Step.rekeyTeam hauth hkeep, ?_, ?_, ?_⟩
  · intro h
    have := (List.mem_filter.mp h).2
    simp at this
  · intro m hm h1 h2
    have h := (List.mem_filter.mp hm).2
    simp only [decide_eq_true_eq] at h
    rcases h with h | h
    · exact absurd ⟨h1, h2⟩ h
    · exact h
  · intro g hg ⟨h1, h2⟩
    have := (List.mem_filter.mp hg).2
    simp [h1, h2] at this

end TrustWeb
