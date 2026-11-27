import TrustWeb.SphereApprovals

/-!
# Trust spheres: an attacker's chain of acts

What one sphere can reach by a chain of acts of its own, helped only by the
secrets persuadable spheres pass on.
-/

namespace TrustWeb

/-- `Attack ask Talk P a w0 w`: world `w` is reached from `w0` by acts that
sphere `a` asks for, with any secret it holds, and by persuadable spheres
giving secrets to spheres they talk to. No other sphere acts, and an act
needs no approval beyond the model's own premises. -/
inductive Attack (ask : AskRule) (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop)
    (a : Sphere) (w0 : World) : World → Prop where
  | start : Attack ask Talk P a w0 w0
  | act {w : World} {s' : State} {who : Party} :
      Attack ask Talk P a w0 w → w.holds a who.secret → Step ask w.record who s' →
      Attack ask Talk P a w0 ⟨s', w.holds⟩
  | leak {w : World} {z z' : Sphere} {x : Secret} :
      Attack ask Talk P a w0 w → w.holds z x → P z → Talk z z' →
      Attack ask Talk P a w0 ⟨w.record, fun y v => w.holds y v ∨ (y = z' ∧ v = x)⟩

/-- `CanReach Talk P w0 a x`: some sphere holds `x` in `w0`, and `x` flows
from it to `a`. -/
def CanReach (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop) (w0 : World)
    (a : Sphere) (x : Secret) : Prop :=
  ∃ z0, w0.holds z0 x ∧ Flows Talk P z0 a

/-- In every world an attack reaches, if sphere `z` holds secret `x`, `x`
flows to `z` from a sphere that held it in `w0`. -/
theorem Attack.held_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 w : World} (hw : Attack ask Talk P a w0 w)
    {z : Sphere} {x : Secret} (hz : w.holds z x) : CanReach Talk P w0 z x := by
  induction hw generalizing z x with
  | start => exact ⟨z, hz, .refl z⟩
  | act _ _ _ ih => exact ih hz
  | leak _ hzx hp ht ih =>
      rcases hz with hz | ⟨rfl, rfl⟩
      · exact ih hz
      · obtain ⟨z0, h0, hf⟩ := ih hzx
        exact ⟨z0, h0, .step hf hp ht⟩

/-- A secret does not reach `a` if every sphere holding it in `w0` is neither
`a` nor persuadable. -/
theorem not_canReach {Talk : Sphere → Sphere → Prop} {P : Sphere → Prop} {w0 : World}
    {a : Sphere} {x : Secret} (h : ∀ z0, w0.holds z0 x → z0 ≠ a ∧ ¬ P z0) :
    ¬ CanReach Talk P w0 a x := by
  rintro ⟨z0, h0, hf⟩
  exact (h z0 h0).2 (hf.source_persuadable (h z0 h0).1)

/-- Any chain of acts. Suppose the rule lets only members of `o`'s admin team
ask for admitting an admin of `o`, the admin team's key does not reach sphere
`a`, and the identity key of no member of the admin team in `w0` reaches `a`.
Then in every world an attack by `a` reaches, the identity key of no member
of `o`'s admin team reaches `a`. -/
theorem attack_reaches_no_admin_key {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k → (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hkey : ¬ CanReach Talk P w0 a (.orgKey (.team o .admin)))
    (hadm : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ¬ CanReach Talk P w0 a (.idKey k))
    {w : World} (hw : Attack ask Talk P a w0 w) :
    ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w.record.members → ¬ CanReach Talk P w0 a (.idKey k) := by
  induction hw with
  | start => exact hadm
  | @act w s' who hw' hz hs ih =>
      intro k hk
      by_cases hold : (⟨o, .admin, k⟩ : Membership) ∈ w.record.members
      · exact ih k hold
      · rcases new_admin_needs_controller_or_asker hs hk hold rfl with h | ⟨b, h, hask⟩
        · subst h
          exact absurd (hw'.held_secret_flowed hz) hkey
        · subst h
          exact absurd (hw'.held_secret_flowed hz) (ih b (hrule _ _ hask))
  | leak _ _ _ _ ih => exact ih

/-- Any chain of acts, in the same setting: in every world an attack by `a`
reaches, `a` holds neither the admin team's key nor the identity key of an
admin of `o`, and no persuadable sphere that talks to `a` holds an admin's
identity key. -/
theorem attacker_holds_no_admin_key {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k → (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hkey : ¬ CanReach Talk P w0 a (.orgKey (.team o .admin)))
    (hadm : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ¬ CanReach Talk P w0 a (.idKey k))
    {w : World} (hw : Attack ask Talk P a w0 w) :
    ¬ w.holds a (.orgKey (.team o .admin)) ∧
      ∀ k, Admin w.record o k → ¬ Available Talk P w a k := by
  refine ⟨fun h => hkey (hw.held_secret_flowed h), fun k hk ha => ?_⟩
  have hnot := attack_reaches_no_admin_key hrule hkey hadm hw k hk.1
  rcases ha with h | ⟨z', h, hp, ht⟩
  · exact hnot (hw.held_secret_flowed h)
  · obtain ⟨z0, h0, hf⟩ := hw.held_secret_flowed h
    exact hnot ⟨z0, h0, .step hf hp ht⟩

/-- World 2, any chain of acts. Suppose the rule lets only members of `o`'s
admin team ask for admitting an admin of `o`, and every sphere that holds in
`w0` the admin team's key, or the identity key of a member of the admin team,
is neither `a` nor an agent's. Then in every world an attack by `a` reaches,
with agents' spheres persuadable, `a` holds neither the admin team's key nor
the identity key of an admin of `o`, and no agent's sphere that talks to `a`
holds an admin's identity key. -/
theorem world2_attacker_holds_no_admin_key {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k → (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hkey : ∀ z0, w0.holds z0 (.orgKey (.team o .admin)) → z0 ≠ a ∧ occ z0 ≠ .agent)
    (hadm : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ∀ z0, w0.holds z0 (.idKey k) → z0 ≠ a ∧ occ z0 ≠ .agent)
    {w : World} (hw : Attack ask Talk (agentsSwayed occ) a w0 w) :
    ¬ w.holds a (.orgKey (.team o .admin)) ∧
      ∀ k, Admin w.record o k → ¬ Available Talk (agentsSwayed occ) w a k :=
  attacker_holds_no_admin_key hrule (not_canReach hkey)
    (fun k hk => not_canReach (hadm k hk)) hw

/-- The admin rule lets only members of `o`'s admin team ask for admitting an
admin of `o`; so does the team rule when admitting admins of `o` is assigned
to the admin team. -/
theorem adminRule_admits_only_by_admins (o : Org) :
    ∀ s k, adminRule s o .admitAdmin k → (⟨o, .admin, k⟩ : Membership) ∈ s.members :=
  fun _ _ h => h.1

theorem teamRule_admits_only_by_admins {assign : Assignment} {o : Org}
    (hassign : assign o .admitAdmin = .admin) :
    ∀ s k, teamRule assign s o .admitAdmin k → (⟨o, .admin, k⟩ : Membership) ∈ s.members :=
  fun _ _ h => hassign ▸ h.1

/-- Under the team rule with admitting admins of `o` assigned to team `n`, for
any talk and any persuadable spheres: there is a world in which no sphere
holds `o`'s admin team key, `o`'s admin team has no member, and sphere 0 holds
only identity 1's key, and an attack by sphere 0 from it reaches a world in
which 1 is an admin of `o` and sphere 0 holds 1's key. In the construction 1 is
a valid agent of `o` and a member of team `n`, the admin team's key is with a
key holder, the policy is empty, and 1 asks for its own admission to the
admin team. -/
theorem named_team_admission_lets_attacker_become_admin (assign : Assignment) (o n : Nat)
    (hassign : assign o .admitAdmin = .named n) (Talk : Sphere → Sphere → Prop)
    (P : Sphere → Prop) :
    ∃ w0 w, (∀ z, ¬ w0.holds z (.orgKey (.team o .admin))) ∧
      (∀ k, (⟨o, .admin, k⟩ : Membership) ∉ w0.record.members) ∧
      (∀ z x, w0.holds z x ↔ z = 0 ∧ x = .idKey 1) ∧
      Attack (teamRule assign) Talk P 0 w0 w ∧ Admin w.record o 1 ∧ w.holds 0 (.idKey 1) := by
  let c : Cert := ⟨o, 1, .agent, .root⟩
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let s : State :=
    { e with orgs := [o], certs := [c], members := [⟨o, .named n, 1⟩], held := [.team o .admin] }
  let m : Membership := ⟨o, .admin, 1⟩
  let s' : State := { s with members := m :: s.members }
  let w0 : World := ⟨s, fun z x => z = 0 ∧ x = .idKey 1⟩
  have hv : Valid s o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s]) rfl rfl rfl rfl (by simp [s, e])
  have hv' : Valid s' o 1 .agent :=
    Valid.mono (s := s) (t := s') (fun _ h => h) (fun _ h => h) hv
  have hstep : Step (teamRule assign) s (.id 1) s' :=
    Step.admitAdmin (m := m) (kind := .agent) (who := .id 1) (approvals := []) rfl hv
      (.inr ⟨by simp [s, m], 1, rfl, ⟨by simp [s, m, OrgKey.org, hassign], .agent, hv⟩,
        fun r hr => by simp [s, e] at hr⟩)
  refine ⟨w0, ⟨s', w0.holds⟩, fun z h => by simp [w0] at h, fun k h => by simp [w0, s] at h,
    fun _ _ => Iff.rfl, .act .start ⟨rfl, rfl⟩ hstep, ⟨by simp [s', m], .agent, hv'⟩, ⟨rfl, rfl⟩⟩

end TrustWeb
