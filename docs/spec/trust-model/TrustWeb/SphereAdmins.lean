import TrustWeb.SphereApprovals

/-!
# Trust spheres: an attacker's chain of acts

What one sphere can reach by a chain of acts of its own, helped only by the
secrets persuadable spheres pass on.
-/

namespace TrustWeb

/-- `Attack ask Talk P a w0 w`: world `w` is reached from `w0` by acts that
sphere `a` asks for, with any secret it holds, and by persuadable spheres
giving secrets to spheres they talk to. No other sphere acts, an act needs no
approval beyond the model's own premises, and `a` holds and has got every
secret its acts give. -/
inductive Attack (ask : AskRule) (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop)
    (a : Sphere) (w0 : World) : World → Prop where
  | start : Attack ask Talk P a w0 w0
  | act {w : World} {s' : State} {who : Party} {approvals : List Key} {received : List Secret} :
      Attack ask Talk P a w0 w → w.holds a who.secret →
      StepVia ask w.record who approvals received s' →
      Attack ask Talk P a w0
        ⟨s', fun y v => w.holds y v ∨ (y = a ∧ v ∈ received),
          fun y v => w.received y v ∨ (y = a ∧ v ∈ received)⟩
  | leak {w : World} {z z' : Sphere} {x : Secret} :
      Attack ask Talk P a w0 w → w.holds z x → P z → Talk z z' →
      Attack ask Talk P a w0
        ⟨w.record, fun y v => w.holds y v ∨ (y = z' ∧ v = x), w.received⟩

/-- `CanReach Talk P w0 a x`: some sphere holds `x` in `w0`, and `x` flows
from it to `a`. -/
def CanReach (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop) (w0 : World)
    (a : Sphere) (x : Secret) : Prop :=
  ∃ z0, w0.holds z0 x ∧ Flows Talk P z0 a

/-- In every world an attack by `a` reaches, if sphere `z` holds secret `x`,
`x` flows to `z` from a sphere that held it in `w0`, or `x` is a secret an act
makes and flows to `z` from `a`. -/
theorem Attack.held_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 w : World} (hw : Attack ask Talk P a w0 w)
    {z : Sphere} {x : Secret} (hz : w.holds z x) :
    CanReach Talk P w0 z x ∨ (x.Givable ∧ Flows Talk P a z) := by
  induction hw generalizing z x with
  | start => exact .inl ⟨z, hz, .refl z⟩
  | act _ _ hs ih =>
      rcases hz with hz | ⟨rfl, hx⟩
      · exact ih hz
      · exact .inr ⟨hs.given_givable hx, .refl _⟩
  | leak _ hzx hp ht ih =>
      rcases hz with hz | ⟨rfl, rfl⟩
      · exact ih hz
      · rcases ih hzx with ⟨z0, h0, hf⟩ | ⟨hm, hf⟩
        · exact .inl ⟨z0, h0, .step hf hp ht⟩
        · exact .inr ⟨hm, .step hf hp ht⟩

/-- In every world an attack reaches, if sphere `z` holds secret `x` and `x`
is not a secret an act gives, `x` flows to `z` from a sphere that held it in
`w0`. -/
theorem Attack.held_placed_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 w : World} (hw : Attack ask Talk P a w0 w)
    {z : Sphere} {x : Secret} (hx : ¬ x.Givable) (hz : w.holds z x) :
    CanReach Talk P w0 z x :=
  (hw.held_secret_flowed hz).resolve_right (fun h => hx h.1)

/-- A secret does not reach `a` if every sphere holding it in `w0` is neither
`a` nor persuadable. -/
theorem not_canReach {Talk : Sphere → Sphere → Prop} {P : Sphere → Prop} {w0 : World}
    {a : Sphere} {x : Secret} (h : ∀ z0, w0.holds z0 x → z0 ≠ a ∧ ¬ P z0) :
    ¬ CanReach Talk P w0 a x := by
  rintro ⟨z0, h0, hf⟩
  exact (h z0 h0).2 (hf.source_persuadable (h z0 h0).1)

/-- Any chain of acts. Suppose the rule lets only members of `o`'s admin team
ask for admitting an admin of `o`, for a re-key in `o`, or for having a key of
`o` given back, and neither `o`'s domain credential, nor `o`'s root key, nor
the admin team's key, nor the identity key of a member of the admin team in
`w0` reaches sphere `a`. Then in every world an attack by `a` reaches, a
sphere holds `o`'s root key or the admin team's key only if it reaches that
sphere from `w0`, and every member of `o`'s admin team was one in `w0`. -/
theorem attack_keeps_admin_keys_away {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k ∨ ask s o .rekey k ∨ ask s o .release k →
      (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hdns : ¬ CanReach Talk P w0 a (.dns o))
    (hroot : ¬ CanReach Talk P w0 a (.orgKey (.root o)))
    (hkey : ¬ CanReach Talk P w0 a (.orgKey (.team o .admin)))
    (hadm : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ¬ CanReach Talk P w0 a (.idKey k))
    {w : World} (hw : Attack ask Talk P a w0 w) :
    (∀ z, w.holds z (.orgKey (.root o)) → CanReach Talk P w0 z (.orgKey (.root o))) ∧
    (∀ z, w.holds z (.orgKey (.team o .admin)) →
      CanReach Talk P w0 z (.orgKey (.team o .admin))) ∧
    ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w.record.members →
      (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members := by
  induction hw with
  | start => exact ⟨fun z h => ⟨z, h, .refl z⟩, fun z h => ⟨z, h, .refl z⟩, fun _ h => h⟩
  | @act w s' who approvals received hw' hz hs ih =>
      obtain ⟨ihr, iht, iha⟩ := ih
      have noAdmin : ∀ b, (⟨o, .admin, b⟩ : Membership) ∈ w.record.members →
          ¬ w.holds a (.idKey b) := fun b hb h =>
        hadm b (iha b hb) (hw'.held_placed_secret_flowed (x := .idKey b) (fun h => h) h)
      refine ⟨fun z h => ?_, fun z h => ?_, fun k hk => ?_⟩
      · rcases h with h | ⟨rfl, hx⟩
        · exact ihr z h
        · rcases hs.given_root hx with rfl | (⟨_, rfl⟩ | ⟨_, b, rfl, hask, _⟩)
          · exact absurd (hw'.held_placed_secret_flowed (x := .dns o) (fun h => h) hz) hdns
          · exact absurd (ihr _ hz) hroot
          · exact (noAdmin b (hrule _ _ (.inr (.inr hask))) hz).elim
      · rcases h with h | ⟨rfl, hx⟩
        · exact iht z h
        · rcases hs.given_team hx with (⟨_, rfl⟩ | ⟨_, b, rfl, hask, _⟩) |
            (⟨_, rfl⟩ | ⟨_, b, rfl, hask, _⟩)
          · exact absurd (ihr _ hz) hroot
          · exact (noAdmin b (hrule _ _ (.inr (.inl hask))) hz).elim
          · exact absurd (iht _ hz) hkey
          · exact (noAdmin b (hrule _ _ (.inr (.inr hask))) hz).elim
      · by_cases hold : (⟨o, .admin, k⟩ : Membership) ∈ w.record.members
        · exact iha k hold
        · rcases new_admin_needs_controller_or_asker hs.toStep hk hold rfl with h | ⟨b, h, hask⟩
          · subst h
            exact absurd (iht _ hz) hkey
          · subst h
            exact (noAdmin b (hrule _ _ (.inl hask)) hz).elim
  | leak _ hzx hp ht ih =>
      obtain ⟨ihr, iht, iha⟩ := ih
      refine ⟨fun z h => ?_, fun z h => ?_, iha⟩
      · rcases h with h | ⟨rfl, rfl⟩
        · exact ihr z h
        · obtain ⟨z0, h0, hf⟩ := ihr _ hzx
          exact ⟨z0, h0, .step hf hp ht⟩
      · rcases h with h | ⟨rfl, rfl⟩
        · exact iht z h
        · obtain ⟨z0, h0, hf⟩ := iht _ hzx
          exact ⟨z0, h0, .step hf hp ht⟩

/-- Any chain of acts, in the same setting: in every world an attack by `a`
reaches, the identity key of no member of `o`'s admin team reaches `a`. -/
theorem attack_reaches_no_admin_key {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k ∨ ask s o .rekey k ∨ ask s o .release k →
      (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hdns : ¬ CanReach Talk P w0 a (.dns o))
    (hroot : ¬ CanReach Talk P w0 a (.orgKey (.root o)))
    (hkey : ¬ CanReach Talk P w0 a (.orgKey (.team o .admin)))
    (hadm : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ¬ CanReach Talk P w0 a (.idKey k))
    {w : World} (hw : Attack ask Talk P a w0 w) :
    ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w.record.members → ¬ CanReach Talk P w0 a (.idKey k) :=
  fun k hk => hadm k ((attack_keeps_admin_keys_away hrule hdns hroot hkey hadm hw).2.2 k hk)

/-- Any chain of acts, in the same setting, and with no secret that lets a
member of the admin team in `w0` approve reaching `a`: in every world an
attack by `a` reaches, `a` holds neither `o`'s root key nor the admin team's
key, and no admin of `o`'s approval is available to `a`. -/
theorem attacker_holds_no_admin_key {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k ∨ ask s o .rekey k ∨ ask s o .release k →
      (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hdns : ¬ CanReach Talk P w0 a (.dns o))
    (hroot : ¬ CanReach Talk P w0 a (.orgKey (.root o)))
    (hkey : ¬ CanReach Talk P w0 a (.orgKey (.team o .admin)))
    (happ : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ∀ x, x.ApprovesAs k → ¬ CanReach Talk P w0 a x)
    {w : World} (hw : Attack ask Talk P a w0 w) :
    ¬ w.holds a (.orgKey (.root o)) ∧ ¬ w.holds a (.orgKey (.team o .admin)) ∧
      ∀ k, Admin w.record o k → ¬ Available Talk P w a k := by
  obtain ⟨hr, ht, ha⟩ := attack_keeps_admin_keys_away hrule hdns hroot hkey
    (fun k hk => happ k hk _ (.inl rfl)) hw
  refine ⟨fun h => hroot (hr a h), fun h => hkey (ht a h), fun k hk hav => ?_⟩
  obtain ⟨x, hx, h | ⟨z', h, hp, htalk⟩⟩ := hav
  · exact happ k (ha k hk.1) x hx (hw.held_placed_secret_flowed hx.not_givable h)
  · obtain ⟨z0, h0, hf⟩ := hw.held_placed_secret_flowed hx.not_givable h
    exact happ k (ha k hk.1) x hx ⟨z0, h0, .step hf hp htalk⟩

/-- World 2, any chain of acts. Suppose the rule lets only members of `o`'s
admin team ask for admitting an admin of `o`, for a re-key in `o`, or for
having a key of `o` given back, and every sphere that holds in `w0` `o`'s
domain credential, `o`'s root key, the admin team's key, or a secret that
lets a member of the admin team approve, is neither `a` nor an agent's. Then
in every world an attack by `a` reaches, with agents' spheres persuadable,
`a` holds neither `o`'s root key nor the admin team's key, and no admin of
`o`'s approval is available to `a`. -/
theorem world2_attacker_holds_no_admin_key {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {a : Sphere} {w0 : World} {o : Org}
    (hrule : ∀ s k, ask s o .admitAdmin k ∨ ask s o .rekey k ∨ ask s o .release k →
      (⟨o, .admin, k⟩ : Membership) ∈ s.members)
    (hdns : ∀ z0, w0.holds z0 (.dns o) → z0 ≠ a ∧ occ z0 ≠ .agent)
    (hroot : ∀ z0, w0.holds z0 (.orgKey (.root o)) → z0 ≠ a ∧ occ z0 ≠ .agent)
    (hkey : ∀ z0, w0.holds z0 (.orgKey (.team o .admin)) → z0 ≠ a ∧ occ z0 ≠ .agent)
    (happ : ∀ k, (⟨o, .admin, k⟩ : Membership) ∈ w0.record.members →
      ∀ x, x.ApprovesAs k → ∀ z0, w0.holds z0 x → z0 ≠ a ∧ occ z0 ≠ .agent)
    {w : World} (hw : Attack ask Talk (agentsSwayed occ) a w0 w) :
    ¬ w.holds a (.orgKey (.root o)) ∧ ¬ w.holds a (.orgKey (.team o .admin)) ∧
      ∀ k, Admin w.record o k → ¬ Available Talk (agentsSwayed occ) w a k :=
  attacker_holds_no_admin_key hrule (not_canReach hdns) (not_canReach hroot)
    (not_canReach hkey) (fun k hk x hx => not_canReach (happ k hk x hx)) hw

/-- The admin rule lets only members of `o`'s admin team ask for admitting an
admin of `o`, for a re-key in `o`, or for having a key of `o` given back; so
does the team rule when all three are assigned to the admin team. -/
theorem adminRule_admits_only_by_admins (o : Org) :
    ∀ s k, adminRule s o .admitAdmin k ∨ adminRule s o .rekey k ∨ adminRule s o .release k →
      (⟨o, .admin, k⟩ : Membership) ∈ s.members :=
  fun _ _ h => h.elim (·.1) (fun h => h.elim (·.1) (·.1))

theorem teamRule_admits_only_by_admins {assign : Assignment} {o : Org}
    (hadmit : assign o .admitAdmin = .admin) (hrekey : assign o .rekey = .admin)
    (hrelease : assign o .release = .admin) :
    ∀ s k, teamRule assign s o .admitAdmin k ∨ teamRule assign s o .rekey k ∨
        teamRule assign s o .release k →
      (⟨o, .admin, k⟩ : Membership) ∈ s.members :=
  fun _ _ h => h.elim (fun h => hadmit ▸ h.1)
    (fun h => h.elim (fun h => hrekey ▸ h.1) (fun h => hrelease ▸ h.1))

/-- Under the admin rule, for any talk and any persuadable spheres: there is a
world in which the key of `o`'s admin team is with a key holder, the admin
team has no member, and sphere 0 holds only `o`'s root key and identity 1's
key, and an attack by sphere 0 from it reaches a world in which 1 is an admin
of `o`. In the construction 1 is a valid agent of `o`, the policy is empty,
sphere 0 re-keys the admin team through the root key, which gives the team's
key and puts it in sphere 0, and then admits 1 to the admin team through that
key. -/
theorem root_holder_rekeys_then_admits_admin (o : Org) (Talk : Sphere → Sphere → Prop)
    (P : Sphere → Prop) :
    ∃ w0 w, OrgKey.team o .admin ∈ w0.record.held ∧
      (∀ k, (⟨o, .admin, k⟩ : Membership) ∉ w0.record.members) ∧
      (∀ z x, w0.holds z x ↔ z = 0 ∧ (x = .orgKey (.root o) ∨ x = .idKey 1)) ∧
      Attack adminRule Talk P 0 w0 w ∧ Admin w.record o 1 := by
  let c : Cert := ⟨o, 1, .agent, .root⟩
  let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  let s : State := { e with orgs := [o], certs := [c], held := [.team o .admin] }
  let s1 : State := { s with held := [], members := [], grants := [] }
  let m : Membership := ⟨o, .admin, 1⟩
  let s2 : State := { s1 with members := [m] }
  let w0 : World :=
    ⟨s, fun z x => z = 0 ∧ (x = .orgKey (.root o) ∨ x = .idKey 1), fun _ _ => False⟩
  have hrekey : StepVia adminRule s (.controller (.root o)) [] [.orgKey (.team o .admin)] s1 := by
    simpa [s1, s, e] using (StepVia.rekeyTeam (ask := adminRule) (s := s) (o := o)
      (t := .admin) (keep := []) (who := .controller (.root o)) (approvals := [])
      (.inl ⟨by simp [s], rfl⟩) (by simp [s]))
  have hv : Valid s1 o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s1, s]) rfl rfl rfl rfl (by simp [s1, s, e])
  have hadmit : StepVia adminRule s1 (.controller (.team o .admin)) [] [] s2 :=
    StepVia.admitAdmin (m := m) (kind := .agent) rfl hv (.inl ⟨by simp [s1], rfl⟩)
  have h1 := Attack.act (Talk := Talk) (P := P) (a := 0) (w0 := w0) .start
    ⟨rfl, .inl rfl⟩ hrekey
  have h2 := Attack.act h1 (.inr ⟨rfl, List.mem_singleton_self _⟩) hadmit
  exact ⟨w0, _, by simp [w0, s], fun k h => by simp [w0, s, e] at h, fun _ _ => Iff.rfl, h2,
    ⟨by simp [s2, m], .agent, Valid.mono (s := s1) (t := s2) (fun _ h => h) (fun _ h => h) hv⟩⟩

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
  let w0 : World := ⟨s, fun z x => z = 0 ∧ x = .idKey 1, fun _ _ => False⟩
  have hv : Valid s o 1 .agent :=
    .agentOfRoot (c := c) (by simp [s]) rfl rfl rfl rfl (by simp [s, e])
  have hv' : Valid s' o 1 .agent :=
    Valid.mono (s := s) (t := s') (fun _ h => h) (fun _ h => h) hv
  have hstep : StepVia (teamRule assign) s (.id 1) [] [] s' :=
    StepVia.admitAdmin (m := m) (kind := .agent) (who := .id 1) (approvals := []) rfl hv
      (.inr ⟨by simp [s, m], 1, rfl, ⟨by simp [s, m, OrgKey.org, hassign], .agent, hv⟩,
        fun r hr => by simp [s, e] at hr⟩)
  have h1 := Attack.act (Talk := Talk) (P := P) (a := 0) (w0 := w0) .start ⟨rfl, rfl⟩ hstep
  exact ⟨w0, _, fun z h => by simp [w0] at h, fun k h => by simp [w0, s] at h,
    fun _ _ => Iff.rfl, h1, ⟨by simp [s', m], .agent, hv'⟩, .inl ⟨rfl, rfl⟩⟩

end TrustWeb
