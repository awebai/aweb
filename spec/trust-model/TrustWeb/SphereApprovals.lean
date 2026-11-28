import TrustWeb.Spheres

/-!
# Trust spheres: approvals, named invitations, and admins

Three additions to the sphere layer, none of which changes the model: a
sphere layer in which an adversarial sphere's act counts an approval only
when it is available to that sphere; a planned step in which an invitation
names the identity that joins; and results that join the model's rules to
where keys are held.
-/

namespace TrustWeb

/-- `Available Talk P w z k`: sphere `z` holds `k`'s identity key or the
credential `k` enrolled to approve with, or a persuadable sphere that holds one
of them talks to `z`. -/
def Available (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop) (w : World)
    (z : Sphere) (k : Key) : Prop :=
  ∃ x, x.ApprovesAs k ∧ (w.holds z x ∨ ∃ z', w.holds z' x ∧ P z' ∧ Talk z' z)

/-- `AStep ask Talk P Adv w w'`: either an act of `StepVia`, asked for by a
party whose secret sphere `z` holds, takes the record from `w`'s to `w'`'s,
`z` holds and has got every secret the act gives, and if `z` is adversarial
every approval of the act is available to `z`; or a persuadable sphere gives
one of its secrets to a sphere it talks to. -/
inductive AStep (ask : AskRule) (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop)
    (Adv : Sphere → Prop) : World → World → Prop where
  | act {w : World} {s' : State} {who : Party} {z : Sphere} {approvals : List Key}
      {received : List Secret} :
      w.holds z who.secret → StepVia ask w.record who approvals received s' →
      (Adv z → ∀ k, k ∈ approvals → Available Talk P w z k) →
      AStep ask Talk P Adv w
        ⟨s', fun y v => w.holds y v ∨ (y = z ∧ v ∈ received),
          fun y v => w.received y v ∨ (y = z ∧ v ∈ received)⟩
  | leak {w : World} {z z' : Sphere} {x : Secret} :
      w.holds z x → P z → Talk z z' →
      AStep ask Talk P Adv w
        ⟨w.record, fun y v => w.holds y v ∨ (y = z' ∧ v = x), w.received⟩

/-- The worlds reached by such steps from a record with nothing in it but a
policy, the placement `init`, and no secret got from an act. -/
inductive AReachable (ask : AskRule) (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop)
    (Adv : Sphere → Prop) (init : Sphere → Secret → Prop) : World → Prop where
  | start (policy : List Rule) :
      AReachable ask Talk P Adv init
        ⟨⟨[], [], [], [], [], policy, [], [], [], []⟩, init, fun _ _ => False⟩
  | step {w w' : World} :
      AReachable ask Talk P Adv init w → AStep ask Talk P Adv w w' →
      AReachable ask Talk P Adv init w'

/-- In every world this layer reaches, the record is a record the model
reaches under the same rule. -/
theorem AReachable.record_reachable {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk P Adv init w) : Reachable ask w.record := by
  induction hr with
  | start policy => exact .start policy
  | step _ hstep ih =>
      cases hstep with
      | act _ hs _ => exact .step ih hs.toStep
      | leak _ _ _ => exact ih

/-- In every world this layer reaches, a secret a sphere got from an act is an
organisation key, an invitation secret or a session key. -/
theorem AReachable.given_givable {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk P Adv init w) {z : Sphere} {x : Secret} (hm : w.received z x) :
    x.Givable := by
  induction hr generalizing z x with
  | start _ => exact hm.elim
  | step _ hstep ih =>
      cases hstep with
      | act _ hs _ =>
          rcases hm with hm | ⟨_, hx⟩
          · exact ih hm
          · exact hs.given_givable hx
      | leak _ _ _ => exact ih hm

/-- In every world this layer reaches, if sphere `z` holds secret `x`, some
sphere held `x` in the initial placement or got it from an act, and `x` flows from it to
`z`. -/
theorem AReachable.held_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk P Adv init w) {z : Sphere} {x : Secret} (hz : w.holds z x) :
    ∃ z0, (init z0 x ∨ w.received z0 x) ∧ Flows Talk P z0 z := by
  induction hr generalizing z x with
  | start _ => exact ⟨z, .inl hz, .refl z⟩
  | step _ hstep ih =>
      cases hstep with
      | act _ _ _ =>
          rcases hz with hz | ⟨rfl, hx⟩
          · obtain ⟨z0, h0, hf⟩ := ih hz
            exact ⟨z0, h0.imp id .inl, hf⟩
          · exact ⟨_, .inr (.inr ⟨rfl, hx⟩), .refl _⟩
      | leak hzx hp ht =>
          rcases hz with hz | ⟨rfl, rfl⟩
          · exact ih hz
          · obtain ⟨z0, h0, hf⟩ := ih hzx
            exact ⟨z0, h0, .step hf hp ht⟩

/-- In every world this layer reaches, if sphere `z` holds secret `x` and `x`
is not a secret an act gives, some sphere held `x` in the initial placement
and `x` flows from it to `z`. -/
theorem AReachable.held_placed_secret_flowed {ask : AskRule}
    {Talk : Sphere → Sphere → Prop} {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop}
    {w : World} (hr : AReachable ask Talk P Adv init w) {z : Sphere} {x : Secret}
    (hx : ¬ x.Givable) (hz : w.holds z x) : ∃ z0, init z0 x ∧ Flows Talk P z0 z := by
  obtain ⟨z0, h0 | h0, hf⟩ := hr.held_secret_flowed hz
  · exact ⟨z0, h0, hf⟩
  · exact absurd (hr.given_givable h0) hx

/-- In every world this layer reaches, if `k`'s approval is available to
sphere `z`, some sphere `z0` held `k`'s identity key or approval credential in
the initial placement, and `z0` is `z` or is persuadable. -/
theorem available_approval_came_from {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk P Adv init w) {z : Sphere} {k : Key}
    (ha : Available Talk P w z k) :
    ∃ z0 x, x.ApprovesAs k ∧ init z0 x ∧ (z0 = z ∨ P z0) := by
  obtain ⟨x, hx, hz | ⟨z', hz', hp, _⟩⟩ := ha
  · obtain ⟨z0, h0, hf⟩ := hr.held_placed_secret_flowed hx.not_givable hz
    by_cases h : z0 = z
    · exact ⟨z0, x, hx, h0, .inl h⟩
    · exact ⟨z0, x, hx, h0, .inr (hf.source_persuadable h)⟩
  · obtain ⟨z0, h0, hf⟩ := hr.held_placed_secret_flowed hx.not_givable hz'
    by_cases h : z0 = z'
    · exact ⟨z0, x, hx, h0, .inr (h ▸ hp)⟩
    · exact ⟨z0, x, hx, h0, .inr (hf.source_persuadable h)⟩

/-- World 2. In every world this layer reaches with agents' spheres
persuadable, if `z` is adversarial and every sphere that held `k`'s identity
key or approval credential in the initial placement is neither an agent's nor
adversarial, `k`'s approval is not available to `z`. -/
theorem world2_approval_not_available {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {Adv : Sphere → Prop} {init : Sphere → Secret → Prop}
    {w : World} (hr : AReachable ask Talk (agentsSwayed occ) Adv init w) {z : Sphere}
    (hadv : Adv z) {k : Key}
    (hk : ∀ z0 x, x.ApprovesAs k → init z0 x → occ z0 ≠ .agent ∧ ¬ Adv z0) :
    ¬ Available Talk (agentsSwayed occ) w z k := by
  intro ha
  obtain ⟨z0, x, hx, h0, h | h⟩ := available_approval_came_from hr ha
  · exact (hk z0 x hx h0).2 (h ▸ hadv)
  · exact (hk z0 x hx h0).1 h

/-- World 2. In every world this layer reaches with agents' spheres
persuadable, if `z` is adversarial, every approval in `approvals` is available
to `z`, and every sphere that held the identity key or approval credential of
a valid person of `o` in the initial placement is neither an agent's nor
adversarial, the approvals do not satisfy a rule of `o` asking for any
person. -/
theorem world2_adversary_has_no_person_approval {ask : AskRule}
    {Talk : Sphere → Sphere → Prop} {occ : Sphere → Occupant} {Adv : Sphere → Prop}
    {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk (agentsSwayed occ) Adv init w) {z : Sphere} (hadv : Adv z)
    {approvals : List Key}
    (hall : ∀ k, k ∈ approvals → Available Talk (agentsSwayed occ) w z k) {o : Org}
    (hp : ∀ p, Valid w.record o p .person → ∀ z0 x, x.ApprovesAs p → init z0 x →
      occ z0 ≠ .agent ∧ ¬ Adv z0) :
    ¬ Satisfies w.record o approvals .anyPerson := by
  rintro ⟨p, hmem, hv⟩
  exact world2_approval_not_available hr hadv (hp p hv) (hall p hmem)

/-- World 3. If sphere `z'` holds `k`'s identity key or approval credential, a
person occupies `z'`, and `z'` talks to `z`, `k`'s approval is available to
`z` when agents' and persons' spheres are persuadable. -/
theorem world3_persuaded_person_approves {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {w : World} {z z' : Sphere} {k : Key} {x : Secret}
    (hx : x.ApprovesAs k) (hz' : w.holds z' x) (hperson : occ z' = .person)
    (ht : Talk z' z) : Available Talk (agentsAndPersonsSwayed occ) w z k :=
  ⟨x, hx, .inr ⟨z', hz', .inr hperson, ht⟩⟩

/-- World 2. In every world this layer reaches with agents' spheres
persuadable, if sphere `z` is adversarial, every approval in `approvals` is
available to `z`, `key` is held, the policy has a rule asking any person to
approve this kind of act in `key`'s organisation, and every sphere that held
the identity key or approval credential of a valid person of that organisation
in the initial placement is neither an agent's nor adversarial, `Authorised` does not hold
for `key` with those approvals. -/
theorem world2_adversary_not_authorised_where_person_needed {ask : AskRule}
    {Talk : Sphere → Sphere → Prop} {occ : Sphere → Occupant} {Adv : Sphere → Prop}
    {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk (agentsSwayed occ) Adv init w) {z : Sphere} (hadv : Adv z)
    {approvals : List Key}
    (hall : ∀ k, k ∈ approvals → Available Talk (agentsSwayed occ) w z k)
    {key : OrgKey} (hheld : key ∈ w.record.held) {act : ActKind}
    (hrule : ∃ r, r ∈ w.record.policy ∧ r.org = key.org ∧ r.act = act ∧
      r.approver = .anyPerson)
    (hp : ∀ p, Valid w.record key.org p .person → ∀ z0 x, x.ApprovesAs p → init z0 x →
      occ z0 ≠ .agent ∧ ¬ Adv z0) {who : Party} :
    ¬ Authorised ask w.record key act who approvals := by
  rintro (⟨hn, _⟩ | ⟨_, _, _, _, happ⟩)
  · exact hn hheld
  · obtain ⟨r, hr', ho, ha, hap⟩ := hrule
    have := happ r hr' ho ha
    rw [hap] at this
    exact world2_adversary_has_no_person_approval hr hadv hall hp this

/-- Planned, id-specific invitations: the acts of `Step`, except that
redeeming an invitation adds a certificate for the key `joiner` names for its
secret, and for no other key. -/
inductive NamedStep (ask : AskRule) (joiner : Nat → Key) : State → Party → State → Prop where
  | other {s s' : State} {who : Party} :
      Step ask s who s' → (∀ t, who ≠ .bearer t) → NamedStep ask joiner s who s'
  | redeem {s : State} {i : Invite} :
      i ∈ s.invites → i.team ≠ .admin → OneTeamIfLocal s (joiner i.token) →
      NamedStep ask joiner s (.bearer i.token)
        { s with members := ⟨i.org, i.team, joiner i.token⟩ :: s.members,
                 invites := s.invites.filter (fun x => decide (x ≠ i)) }

/-- Every act of `NamedStep` is an act of `Step`. -/
theorem NamedStep.toStep {ask : AskRule} {joiner : Nat → Key} {s s' : State} {who : Party}
    (h : NamedStep ask joiner s who s') : Step ask s who s' := by
  cases h with
  | other hs _ => exact hs
  | redeem h0 h1 h2 => exact .redeem h0 h1 h2

/-- In one act of `NamedStep` asked for by the holder of invitation secret
`t`, every certificate of a team added is for `joiner t`. -/
theorem named_invitation_joins_only_its_identity {ask : AskRule} {joiner : Nat → Key}
    {s s' : State} {t : Nat} (h : NamedStep ask joiner s (.bearer t) s') {m : Membership}
    (hnew : m ∈ s'.members) (hold : m ∉ s.members) : m.member = joiner t := by
  cases h with
  | other _ hne => exact absurd rfl (hne t)
  | redeem _ _ _ =>
      rcases List.mem_cons.mp hnew with rfl | h
      · rfl
      · exact absurd h hold

/-- Under any rule, for every key `k` there is a record and an act of `Step`
asked for by the holder of invitation secret 5 that adds a certificate of
team 1 of organisation 0 for `k`. -/
theorem invitation_holder_names_any_key (ask : AskRule) (k : Key) :
    ∃ s s', Step ask s (.bearer 5) s' ∧ (⟨0, .named 1, k⟩ : Membership) ∈ s'.members := by
  let i : Invite := ⟨5, 0, .named 1⟩
  let s : State := ⟨[], [], [], [], [], [], [], [], [i], []⟩
  refine ⟨s, _, Step.redeem (i := i) (k := k) (by simp [s]) (by simp [i])
    (.inr (fun m hm => by simp [s] at hm)), List.mem_cons_self⟩

/-- Under the admin rule, if sphere `z` holds the secret of the party that
asks for an act of `Step` adding a certificate of an admin team, `z` holds
that admin team's key, or the identity key of an admin of its organisation. -/
theorem new_admin_needs_a_held_key {w : World} {z : Sphere} {who : Party} {s' : State}
    (hz : w.holds z who.secret) (hstep : Step adminRule w.record who s')
    {m : Membership} (hnew : m ∈ s'.members) (hold : m ∉ w.record.members)
    (hteam : m.team = .admin) :
    w.holds z (.orgKey (.team m.org .admin)) ∨
      ∃ a, w.holds z (.idKey a) ∧ Admin w.record m.org a := by
  rcases new_admin_needs_controller_or_asker hstep hnew hold hteam with h | ⟨a, h, hask⟩
  · subst h; exact .inl hz
  · subst h; exact .inr ⟨a, hz, hask⟩

/-- World 2, under the admin rule. In every world the sphere layer reaches
with agents' spheres persuadable, if an agent occupies sphere `z`, `z` holds
the secret of the party that asks for an act adding a certificate of `o`'s
admin team, and neither the admin team's key nor any admin of `o`'s identity
key was held by an agent's sphere in the initial placement, and no agent's
sphere got the admin team's key from an act: contradiction. -/
theorem world2_agent_sphere_adds_no_admin {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable adminRule Talk (agentsSwayed occ) init w) {z : Sphere}
    (hagent : occ z = .agent) {who : Party} {s' : State}
    (hz : w.holds z who.secret) (hstep : Step adminRule w.record who s') {m : Membership}
    (hnew : m ∈ s'.members) (hold : m ∉ w.record.members) (hteam : m.team = .admin)
    (hkey : ∀ z0, init z0 (.orgKey (.team m.org .admin)) ∨ w.received z0 (.orgKey (.team m.org .admin)) →
      occ z0 ≠ .agent)
    (hadmins : ∀ a, Admin w.record m.org a → ∀ z0, init z0 (.idKey a) → occ z0 ≠ .agent) :
    False := by
  rcases new_admin_needs_a_held_key hz hstep hnew hold hteam with h | ⟨a, h, ha⟩
  · exact hkey z (world2_non_agent_secret_stays hr hkey h) hagent
  · have hx : ∀ z0, init z0 (.idKey a) ∨ w.received z0 (.idKey a) → occ z0 ≠ .agent :=
      fun z0 h0 => h0.elim (hadmins a ha z0) (fun hm => absurd (hr.given_givable hm) id)
    exact hx z (world2_non_agent_secret_stays hr hx h) hagent

end TrustWeb
