import TrustWeb.SphereActs

/-!
# Trust spheres

A layer on the model: which spheres hold which secrets, how a secret moves
between spheres, and from which sphere an act can be asked for.
-/

namespace TrustWeb

/-- A sphere. -/
abbrev Sphere := Nat

/-- A record of the model, which spheres hold which secrets, and which spheres
have got which secrets from acts. -/
structure World where
  record : State
  holds : Sphere → Secret → Prop
  received : Sphere → Secret → Prop

/-- `WStep ask Talk Persuadable w w'`: either an act of the model, asked for
by a party whose secret sphere `z` holds, takes the record from `w`'s to
`w'`'s, and `z` holds and has got every secret the act gives; or a sphere
`z` that holds a secret `x`, is persuadable, and talks to `z'`, gives `x` to
`z'` and the record stays as it is. -/
inductive WStep (ask : AskRule) (Talk : Sphere → Sphere → Prop)
    (Persuadable : Sphere → Prop) : World → World → Prop where
  | act {w : World} {s' : State} {who : Party} {z : Sphere} {approvals : List Key}
      {received : List Secret} :
      w.holds z who.secret → StepVia ask w.record who approvals received s' →
      WStep ask Talk Persuadable w
        ⟨s', fun y v => w.holds y v ∨ (y = z ∧ v ∈ received),
          fun y v => w.received y v ∨ (y = z ∧ v ∈ received)⟩
  | leak {w : World} {z z' : Sphere} {x : Secret} :
      w.holds z x → Persuadable z → Talk z z' →
      WStep ask Talk Persuadable w
        ⟨w.record, fun y v => w.holds y v ∨ (y = z' ∧ v = x), w.received⟩

/-- The worlds reached by such steps from a record with nothing in it but a
policy, the placement `init`, and no secret got from an act. -/
inductive WReachable (ask : AskRule) (Talk : Sphere → Sphere → Prop)
    (Persuadable : Sphere → Prop) (init : Sphere → Secret → Prop) : World → Prop where
  | start (policy : List Rule) :
      WReachable ask Talk Persuadable init
        ⟨⟨[], [], [], [], [], policy, [], [], [], []⟩, init, fun _ _ => False⟩
  | step {w w' : World} :
      WReachable ask Talk Persuadable init w → WStep ask Talk Persuadable w w' →
      WReachable ask Talk Persuadable init w'

/-- `Flows Talk Persuadable a b`: `a` is `b`, or a chain of spheres runs from
`a` to `b` in which each sphere that passes a secret on is persuadable and
talks to the next. -/
inductive Flows (Talk : Sphere → Sphere → Prop) (Persuadable : Sphere → Prop) :
    Sphere → Sphere → Prop where
  | refl (z : Sphere) : Flows Talk Persuadable z z
  | step {a b c : Sphere} :
      Flows Talk Persuadable a b → Persuadable b → Talk b c → Flows Talk Persuadable a c

/-- Who occupies a sphere. -/
inductive Occupant where
  | agent
  | person
  | keyHolder
  | service
  deriving DecidableEq, Repr

/-- World 1: no sphere is persuadable. -/
def noneSwayed (_ : Sphere → Occupant) : Sphere → Prop := fun _ => False

/-- World 2: the spheres an agent occupies are persuadable. -/
def agentsSwayed (occ : Sphere → Occupant) : Sphere → Prop := fun z => occ z = .agent

/-- World 3: the spheres an agent or a person occupies are persuadable. -/
def agentsAndPersonsSwayed (occ : Sphere → Occupant) : Sphere → Prop :=
  fun z => occ z = .agent ∨ occ z = .person

/-- In every reachable world, the record is a record the model reaches under
the same rule. -/
theorem WReachable.record_reachable {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk P init w) : Reachable ask w.record := by
  induction hr with
  | start policy => exact .start policy
  | step _ hstep ih =>
      cases hstep with
      | act _ hs => exact .step ih hs.toStep
      | leak _ _ _ => exact ih

/-- In one step, if the record changes, some sphere holds the secret of a
party, and an act of the model asked for by that party takes the record
before to the record after. -/
theorem WStep.record_change {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {w w' : World} (hstep : WStep ask Talk P w w')
    (hchg : w'.record ≠ w.record) :
    ∃ z who, w.holds z who.secret ∧ Step ask w.record who w'.record := by
  cases hstep with
  | act hz hs => exact ⟨_, _, hz, hs.toStep⟩
  | leak _ _ _ => exact absurd rfl hchg

/-- In every reachable world, a secret a sphere got from an act is an organisation
key, an invitation secret or a session key. -/
theorem WReachable.given_givable {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk P init w) {z : Sphere} {x : Secret} (hm : w.received z x) :
    x.Givable := by
  induction hr generalizing z x with
  | start _ => exact hm.elim
  | step _ hstep ih =>
      cases hstep with
      | act _ hs =>
          rcases hm with hm | ⟨_, hx⟩
          · exact ih hm
          · exact hs.given_givable hx
      | leak _ _ _ => exact ih hm

/-- In every reachable world, if sphere `z` holds secret `x`, some sphere held
`x` in the initial placement or got it from an act, and `x` flows from it to `z`. -/
theorem held_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk P init w) {z : Sphere} {x : Secret} (hz : w.holds z x) :
    ∃ z0, (init z0 x ∨ w.received z0 x) ∧ Flows Talk P z0 z := by
  induction hr generalizing z x with
  | start _ => exact ⟨z, .inl hz, .refl z⟩
  | step _ hstep ih =>
      cases hstep with
      | act _ _ =>
          rcases hz with hz | ⟨rfl, hx⟩
          · obtain ⟨z0, h0, hf⟩ := ih hz
            exact ⟨z0, h0.imp id .inl, hf⟩
          · exact ⟨_, .inr (.inr ⟨rfl, hx⟩), .refl _⟩
      | leak hzx hp ht =>
          rcases hz with hz | ⟨rfl, rfl⟩
          · exact ih hz
          · obtain ⟨z0, h0, hf⟩ := ih hzx
            exact ⟨z0, h0, .step hf hp ht⟩

/-- In every reachable world, if sphere `z` holds secret `x` and `x` is not a
secret an act gives, some sphere held `x` in the initial placement and `x`
flows from it to `z`. -/
theorem held_placed_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk P init w) {z : Sphere} {x : Secret} (hx : ¬ x.Givable)
    (hz : w.holds z x) : ∃ z0, init z0 x ∧ Flows Talk P z0 z := by
  obtain ⟨z0, h0 | h0, hf⟩ := held_secret_flowed hr hz
  · exact ⟨z0, h0, hf⟩
  · exact absurd (hr.given_givable h0) hx

/-- If a secret flows from `a` to a different sphere `b`, `a` is persuadable. -/
theorem Flows.source_persuadable {Talk : Sphere → Sphere → Prop} {P : Sphere → Prop}
    {a b : Sphere} (hf : Flows Talk P a b) (hne : a ≠ b) : P a := by
  induction hf with
  | refl => exact absurd rfl hne
  | @step m _ _ hp _ ih =>
      by_cases h : a = m
      · exact h ▸ hp
      · exact ih h

/-- In every reachable world, if sphere `z` holds secret `x`, some sphere `z0`
held `x` in the initial placement or got it from an act, and `z0` is `z` or is
persuadable. -/
theorem held_secret_came_from_persuadable {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk P init w) {z : Sphere} {x : Secret} (hz : w.holds z x) :
    ∃ z0, (init z0 x ∨ w.received z0 x) ∧ (z0 = z ∨ P z0) := by
  obtain ⟨z0, h0, hf⟩ := held_secret_flowed hr hz
  by_cases h : z0 = z
  · exact ⟨z0, h0, .inl h⟩
  · exact ⟨z0, h0, .inr (hf.source_persuadable h)⟩

/-- World 1. In every reachable world in which no sphere is persuadable, a
sphere holds a secret only if it held it in the initial placement or got
it from an act. -/
theorem world1_secrets_stay {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk (noneSwayed occ) init w) {z : Sphere} {x : Secret}
    (hz : w.holds z x) : init z x ∨ w.received z x := by
  obtain ⟨z0, h0, h | h⟩ := held_secret_came_from_persuadable hr hz
  · exact h ▸ h0
  · exact h.elim

/-- World 2. In every reachable world in which the spheres agents occupy are
persuadable, if no sphere an agent occupies held secret `x` in the initial
placement or got it from an act, a sphere holds `x` only if it held it in the initial
placement or got it from an act. -/
theorem world2_non_agent_secret_stays {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk (agentsSwayed occ) init w) {x : Secret}
    (hx : ∀ z0, init z0 x ∨ w.received z0 x → occ z0 ≠ .agent) {z : Sphere} (hz : w.holds z x) :
    init z x ∨ w.received z x := by
  obtain ⟨z0, h0, h | h⟩ := held_secret_came_from_persuadable hr hz
  · exact h ▸ h0
  · exact absurd h (hx z0 h0)

/-- World 3. In every reachable world in which the spheres agents and persons
occupy are persuadable, if no sphere an agent or a person occupies held secret
`x` in the initial placement or got it from an act, a sphere holds `x` only if it held it
in the initial placement or got it from an act. -/
theorem world3_other_secret_stays {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable ask Talk (agentsAndPersonsSwayed occ) init w) {x : Secret}
    (hx : ∀ z0, init z0 x ∨ w.received z0 x → occ z0 ≠ .agent ∧ occ z0 ≠ .person) {z : Sphere}
    (hz : w.holds z x) : init z x ∨ w.received z x := by
  obtain ⟨z0, h0, h | h | h⟩ := held_secret_came_from_persuadable hr hz
  · exact h ▸ h0
  · exact absurd h (hx z0 h0).1
  · exact absurd h (hx z0 h0).2

/-- Under any rule and any persuadable spheres that include sphere 1: with
sphere 1 the only holder of identity 5's key in the initial placement and
sphere 1 talking to sphere 0, there is a reachable world in which sphere 0
holds that key and a message attributed to 5 has been sent. In the
construction sphere 1 gives the key to sphere 0, and sphere 0 sends as 5. -/
theorem persuaded_key_lets_another_sphere_send (ask : AskRule) {P : Sphere → Prop}
    (h1 : P 1) :
    ∃ w, WReachable ask (fun a b => a = 1 ∧ b = 0) P
        (fun z x => z = 1 ∧ x = .idKey 5) w ∧
      w.holds 0 (.idKey 5) ∧ (⟨5⟩ : Message) ∈ w.record.sent := by
  let init : Sphere → Secret → Prop := fun z x => z = 1 ∧ x = .idKey 5
  let s0 : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
  have r0 : WReachable ask (fun a b => a = 1 ∧ b = 0) P init ⟨s0, init, fun _ _ => False⟩ :=
    .start []
  have r1 := WReachable.step r0
    (WStep.leak (z := 1) (z' := 0) (x := .idKey 5) ⟨rfl, rfl⟩ h1 ⟨rfl, rfl⟩)
  have hcan : CanAct s0 5 := .inl (fun ⟨c, hc, _⟩ => by simp [s0] at hc)
  have r2 := WReachable.step r1
    (WStep.act (who := .id 5) (z := 0) (.inr ⟨rfl, rfl⟩) (StepVia.sendOwn hcan))
  exact ⟨_, r2, .inl (.inr ⟨rfl, rfl⟩), List.mem_cons_self⟩

/-- World 1, the same setting: when no sphere is persuadable, no reachable
world has sphere 0 holding identity 5's key. -/
theorem world1_key_stays_put (ask : AskRule) (occ : Sphere → Occupant) {w : World}
    (hr : WReachable ask (fun a b => a = 1 ∧ b = 0) (noneSwayed occ)
      (fun z x => z = 1 ∧ x = .idKey 5) w) : ¬ w.holds 0 (.idKey 5) := by
  intro h
  rcases world1_secrets_stay hr h with h | h
  · exact absurd h.1 (by decide)
  · exact hr.given_givable h

end TrustWeb
