import TrustWeb.Spheres

/-!
# Trust spheres: approvals, named invitations, and admins

Three additions to the sphere layer, none of which changes the model:
`StepVia`, the model's acts with their approvals visible, proved to agree
with `Step`; a sphere layer in which an adversarial sphere's act counts an
approval only when it is available to that sphere; a planned step in which
an invitation names the identity that joins; and results that join the
model's rules to where keys are held.
-/

namespace TrustWeb

/-- `StepVia ask s who approvals s'`: the acts of `Step`, each with the approvals
it is accepted with; an act with no `Authorised` premise carries none. -/
inductive StepVia (ask : AskRule) : State → Party → List Key → State → Prop where
  | createOrg {s : State} {o : Org} :
      o ∉ s.orgs →
      StepVia ask s (.dns o) [] { s with orgs := o :: s.orgs }
  | replaceRoot {s : State} {o : Org} :
      o ∈ s.orgs →
      StepVia ask s (.dns o) []
        { s with
          revoked := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.revoked,
          cutOff := ((s.certs.filter (fun c => decide (c.org = o ∧ c.subject ∉ s.revoked))).map
            (·.subject)) ++ s.cutOff,
          held := s.held.filter (fun k => decide (k ≠ .root o)) }
  | readmitByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → c.issuer = .root → c.subject ∈ s.cutOff →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      StepVia ask s who approvals
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | readmitByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → c.subject ∈ s.cutOff → Valid s c.org p pk →
      StepVia ask s (.id p) []
        { s with revoked := s.revoked.filter (fun k => decide (k ≠ c.subject)),
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | release {s : State} {key : OrgKey} {who : Party} {approvals : List Key} :
      key ∈ s.held → Authorised ask s key .release who approvals →
      StepVia ask s who approvals { s with held := s.held.filter (fun k => decide (k ≠ key)) }
  | rekeyTeam {s : State} {o : Org} {t : Team} {keep : List Key} {who : Party}
      {approvals : List Key} :
      Authorised ask s (.root o) .rekey who approvals →
      (.root o ∈ s.held → t = .admin → ∃ k, k ∈ keep ∧ Admin s o k) →
      StepVia ask s who approvals
        { s with held := s.held.filter (fun k => decide (k ≠ .team o t)),
                 members := s.members.filter
                   (fun m => decide (¬ (m.org = o ∧ m.team = t) ∨ m.member ∈ keep)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = o ∧ g.team = t))) }
  | entrust {s : State} {key : OrgKey} :
      key ∉ s.held →
      StepVia ask s (.controller key) [] { s with held := key :: s.held }
  | registerByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c.issuer = .root → c.org ∈ s.orgs → Fresh s c.subject →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      StepVia ask s who approvals { s with certs := c :: s.certs }
  | registerByParent {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c.issuer = .member p → Fresh s c.subject → Valid s c.org p pk → MayIssue pk c.kind →
      StepVia ask s (.id p) [] { s with certs := c :: s.certs }
  | revokeSelf {s : State} {c : Cert} :
      c ∈ s.certs →
      StepVia ask s (.id c.subject) []
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | revokeChild {s : State} {c : Cert} {p : Key} {pk : Kind} :
      c ∈ s.certs → c.issuer = .member p → Valid s c.org p pk →
      StepVia ask s (.id p) []
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | revokeByOrg {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → Authorised ask s (.root c.org) .revoke who approvals →
      StepVia ask s who approvals
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | admit {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      m.team ≠ .admin → Authorised ask s (.team m.org m.team) .admit who approvals →
      OneTeamIfLocal s m.member →
      StepVia ask s who approvals { s with members := m :: s.members }
  | admitAdmin {s : State} {m : Membership} {kind : Kind} {who : Party} {approvals : List Key} :
      m.team = .admin → Valid s m.org m.member kind →
      Authorised ask s (.team m.org m.team) .admitAdmin who approvals →
      StepVia ask s who approvals { s with members := m :: s.members }
  | remove {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      Authorised ask s (.team m.org m.team) .remove who approvals →
      (.team m.org m.team ∈ s.held → KeepsAnAdmin s m) →
      StepVia ask s who approvals
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  | leave {s : State} {m : Membership} :
      m ∈ s.members → .team m.org m.team ∈ s.held → KeepsAnAdmin s m →
      StepVia ask s (.id m.member) []
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }
  | invite {s : State} {i : Invite} {who : Party} {approvals : List Key} :
      i.team ≠ .admin → Authorised ask s (.team i.org i.team) .admit who approvals →
      (∀ j, j ∈ s.invites → j.token ≠ i.token) →
      StepVia ask s who approvals { s with invites := i :: s.invites }
  | redeem {s : State} {i : Invite} {k : Key} :
      i ∈ s.invites → i.team ≠ .admin → OneTeamIfLocal s k →
      StepVia ask s (.bearer i.token) []
        { s with members := ⟨i.org, i.team, k⟩ :: s.members,
                 invites := s.invites.filter (fun x => decide (x ≠ i)) }
  | mintGrant {s : State} {g : Grant} :
      InTeam s g.org g.team g.subject → (∀ g', g' ∈ s.grants → g'.session ≠ g.session) →
      StepVia ask s (.id g.subject) [] { s with grants := g :: s.grants }
  | revokeGrant {s : State} {g : Grant} :
      g ∈ s.grants →
      StepVia ask s (.id g.subject) [] { s with grants := s.grants.filter (fun x => decide (x ≠ g)) }
  | sendOwn {s : State} {k : Key} :
      CanAct s k →
      StepVia ask s (.id k) [] { s with sent := ⟨k⟩ :: s.sent }
  | sendGrant {s : State} {g : Grant} :
      GrantLive s g → g.maySend = true →
      StepVia ask s (.session g.session) [] { s with sent := ⟨g.subject⟩ :: s.sent }

/-- Every act of `StepVia` is an act of `Step`. -/
theorem StepVia.toStep {ask : AskRule} {s s' : State} {who : Party} {approvals : List Key}
    (h : StepVia ask s who approvals s') : Step ask s who s' := by
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

/-- Every act of `Step` is an act of `StepVia` with some approvals. -/
theorem Step.toVia {ask : AskRule} {s s' : State} {who : Party}
    (h : Step ask s who s') : ∃ approvals, StepVia ask s who approvals s' := by
  cases h with
  | createOrg h0 => exact ⟨_, .createOrg h0⟩
  | replaceRoot h0 => exact ⟨_, .replaceRoot h0⟩
  | readmitByRoot h0 h1 h2 h3 => exact ⟨_, .readmitByRoot h0 h1 h2 h3⟩
  | readmitByParent h0 h1 h2 h3 => exact ⟨_, .readmitByParent h0 h1 h2 h3⟩
  | release h0 h1 => exact ⟨_, .release h0 h1⟩
  | rekeyTeam h0 h1 => exact ⟨_, .rekeyTeam h0 h1⟩
  | entrust h0 => exact ⟨_, .entrust h0⟩
  | registerByRoot h0 h1 h2 h3 => exact ⟨_, .registerByRoot h0 h1 h2 h3⟩
  | registerByParent h0 h1 h2 h3 => exact ⟨_, .registerByParent h0 h1 h2 h3⟩
  | revokeSelf h0 => exact ⟨_, .revokeSelf h0⟩
  | revokeChild h0 h1 h2 => exact ⟨_, .revokeChild h0 h1 h2⟩
  | revokeByOrg h0 h1 => exact ⟨_, .revokeByOrg h0 h1⟩
  | admit h0 h1 h2 => exact ⟨_, .admit h0 h1 h2⟩
  | admitAdmin h0 h1 h2 => exact ⟨_, .admitAdmin h0 h1 h2⟩
  | remove h0 h1 => exact ⟨_, .remove h0 h1⟩
  | leave h0 h1 h2 => exact ⟨_, .leave h0 h1 h2⟩
  | invite h0 h1 h2 => exact ⟨_, .invite h0 h1 h2⟩
  | redeem h0 h1 h2 => exact ⟨_, .redeem h0 h1 h2⟩
  | mintGrant h0 h1 => exact ⟨_, .mintGrant h0 h1⟩
  | revokeGrant h0 => exact ⟨_, .revokeGrant h0⟩
  | sendOwn h0 => exact ⟨_, .sendOwn h0⟩
  | sendGrant h0 h1 => exact ⟨_, .sendGrant h0 h1⟩

/-- `Available Talk P w z k`: sphere `z` holds `k`'s identity key, or a
persuadable sphere that holds it talks to `z`. -/
def Available (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop) (w : World)
    (z : Sphere) (k : Key) : Prop :=
  w.holds z (.idKey k) ∨ ∃ z', w.holds z' (.idKey k) ∧ P z' ∧ Talk z' z

/-- `AStep ask Talk P Adv w w'`: either an act of `StepVia`, asked for by a
party whose secret sphere `z` holds, takes the record from `w`'s to `w'`'s,
and if `z` is adversarial every approval of the act is available to `z`; or
a persuadable sphere gives one of its secrets to a sphere it talks to. -/
inductive AStep (ask : AskRule) (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop)
    (Adv : Sphere → Prop) : World → World → Prop where
  | act {w : World} {s' : State} {who : Party} {z : Sphere} {approvals : List Key} :
      w.holds z who.secret → StepVia ask w.record who approvals s' →
      (Adv z → ∀ k, k ∈ approvals → Available Talk P w z k) →
      AStep ask Talk P Adv w ⟨s', w.holds⟩
  | leak {w : World} {z z' : Sphere} {x : Secret} :
      w.holds z x → P z → Talk z z' →
      AStep ask Talk P Adv w ⟨w.record, fun y v => w.holds y v ∨ (y = z' ∧ v = x)⟩

/-- The worlds reached by such steps from a record with nothing in it but a
policy and the placement `init`. -/
inductive AReachable (ask : AskRule) (Talk : Sphere → Sphere → Prop) (P : Sphere → Prop)
    (Adv : Sphere → Prop) (init : Sphere → Secret → Prop) : World → Prop where
  | start (policy : List Rule) :
      AReachable ask Talk P Adv init ⟨⟨[], [], [], [], [], policy, [], [], [], []⟩, init⟩
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

/-- In every world this layer reaches, if sphere `z` holds secret `x`, some
sphere held `x` in the initial placement and `x` flows from it to `z`. -/
theorem AReachable.held_secret_flowed {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk P Adv init w) {z : Sphere} {x : Secret} (hz : w.holds z x) :
    ∃ z0, init z0 x ∧ Flows Talk P z0 z := by
  induction hr generalizing z x with
  | start _ => exact ⟨z, hz, .refl z⟩
  | step _ hstep ih =>
      cases hstep with
      | act _ _ _ => exact ih hz
      | leak hzx hp ht =>
          rcases hz with hz | ⟨rfl, rfl⟩
          · exact ih hz
          · obtain ⟨z0, h0, hf⟩ := ih hzx
            exact ⟨z0, h0, .step hf hp ht⟩

/-- In every world this layer reaches, if `k`'s approval is available to
sphere `z`, some sphere `z0` held `k`'s identity key in the initial
placement, and `z0` is `z` or is persuadable. -/
theorem available_approval_came_from {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {P Adv : Sphere → Prop} {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk P Adv init w) {z : Sphere} {k : Key}
    (ha : Available Talk P w z k) : ∃ z0, init z0 (.idKey k) ∧ (z0 = z ∨ P z0) := by
  rcases ha with hz | ⟨z', hz', hp, _⟩
  · obtain ⟨z0, h0, hf⟩ := hr.held_secret_flowed hz
    by_cases h : z0 = z
    · exact ⟨z0, h0, .inl h⟩
    · exact ⟨z0, h0, .inr (hf.source_persuadable h)⟩
  · obtain ⟨z0, h0, hf⟩ := hr.held_secret_flowed hz'
    by_cases h : z0 = z'
    · exact ⟨z0, h0, .inr (h ▸ hp)⟩
    · exact ⟨z0, h0, .inr (hf.source_persuadable h)⟩

/-- World 2. In every world this layer reaches with agents' spheres
persuadable, if `z` is adversarial and every sphere that held `k`'s identity
key in the initial placement is neither an agent's nor adversarial, `k`'s
approval is not available to `z`. -/
theorem world2_approval_not_available {ask : AskRule} {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {Adv : Sphere → Prop} {init : Sphere → Secret → Prop}
    {w : World} (hr : AReachable ask Talk (agentsSwayed occ) Adv init w) {z : Sphere}
    (hadv : Adv z) {k : Key}
    (hk : ∀ z0, init z0 (.idKey k) → occ z0 ≠ .agent ∧ ¬ Adv z0) :
    ¬ Available Talk (agentsSwayed occ) w z k := by
  intro ha
  obtain ⟨z0, h0, h | h⟩ := available_approval_came_from hr ha
  · exact (hk z0 h0).2 (h ▸ hadv)
  · exact (hk z0 h0).1 h

/-- World 2. In every world this layer reaches with agents' spheres
persuadable, if `z` is adversarial, every approval in `approvals` is available
to `z`, and every sphere that held the identity key of a valid person of `o`
in the initial placement is neither an agent's nor adversarial, the approvals
do not satisfy a rule of `o` asking for any person. -/
theorem world2_adversary_has_no_person_approval {ask : AskRule}
    {Talk : Sphere → Sphere → Prop} {occ : Sphere → Occupant} {Adv : Sphere → Prop}
    {init : Sphere → Secret → Prop} {w : World}
    (hr : AReachable ask Talk (agentsSwayed occ) Adv init w) {z : Sphere} (hadv : Adv z)
    {approvals : List Key}
    (hall : ∀ k, k ∈ approvals → Available Talk (agentsSwayed occ) w z k) {o : Org}
    (hp : ∀ p, Valid w.record o p .person → ∀ z0, init z0 (.idKey p) →
      occ z0 ≠ .agent ∧ ¬ Adv z0) :
    ¬ Satisfies w.record o approvals .anyPerson := by
  rintro ⟨p, hmem, hv⟩
  exact world2_approval_not_available hr hadv (hp p hv) (hall p hmem)

/-- World 3. If sphere `z'` holds `k`'s identity key, a person occupies `z'`,
and `z'` talks to `z`, `k`'s approval is available to `z` when agents' and
persons' spheres are persuadable. -/
theorem world3_persuaded_person_approves {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {w : World} {z z' : Sphere} {k : Key}
    (hz' : w.holds z' (.idKey k)) (hperson : occ z' = .person) (ht : Talk z' z) :
    Available Talk (agentsAndPersonsSwayed occ) w z k :=
  .inr ⟨z', hz', .inr hperson, ht⟩

/-- World 2. In every world this layer reaches with agents' spheres
persuadable, if sphere `z` is adversarial, every approval in `approvals` is
available to `z`, `key` is held, the policy has a rule asking any person to
approve this kind of act in `key`'s organisation, and every sphere that held
the identity key of a valid person of that organisation in the initial
placement is neither an agent's nor adversarial, `Authorised` does not hold
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
    (hp : ∀ p, Valid w.record key.org p .person → ∀ z0, init z0 (.idKey p) →
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
key was held by an agent's sphere in the initial placement: contradiction. -/
theorem world2_agent_sphere_adds_no_admin {Talk : Sphere → Sphere → Prop}
    {occ : Sphere → Occupant} {init : Sphere → Secret → Prop} {w : World}
    (hr : WReachable adminRule Talk (agentsSwayed occ) init w) {z : Sphere}
    (hagent : occ z = .agent) {who : Party} {s' : State}
    (hz : w.holds z who.secret) (hstep : Step adminRule w.record who s') {m : Membership}
    (hnew : m ∈ s'.members) (hold : m ∉ w.record.members) (hteam : m.team = .admin)
    (hkey : ∀ z0, init z0 (.orgKey (.team m.org .admin)) → occ z0 ≠ .agent)
    (hadmins : ∀ a, Admin w.record m.org a → ∀ z0, init z0 (.idKey a) → occ z0 ≠ .agent) :
    False := by
  rcases new_admin_needs_a_held_key hz hstep hnew hold hteam with h | ⟨a, h, ha⟩
  · exact hkey z (world2_non_agent_secret_stays hr hkey h) hagent
  · exact hadmins a ha z (world2_non_agent_secret_stays hr (hadmins a ha) h) hagent

end TrustWeb
