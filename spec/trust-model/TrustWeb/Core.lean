import TrustWeb.Properties

/-!
# The core: six acts and five properties

`CoreStep` keeps six of the model's 22 acts, each exactly as in `Step`, and
`CoreStep.toStep` proves that each is an act of the model. Five properties
are proved as `core_one`, `core_two` with `core_two_design`, `core_three`,
`core_four` and `core_five`; each theorem's doc comment says what it states.
Some parts, `core_five` among them, are about any record, not only the
core's. It is an experiment in reducing the model, not a proposal.
-/

namespace TrustWeb

/-- The six acts of the core, each exactly as in `Step`. -/
inductive CoreStep (ask : AskRule) : State → Party → State → Prop where
  | createOrg {s : State} {o : Org} :
      o ∉ s.orgs →
      CoreStep ask s (.dns o) { s with orgs := o :: s.orgs }
  | entrust {s : State} {key : OrgKey} :
      key ∉ s.held →
      CoreStep ask s (.controller key) { s with held := key :: s.held }
  | registerByRoot {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c.issuer = .root → c.org ∈ s.orgs → Fresh s c.subject →
      Authorised ask s (.root c.org) (.registerOf c.kind) who approvals →
      CoreStep ask s who { s with certs := c :: s.certs }
  | revokeByOrg {s : State} {c : Cert} {who : Party} {approvals : List Key} :
      c ∈ s.certs → Authorised ask s (.root c.org) .revoke who approvals →
      CoreStep ask s who
        { s with revoked := c.subject :: s.revoked,
                 cutOff := s.cutOff.filter (fun k => decide (k ≠ c.subject)) }
  | admitAdmin {s : State} {m : Membership} {kind : Kind} {who : Party} {approvals : List Key} :
      m.team = .admin → Valid s m.org m.member kind →
      Authorised ask s (.team m.org m.team) .admitAdmin who approvals →
      CoreStep ask s who { s with members := m :: s.members }
  | remove {s : State} {m : Membership} {who : Party} {approvals : List Key} :
      Authorised ask s (.team m.org m.team) .remove who approvals →
      (.team m.org m.team ∈ s.held → KeepsAnAdmin s m) →
      CoreStep ask s who
        { s with members := s.members.filter (fun x => decide (x ≠ m)),
                 grants := s.grants.filter (fun g => decide (¬ (g.org = m.org ∧ g.team = m.team ∧ g.subject = m.member))) }

/-- The records the core can reach. -/
inductive CoreReachable (ask : AskRule) : State → Prop where
  | start (policy : List Rule) : CoreReachable ask ⟨[], [], [], [], [], policy, [], [], [], []⟩
  | step {s s' : State} {who : Party} :
      CoreReachable ask s → CoreStep ask s who s' → CoreReachable ask s'

/-- **The core is a part of the full model.** Every act of the core is an act of the model. -/
theorem CoreStep.toStep {ask : AskRule} {s s' : State} {who : Party}
    (h : CoreStep ask s who s') : Step ask s who s' := by
  cases h with
  | createOrg h => exact .createOrg h
  | entrust h => exact .entrust h
  | registerByRoot h1 h2 h3 h4 => exact .registerByRoot h1 h2 h3 h4
  | revokeByOrg h1 h2 => exact .revokeByOrg h1 h2
  | admitAdmin h1 h2 h3 => exact .admitAdmin h1 h2 h3
  | remove h g => exact .remove h g

/-- Every record the core reaches, the model reaches. -/
theorem CoreReachable.toReachable {ask : AskRule} {s : State}
    (h : CoreReachable ask s) : Reachable ask s := by
  induction h with
  | start p => exact .start p
  | step _ hstep ih => exact .step ih hstep.toStep

/-- **In the core every member is directly under its organisation's root.**
Nobody is created by another member, and the only team is the admin team. -/
theorem core_is_flat {ask : AskRule} {s : State} (h : CoreReachable ask s) :
    (∀ c, c ∈ s.certs → c.issuer = .root) ∧ (∀ m, m ∈ s.members → m.team = .admin) := by
  induction h with
  | start _ =>
      refine ⟨?_, ?_⟩
      · intro c hc; cases hc
      · intro m hm; cases hm
  | step _ hstep ih =>
      obtain ⟨hc, hm⟩ := ih
      cases hstep with
      | createOrg _ => exact ⟨hc, hm⟩
      | entrust _ => exact ⟨hc, hm⟩
      | revokeByOrg _ _ => exact ⟨hc, hm⟩
      | registerByRoot hi _ _ _ =>
          refine ⟨?_, hm⟩
          intro c hmem
          rcases List.mem_cons.mp hmem with rfl | h
          · exact hi
          · exact hc c h
      | admitAdmin ht _ _ =>
          refine ⟨hc, ?_⟩
          intro m hmem
          rcases List.mem_cons.mp hmem with rfl | h
          · exact ht
          · exact hm m h
      | remove _ _ =>
          exact ⟨hc, fun m hmem => hm m (List.mem_filter.mp hmem).1⟩

/-! ## The five, in the core -/

/-- **1. An agent does not pass as a person.** In every record the core
reaches, no identity is valid as an agent and as a person; and in one core
act that makes someone newly hold a chain of person certificates, the act
added one person certificate, issued by the root or by a valid person. That agents
cannot give a person's approval is `agents_cannot_approve_as_person`, which
holds in any record. -/
theorem core_one (ask : AskRule) :
    (∀ {s : State}, CoreReachable ask s → ∀ {o o' : Org} {k : Key},
        Valid s o k .agent → Valid s o' k .person → False) ∧
    (∀ {s s' : State} {who : Party} {o : Org} {k : Key},
        CoreStep ask s who s' → Person s' o k → ¬ Person s o k →
        ∃ c, s'.certs = c :: s.certs ∧ c.kind = .person ∧
          (c.issuer = .root ∨ ∃ p, c.issuer = .member p ∧ Valid s c.org p .person)) :=
  ⟨fun hr _ _ _ ha hp => one_kind hr.toReachable.oneCertEach ha hp,
   fun hstep hnew hold => new_person_is_vouched_for hstep.toStep hnew hold⟩

/-- **2. Where its key is not with a key holder, whoever controls it ends an
admin in one act.** In the core: when the
admin team's key is not with a key holder, whoever controls it can end any
admin by one act; when the root key is not with a key holder, whoever
controls it can end any admin by one act. -/
theorem core_two (ask : AskRule) {s : State} {o : Org} :
    (OrgKey.team o .admin ∉ s.held → ∀ b : Key,
        ∃ s', CoreStep ask s (.controller (.team o .admin)) s' ∧ ¬ Admin s' o b) ∧
    (OrgKey.root o ∉ s.held → ∀ {b : Key}, Admin s o b →
        ∃ s', CoreStep ask s (.controller (.root o)) s' ∧ ¬ Admin s' o b) := by
  refine ⟨?_, ?_⟩
  · intro hfree b
    refine ⟨_, CoreStep.remove (m := ⟨o, .admin, b⟩) (approvals := []) (.inl ⟨hfree, rfl⟩)
      (fun h => absurd h hfree), ?_⟩
    intro ⟨hm, _⟩
    exact not_mem_filter_ne hm
  · intro hfree b hb
    obtain ⟨_, kind, hv⟩ := hb
    obtain ⟨c, hc, hcs, _, hco⟩ := hv.cert
    subst hco
    subst hcs
    refine ⟨_, CoreStep.revokeByOrg (approvals := []) hc (.inl ⟨hfree, rfl⟩), ?_⟩
    intro ⟨_, _, hv'⟩
    exact revoked_not_valid (List.mem_cons_self) hv'

/-- **2, the design.** In the core under the admin rule: when the admin
team's key is with a key holder, an admin with approvals that satisfy the
policy for a removal can end any other admin by one act. -/
theorem core_two_design {s : State} {o : Org}
    (hheld : OrgKey.team o .admin ∈ s.held) {a : Key} (ha : Admin s o a)
    {approvals : List Key} (happ : Approved s o .remove approvals) {b : Key} (hne : a ≠ b) :
    ∃ s', CoreStep adminRule s (.id a) s' ∧ ¬ Admin s' o b := by
  refine ⟨_, CoreStep.remove (m := ⟨o, .admin, b⟩) (approvals := approvals)
    (.inr ⟨hheld, a, rfl, ha, happ⟩) (fun _ _ => ⟨a, hne, ha⟩), ?_⟩
  intro ⟨hm, _⟩
  exact not_mem_filter_ne hm

/-- **3, the part the core carries: admins have a chain back to a root.**
Every admin has certificates leading to its organisation's root; and in one
core act, a new admin-team certificate is added only when whoever controls
the admin team's key asks, or an identity the rule lets ask. Whether that
identity has a chain depends on the rule: the rules in this model require a
valid member, a rule that let anyone ask would not. -/
theorem core_three (ask : AskRule) :
    (∀ {s : State} {o : Org} {k : Key}, Admin s o k → ChainToRoot s o k) ∧
    (∀ {s s' : State} {who : Party} {m : Membership},
        CoreStep ask s who s' → m ∈ s'.members → m ∉ s.members → m.team = .admin →
        who = .controller (.team m.org .admin) ∨ ∃ a, who = .id a ∧ ask s m.org .admitAdmin a) :=
  ⟨fun ha => admin_has_chain_to_root ha,
   fun hstep hnew hold hteam => new_admin_needs_controller_or_asker hstep.toStep hnew hold hteam⟩

/-- **4. A revoked member is not valid, not an admin, and cannot act in a
team.** In every record the core reaches. Whether it can ask a key holder
depends on the rule, as in 3. -/
theorem core_four {ask : AskRule} {s : State} (hr : CoreReachable ask s) {k : Key}
    (hrev : k ∈ s.revoked) :
    (∀ o kind, ¬ Valid s o k kind) ∧ (∀ o, ¬ Admin s o k) ∧ (∀ o t, ¬ InTeam s o t k) :=
  ⟨fun _ _ => revoked_not_valid hrev,
   (revoked_has_no_authority hr.toReachable.revokedAreRegistered hrev).1,
   (revoked_has_no_authority hr.toReachable.revokedAreRegistered hrev).2⟩

/-- **5. An organisation with no policy requires no approval.** If no rule of
the policy is for `o`, every kind of act is approved for `o` with no
approvals. -/
theorem core_five {s : State} {o : Org}
    (h : ∀ r, r ∈ s.policy → r.org ≠ o) (act : ActKind) : Approved s o act [] :=
  no_policy_no_approval h act

end TrustWeb
