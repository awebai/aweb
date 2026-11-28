import TrustWeb.Properties

/-!
# The core: six acts and five properties

An experiment: six of the acts (`CoreStep`), and results proved for them.
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

/-- Every act of the core is an act of the model. -/
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

/-- In every record the core reaches, every identity certificate is issued by
the root and every team certificate is of an admin team. -/
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

/-- In every record the core reaches, no identity is valid as an agent in one
organisation and as a person in any; and in one core act that makes `k` newly
hold a chain of person certificates in `o`, the act added one person
certificate, issued by the root or by a member that was a valid person of the
certificate's organisation before the act. That approvals with no valid person do not satisfy
a rule asking for any person is `agents_cannot_approve_as_person`, which holds
in any record. -/
theorem core_one (ask : AskRule) :
    (∀ {s : State}, CoreReachable ask s → ∀ {o o' : Org} {k : Key},
        Valid s o k .agent → Valid s o' k .person → False) ∧
    (∀ {s s' : State} {who : Party} {o : Org} {k : Key},
        CoreStep ask s who s' → Person s' o k → ¬ Person s o k →
        ∃ c, s'.certs = c :: s.certs ∧ c.kind = .person ∧
          (c.issuer = .root ∨ ∃ p, c.issuer = .member p ∧ Valid s c.org p .person)) :=
  ⟨fun hr _ _ _ ha hp => one_kind hr.toReachable.oneCertEach ha hp,
   fun hstep hnew hold => new_person_is_vouched_for hstep.toStep hnew hold⟩

/-- In the core: if the admin team's key of `o` is not with a key holder, then
for any identity `b` there is a core act that whoever controls that key asks
for, after which `b` is not an admin of `o`; and if `o`'s root key is not with
a key holder, then for any admin `b` of `o` there is a core act that whoever
controls the root key asks for, after which `b` is not an admin of `o`. -/
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

/-- In the core under the admin rule: if the admin team's key of `o` is with a
key holder, `a` is an admin of `o`, the approvals satisfy `o`'s policy for a
removal, and `b` is not `a`, there is a core act that `a` asks for, after
which `b` is not an admin of `o`. -/
theorem core_two_design {s : State} {o : Org}
    (hheld : OrgKey.team o .admin ∈ s.held) {a : Key} (ha : Admin s o a)
    {approvals : List Key} (happ : Approved s o .remove approvals) {b : Key} (hne : a ≠ b) :
    ∃ s', CoreStep adminRule s (.id a) s' ∧ ¬ Admin s' o b := by
  refine ⟨_, CoreStep.remove (m := ⟨o, .admin, b⟩) (approvals := approvals)
    (.inr ⟨hheld, a, rfl, ha, happ⟩) (fun _ _ => ⟨a, hne, ha⟩), ?_⟩
  intro ⟨hm, _⟩
  exact not_mem_filter_ne hm

/-- Every admin of `o` has certificates leading to `o`'s root; and in one core
act that adds a certificate of an admin team, the asker is whoever controls
that admin team's key, or an identity the rule lets ask for admitting an admin
in that organisation. The three rules let only valid members ask (`builtRule`,
`adminRule`, `teamRule`); a rule that let anyone ask would not. -/
theorem core_three (ask : AskRule) :
    (∀ {s : State} {o : Org} {k : Key}, Admin s o k → ChainToRoot s o k) ∧
    (∀ {s s' : State} {who : Party} {m : Membership},
        CoreStep ask s who s' → m ∈ s'.members → m ∉ s.members → m.team = .admin →
        who = .controller (.team m.org .admin) ∨ ∃ a, who = .id a ∧ ask s m.org .admitAdmin a) :=
  ⟨fun ha => admin_has_chain_to_root ha,
   fun hstep hnew hold hteam => new_admin_needs_controller_or_asker hstep.toStep hnew hold hteam⟩

/-- In every record the core reaches, a revoked identity is not valid in any
organisation, is not an admin of any, and cannot act in any team. -/
theorem core_four {ask : AskRule} {s : State} (hr : CoreReachable ask s) {k : Key}
    (hrev : k ∈ s.revoked) :
    (∀ o kind, ¬ Valid s o k kind) ∧ (∀ o, ¬ Admin s o k) ∧ (∀ o t, ¬ InTeam s o t k) :=
  ⟨fun _ _ => revoked_not_valid hrev,
   (revoked_has_no_authority hr.toReachable.revokedAreRegistered hrev).1,
   (revoked_has_no_authority hr.toReachable.revokedAreRegistered hrev).2⟩

/-- If no rule of the policy is for `o`, every kind of act is approved for `o`
with no approvals. -/
theorem core_five {s : State} {o : Org}
    (h : ∀ r, r ∈ s.policy → r.org ≠ o) (act : ActKind) : Approved s o act [] :=
  no_policy_no_approval h act

end TrustWeb
