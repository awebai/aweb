import TrustWeb.Model

/-!
# The trust web: what is proved

Each theorem has a one-sentence reading above it. `lake build` checks them all.
-/

namespace TrustWeb

/-! ## Helping facts -/

theorem Person.mono {s t : State} {o : Org} (h : ∀ c, c ∈ s.certs → c ∈ t.certs) {k : Key}
    (hp : Person s o k) : Person t o k := by
  induction hp with
  | byRoot hc ho hk hi hs => exact .byRoot (h _ hc) ho hk hi hs
  | byPerson hc ho hk hi hs _ ih => exact .byPerson (h _ hc) ho hk hi hs ih

/-- Being a person depends only on the certificates. -/
theorem Person.of_certs_eq {s t : State} {o : Org} {k : Key} (hp : Person s o k)
    (h : s.certs = t.certs) : Person t o k :=
  hp.mono (by intro c hc; rw [← h]; exact hc)

/-- A person holds a person certificate of their organisation. -/
theorem Person.cert {s : State} {o : Org} {k : Key} (hp : Person s o k) :
    ∃ c, c ∈ s.certs ∧ c.subject = k ∧ c.kind = .person ∧ c.org = o := by
  cases hp with
  | byRoot hc ho hk _ hs => exact ⟨_, hc, hs, hk, ho⟩
  | byPerson hc ho hk _ hs _ => exact ⟨_, hc, hs, hk, ho⟩

/-- A valid member holds a certificate of its kind and organisation. -/
theorem Valid.cert {s : State} {o : Org} {k : Key} {kind : Kind} (hv : Valid s o k kind) :
    ∃ c, c ∈ s.certs ∧ c.subject = k ∧ c.kind = kind ∧ c.org = o := by
  cases hv with
  | person hp _ => exact hp.cert
  | agentOfRoot hc ho hk _ hs _ => exact ⟨_, hc, hs, hk, ho⟩
  | agentOf hc ho hk _ hs _ _ => exact ⟨_, hc, hs, hk, ho⟩

/-- Registering an agent certificate makes nobody a person. -/
theorem Person.of_cons_agent {s : State} {o : Org} {c : Cert} (hc : c.kind = .agent) {k : Key}
    (hp : Person { s with certs := c :: s.certs } o k) : Person s o k := by
  induction hp with
  | byRoot hm ho hk hi hs =>
      rcases List.mem_cons.mp hm with rfl | hm
      · rw [hc] at hk; cases hk
      · exact .byRoot hm ho hk hi hs
  | byPerson hm ho hk hi hs _ ih =>
      rcases List.mem_cons.mp hm with rfl | hm
      · rw [hc] at hk; cases hk
      · exact .byPerson hm ho hk hi hs ih

theorem not_mem_filter_ne {m : Membership} {l : List Membership} :
    m ∉ l.filter (fun x => decide (x ≠ m)) := by
  intro h
  have := (List.mem_filter.mp h).2
  simp at this

/-- More certificates and no more revocations keep a valid member valid. -/
theorem Valid.mono {s t : State} (hc : ∀ c, c ∈ s.certs → c ∈ t.certs)
    (hr : ∀ k, k ∈ t.revoked → k ∈ s.revoked) {o : Org} {k : Key} {kind : Kind}
    (hv : Valid s o k kind) : Valid t o k kind := by
  induction hv with
  | person hp hn => exact .person (hp.mono hc) (fun h => hn (hr _ h))
  | agentOfRoot hm ho hk hi hs hn =>
      exact .agentOfRoot (hc _ hm) ho hk hi hs (fun h => hn (hr _ h))
  | agentOf hm ho hk hi hs hn _ ih =>
      exact .agentOf (hc _ hm) ho hk hi hs (fun h => hn (hr _ h)) ih

/-! ## An agent can never pass as a person -/

/-- **A member has one kind.** No identity is valid as an agent and as a person. -/
theorem one_kind {s : State} (h1 : OneCertEach s) {o o' : Org} {k : Key}
    (ha : Valid s o k .agent) (hp : Valid s o' k .person) : False := by
  obtain ⟨c, hc, hcs, hck, _⟩ := ha.cert
  obtain ⟨d, hd, hds, hdk, _⟩ := hp.cert
  have := h1 c hc d hd (hcs.trans hds.symm)
  subst this
  rw [hck] at hdk; cases hdk

/-- **In one act, a new person's certificate is issued by the root or by a
valid person.** If an accepted act makes someone hold a standing person
certificate, the act registered that certificate, and its issuer is the root
or a member who is a valid person, never an agent. This is about who signs,
not about who asked. -/
theorem new_person_is_vouched_for {ask : AskRule} {s s' : State} {who : Party} {o : Org} {k : Key}
    (hstep : Step ask s who s') (hnew : Person s' o k) (hold : ¬ Person s o k) :
    ∃ c, s'.certs = c :: s.certs ∧ c.kind = .person ∧
      (c.issuer = .root ∨ ∃ p, c.issuer = .member p ∧ Valid s c.org p .person) := by
  cases hstep with
  | createOrg _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | entrust _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeSelf _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeChild _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeByOrg _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | admit _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | admitAdmin _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | remove _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | leave _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | invite _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | redeem _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | mintGrant _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeGrant _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | release _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | replaceRoot _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | readmitByRoot _ _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | readmitByParent _ _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | sendOwn _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | sendGrant _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | registerByRoot hi ho hf hauth =>
      rename_i c approvals
      cases hkind : c.kind with
      | agent => exact absurd (Person.of_cons_agent hkind hnew) hold
      | person => exact ⟨c, rfl, hkind, .inl hi⟩
  | registerByParent hi hf hv hmay =>
      rename_i c p pk
      cases hkind : c.kind with
      | agent => exact absurd (Person.of_cons_agent hkind hnew) hold
      | person =>
          rcases hmay with rfl | h
          · exact ⟨c, rfl, hkind, .inr ⟨p, hi, hv⟩⟩
          · rw [hkind] at h; cases h

/-- **Certificates that are neither root-issued nor issued by someone already
a person make nobody a person.** Add any such certificates to the record:
nobody becomes a person. A certificate issued by a person does make one. -/
theorem no_person_from_outside {s : State} {o : Org} {extra : List Cert}
    (hextra : ∀ c, c ∈ extra →
      c.issuer ≠ .root ∧ ∀ p, c.issuer = .member p → ¬ Person s c.org p)
    {k : Key} (hp : Person { s with certs := extra ++ s.certs } o k) : Person s o k := by
  induction hp with
  | byRoot hm ho hk hi hs =>
      rcases List.mem_append.mp hm with he | hm
      · exact absurd hi (hextra _ he).1
      · exact .byRoot hm ho hk hi hs
  | byPerson hm ho hk hi hs _ ih =>
      rcases List.mem_append.mp hm with he | hm
      · exact absurd (ho ▸ ih) ((hextra _ he).2 _ hi)
      · exact .byPerson hm ho hk hi hs ih

/-- **Agents cannot give a person's approval.** If none of the approvers is a
valid person, a rule asking for a person is not satisfied. -/
theorem agents_cannot_approve_as_person {s : State} {o : Org} {approvals : List Key}
    (h : ∀ k, k ∈ approvals → ¬ Valid s o k .person) :
    ¬ Satisfies s o approvals .anyPerson := by
  intro ⟨k, hk, hv⟩
  exact h k hk hv

/-! ## Authority comes from the root -/

theorem Person.chainToRoot {s : State} {o : Org} {k : Key} (hp : Person s o k) :
    ChainToRoot s o k := by
  induction hp with
  | byRoot hc ho _ hi hs => exact .root hc ho hi hs
  | byPerson hc ho _ hi hs _ ih => exact .link hc ho hi hs ih

/-- **Every valid member has certificates leading to its organisation's root.** -/
theorem valid_has_chain_to_root {s : State} {o : Org} {k : Key} {kind : Kind}
    (hv : Valid s o k kind) : ChainToRoot s o k := by
  induction hv with
  | person hp _ => exact hp.chainToRoot
  | agentOfRoot hc ho _ hi hs _ => exact .root hc ho hi hs
  | agentOf hc ho _ hi hs _ _ ih => exact .link hc ho hi hs ih

/-- **Every admin has certificates leading to its organisation's root.** -/
theorem admin_has_chain_to_root {s : State} {o : Org} {k : Key}
    (ha : Admin s o k) : ChainToRoot s o k := by
  obtain ⟨_, _, hv⟩ := ha
  exact valid_has_chain_to_root hv

/-- **Only whoever controls the admin team's key, or someone the rule lets
ask, admits an admin.** An invitation never does. -/
theorem new_admin_needs_controller_or_asker {ask : AskRule} {s s' : State} {who : Party}
    {m : Membership}
    (hstep : Step ask s who s') (hnew : m ∈ s'.members) (hold : m ∉ s.members)
    (hteam : m.team = .admin) :
    who = .controller (.team m.org .admin) ∨ ∃ a, who = .id a ∧ ask s m.org .admitAdmin a := by
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
      · rcases hauth with ⟨_, hr⟩ | ⟨_, a, ha, hask, _⟩
        · rw [hteam] at hr; exact .inl hr
        · exact .inr ⟨a, ha, hask⟩
      · exact absurd h hold

/-! ## Revoking and removing -/

/-- **A revoked identity is not a valid member of any organisation.** -/
theorem revoked_not_valid {s : State} {o : Org} {k : Key} {kind : Kind}
    (hr : k ∈ s.revoked) : ¬ Valid s o k kind := by
  intro hv
  cases hv with
  | person _ hn => exact hn hr
  | agentOfRoot _ _ _ _ _ hn => exact hn hr
  | agentOf _ _ _ _ _ hn _ => exact hn hr

/-- **A revoked identity has no authority.** It is not an admin anywhere and
cannot act in any team. -/
theorem revoked_has_no_authority {s : State} (hrr : RevokedAreRegistered s) {k : Key}
    (hr : k ∈ s.revoked) : (∀ o, ¬ Admin s o k) ∧ (∀ o t, ¬ InTeam s o t k) := by
  refine ⟨?_, ?_⟩
  · intro o ⟨_, _, hv⟩
    exact revoked_not_valid hr hv
  · intro o t ⟨_, h⟩
    rcases h with hnr | ⟨_, _, hv⟩
    · exact hnr (hrr k hr)
    · exact revoked_not_valid hr hv

/-- **A revoked identity cannot act.** In a reachable record it is registered,
so it is not among those that can act: it sends nothing with its own key and
no grant on it is live. -/
theorem revoked_cannot_act {s : State} (hrr : RevokedAreRegistered s) {k : Key}
    (hr : k ∈ s.revoked) : ¬ CanAct s k := by
  intro h
  rcases h with hnr | ⟨_, _, hv⟩
  · exact hnr (hrr k hr)
  · exact revoked_not_valid hr hv

/-- **An agent needs a valid parent.** If the member that issued an agent is
not valid, the agent is not valid. -/
theorem agent_needs_valid_parent {s : State} (h1 : OneCertEach s) {c : Cert} {p : Key}
    (hc : c ∈ s.certs) (hkind : c.kind = .agent) (hiss : c.issuer = .member p)
    (hparent : ∀ o pk, ¬ Valid s o p pk) (o : Org) (kind : Kind) :
    ¬ Valid s o c.subject kind := by
  intro hv
  cases hv with
  | person hp _ =>
      obtain ⟨d, hd, hds, hdk, _⟩ := hp.cert
      have := h1 d hd c hc hds
      subst this
      rw [hkind] at hdk; cases hdk
  | agentOfRoot hd _ _ hdi hds _ =>
      have := h1 _ hd c hc hds
      subst this
      rw [hiss] at hdi; cases hdi
  | agentOf hd _ _ hdi hds _ hpv =>
      have := h1 _ hd c hc hds
      subst this
      rw [hiss] at hdi
      cases hdi
      exact hparent _ _ hpv

/-- **Revoking a member ends the agents it issued.** -/
theorem revoking_parent_ends_agent {s : State} (h1 : OneCertEach s) {c : Cert} {p : Key}
    (hc : c ∈ s.certs) (hkind : c.kind = .agent) (hiss : c.issuer = .member p)
    (hr : p ∈ s.revoked) (o : Org) (kind : Kind) : ¬ Valid s o c.subject kind :=
  agent_needs_valid_parent h1 hc hkind hiss (fun _ _ => revoked_not_valid hr) o kind

/-- **A person outlasts whoever invited them.** Revoking someone else leaves a
valid person valid. -/
theorem person_survives_others {s : State} {o : Org} {k j : Key}
    (hv : Valid s o k .person) (hne : k ≠ j) :
    Valid { s with revoked := j :: s.revoked } o k .person := by
  cases hv with
  | person hp hn =>
      refine .person (hp.of_certs_eq rfl) ?_
      intro hm
      rcases List.mem_cons.mp hm with h | h
      · exact hne h
      · exact hn h

/-- **An agent whose issuer is revoked cannot act in any team**, though its
team certificates still stand. -/
theorem orphaned_agent_cannot_act_in_team {s : State} (h1 : OneCertEach s) {c : Cert} {p : Key}
    (hc : c ∈ s.certs) (hkind : c.kind = .agent) (hiss : c.issuer = .member p)
    (hr : p ∈ s.revoked) (o : Org) (t : Team) : ¬ InTeam s o t c.subject := by
  intro ⟨_, h⟩
  rcases h with hnr | ⟨o', kind, hv⟩
  · exact hnr ⟨c, hc, rfl⟩
  · exact revoking_parent_ends_agent h1 hc hkind hiss hr o' kind hv

/-- **When the admin team's key is not with a key holder, whoever controls it
can remove any admin's team certificate.** It needs nobody's cooperation and
no approval. -/
theorem controller_can_remove_admin {ask : AskRule} {s : State} {o : Org}
    (hfree : OrgKey.team o .admin ∉ s.held) (b : Key) :
    ∃ s', Step ask s (.controller (.team o .admin)) s' ∧ ¬ Admin s' o b := by
  refine ⟨_, Step.remove (m := ⟨o, .admin, b⟩) (approvals := []) (.inl ⟨hfree, rfl⟩)
    (fun h => absurd h hfree), ?_⟩
  intro ⟨hm, _⟩
  exact not_mem_filter_ne hm

/-- **Design. Through a key holder, an admin can remove any other admin.** It
needs only the approvals the organisation's own policy names for a removal.
The removed admin signs nothing. -/
theorem admin_can_remove_admin {s : State} {o : Org}
    (hheld : OrgKey.team o .admin ∈ s.held) {a : Key}
    (ha : Admin s o a) {approvals : List Key} (happ : Approved s o .remove approvals)
    {b : Key} (hne : a ≠ b) : ∃ s', Step adminRule s (.id a) s' ∧ ¬ Admin s' o b := by
  refine ⟨_, Step.remove (m := ⟨o, .admin, b⟩) (approvals := approvals)
    (.inr ⟨hheld, a, rfl, ha, happ⟩) (fun _ _ => ⟨a, hne, ha⟩), ?_⟩
  intro ⟨hm, _⟩
  exact not_mem_filter_ne hm

/-- **When the root key is not with a key holder, whoever controls it can end
any admin**, by revoking that admin's identity. It needs nobody's cooperation
and no approval. -/
theorem root_can_end_admin {ask : AskRule} {s : State} {o : Org}
    (hfree : OrgKey.root o ∉ s.held) {b : Key} (hb : Admin s o b) :
    ∃ s', Step ask s (.controller (.root o)) s' ∧ ¬ Admin s' o b := by
  obtain ⟨_, kind, hv⟩ := hb
  obtain ⟨c, hc, hcs, _, hco⟩ := hv.cert
  subst hco
  subst hcs
  refine ⟨_, Step.revokeByOrg (approvals := []) hc (.inl ⟨hfree, rfl⟩), ?_⟩
  intro ⟨_, _, hv'⟩
  exact revoked_not_valid (List.mem_cons_self) hv'

/-- **Design, in one act. If an admin's team certificate goes while the admin
team's key is with a key holder, another admin remains afterwards.** This is
about team certificates only: the last admin can still revoke its own identity. -/
theorem key_holder_keeps_an_admin {ask : AskRule} {s s' : State} {who : Party} {o : Org}
    {b : Key} (hstep : Step ask s who s') (hheld : OrgKey.team o .admin ∈ s.held)
    (hb : HasTeamCert s o .admin b) (hgone : ¬ HasTeamCert s' o .admin b) :
    ∃ k, k ≠ b ∧ Admin s' o k := by
  have stay : ∀ (m0 : Membership) (gs : List Grant), KeepsAnAdmin s m0 →
      ¬ HasTeamCert { s with members := s.members.filter (fun x => decide (x ≠ m0)),
                             grants := gs } o .admin b →
      ∃ k, k ≠ b ∧ Admin { s with members := s.members.filter (fun x => decide (x ≠ m0)),
                                  grants := gs } o k := by
    intro m0 gs hkeep hg
    have hm : m0 = ⟨o, .admin, b⟩ := by
      apply Decidable.byContradiction
      intro hne
      exact hg (List.mem_filter.mpr ⟨hb, by simpa using fun h => hne h.symm⟩)
    subst hm
    obtain ⟨k, hk, hm, kind, hv⟩ := hkeep rfl
    refine ⟨k, hk, List.mem_filter.mpr ⟨hm, ?_⟩, kind, ?_⟩
    · simpa using fun h : k = b => hk h
    · exact Valid.mono (s := s) (by intro c h; exact h) (by intro j h; exact h) hv
  cases hstep with
  | remove hauth hkeep =>
      rename_i m0 approvals
      by_cases hm : m0 = ⟨o, .admin, b⟩
      · subst hm
        exact stay _ _ (hkeep hheld) hgone
      · exact absurd (List.mem_filter.mpr ⟨hb, by simpa using fun h => hm h.symm⟩) hgone
  | leave _ hh hkeep => exact stay _ _ hkeep hgone
  | replaceRoot _ => exact absurd hb hgone
  | admit _ _ _ => exact absurd (List.mem_cons_of_mem _ hb) hgone
  | admitAdmin _ _ _ => exact absurd (List.mem_cons_of_mem _ hb) hgone
  | redeem _ _ _ => exact absurd (List.mem_cons_of_mem _ hb) hgone
  | createOrg _ => exact absurd hb hgone
  | entrust _ => exact absurd hb hgone
  | release _ _ => exact absurd hb hgone
  | registerByRoot _ _ _ _ => exact absurd hb hgone
  | registerByParent _ _ _ _ => exact absurd hb hgone
  | revokeSelf _ => exact absurd hb hgone
  | revokeChild _ _ _ => exact absurd hb hgone
  | revokeByOrg _ _ => exact absurd hb hgone
  | readmitByRoot _ _ _ _ => exact absurd hb hgone
  | readmitByParent _ _ _ _ => exact absurd hb hgone
  | invite _ _ _ => exact absurd hb hgone
  | mintGrant _ _ => exact absurd hb hgone
  | revokeGrant _ => exact absurd hb hgone
  | sendOwn _ => exact absurd hb hgone
  | sendGrant _ _ => exact absurd hb hgone

/-- **A grant ends with the team certificate it came from, for good.** When a
member's team certificate goes, no grant from it remains, so admitting the
member again does not bring an old grant back. -/
theorem grant_ends_with_its_certificate {ask : AskRule} {s s' : State} {who : Party}
    {o : Org} {t : Team} {k : Key} (hstep : Step ask s who s')
    (hb : HasTeamCert s o t k) (hgone : ¬ HasTeamCert s' o t k) :
    ∀ g, g ∈ s'.grants → ¬ (g.org = o ∧ g.team = t ∧ g.subject = k) := by
  have gone : ∀ m0 : Membership, m0 = ⟨o, t, k⟩ → ∀ g,
      g ∈ s.grants.filter
        (fun g => decide (¬ (g.org = m0.org ∧ g.team = m0.team ∧ g.subject = m0.member))) →
      ¬ (g.org = o ∧ g.team = t ∧ g.subject = k) := by
    intro m0 hm g hg
    subst hm
    have h2 := (List.mem_filter.mp hg).2
    intro ⟨h1, h3, h4⟩
    simp [h1, h3, h4] at h2
  have same : ∀ m0 : Membership,
      ¬ HasTeamCert { s with members := s.members.filter (fun x => decide (x ≠ m0)) } o t k →
      m0 = ⟨o, t, k⟩ := by
    intro m0 hg
    apply Decidable.byContradiction
    intro hne
    exact hg (List.mem_filter.mpr ⟨hb, by simpa using fun h => hne h.symm⟩)
  cases hstep with
  | remove _ _ => exact gone _ (same _ hgone)
  | leave _ _ _ => exact gone _ (same _ hgone)
  | replaceRoot _ => exact absurd hb hgone
  | admit _ _ _ => exact absurd (List.mem_cons_of_mem _ hb) hgone
  | admitAdmin _ _ _ => exact absurd (List.mem_cons_of_mem _ hb) hgone
  | redeem _ _ _ => exact absurd (List.mem_cons_of_mem _ hb) hgone
  | createOrg _ => exact absurd hb hgone
  | entrust _ => exact absurd hb hgone
  | release _ _ => exact absurd hb hgone
  | registerByRoot _ _ _ _ => exact absurd hb hgone
  | registerByParent _ _ _ _ => exact absurd hb hgone
  | revokeSelf _ => exact absurd hb hgone
  | revokeChild _ _ _ => exact absurd hb hgone
  | revokeByOrg _ _ => exact absurd hb hgone
  | readmitByRoot _ _ _ _ => exact absurd hb hgone
  | readmitByParent _ _ _ _ => exact absurd hb hgone
  | invite _ _ _ => exact absurd hb hgone
  | mintGrant _ _ => exact absurd hb hgone
  | revokeGrant _ => exact absurd hb hgone
  | sendOwn _ => exact absurd hb hgone
  | sendGrant _ _ => exact absurd hb hgone

/-! ## Approval -/

/-- **An organisation with no policy requires no approval.** -/
theorem no_policy_no_approval {s : State} {o : Org}
    (h : ∀ r, r ∈ s.policy → r.org ≠ o) (act : ActKind) : Approved s o act [] := by
  intro r hr ho _
  exact absurd ho (h r hr)

/-! ## Built and design: who may ask for a person -/

/-- **As built, in one act: when someone newly holds a chain of person
certificates, whoever controls some organisation key asked directly, or a
valid person exists in some organisation.** Under review: this statement is
weaker than intended. The proof finds the person who asked or approved, but
the statement does not say so. -/
theorem built_person_needs_a_person {s s' : State} {who : Party} {o : Org} {k : Key}
    (hstep : Step builtRule s who s') (hnew : Person s' o k) (hold : ¬ Person s o k) :
    (∃ key, who = .controller key) ∨ ∃ p o', Valid s o' p .person := by
  cases hstep with
  | createOrg _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | entrust _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeSelf _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeChild _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeByOrg _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | admit _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | admitAdmin _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | remove _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | leave _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | invite _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | redeem _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | mintGrant _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | revokeGrant _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | release _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | replaceRoot _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | readmitByRoot _ _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | readmitByParent _ _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | sendOwn _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | sendGrant _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | registerByRoot hi ho hf hauth =>
      rcases hauth with ⟨_, hw⟩ | ⟨_, p, hw, ⟨hact, hv | ⟨⟨r, hr, hro, hra, hrp⟩, _⟩⟩, happ⟩
      · exact .inl ⟨_, hw⟩
      · exact .inr ⟨p, _, hv⟩
      · have h := happ r hr hro (hra.trans hact.symm)
        rw [hrp] at h
        obtain ⟨q, _, hq⟩ := h
        exact .inr ⟨q, _, hq⟩
  | registerByParent hi hf hv hmay =>
      rename_i c p pk
      cases hkind : c.kind with
      | agent => exact absurd (Person.of_cons_agent hkind hnew) hold
      | person =>
          rcases hmay with rfl | h
          · exact .inr ⟨p, _, hv⟩
          · rw [hkind] at h; cases h

/-- **In the design, an agent can ask for a person.** There is a record where
an agent admin asks the key holder, and a person is registered. The root key
signs, so results 1 to 4 still hold; what changes is who may ask. -/
theorem design_agent_admin_can_ask_for_person :
    ∃ (s s' : State) (a k : Key),
      Valid s 0 a .agent ∧ Step adminRule s (.id a) s' ∧ Person s' 0 k ∧ ¬ Person s 0 k := by
  let agentCert : Cert := ⟨0, 1, .agent, .root⟩
  let s : State := ⟨[0], [agentCert], [], [], [⟨0, .admin, 1⟩], [], [.root 0], [], [], []⟩
  let c : Cert := ⟨0, 2, .person, .root⟩
  have hvalid : Valid s 0 1 .agent :=
    .agentOfRoot (c := agentCert) (List.mem_cons_self) rfl rfl rfl rfl (by simp [s])
  have hadmin : Admin s 0 1 := ⟨List.mem_cons_self, .agent, hvalid⟩
  refine ⟨s, { s with certs := c :: s.certs }, 1, 2, hvalid, ?_, ?_, ?_⟩
  · refine Step.registerByRoot (c := c) (approvals := []) rfl (by simp [s, c]) ?_ ?_
    · intro d hd
      have : d = agentCert := by simpa [s] using hd
      subst this
      simp [agentCert, c]
    · refine .inr ⟨by simp [s, c], 1, rfl, hadmin, ?_⟩
      intro r hr
      simp [s] at hr
  · exact .byRoot (c := c) List.mem_cons_self rfl rfl rfl rfl
  · intro hp
    obtain ⟨d, hd, hds, _, _⟩ := hp.cert
    have : d = agentCert := by simpa [s] using hd
    subst this
    simp [agentCert] at hds

/-! ## Grants and invitations -/

theorem Authorised.not_session {ask : AskRule} {s : State} {key : OrgKey} {act : ActKind}
    {x : Key} {approvals : List Key} : ¬ Authorised ask s key act (.session x) approvals := by
  intro h
  rcases h with ⟨_, h⟩ | ⟨_, _, h, _⟩ <;> cases h

theorem Authorised.not_bearer {ask : AskRule} {s : State} {key : OrgKey} {act : ActKind}
    {t : Nat} {approvals : List Key} : ¬ Authorised ask s key act (.bearer t) approvals := by
  intro h
  rcases h with ⟨_, h⟩ | ⟨_, _, h, _⟩ <;> cases h

/-- **A grant holder can send messages, and nothing else.** No identity, team
certificate, revocation, key, grant or invitation changes. -/
theorem session_only_sends {ask : AskRule} {s s' : State} {x : Key}
    (hstep : Step ask s (.session x) s') :
    s'.certs = s.certs ∧ s'.revoked = s.revoked ∧ s'.members = s.members ∧
      s'.grants = s.grants ∧ s'.held = s.held ∧ s'.invites = s.invites := by
  cases hstep with
  | sendGrant _ _ => exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
  | registerByRoot _ _ _ h => exact absurd h Authorised.not_session
  | revokeByOrg _ h => exact absurd h Authorised.not_session
  | admit _ h _ => exact absurd h Authorised.not_session
  | admitAdmin _ _ h => exact absurd h Authorised.not_session
  | remove h _ => exact absurd h Authorised.not_session
  | invite _ h _ => exact absurd h Authorised.not_session
  | release _ h => exact absurd h Authorised.not_session
  | readmitByRoot _ _ _ h => exact absurd h Authorised.not_session

/-- **In one act, an invitation's secret lets its holder join the team the
invitation names, and nothing else.** No identity, revocation, key or grant
changes; the only new team certificate is for the invitation's organisation
and team; and that team is not an admin team. -/
theorem bearer_only_joins {ask : AskRule} {s s' : State} {t : Nat}
    (hstep : Step ask s (.bearer t) s') :
    s'.certs = s.certs ∧ s'.revoked = s.revoked ∧ s'.grants = s.grants ∧ s'.held = s.held ∧
      ∀ m, m ∈ s'.members → m ∉ s.members →
        m.team ≠ .admin ∧ ∃ i, i ∈ s.invites ∧ i.token = t ∧ m.org = i.org ∧ m.team = i.team := by
  cases hstep with
  | redeem hi hne hk =>
      rename_i i k
      refine ⟨rfl, rfl, rfl, rfl, ?_⟩
      intro m hm hold
      rcases List.mem_cons.mp hm with rfl | h
      · exact ⟨hne, i, hi, rfl, rfl, rfl⟩
      · exact absurd h hold
  | registerByRoot _ _ _ h => exact absurd h Authorised.not_bearer
  | revokeByOrg _ h => exact absurd h Authorised.not_bearer
  | admit _ h _ => exact absurd h Authorised.not_bearer
  | admitAdmin _ _ h => exact absurd h Authorised.not_bearer
  | remove h _ => exact absurd h Authorised.not_bearer
  | invite _ h _ => exact absurd h Authorised.not_bearer
  | release _ h => exact absurd h Authorised.not_bearer
  | readmitByRoot _ _ _ h => exact absurd h Authorised.not_bearer

/-- **A message is attributed to an identity only if that identity, able to
act, sent it, or a live grant on it did.** -/
theorem message_from_owner_or_live_grant {ask : AskRule} {s s' : State} {who : Party}
    {m : Message} (hstep : Step ask s who s') (hnew : m ∈ s'.sent) (hold : m ∉ s.sent) :
    (who = .id m.sender ∧ CanAct s m.sender) ∨
      ∃ g, who = .session g.session ∧ GrantLive s g ∧ g.subject = m.sender ∧ g.maySend = true := by
  cases hstep with
  | createOrg _ => exact absurd hnew hold
  | entrust _ => exact absurd hnew hold
  | registerByRoot _ _ _ _ => exact absurd hnew hold
  | registerByParent _ _ _ _ => exact absurd hnew hold
  | revokeSelf _ => exact absurd hnew hold
  | revokeChild _ _ _ => exact absurd hnew hold
  | revokeByOrg _ _ => exact absurd hnew hold
  | admit _ _ _ => exact absurd hnew hold
  | admitAdmin _ _ _ => exact absurd hnew hold
  | remove _ _ => exact absurd hnew hold
  | leave _ _ _ => exact absurd hnew hold
  | invite _ _ _ => exact absurd hnew hold
  | redeem _ _ _ => exact absurd hnew hold
  | mintGrant _ _ => exact absurd hnew hold
  | revokeGrant _ => exact absurd hnew hold
  | release _ _ => exact absurd hnew hold
  | replaceRoot _ => exact absurd hnew hold
  | readmitByRoot _ _ _ _ => exact absurd hnew hold
  | readmitByParent _ _ _ _ => exact absurd hnew hold
  | sendOwn hca =>
      rcases List.mem_cons.mp hnew with rfl | h
      · exact .inl ⟨rfl, hca⟩
      · exact absurd h hold
  | sendGrant hlive hsend =>
      rename_i g
      rcases List.mem_cons.mp hnew with rfl | h
      · exact .inr ⟨g, rfl, hlive, rfl, hsend⟩
      · exact absurd h hold

/-- **Only the identity itself gives a grant on itself.** -/
theorem new_grant_by_subject {ask : AskRule} {s s' : State} {who : Party} {g : Grant}
    (hstep : Step ask s who s') (hnew : g ∈ s'.grants) (hold : g ∉ s.grants) :
    who = .id g.subject := by
  cases hstep with
  | createOrg _ => exact absurd hnew hold
  | entrust _ => exact absurd hnew hold
  | registerByRoot _ _ _ _ => exact absurd hnew hold
  | registerByParent _ _ _ _ => exact absurd hnew hold
  | revokeSelf _ => exact absurd hnew hold
  | revokeChild _ _ _ => exact absurd hnew hold
  | revokeByOrg _ _ => exact absurd hnew hold
  | admit _ _ _ => exact absurd hnew hold
  | admitAdmin _ _ _ => exact absurd hnew hold
  | remove _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
  | leave _ _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
  | invite _ _ _ => exact absurd hnew hold
  | redeem _ _ _ => exact absurd hnew hold
  | release _ _ => exact absurd hnew hold
  | replaceRoot _ => exact absurd hnew hold
  | readmitByRoot _ _ _ _ => exact absurd hnew hold
  | readmitByParent _ _ _ _ => exact absurd hnew hold
  | sendOwn _ => exact absurd hnew hold
  | sendGrant _ _ => exact absurd hnew hold
  | revokeGrant _ => exact absurd (List.mem_filter.mp hnew).1 hold
  | mintGrant _ _ =>
      rcases List.mem_cons.mp hnew with rfl | h
      · rfl
      · exact absurd h hold

/-- **A grant ends with its subject.** Once the subject is revoked, or loses
the team certificate the grant came from, the grant is not live. -/
theorem grant_ends_with_subject {s : State} (hrr : RevokedAreRegistered s) {g : Grant}
    (h : g.subject ∈ s.revoked ∨ ¬ HasTeamCert s g.org g.team g.subject) : ¬ GrantLive s g := by
  intro ⟨_, hin⟩
  rcases h with hr | hc
  · exact (revoked_has_no_authority hrr hr).2 _ _ hin
  · exact hc hin.1

/-! ## More that never happens -/

/-- **A revocation is never undone.** An identity that was revoked, and not
merely cut off by a root replacement, stays revoked whatever happens. -/
theorem revocation_is_permanent {ask : AskRule} {s s' : State} {who : Party} {k : Key}
    (hstep : Step ask s who s') (hk : k ∈ s.revoked) (hc : k ∉ s.cutOff) :
    k ∈ s'.revoked ∧ k ∉ s'.cutOff := by
  have keep : ∀ j : Key, j ∈ s.cutOff →
      k ∈ s.revoked.filter (fun x => decide (x ≠ j)) ∧
        k ∉ s.cutOff.filter (fun x => decide (x ≠ j)) := by
    intro j hj
    refine ⟨List.mem_filter.mpr ⟨hk, ?_⟩, fun h => hc (List.mem_filter.mp h).1⟩
    have : k ≠ j := fun h => hc (h ▸ hj)
    simpa using this
  have drop : ∀ j : Key, k ∈ j :: s.revoked ∧ k ∉ s.cutOff.filter (fun x => decide (x ≠ j)) :=
    fun j => ⟨List.mem_cons_of_mem _ hk, fun h => hc (List.mem_filter.mp h).1⟩
  cases hstep with
  | revokeSelf _ => exact drop _
  | revokeChild _ _ _ => exact drop _
  | revokeByOrg _ _ => exact drop _
  | readmitByRoot _ _ hj _ => exact keep _ hj
  | readmitByParent _ _ hj _ => exact keep _ hj
  | replaceRoot _ =>
      refine ⟨List.mem_append_right _ hk, ?_⟩
      intro h
      rcases List.mem_append.mp h with h | h
      · obtain ⟨c, hcm, rfl⟩ := List.mem_map.mp h
        have := (List.mem_filter.mp hcm).2
        simp at this
        exact this.2 hk
      · exact hc h
  | createOrg _ => exact ⟨hk, hc⟩
  | entrust _ => exact ⟨hk, hc⟩
  | release _ _ => exact ⟨hk, hc⟩
  | registerByRoot _ _ _ _ => exact ⟨hk, hc⟩
  | registerByParent _ _ _ _ => exact ⟨hk, hc⟩
  | admit _ _ _ => exact ⟨hk, hc⟩
  | admitAdmin _ _ _ => exact ⟨hk, hc⟩
  | remove _ _ => exact ⟨hk, hc⟩
  | leave _ _ _ => exact ⟨hk, hc⟩
  | invite _ _ _ => exact ⟨hk, hc⟩
  | redeem _ _ _ => exact ⟨hk, hc⟩
  | mintGrant _ _ => exact ⟨hk, hc⟩
  | revokeGrant _ => exact ⟨hk, hc⟩
  | sendOwn _ => exact ⟨hk, hc⟩
  | sendGrant _ _ => exact ⟨hk, hc⟩

/-- **An identity certificate is never removed or replaced.** With one
certificate per identity, a member's organisation and kind never change:
nothing is relinked. -/
theorem certificate_is_permanent {ask : AskRule} {s s' : State} {who : Party} {c : Cert}
    (hstep : Step ask s who s') (hc : c ∈ s.certs) : c ∈ s'.certs := by
  cases hstep with
  | registerByRoot _ _ _ _ => exact List.mem_cons_of_mem _ hc
  | registerByParent _ _ _ _ => exact List.mem_cons_of_mem _ hc
  | createOrg _ => exact hc
  | entrust _ => exact hc
  | revokeSelf _ => exact hc
  | revokeChild _ _ _ => exact hc
  | revokeByOrg _ _ => exact hc
  | admit _ _ _ => exact hc
  | admitAdmin _ _ _ => exact hc
  | remove _ _ => exact hc
  | leave _ _ _ => exact hc
  | invite _ _ _ => exact hc
  | redeem _ _ _ => exact hc
  | mintGrant _ _ => exact hc
  | revokeGrant _ => exact hc
  | release _ _ => exact hc
  | replaceRoot _ => exact hc
  | readmitByRoot _ _ _ _ => exact hc
  | readmitByParent _ _ _ _ => exact hc
  | sendOwn _ => exact hc
  | sendGrant _ _ => exact hc

/-- **Being issued an identity gives no team.** An act that registers an
identity changes no team certificate. -/
theorem registering_gives_no_team {ask : AskRule} {s s' : State} {who : Party}
    (hstep : Step ask s who s') (hreg : s'.certs ≠ s.certs) : s'.members = s.members := by
  cases hstep with
  | registerByRoot _ _ _ _ => rfl
  | registerByParent _ _ _ _ => rfl
  | createOrg _ => exact absurd rfl hreg
  | entrust _ => exact absurd rfl hreg
  | revokeSelf _ => exact absurd rfl hreg
  | revokeChild _ _ _ => exact absurd rfl hreg
  | revokeByOrg _ _ => exact absurd rfl hreg
  | admit _ _ _ => exact absurd rfl hreg
  | admitAdmin _ _ _ => exact absurd rfl hreg
  | remove _ _ => exact absurd rfl hreg
  | leave _ _ _ => exact absurd rfl hreg
  | invite _ _ _ => exact absurd rfl hreg
  | redeem _ _ _ => exact absurd rfl hreg
  | mintGrant _ _ => exact absurd rfl hreg
  | revokeGrant _ => exact absurd rfl hreg
  | release _ _ => exact absurd rfl hreg
  | replaceRoot _ => exact absurd rfl hreg
  | readmitByRoot _ _ _ _ => exact absurd rfl hreg
  | readmitByParent _ _ _ _ => exact absurd rfl hreg
  | sendOwn _ => exact absurd rfl hreg
  | sendGrant _ _ => exact absurd rfl hreg

theorem Authorised.controller_eq {ask : AskRule} {s : State} {key key' : OrgKey}
    {act : ActKind} {approvals : List Key}
    (h : Authorised ask s key act (.controller key') approvals) : key' = key := by
  rcases h with ⟨_, h⟩ | ⟨_, _, h, _⟩
  · cases h; rfl
  · cases h

/-- **In one act, whoever controls one organisation's key adds or removes
nothing in another organisation, for four kinds of thing.** Every new identity
certificate, every new or removed team certificate and every newly revoked
identity belongs to that key's organisation. Nothing is stated about
invitations, grants, held keys or identities admitted again. -/
theorem controller_stays_in_its_organisation {ask : AskRule} {s s' : State} {key : OrgKey}
    (hstep : Step ask s (.controller key) s') :
    (∀ c, c ∈ s'.certs → c ∉ s.certs → c.org = key.org) ∧
    (∀ m, m ∈ s'.members → m ∉ s.members → m.org = key.org) ∧
    (∀ m, m ∈ s.members → m ∉ s'.members → m.org = key.org) ∧
    (∀ k, k ∈ s'.revoked → k ∉ s.revoked → ∃ c, c ∈ s.certs ∧ c.subject = k ∧ c.org = key.org) := by
  cases hstep with
  | release hheld hauth =>
      rcases hauth with ⟨hn, _⟩ | ⟨_, _, h, _⟩
      · exact absurd hheld hn
      · cases h
  | readmitByRoot _ _ _ _ =>
      exact ⟨fun _ h h' => absurd h h', fun _ h h' => absurd h h',
        fun _ h h' => absurd h h', fun _ h h' => absurd (List.mem_filter.mp h).1 h'⟩
  | entrust _ =>
      exact ⟨fun _ h h' => absurd h h', fun _ h h' => absurd h h',
        fun _ h h' => absurd h h', fun _ h h' => absurd h h'⟩
  | invite _ _ _ =>
      exact ⟨fun _ h h' => absurd h h', fun _ h h' => absurd h h',
        fun _ h h' => absurd h h', fun _ h h' => absurd h h'⟩
  | registerByRoot _ _ _ hauth =>
      have hk := hauth.controller_eq
      subst hk
      refine ⟨?_, fun _ h h' => absurd h h', fun _ h h' => absurd h h',
        fun _ h h' => absurd h h'⟩
      intro c hc hold
      rcases List.mem_cons.mp hc with rfl | h
      · rfl
      · exact absurd h hold
  | revokeByOrg hc hauth =>
      have hk := hauth.controller_eq
      subst hk
      refine ⟨fun _ h h' => absurd h h', fun _ h h' => absurd h h',
        fun _ h h' => absurd h h', ?_⟩
      intro k hmem hold
      rcases List.mem_cons.mp hmem with rfl | h
      · exact ⟨_, hc, rfl, rfl⟩
      · exact absurd h hold
  | admit _ hauth _ =>
      have hk := hauth.controller_eq
      subst hk
      refine ⟨fun _ h h' => absurd h h', ?_, ?_, fun _ h h' => absurd h h'⟩
      · intro m hm hold
        rcases List.mem_cons.mp hm with rfl | h
        · rfl
        · exact absurd h hold
      · intro m hm hgone
        exact absurd (List.mem_cons_of_mem _ hm) hgone
  | admitAdmin _ _ hauth =>
      have hk := hauth.controller_eq
      subst hk
      refine ⟨fun _ h h' => absurd h h', ?_, ?_, fun _ h h' => absurd h h'⟩
      · intro m hm hold
        rcases List.mem_cons.mp hm with rfl | h
        · rfl
        · exact absurd h hold
      · intro m hm hgone
        exact absurd (List.mem_cons_of_mem _ hm) hgone
  | remove hauth hk =>
      rename_i m0 approvals
      have hk := hauth.controller_eq
      subst hk
      refine ⟨fun _ h h' => absurd h h', ?_, ?_, fun _ h h' => absurd h h'⟩
      · intro m hm hold
        exact absurd (List.mem_filter.mp hm).1 hold
      · intro m hm hgone
        have : m = m0 := by
          apply Decidable.byContradiction
          intro hne
          exact hgone (List.mem_filter.mpr ⟨hm, by simpa using hne⟩)
        subst this
        rfl

/-! ## DNS is the root of trust, and a key can leave its holder -/

/-- **Whoever controls the domain can always take the organisation back.**
Nothing can refuse it. Afterwards the root key is not with a key holder, and
every identity issued under the organisation is cut off. -/
theorem dns_owner_can_always_take_over {ask : AskRule} {s : State} {o : Org} (ho : o ∈ s.orgs) :
    ∃ s', Step ask s (.dns o) s' ∧ OrgKey.root o ∉ s'.held ∧ ∀ k kind, ¬ Valid s' o k kind := by
  refine ⟨_, Step.replaceRoot ho, ?_, ?_⟩
  · intro hmem
    have := (List.mem_filter.mp hmem).2
    simp at this
  · intro k kind hv
    obtain ⟨c, hc, hcs, _, hco⟩ := hv.cert
    refine revoked_not_valid ?_ hv
    by_cases hr : k ∈ s.revoked
    · exact List.mem_append_right _ hr
    · refine List.mem_append_left _ (List.mem_map.mpr ⟨c, List.mem_filter.mpr ⟨hc, ?_⟩, hcs⟩)
      simp [hco, hcs, hr]

/-- **After a root replacement, the organisation can admit an identity
again.** Whoever controls the new root key admits an identity directly under
the organisation that the replacement cut off. It is valid again, with the
same key, kind and organisation. -/
theorem replaced_organisation_can_readmit {ask : AskRule} {s : State} {c : Cert}
    (hc : c ∈ s.certs) (hi : c.issuer = .root) (hcut : c.subject ∈ s.cutOff)
    (hfree : OrgKey.root c.org ∉ s.held) :
    ∃ s', Step ask s (.controller (.root c.org)) s' ∧ Valid s' c.org c.subject c.kind := by
  refine ⟨_, Step.readmitByRoot (approvals := []) hc hi hcut (.inl ⟨hfree, rfl⟩), ?_⟩
  have hn : c.subject ∉ s.revoked.filter (fun k => decide (k ≠ c.subject)) := by
    intro h
    have := (List.mem_filter.mp h).2
    simp at this
  cases hk : c.kind with
  | person => exact .person (.byRoot hc rfl hk hi rfl) hn
  | agent => exact .agentOfRoot hc rfl hk hi rfl hn

/-- **A key leaves its holder in only two ways.** Whoever controls the domain
replaced the root, or someone the rule lets ask had it given back. -/
theorem key_leaves_holder_only_two_ways {ask : AskRule} {s s' : State} {who : Party}
    {key : OrgKey} (hstep : Step ask s who s') (hin : key ∈ s.held) (hout : key ∉ s'.held) :
    who = .dns key.org ∨ ∃ k, who = .id k ∧ ask s key.org .release k := by
  cases hstep with
  | createOrg _ => exact absurd hin hout
  | entrust _ => exact absurd (List.mem_cons_of_mem _ hin) hout
  | registerByRoot _ _ _ _ => exact absurd hin hout
  | registerByParent _ _ _ _ => exact absurd hin hout
  | revokeSelf _ => exact absurd hin hout
  | revokeChild _ _ _ => exact absurd hin hout
  | revokeByOrg _ _ => exact absurd hin hout
  | admit _ _ _ => exact absurd hin hout
  | admitAdmin _ _ _ => exact absurd hin hout
  | remove _ _ => exact absurd hin hout
  | leave _ _ _ => exact absurd hin hout
  | invite _ _ _ => exact absurd hin hout
  | redeem _ _ _ => exact absurd hin hout
  | mintGrant _ _ => exact absurd hin hout
  | revokeGrant _ => exact absurd hin hout
  | readmitByRoot _ _ _ _ => exact absurd hin hout
  | readmitByParent _ _ _ _ => exact absurd hin hout
  | sendOwn _ => exact absurd hin hout
  | sendGrant _ _ => exact absurd hin hout
  | replaceRoot ho =>
      rename_i o
      refine .inl ?_
      have hk : key = .root o := by
        apply Decidable.byContradiction
        intro hne
        exact hout (List.mem_filter.mpr ⟨hin, by simpa using hne⟩)
      rw [hk]; rfl
  | release hheld hauth =>
      rename_i key' approvals
      have hk : key = key' := by
        apply Decidable.byContradiction
        intro hne
        exact hout (List.mem_filter.mpr ⟨hin, by simpa using hne⟩)
      subst hk
      rcases hauth with ⟨hn, _⟩ | ⟨_, k, hw, hask, _⟩
      · exact absurd hheld hn
      · exact .inr ⟨k, hw, hask⟩

/-- **As built, a key leaves its holder only when the domain's owner replaces
the root.** The built key holder never gives a key back. -/
theorem built_key_leaves_only_by_dns {s s' : State} {who : Party} {key : OrgKey}
    (hstep : Step builtRule s who s') (hin : key ∈ s.held) (hout : key ∉ s'.held) :
    who = .dns key.org := by
  rcases key_leaves_holder_only_two_ways hstep hin hout with h | ⟨_, _, hask⟩
  · exact h
  · cases hask.1

/-- **Design. An organisation can take a key back, and nothing else changes.**
Through the key holder, an admin with the approvals the policy names has the
key given back. Every identity, revocation and team certificate stays as it was. -/
theorem organisation_can_take_key_back {s : State} {key : OrgKey} {a : Key}
    (hheld : key ∈ s.held) (ha : Admin s key.org a) {approvals : List Key}
    (happ : Approved s key.org .release approvals) :
    ∃ s', Step adminRule s (.id a) s' ∧ key ∉ s'.held ∧
      s'.certs = s.certs ∧ s'.revoked = s.revoked ∧ s'.members = s.members := by
  refine ⟨_, Step.release (approvals := approvals) hheld (.inr ⟨hheld, a, rfl, ha, happ⟩),
    ?_, rfl, rfl, rfl⟩
  intro hmem
  have := (List.mem_filter.mp hmem).2
  simp at this

/-! ## Who answers -/

/-- **Whoever answers for a member is a valid person.** -/
theorem answerer_is_valid_person {s : State} {o : Org} {a h : Key}
    (ha : AnswersFor s o a h) : Valid s o h .person := by
  induction ha with
  | self hv => exact hv
  | up _ _ _ _ _ _ _ ih => exact ih

/-- **At most one person answers for a member.** -/
theorem answerer_unique {s : State} (h1 : OneCertEach s) {o : Org} {a h h' : Key}
    (ha : AnswersFor s o a h) (ha' : AnswersFor s o a h') : h = h' := by
  induction ha generalizing h' with
  | self hv =>
      cases ha' with
      | self _ => rfl
      | up hd _ hdk _ hds _ _ =>
          obtain ⟨e, he, hes, hek, _⟩ := hv.cert
          have := h1 e he _ hd (hes.trans hds.symm)
          subst this
          rw [hdk] at hek; cases hek
  | up hc _ hck hci hcs _ _ ih =>
      cases ha' with
      | self hv =>
          obtain ⟨e, he, hes, hek, _⟩ := hv.cert
          have := h1 e he _ hc (hes.trans hcs.symm)
          subst this
          rw [hck] at hek; cases hek
      | up hd _ _ hdi hds _ hrest =>
          have := h1 _ hc _ hd (hcs.trans hds.symm)
          subst this
          rw [hci] at hdi
          cases hdi
          exact ih hrest

/-! ## Holds in every reachable record -/

/-- **Accepted acts keep one certificate per identity.** -/
theorem Step.oneCertEach {ask : AskRule} {s s' : State} {who : Party}
    (hstep : Step ask s who s') (h1 : OneCertEach s) : OneCertEach s' := by
  have key : ∀ c : Cert, Fresh s c.subject → OneCertEach { s with certs := c :: s.certs } := by
    intro c hf x hx y hy hxy
    rcases List.mem_cons.mp hx with hxc | hx <;> rcases List.mem_cons.mp hy with hyc | hy
    · rw [hxc, hyc]
    · rw [hxc] at hxy; exact absurd hxy.symm (hf y hy)
    · rw [hyc] at hxy; exact absurd hxy (hf x hx)
    · exact h1 x hx y hy hxy
  cases hstep with
  | registerByRoot _ _ hf _ => exact key _ hf
  | registerByParent _ hf _ _ => exact key _ hf
  | createOrg _ => exact h1
  | entrust _ => exact h1
  | revokeSelf _ => exact h1
  | revokeChild _ _ _ => exact h1
  | revokeByOrg _ _ => exact h1
  | admit _ _ _ => exact h1
  | admitAdmin _ _ _ => exact h1
  | remove _ _ => exact h1
  | leave _ _ _ => exact h1
  | invite _ _ _ => exact h1
  | redeem _ _ _ => exact h1
  | mintGrant _ _ => exact h1
  | revokeGrant _ => exact h1
  | release _ _ => exact h1
  | replaceRoot _ => exact h1
  | readmitByRoot _ _ _ _ => exact h1
  | readmitByParent _ _ _ _ => exact h1
  | sendOwn _ => exact h1
  | sendGrant _ _ => exact h1

/-- **Accepted acts revoke only registered identities.** -/
theorem Step.revokedAreRegistered {ask : AskRule} {s s' : State} {who : Party}
    (hstep : Step ask s who s') (h : RevokedAreRegistered s) : RevokedAreRegistered s' := by
  have grow : ∀ c : Cert, RevokedAreRegistered { s with certs := c :: s.certs } := by
    intro c k hk
    obtain ⟨d, hd, hds⟩ := h k hk
    exact ⟨d, List.mem_cons_of_mem _ hd, hds⟩
  have rev : ∀ c : Cert, c ∈ s.certs →
      RevokedAreRegistered { s with revoked := c.subject :: s.revoked } := by
    intro c hc k hk
    rcases List.mem_cons.mp hk with hkc | hk
    · exact ⟨c, hc, hkc.symm⟩
    · exact h k hk
  cases hstep with
  | registerByRoot _ _ _ _ => exact grow _
  | registerByParent _ _ _ _ => exact grow _
  | revokeSelf hc => exact rev _ hc
  | revokeChild hc _ _ => exact rev _ hc
  | revokeByOrg hc _ => exact rev _ hc
  | createOrg _ => exact h
  | entrust _ => exact h
  | admit _ _ _ => exact h
  | admitAdmin _ _ _ => exact h
  | remove _ _ => exact h
  | leave _ _ _ => exact h
  | invite _ _ _ => exact h
  | redeem _ _ _ => exact h
  | mintGrant _ _ => exact h
  | revokeGrant _ => exact h
  | release _ _ => exact h
  | replaceRoot _ =>
      intro k hk
      rcases List.mem_append.mp hk with hk | hk
      · obtain ⟨c, hc, rfl⟩ := List.mem_map.mp hk
        exact ⟨c, (List.mem_filter.mp hc).1, rfl⟩
      · exact h k hk
  | readmitByRoot _ _ _ _ => exact fun k hk => h k (List.mem_filter.mp hk).1
  | readmitByParent _ _ _ _ => exact fun k hk => h k (List.mem_filter.mp hk).1
  | sendOwn _ => exact h
  | sendGrant _ _ => exact h

/-- **Accepted acts keep an unregistered identity in one team.** -/
theorem Step.localInOneTeam {ask : AskRule} {s s' : State} {who : Party}
    (hstep : Step ask s who s') (h : LocalInOneTeam s) : LocalInOneTeam s' := by
  have reg : ∀ c : Cert, LocalInOneTeam { s with certs := c :: s.certs } := by
    intro c m1 h1 m2 h2 he hn
    exact h m1 h1 m2 h2 he (fun ⟨d, hd, hds⟩ => hn ⟨d, List.mem_cons_of_mem _ hd, hds⟩)
  have add : ∀ m : Membership, OneTeamIfLocal s m.member →
      ∀ m1, m1 ∈ m :: s.members → ∀ m2, m2 ∈ m :: s.members → m1.member = m2.member →
        ¬ Registered s m1.member → m1 = m2 := by
    intro m hk m1 h1 m2 h2 he hn
    rcases List.mem_cons.mp h1 with e1 | h1 <;> rcases List.mem_cons.mp h2 with e2 | h2
    · rw [e1, e2]
    · rcases hk with hr | hnone
      · exact absurd (e1 ▸ hr) hn
      · exact absurd (by rw [← he, e1]) (hnone m2 h2)
    · rcases hk with hr | hnone
      · exact absurd (by rw [he, e2]; exact hr) hn
      · exact absurd (by rw [he, e2]) (hnone m1 h1)
    · exact h m1 h1 m2 h2 he hn
  have sub : ∀ p : Membership → Bool,
      LocalInOneTeam { s with members := s.members.filter p } := by
    intro p m1 h1 m2 h2 he hn
    exact h m1 (List.mem_filter.mp h1).1 m2 (List.mem_filter.mp h2).1 he hn
  cases hstep with
  | registerByRoot _ _ _ _ => exact reg _
  | registerByParent _ _ _ _ => exact reg _
  | admit _ _ hk => exact add _ hk
  | admitAdmin ht hv ha =>
      rename_i m _ _
      exact add m (.inl (by obtain ⟨c, hc, hcs, _, _⟩ := hv.cert; exact ⟨c, hc, hcs⟩))
  | redeem _ _ hk => exact add ⟨_, _, _⟩ hk
  | remove _ _ => exact sub _
  | leave _ _ _ => exact sub _
  | replaceRoot _ => exact h
  | createOrg _ => exact h
  | entrust _ => exact h
  | release _ _ => exact h
  | revokeSelf _ => exact h
  | revokeChild _ _ _ => exact h
  | revokeByOrg _ _ => exact h
  | readmitByRoot _ _ _ _ => exact h
  | readmitByParent _ _ _ _ => exact h
  | invite _ _ _ => exact h
  | mintGrant _ _ => exact h
  | revokeGrant _ => exact h
  | sendOwn _ => exact h
  | sendGrant _ _ => exact h

/-- **Every reachable record has one certificate per identity.** So the
theorems above that ask for it hold in every record the system can reach, and
a member's organisation, kind and issuer never change. -/
theorem Reachable.oneCertEach {ask : AskRule} {s : State} (hr : Reachable ask s) : OneCertEach s := by
  induction hr with
  | start _ => intro c hc; cases hc
  | step _ hstep ih => exact hstep.oneCertEach ih

/-- **In every reachable record, only registered identities are revoked.** -/
theorem Reachable.revokedAreRegistered {ask : AskRule} {s : State} (hr : Reachable ask s) :
    RevokedAreRegistered s := by
  induction hr with
  | start _ => intro k hk; cases hk
  | step _ hstep ih => exact hstep.revokedAreRegistered ih

/-- **In every reachable record, an unregistered identity is in at most one team.** -/
theorem Reachable.localInOneTeam {ask : AskRule} {s : State} (hr : Reachable ask s) :
    LocalInOneTeam s := by
  induction hr with
  | start _ => intro m hm; cases hm
  | step _ hstep ih => exact hstep.localInOneTeam ih

end TrustWeb
