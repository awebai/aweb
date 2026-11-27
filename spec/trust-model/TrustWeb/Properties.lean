import TrustWeb.Model

/-!
# The trust web: what is proved

Results about one act, about reachable records and about the definitions, with
the lemmas they use.
-/

namespace TrustWeb

/-! ## Helping facts -/

theorem Person.mono {s t : State} {o : Org} (h : ∀ c, c ∈ s.certs → c ∈ t.certs) {k : Key}
    (hp : Person s o k) : Person t o k := by
  induction hp with
  | byRoot hc ho hk hi hs => exact .byRoot (h _ hc) ho hk hi hs
  | byPerson hc ho hk hi hs _ ih => exact .byPerson (h _ hc) ho hk hi hs ih

/-- If `k` is a person of `o` in one record, it is a person of `o` in any
record with the same certificates. -/
theorem Person.of_certs_eq {s t : State} {o : Org} {k : Key} (hp : Person s o k)
    (h : s.certs = t.certs) : Person t o k :=
  hp.mono (by intro c hc; rw [← h]; exact hc)

/-- A person of `o` holds a person certificate of `o`. -/
theorem Person.cert {s : State} {o : Org} {k : Key} (hp : Person s o k) :
    ∃ c, c ∈ s.certs ∧ c.subject = k ∧ c.kind = .person ∧ c.org = o := by
  cases hp with
  | byRoot hc ho hk _ hs => exact ⟨_, hc, hs, hk, ho⟩
  | byPerson hc ho hk _ hs _ => exact ⟨_, hc, hs, hk, ho⟩

/-- A valid member of `o` holds a certificate of `o` of its kind. -/
theorem Valid.cert {s : State} {o : Org} {k : Key} {kind : Kind} (hv : Valid s o k kind) :
    ∃ c, c ∈ s.certs ∧ c.subject = k ∧ c.kind = kind ∧ c.org = o := by
  cases hv with
  | person hp _ => exact hp.cert
  | agentOfRoot hc ho hk _ hs _ => exact ⟨_, hc, hs, hk, ho⟩
  | agentOf hc ho hk _ hs _ _ => exact ⟨_, hc, hs, hk, ho⟩

/-- If adding an agent certificate to the record makes `k` a person of `o`,
`k` was a person of `o` before. -/
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

/-- If a second record has every certificate of the first and revokes only
identities the first revokes, every valid member of the first is valid in the
second, in the same organisation and of the same kind. -/
theorem Valid.mono {s t : State} (hc : ∀ c, c ∈ s.certs → c ∈ t.certs)
    (hr : ∀ k, k ∈ t.revoked → k ∈ s.revoked) {o : Org} {k : Key} {kind : Kind}
    (hv : Valid s o k kind) : Valid t o k kind := by
  induction hv with
  | person hp hn => exact .person (hp.mono hc) (fun h => hn (hr _ h))
  | agentOfRoot hm ho hk hi hs hn =>
      exact .agentOfRoot (hc _ hm) ho hk hi hs (fun h => hn (hr _ h))
  | agentOf hm ho hk hi hs hn _ ih =>
      exact .agentOf (hc _ hm) ho hk hi hs (fun h => hn (hr _ h)) ih

/-! ## Persons and agents -/

/-- If every identity has one certificate, no identity is valid as an agent in
one organisation and as a person in any. -/
theorem one_kind {s : State} (h1 : OneCertEach s) {o o' : Org} {k : Key}
    (ha : Valid s o k .agent) (hp : Valid s o' k .person) : False := by
  obtain ⟨c, hc, hcs, hck, _⟩ := ha.cert
  obtain ⟨d, hd, hds, hdk, _⟩ := hp.cert
  have := h1 c hc d hd (hcs.trans hds.symm)
  subst this
  rw [hck] at hdk; cases hdk

/-- In one act. If after an accepted act `k` holds a chain of person
certificates in `o` and did not before, the act added one certificate to the
record, a person certificate, whose issuer is the root or a member that was a
valid person of the certificate's organisation before the act. The statement
does not say the certificate is `k`'s. It looks at certificates only, not at
revocation. -/
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
  | rekeyTeam _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
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

/-- If no certificate in a list is issued by the root, and none is issued by a
member that is a person of the certificate's organisation in the record, then
whoever is a person once the list is added to the record was one before. -/
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

/-- If no approver is a valid person of `o`, the approvals do not satisfy a
rule of `o` asking for any person. -/
theorem agents_cannot_approve_as_person {s : State} {o : Org} {approvals : List Key}
    (h : ∀ k, k ∈ approvals → ¬ Valid s o k .person) :
    ¬ Satisfies s o approvals .anyPerson := by
  intro ⟨k, hk, hv⟩
  exact h k hk hv

/-! ## Chains to the root -/

theorem Person.chainToRoot {s : State} {o : Org} {k : Key} (hp : Person s o k) :
    ChainToRoot s o k := by
  induction hp with
  | byRoot hc ho _ hi hs => exact .root hc ho hi hs
  | byPerson hc ho _ hi hs _ ih => exact .link hc ho hi hs ih

/-- If `k` is a valid member of `o`, of either kind, certificates lead from
`k` to `o`'s root. Leading means registered certificates of `o`, each issued
by the next, up to one issued by the root (`ChainToRoot`); kind, revocation
and the issuers' validity are not part of it. -/
theorem valid_has_chain_to_root {s : State} {o : Org} {k : Key} {kind : Kind}
    (hv : Valid s o k kind) : ChainToRoot s o k := by
  induction hv with
  | person hp _ => exact hp.chainToRoot
  | agentOfRoot hc ho _ hi hs _ => exact .root hc ho hi hs
  | agentOf hc ho _ hi hs _ _ ih => exact .link hc ho hi hs ih

/-- If `k` is an admin of `o`, certificates lead from `k` to `o`'s root. -/
theorem admin_has_chain_to_root {s : State} {o : Org} {k : Key}
    (ha : Admin s o k) : ChainToRoot s o k := by
  obtain ⟨_, _, hv⟩ := ha
  exact valid_has_chain_to_root hv

/-- In one act. If an accepted act adds a team certificate of an admin team,
the asker is whoever controls that admin team's key, or an identity the rule
lets ask for admitting an admin in that organisation. So it is not an
invitation's holder. -/
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
      · rcases hauth with ⟨_, hr⟩ | ⟨_, a, ha, hask, _⟩
        · rw [hteam] at hr; exact .inl hr
        · exact .inr ⟨a, ha, hask⟩
      · exact absurd h hold

/-! ## Revoking and removing -/

/-- A revoked identity is not valid in any organisation, of either kind. -/
theorem revoked_not_valid {s : State} {o : Org} {k : Key} {kind : Kind}
    (hr : k ∈ s.revoked) : ¬ Valid s o k kind := by
  intro hv
  cases hv with
  | person _ hn => exact hn hr
  | agentOfRoot _ _ _ _ _ hn => exact hn hr
  | agentOf _ _ _ _ _ hn _ => exact hn hr

/-- If only registered identities are revoked and `k` is revoked, `k` is not
an admin of any organisation and cannot act in any team. In every reachable
record only registered identities are revoked
(`Reachable.revokedAreRegistered`). -/
theorem revoked_has_no_authority {s : State} (hrr : RevokedAreRegistered s) {k : Key}
    (hr : k ∈ s.revoked) : (∀ o, ¬ Admin s o k) ∧ (∀ o t, ¬ InTeam s o t k) := by
  refine ⟨?_, ?_⟩
  · intro o ⟨_, _, hv⟩
    exact revoked_not_valid hr hv
  · intro o t ⟨_, h⟩
    rcases h with hnr | ⟨_, _, hv⟩
    · exact hnr (hrr k hr)
    · exact revoked_not_valid hr hv

/-- If only registered identities are revoked and `k` is revoked, `k` cannot
act (`CanAct`). Sending with its own key needs that (`sendOwn`), and so does
acting in a team (`InTeam`), which a live grant needs (`GrantLive`). In every
reachable record only registered identities are revoked
(`Reachable.revokedAreRegistered`). -/
theorem revoked_cannot_act {s : State} (hrr : RevokedAreRegistered s) {k : Key}
    (hr : k ∈ s.revoked) : ¬ CanAct s k := by
  intro h
  rcases h with hnr | ⟨_, _, hv⟩
  · exact hnr (hrr k hr)
  · exact revoked_not_valid hr hv

/-- If every identity has one certificate and the member that issued a
registered agent certificate is not valid in any organisation, the
certificate's subject is not valid in any organisation. -/
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

/-- If every identity has one certificate and the member that issued a
registered agent certificate is revoked, the certificate's subject is not
valid in any organisation. -/
theorem revoking_parent_ends_agent {s : State} (h1 : OneCertEach s) {c : Cert} {p : Key}
    (hc : c ∈ s.certs) (hkind : c.kind = .agent) (hiss : c.issuer = .member p)
    (hr : p ∈ s.revoked) (o : Org) (kind : Kind) : ¬ Valid s o c.subject kind :=
  agent_needs_valid_parent h1 hc hkind hiss (fun _ _ => revoked_not_valid hr) o kind

/-- If `k` is a valid person of `o`, adding any other identity to the revoked
leaves `k` a valid person of `o`. This is about the record, not about an act. -/
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

/-- If every identity has one certificate and the member that issued a
registered agent certificate is revoked, the certificate's subject cannot act
in any team. Its team certificates are not looked at. -/
theorem orphaned_agent_cannot_act_in_team {s : State} (h1 : OneCertEach s) {c : Cert} {p : Key}
    (hc : c ∈ s.certs) (hkind : c.kind = .agent) (hiss : c.issuer = .member p)
    (hr : p ∈ s.revoked) (o : Org) (t : Team) : ¬ InTeam s o t c.subject := by
  intro ⟨_, h⟩
  rcases h with hnr | ⟨o', kind, hv⟩
  · exact hnr ⟨c, hc, rfl⟩
  · exact revoking_parent_ends_agent h1 hc hkind hiss hr o' kind hv

/-- If the admin team's key of `o` is not with a key holder, then for any
identity `b` there is an accepted act that whoever controls that key asks for,
after which `b` is not an admin of `o`. -/
theorem controller_can_remove_admin {ask : AskRule} {s : State} {o : Org}
    (hfree : OrgKey.team o .admin ∉ s.held) (b : Key) :
    ∃ s', Step ask s (.controller (.team o .admin)) s' ∧ ¬ Admin s' o b := by
  refine ⟨_, Step.remove (m := ⟨o, .admin, b⟩) (approvals := []) (.inl ⟨hfree, rfl⟩)
    (fun h => absurd h hfree), ?_⟩
  intro ⟨hm, _⟩
  exact not_mem_filter_ne hm

/-- Design. If the admin team's key of `o` is with a key holder, `a` is an
admin of `o`, the approvals satisfy `o`'s policy for a removal, and `b` is not
`a`, there is an accepted act under the admin rule that `a` asks for, after
which `b` is not an admin of `o`. Where the policy has a rule for a removal in
`o` naming `b` as its approver, those approvals include `b`'s (`Satisfies`). -/
theorem admin_can_remove_admin {s : State} {o : Org}
    (hheld : OrgKey.team o .admin ∈ s.held) {a : Key}
    (ha : Admin s o a) {approvals : List Key} (happ : Approved s o .remove approvals)
    {b : Key} (hne : a ≠ b) : ∃ s', Step adminRule s (.id a) s' ∧ ¬ Admin s' o b := by
  refine ⟨_, Step.remove (m := ⟨o, .admin, b⟩) (approvals := approvals)
    (.inr ⟨hheld, a, rfl, ha, happ⟩) (fun _ _ => ⟨a, hne, ha⟩), ?_⟩
  intro ⟨hm, _⟩
  exact not_mem_filter_ne hm

/-- If `o`'s root key is not with a key holder and `b` is an admin of `o`,
there is an accepted act that whoever controls the root key asks for, after
which `b` is not an admin of `o`. -/
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

/-- A planned check, under every rule, in one act. If the admin team's key of
`o` is with a key holder before and after an accepted act, and `b` holds a certificate of `o`'s admin team
before an accepted act and not after, some identity other than `b` is an admin
of `o` after it. A revocation can still leave the organisation with no admin
(`revocation_can_leave_no_admin`). -/
theorem key_holder_keeps_an_admin {ask : AskRule} {s s' : State} {who : Party} {o : Org}
    {b : Key} (hstep : Step ask s who s') (hheld : OrgKey.team o .admin ∈ s.held)
    (hheld' : OrgKey.team o .admin ∈ s'.held)
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
  | @rekeyTeam o' t _ _ _ _ =>
      by_cases he : o' = o ∧ t = .admin
      · obtain ⟨rfl, rfl⟩ := he
        have := (List.mem_filter.mp hheld').2
        simp at this
      · exact absurd (List.mem_filter.mpr ⟨hb, by
          simp only [decide_eq_true_eq]; exact Or.inl fun ⟨a, b⟩ => he ⟨a.symm, b.symm⟩⟩) hgone
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

/-- In one act. If `k` holds a certificate of team `t` of `o` before an
accepted act and not after, no grant on `k` from team `t` of `o` remains after
it. -/
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
  | @rekeyTeam o' t' _ _ _ _ =>
      intro g hg ⟨h1, h3, _⟩
      have h2 := (List.mem_filter.mp hg).2
      by_cases he : o = o' ∧ t = t'
      · obtain ⟨rfl, rfl⟩ := he
        simp [h1, h3] at h2
      · exact hgone (List.mem_filter.mpr ⟨hb, by
          simp only [decide_eq_true_eq]; exact Or.inl fun ⟨a, b⟩ => he ⟨a, b⟩⟩)
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

/-- If no rule of the policy is for `o`, every kind of act is approved for `o`
with no approvals. -/
theorem no_policy_no_approval {s : State} {o : Org}
    (h : ∀ r, r ∈ s.policy → r.org ≠ o) (act : ActKind) : Approved s o act [] := by
  intro r hr ho _
  exact absurd ho (h r hr)

/-! ## Who may ask for a person, as built and as designed -/

/-- If `k` is a person of `o` once one certificate is added, and was not
before, the added certificate is of `o`. -/
theorem Person.added_cert_org {s : State} {o : Org} {c : Cert} {k : Key}
    (hp : Person { s with certs := c :: s.certs } o k) (hold : ¬ Person s o k) :
    c.org = o := by
  induction hp with
  | byRoot hc ho hk hi hs =>
      rename_i d k'
      rcases List.mem_cons.mp hc with rfl | hd
      · exact ho
      · exact absurd (.byRoot hd ho hk hi hs) hold
  | byPerson hc ho hk hi hs hp' ih =>
      rename_i d k' p
      rcases List.mem_cons.mp hc with rfl | hd
      · exact ho
      · by_cases hpp : Person s o p
        · exact absurd (.byPerson hd ho hk hi hs hpp) hold
        · exact ih hpp

/-- As built, in one act. If an accepted act under the built rule makes
someone hold a chain of person certificates in organisation `o` who did not
before, the act added one person certificate of `o`, and one of three things
holds: whoever controls `o`'s root key asked directly, the key not being with
a key holder; or a valid person of `o` asked; or the root key is with a key
holder, a valid member of `o` asked, and approvals exist that satisfy `o`'s
policy for adding a person and include a valid person of `o`. The model does
not record which approvals an act carried; the act's premise is that such
approvals exist. -/
theorem built_person_needs_a_person {s s' : State} {who : Party} {o : Org} {k : Key}
    (hstep : Step builtRule s who s') (hnew : Person s' o k) (hold : ¬ Person s o k) :
    ∃ c, s'.certs = c :: s.certs ∧ c.kind = .person ∧ c.org = o ∧
      ((who = .controller (.root o) ∧ OrgKey.root o ∉ s.held) ∨
        (∃ p, who = .id p ∧ Valid s o p .person) ∨
        (∃ a kind approvals, who = .id a ∧ Valid s o a kind ∧ OrgKey.root o ∈ s.held ∧
          Approved s o .registerPerson approvals ∧ ∃ p, p ∈ approvals ∧ Valid s o p .person)) := by
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
  | rekeyTeam _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | replaceRoot _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | readmitByRoot _ _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | readmitByParent _ _ _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | sendOwn _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | sendGrant _ _ => exact absurd (hnew.of_certs_eq (t := s) rfl) hold
  | registerByRoot hi ho hf hauth =>
      rename_i c approvals
      cases hkind : c.kind with
      | agent => exact absurd (Person.of_cons_agent hkind hnew) hold
      | person =>
          have hco : c.org = o := Person.added_cert_org hnew hold
          subst hco
          rw [hkind] at hauth
          refine ⟨c, rfl, hkind, rfl, ?_⟩
          rcases hauth with ⟨hfree, hw⟩ | ⟨hheld, a, hw, ⟨_, hv | ⟨⟨r, hr, hro, hra, hrp⟩, kind, hv⟩⟩, happ⟩
          · exact .inl ⟨hw, hfree⟩
          · exact .inr (.inl ⟨a, hw, hv⟩)
          · have h := happ r hr hro hra
            rw [hrp] at h
            obtain ⟨q, hq, hqv⟩ := h
            exact .inr (.inr ⟨a, kind, approvals, hw, hv, hheld, happ, q, hq, hqv⟩)
  | registerByParent hi hf hv hmay =>
      rename_i c p pk
      cases hkind : c.kind with
      | agent => exact absurd (Person.of_cons_agent hkind hnew) hold
      | person =>
          have hco : c.org = o := Person.added_cert_org hnew hold
          subst hco
          rcases hmay with rfl | h
          · exact ⟨c, rfl, hkind, rfl, .inr (.inl ⟨p, rfl, hv⟩)⟩
          · rw [hkind] at h; cases h

/-- Design. There is a record the system reaches under the admin rule, and an
agent `a` valid in organisation 0, such that an act `a` asks for is accepted
and afterwards some `k` holds a chain of person certificates in 0 that it did
not hold before. In the construction the root key is with a key holder, `a` is
an admin, and the root is the new certificate's issuer. -/
theorem design_agent_admin_can_ask_for_person :
    ∃ (s s' : State) (a k : Key), Reachable adminRule s ∧
      Valid s 0 a .agent ∧ Step adminRule s (.id a) s' ∧ Person s' 0 k ∧ ¬ Person s 0 k := by
  let agentCert : Cert := ⟨0, 1, .agent, .root⟩
  let s : State := ⟨[0], [agentCert], [], [], [⟨0, .admin, 1⟩], [], [.root 0], [], [], []⟩
  let c : Cert := ⟨0, 2, .person, .root⟩
  have hvalid : Valid s 0 1 .agent :=
    .agentOfRoot (c := agentCert) (List.mem_cons_self) rfl rfl rfl rfl (by simp [s])
  have hadmin : Admin s 0 1 := ⟨List.mem_cons_self, .agent, hvalid⟩
  have hreach : Reachable adminRule s := by
    let e : State := ⟨[], [], [], [], [], [], [], [], [], []⟩
    let ma : Membership := ⟨0, .admin, 1⟩
    let s1 : State := { e with orgs := [0] }
    let s2 : State := { s1 with certs := [agentCert] }
    let s3 : State := { s2 with members := [ma] }
    have r1 : Reachable adminRule s1 := .step (.start []) (Step.createOrg (o := 0) (by simp))
    have r2 : Reachable adminRule s2 :=
      .step r1 (Step.registerByRoot (c := agentCert) (who := .controller (.root 0)) (approvals := [])
        rfl (by simp [s1, agentCert]) (by intro d hd; simp [s1, e] at hd)
        (.inl ⟨by simp [s1, e], rfl⟩))
    have v2 : Valid s2 0 1 .agent :=
      .agentOfRoot (c := agentCert) (by simp [s2]) rfl rfl rfl rfl (by simp [s2, s1, e])
    have r3 : Reachable adminRule s3 :=
      .step r2 (Step.admitAdmin (m := ma) (kind := .agent) (who := .controller (.team 0 .admin))
        (approvals := []) rfl v2 (.inl ⟨by simp [s2, s1, e], rfl⟩))
    exact .step r3 (Step.entrust (key := .root 0) (by simp [s3, s2, s1, e]))
  refine ⟨s, { s with certs := c :: s.certs }, 1, 2, hreach, hvalid, ?_, ?_, ?_⟩
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

theorem Authorised.not_dns {ask : AskRule} {s : State} {key : OrgKey} {act : ActKind}
    {o : Org} {approvals : List Key} : ¬ Authorised ask s key act (.dns o) approvals := by
  intro h
  rcases h with ⟨_, h⟩ | ⟨_, _, h, _⟩ <;> cases h

/-- In one act. If an act asked for by whoever holds session key `x` is
accepted, there is a grant with session key `x` that is live and may send, and
the record after the act is the record before with one message attributed to
the grant's subject added. -/
theorem session_only_sends {ask : AskRule} {s s' : State} {x : Key}
    (hstep : Step ask s (.session x) s') :
    ∃ g, g.session = x ∧ GrantLive s g ∧ g.maySend = true ∧
      s' = { s with sent := ⟨g.subject⟩ :: s.sent } := by
  cases hstep with
  | sendGrant hlive hsend =>
      rename_i g
      exact ⟨g, rfl, hlive, hsend, rfl⟩
  | registerByRoot _ _ _ h => exact absurd h Authorised.not_session
  | revokeByOrg _ h => exact absurd h Authorised.not_session
  | admit _ h _ => exact absurd h Authorised.not_session
  | admitAdmin _ _ h => exact absurd h Authorised.not_session
  | remove h _ => exact absurd h Authorised.not_session
  | invite _ h _ => exact absurd h Authorised.not_session
  | release _ h => exact absurd h Authorised.not_session
  | rekeyTeam h _ => exact absurd h Authorised.not_session
  | readmitByRoot _ _ _ h => exact absurd h Authorised.not_session

/-- In one act. If an act asked for by whoever holds secret `t` is accepted,
the identity certificates, revocations, grants and held keys are as before,
and each team certificate it adds is not of an admin team and is for the
organisation and team of an unused invitation with that secret. -/
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
  | rekeyTeam h _ => exact absurd h Authorised.not_bearer
  | readmitByRoot _ _ _ h => exact absurd h Authorised.not_bearer

/-- In one act. If an accepted act changes the messages, it added one message
`m`, and either the asker is `m`'s sender as an identity and can act, or the
asker holds the session key of a grant on `m`'s sender that is live and may
send. -/
theorem message_from_owner_or_live_grant {ask : AskRule} {s s' : State} {who : Party}
    (hstep : Step ask s who s') (hchg : s'.sent ≠ s.sent) :
    ∃ m, s'.sent = m :: s.sent ∧
      ((who = .id m.sender ∧ CanAct s m.sender) ∨
        ∃ g, who = .session g.session ∧ GrantLive s g ∧ g.subject = m.sender ∧ g.maySend = true) := by
  cases hstep with
  | createOrg _ => exact absurd rfl hchg
  | entrust _ => exact absurd rfl hchg
  | registerByRoot _ _ _ _ => exact absurd rfl hchg
  | registerByParent _ _ _ _ => exact absurd rfl hchg
  | revokeSelf _ => exact absurd rfl hchg
  | revokeChild _ _ _ => exact absurd rfl hchg
  | revokeByOrg _ _ => exact absurd rfl hchg
  | admit _ _ _ => exact absurd rfl hchg
  | admitAdmin _ _ _ => exact absurd rfl hchg
  | remove _ _ => exact absurd rfl hchg
  | leave _ _ _ => exact absurd rfl hchg
  | invite _ _ _ => exact absurd rfl hchg
  | redeem _ _ _ => exact absurd rfl hchg
  | mintGrant _ _ => exact absurd rfl hchg
  | revokeGrant _ => exact absurd rfl hchg
  | release _ _ => exact absurd rfl hchg
  | rekeyTeam _ _ => exact absurd rfl hchg
  | replaceRoot _ => exact absurd rfl hchg
  | readmitByRoot _ _ _ _ => exact absurd rfl hchg
  | readmitByParent _ _ _ _ => exact absurd rfl hchg
  | sendOwn hca =>
      rename_i k
      exact ⟨⟨k⟩, rfl, .inl ⟨rfl, hca⟩⟩
  | sendGrant hlive hsend =>
      rename_i g
      exact ⟨⟨g.subject⟩, rfl, .inr ⟨g, rfl, hlive, rfl, hsend⟩⟩

/-- In one act. If an accepted act adds a grant, the asker is its subject, as
an identity. -/
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
  | rekeyTeam _ _ => exact absurd (List.mem_filter.mp hnew).1 hold
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

/-- If only registered identities are revoked, and a grant's subject is
revoked or lacks the team certificate the grant came from, the grant is not
live. In every reachable record only registered identities are revoked
(`Reachable.revokedAreRegistered`). `revokeSelf`, `revokeChild` and
`revokeByOrg` and `replaceRoot` leave the grants as they are. -/
theorem grant_ends_with_subject {s : State} (hrr : RevokedAreRegistered s) {g : Grant}
    (h : g.subject ∈ s.revoked ∨ ¬ HasTeamCert s g.org g.team g.subject) : ¬ GrantLive s g := by
  intro ⟨_, hin⟩
  rcases h with hr | hc
  · exact (revoked_has_no_authority hrr hr).2 _ _ hin
  · exact hc hin.1

/-! ## Further results about one act -/

/-- In one act. If `k` is revoked and not cut off before an accepted act, it
is revoked and not cut off after it. -/
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
  | rekeyTeam _ _ => exact ⟨hk, hc⟩
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

/-- In one act. Every identity certificate in the record before an accepted
act is in it after. -/
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
  | rekeyTeam _ _ => exact hc
  | replaceRoot _ => exact hc
  | readmitByRoot _ _ _ _ => exact hc
  | readmitByParent _ _ _ _ => exact hc
  | sendOwn _ => exact hc
  | sendGrant _ _ => exact hc

/-- In one act. If an accepted act changes the identity certificates, it
leaves the team certificates as they were. -/
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
  | rekeyTeam _ _ => exact absurd rfl hreg
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

/-- In one act asked for by whoever controls an organisation's key: every new
identity certificate and every new or removed team certificate is of that
key's organisation, and every newly revoked identity has a certificate of it.
Nothing is stated about invitations, grants, held keys or identities admitted
again. -/
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
  | rekeyTeam hauth _ =>
      have hk := hauth.controller_eq
      subst hk
      refine ⟨fun _ h h' => absurd h h', fun _ h h' => absurd (List.mem_filter.mp h).1 h', ?_,
        fun _ h h' => absurd h h'⟩
      intro m hm hgone
      apply Classical.byContradiction
      intro hne
      exact hgone (List.mem_filter.mpr ⟨hm, by
        simp only [decide_eq_true_eq]; exact Or.inl fun ⟨h, _⟩ => hne h⟩)
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

/-! ## DNS, and leaving a key holder -/

/-- If `o` exists, there is an accepted act that `o`'s domain owner asks for,
after which `o`'s root key is not with a key holder and no identity is valid
in `o`. -/
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

/-- If `c` is a registered certificate issued by the root, its subject is cut
off, and the root key of `c`'s organisation is not with a key holder, there is
an accepted act that whoever controls that root key asks for, after which
`c`'s subject is valid in `c`'s organisation with `c`'s kind. -/
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

/-- In one act. If a key is with a key holder before an accepted act and not
after, the asker is the domain owner of the key's organisation; or an identity
the rule lets ask for giving a key back; or the key is a team key of that
organisation, and the asker is whoever controls its root key or an identity
the rule lets ask for a re-key. -/
theorem key_leaves_holder_only_three_ways {ask : AskRule} {s s' : State} {who : Party}
    {key : OrgKey} (hstep : Step ask s who s') (hin : key ∈ s.held) (hout : key ∉ s'.held) :
    who = .dns key.org ∨ (∃ k, who = .id k ∧ ask s key.org .release k) ∨
      ∃ t, key = .team key.org t ∧
        (who = .controller (.root key.org) ∨ ∃ k, who = .id k ∧ ask s key.org .rekey k) := by
  cases hstep with
  | @rekeyTeam o t _ _ _ hauth _ =>
      have hk : key = .team o t := by
        apply Decidable.byContradiction
        intro hne
        exact hout (List.mem_filter.mpr ⟨hin, by simpa using hne⟩)
      subst hk
      rcases hauth with ⟨_, hw⟩ | ⟨_, k, hw, hask, _⟩
      · exact .inr (.inr ⟨t, rfl, .inl hw⟩)
      · exact .inr (.inr ⟨t, rfl, .inr ⟨k, hw, hask⟩⟩)
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
      · exact .inr (.inl ⟨k, hw, hask⟩)

/-- As built, in one act. Under the built rule, if a key is with a key holder
before an accepted act and not after, the asker is the domain owner of the
key's organisation, or the key is a team key of that organisation and the
asker is whoever controls its root key. -/
theorem built_key_leaves_only_by_dns_or_root {s s' : State} {who : Party} {key : OrgKey}
    (hstep : Step builtRule s who s') (hin : key ∈ s.held) (hout : key ∉ s'.held) :
    who = .dns key.org ∨ ∃ t, key = .team key.org t ∧ who = .controller (.root key.org) := by
  rcases key_leaves_holder_only_three_ways hstep hin hout with
    h | ⟨_, _, hask⟩ | ⟨t, ht, hw | ⟨_, _, hask⟩⟩
  · exact .inl h
  · cases hask.1
  · exact .inr ⟨t, ht, hw⟩
  · cases hask.1

/-- In one act. If an act asked for by `o`'s domain owner is accepted, and a
key is with a key holder before it and not after, the key is `o`'s root key
and no identity is valid in `o` after the act. -/
theorem dns_takes_out_only_the_root {ask : AskRule} {s s' : State} {o : Org}
    {key : OrgKey} (hstep : Step ask s (.dns o) s') (hin : key ∈ s.held) (hout : key ∉ s'.held) :
    key = .root o ∧ ∀ k kind, ¬ Valid s' o k kind := by
  cases hstep with
  | createOrg _ => exact absurd hin hout
  | registerByRoot _ _ _ h => exact absurd h Authorised.not_dns
  | revokeByOrg _ h => exact absurd h Authorised.not_dns
  | admit _ h _ => exact absurd h Authorised.not_dns
  | admitAdmin _ _ h => exact absurd h Authorised.not_dns
  | remove h _ => exact absurd h Authorised.not_dns
  | invite _ h _ => exact absurd h Authorised.not_dns
  | release _ h => exact absurd h Authorised.not_dns
  | rekeyTeam h _ => exact absurd h Authorised.not_dns
  | readmitByRoot _ _ _ h => exact absurd h Authorised.not_dns
  | replaceRoot ho =>
      refine ⟨?_, ?_⟩
      · apply Decidable.byContradiction
        intro hne
        exact hout (List.mem_filter.mpr ⟨hin, by simpa using hne⟩)
      · intro k kind hv
        obtain ⟨c, hc, hcs, _, hco⟩ := hv.cert
        refine revoked_not_valid ?_ hv
        by_cases hr : k ∈ s.revoked
        · exact List.mem_append_right _ hr
        · refine List.mem_append_left _ (List.mem_map.mpr ⟨c, List.mem_filter.mpr ⟨hc, ?_⟩, hcs⟩)
          simp [hco, hcs, hr]

/-- Design. If a key is with a key holder, `a` is an admin of its
organisation, and the approvals satisfy that organisation's policy for giving
a key back, there is an accepted act under the admin rule that `a` asks for,
after which the key is not with a key holder and the identity certificates,
revocations and team certificates are as before. -/
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

/-- If `h` answers for `a` in `o`, `h` is a valid person of `o`. -/
theorem answerer_is_valid_person {s : State} {o : Org} {a h : Key}
    (ha : AnswersFor s o a h) : Valid s o h .person := by
  induction ha with
  | self hv => exact hv
  | up _ _ _ _ _ _ _ ih => exact ih

/-- If every identity has one certificate and `h` and `h'` both answer for `a`
in `o`, `h` is `h'`. -/
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

/-- If every identity has at most one certificate before an accepted act, the
same holds after it. -/
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
  | rekeyTeam _ _ => exact h1
  | replaceRoot _ => exact h1
  | readmitByRoot _ _ _ _ => exact h1
  | readmitByParent _ _ _ _ => exact h1
  | sendOwn _ => exact h1
  | sendGrant _ _ => exact h1

/-- If only registered identities are revoked before an accepted act, the same
holds after it. -/
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
  | rekeyTeam _ _ => exact h
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

/-- If every unregistered identity holds at most one team certificate before
an accepted act, the same holds after it. -/
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
  | rekeyTeam _ _ => exact sub _
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

/-- In every reachable record every identity has at most one certificate. -/
theorem Reachable.oneCertEach {ask : AskRule} {s : State} (hr : Reachable ask s) : OneCertEach s := by
  induction hr with
  | start _ => intro c hc; cases hc
  | step _ hstep ih => exact hstep.oneCertEach ih

/-- In every reachable record only registered identities are revoked. -/
theorem Reachable.revokedAreRegistered {ask : AskRule} {s : State} (hr : Reachable ask s) :
    RevokedAreRegistered s := by
  induction hr with
  | start _ => intro k hk; cases hk
  | step _ hstep ih => exact hstep.revokedAreRegistered ih

/-- In every reachable record every unregistered identity holds at most one
team certificate. -/
theorem Reachable.localInOneTeam {ask : AskRule} {s : State} (hr : Reachable ask s) :
    LocalInOneTeam s := by
  induction hr with
  | start _ => intro m hm; cases hm
  | step _ hstep ih => exact hstep.localInOneTeam ih

/-- In every reachable record every cut-off identity is revoked. -/
theorem Reachable.cutOffAreRevoked {ask : AskRule} {s : State} (hr : Reachable ask s) :
    ∀ k, k ∈ s.cutOff → k ∈ s.revoked := by
  induction hr with
  | start _ => intro k hk; cases hk
  | step _ hstep ih =>
      rename_i t t' _ _
      have flt : ∀ j k, k ∈ t.cutOff.filter (fun x => decide (x ≠ j)) →
          k ∈ t.revoked.filter (fun x => decide (x ≠ j)) := by
        intro j k hk
        have h := List.mem_filter.mp hk
        exact List.mem_filter.mpr ⟨ih k h.1, h.2⟩
      have rev : ∀ j k, k ∈ t.cutOff.filter (fun x => decide (x ≠ j)) → k ∈ j :: t.revoked :=
        fun j k hk => List.mem_cons_of_mem _ (ih k (List.mem_filter.mp hk).1)
      cases hstep with
      | readmitByRoot _ _ _ _ => exact flt _
      | readmitByParent _ _ _ _ => exact flt _
      | revokeSelf _ => exact rev _
      | revokeChild _ _ _ => exact rev _
      | revokeByOrg _ _ => exact rev _
      | replaceRoot _ =>
          intro k hk
          rcases List.mem_append.mp hk with h | h
          · exact List.mem_append_left _ h
          · exact List.mem_append_right _ (ih k h)
      | createOrg _ => exact ih
      | entrust _ => exact ih
      | registerByRoot _ _ _ _ => exact ih
      | registerByParent _ _ _ _ => exact ih
      | admit _ _ _ => exact ih
      | admitAdmin _ _ _ => exact ih
      | remove _ _ => exact ih
      | leave _ _ _ => exact ih
      | invite _ _ _ => exact ih
      | redeem _ _ _ => exact ih
      | mintGrant _ _ => exact ih
      | revokeGrant _ => exact ih
      | release _ _ => exact ih
      | rekeyTeam _ _ => exact ih
      | sendOwn _ => exact ih
      | sendGrant _ _ => exact ih

/-- In one act. If a key is with a key holder after an accepted act and not
before, the asker is whoever controls that key, and the record after is the
record before with that key held. -/
theorem only_entrust_puts_a_key_with_a_holder {ask : AskRule} {s s' : State} {who : Party}
    {key : OrgKey} (hstep : Step ask s who s') (hin : key ∈ s'.held) (hout : key ∉ s.held) :
    who = .controller key ∧ s' = { s with held := key :: s.held } := by
  cases hstep with
  | entrust _ =>
      rename_i key'
      rcases List.mem_cons.mp hin with rfl | h
      · exact ⟨rfl, rfl⟩
      · exact absurd h hout
  | replaceRoot _ => exact absurd (List.mem_filter.mp hin).1 hout
  | release _ _ => exact absurd (List.mem_filter.mp hin).1 hout
  | rekeyTeam _ _ => exact absurd (List.mem_filter.mp hin).1 hout
  | createOrg _ => exact absurd hin hout
  | readmitByRoot _ _ _ _ => exact absurd hin hout
  | readmitByParent _ _ _ _ => exact absurd hin hout
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
  | sendOwn _ => exact absurd hin hout
  | sendGrant _ _ => exact absurd hin hout

/-- In every reachable record in which a key is with a key holder, there is a
reachable record in which it is not, from which an act asked for by whoever
controls the key puts it with a key holder. -/
theorem held_key_was_entrusted {ask : AskRule} {s : State} (hr : Reachable ask s)
    {key : OrgKey} (hk : key ∈ s.held) :
    ∃ t, Reachable ask t ∧ key ∉ t.held ∧
      Step ask t (.controller key) { t with held := key :: t.held } := by
  induction hr with
  | start _ => cases hk
  | step hr' hstep ih =>
      rename_i t t' _
      by_cases hold : key ∈ t.held
      · exact ih hold
      · obtain ⟨hw, he⟩ := only_entrust_puts_a_key_with_a_holder hstep hk hold
        subst hw
        exact ⟨t, hr', hold, he ▸ hstep⟩

end TrustWeb
