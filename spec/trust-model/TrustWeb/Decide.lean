import TrustWeb.Model

/-!
# Deciding the model's conditions

A decision for every condition the acts check, each proved to agree with the
model's definition. `Person` and `Valid` follow chains of certificates, which
can loop in an arbitrary record; a chain that repeats a certificate can be
shortened, so a search as long as the list of certificates decides them.
-/

namespace TrustWeb

/-! ## Chains of certificates -/

section Chains

variable (certs : List Cert) (ok base : Cert → Prop)

/-- `CertChain certs ok base k l`: `l` is a chain of certificates from `certs`,
each meeting `ok`, from `k` upward through each certificate's issuer, whose
last certificate meets `base`. -/
inductive CertChain : Key → List Cert → Prop where
  | base {c : Cert} {k : Key} :
      c ∈ certs → ok c → c.subject = k → base c → CertChain k [c]
  | link {c : Cert} {k p : Key} {l : List Cert} :
      c ∈ certs → ok c → c.subject = k → c.issuer = .member p → CertChain p l →
      CertChain k (c :: l)

/-- The search for a chain from `k` of at most `n` certificates. -/
def chainB [DecidablePred ok] [DecidablePred base] : Nat → Key → Bool
  | 0, _ => false
  | n + 1, k => certs.any fun c =>
      decide (ok c) && decide (c.subject = k) &&
        (decide (base c) ||
          match c.issuer with
          | .root => false
          | .member p => chainB n p)

variable {certs ok base}

theorem CertChain.subset {k : Key} {l : List Cert} (h : CertChain certs ok base k l) :
    ∀ c, c ∈ l → c ∈ certs := by
  induction h with
  | base hc =>
    intro c hm
    simp at hm
    exact hm ▸ hc
  | link hc _ _ _ _ ih =>
    intro c hm
    simp at hm
    rcases hm with rfl | hm
    · exact hc
    · exact ih c hm

theorem CertChain.ne_nil {k : Key} {l : List Cert} (h : CertChain certs ok base k l) : l ≠ [] := by
  cases h <;> simp

/-- A certificate on a chain starts a chain of its own, a suffix of it. -/
theorem CertChain.suffix_at {k : Key} {l : List Cert} (h : CertChain certs ok base k l) :
    ∀ c, c ∈ l → ∃ l', CertChain certs ok base c.subject l' ∧ l' <:+ l := by
  induction h with
  | base hc hok _ hb =>
    intro c hm
    simp at hm
    subst hm
    exact ⟨_, .base hc hok rfl hb, List.suffix_refl _⟩
  | link hc hok _ hi hl ih =>
    intro c hm
    simp at hm
    rcases hm with rfl | hm
    · exact ⟨_, .link hc hok rfl hi hl, List.suffix_refl _⟩
    · obtain ⟨l', h', hsuf⟩ := ih c hm
      exact ⟨l', h', hsuf.trans (List.suffix_cons _ _)⟩

/-- Every chain can be shortened to one with no certificate twice. -/
theorem CertChain.nodup_of {k : Key} {l : List Cert} (h : CertChain certs ok base k l) :
    ∃ l', CertChain certs ok base k l' ∧ l'.Nodup := by
  induction h with
  | base hc hok hs hb => exact ⟨_, .base hc hok hs hb, by simp⟩
  | link hc hok hs hi hl ih =>
    rename_i c0 k0 p0 l0
    obtain ⟨l', h', hnd⟩ := ih
    by_cases hm : c0 ∈ l'
    · obtain ⟨l'', h'', hsuf⟩ := h'.suffix_at c0 hm
      exact ⟨l'', hs ▸ h'', hnd.sublist hsuf.sublist⟩
    · exact ⟨_, .link hc hok hs hi h', List.nodup_cons.2 ⟨hm, hnd⟩⟩

theorem chainB_iff_bounded [DecidablePred ok] [DecidablePred base] : ∀ n k,
    chainB certs ok base n k = true ↔ ∃ l, CertChain certs ok base k l ∧ l.length ≤ n := by
  intro n
  induction n with
  | zero =>
    intro k
    simp only [chainB, Bool.false_eq_true, false_iff, not_exists, not_and]
    intro l h hlen
    exact h.ne_nil (List.eq_nil_of_length_eq_zero (by omega))
  | succ n ih =>
    intro k
    simp only [chainB, List.any_eq_true, Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq]
    constructor
    · rintro ⟨c, hc, ⟨hok, hs⟩, hb | hi⟩
      · exact ⟨[c], .base hc hok hs hb, by simp⟩
      · cases hcase : c.issuer with
        | root => rw [hcase] at hi; simp at hi
        | member p =>
          rw [hcase] at hi
          obtain ⟨l, hl, hlen⟩ := (ih p).1 hi
          exact ⟨c :: l, .link hc hok hs hcase hl, by simp; omega⟩
    · rintro ⟨l, hl, hlen⟩
      cases hl with
      | base hc hok hs hb => exact ⟨_, hc, ⟨hok, hs⟩, Or.inl hb⟩
      | link hc hok hs hi hl' =>
        refine ⟨_, hc, ⟨hok, hs⟩, Or.inr ?_⟩
        rw [hi]
        exact (ih _).2 ⟨_, hl', by simp at hlen; omega⟩

/-- A search as long as the list of certificates finds a chain if there is one. -/
theorem chainB_iff [DecidablePred ok] [DecidablePred base] {k : Key} :
    chainB certs ok base certs.length k = true ↔ ∃ l, CertChain certs ok base k l := by
  rw [chainB_iff_bounded]
  constructor
  · rintro ⟨l, hl, -⟩
    exact ⟨l, hl⟩
  · rintro ⟨l, hl⟩
    obtain ⟨l', hl', hnd⟩ := hl.nodup_of
    exact ⟨l', hl', hnd.length_le_of_subset hl'.subset⟩

instance CertChain.decidableExists [DecidablePred ok] [DecidablePred base] (k : Key) : Decidable (∃ l, CertChain certs ok base k l) :=
  decidable_of_iff _ chainB_iff

end Chains

/-! ## Persons and valid identities -/

/-- `Person` is a chain of person certificates of `o` ending at the root. -/
theorem person_iff_chain {s : State} {o : Org} {k : Key} :
    Person s o k ↔ ∃ l, CertChain s.certs (fun c => c.org = o ∧ c.kind = .person)
      (fun c => c.issuer = .root) k l := by
  constructor
  · intro h
    induction h with
    | byRoot hc ho hk hi hs => exact ⟨_, .base hc ⟨ho, hk⟩ hs hi⟩
    | byPerson hc ho hk hi hs _ ih =>
      obtain ⟨l, hl⟩ := ih
      exact ⟨_, .link hc ⟨ho, hk⟩ hs hi hl⟩
  · rintro ⟨l, hl⟩
    induction hl with
    | base hc hok hs hb => exact .byRoot hc hok.1 hok.2 hb hs
    | link hc hok hs hi _ ih => exact .byPerson hc hok.1 hok.2 hi hs ih

instance Person.decidable (s : State) (o : Org) (k : Key) : Decidable (Person s o k) :=
  decidable_of_iff _ person_iff_chain.symm

theorem valid_person_iff {s : State} {o : Org} {k : Key} :
    Valid s o k .person ↔ Person s o k ∧ k ∉ s.revoked := by
  constructor
  · intro h
    cases h with
    | person hp hr => exact ⟨hp, hr⟩
  · rintro ⟨hp, hr⟩
    exact .person hp hr

instance Valid.decidablePerson (s : State) (o : Org) (k : Key) : Decidable (Valid s o k .person) :=
  decidable_of_iff _ valid_person_iff.symm

/-- The last certificate of an agent's chain: issued by the root, or by a
valid person of the organisation. -/
def agentBase (s : State) (o : Org) (c : Cert) : Prop :=
  match c.issuer with
  | .root => True
  | .member p => Valid s o p .person

instance agentBase.decidable (s : State) (o : Org) : DecidablePred (agentBase s o) := by
  intro c
  unfold agentBase
  cases c.issuer with
  | root => exact instDecidableTrue
  | member p => exact Valid.decidablePerson s o p

/-- A valid agent is a chain of unrevoked agent certificates of `o` ending at
one issued by the root or by a valid person. -/
theorem valid_agent_iff_chain {s : State} {o : Org} {k : Key} :
    Valid s o k .agent ↔ ∃ l, CertChain s.certs
      (fun c => c.org = o ∧ c.kind = .agent ∧ c.subject ∉ s.revoked) (agentBase s o) k l := by
  constructor
  · intro h
    have key : ∀ kind, Valid s o k kind → kind = .agent → ∃ l, CertChain s.certs
        (fun c => c.org = o ∧ c.kind = .agent ∧ c.subject ∉ s.revoked) (agentBase s o) k l := by
      intro kind hv
      induction hv with
      | person => intro h; cases h
      | agentOfRoot hc ho hk hi hs hr =>
        intro _
        exact ⟨_, .base hc ⟨ho, hk, hs ▸ hr⟩ hs (by simp [agentBase, hi])⟩
      | agentOf hc ho hk hi hs hr hp ih =>
        rename_i c0 k0 p0 pk0
        intro _
        cases pk0 with
        | person => exact ⟨_, .base hc ⟨ho, hk, hs ▸ hr⟩ hs (by simp [agentBase, hi]; exact hp)⟩
        | agent =>
          obtain ⟨l, hl⟩ := ih hp rfl
          exact ⟨_, .link hc ⟨ho, hk, hs ▸ hr⟩ hs hi hl⟩
    exact key _ h rfl
  · rintro ⟨l, hl⟩
    induction hl with
    | base hc hok hs hb =>
      rename_i c0 k0
      unfold agentBase at hb
      cases hi : c0.issuer with
      | root => exact .agentOfRoot hc hok.1 hok.2.1 hi hs (hs ▸ hok.2.2)
      | member p =>
        rw [hi] at hb
        exact .agentOf hc hok.1 hok.2.1 hi hs (hs ▸ hok.2.2) hb
    | link hc hok hs hi _ ih => exact .agentOf hc hok.1 hok.2.1 hi hs (hs ▸ hok.2.2) ih

instance Valid.decidable (s : State) (o : Org) (k : Key) : (kind : Kind) → Decidable (Valid s o k kind)
  | .person => Valid.decidablePerson s o k
  | .agent => decidable_of_iff _ valid_agent_iff_chain.symm

/-! ## The other conditions -/

theorem exists_kind_iff {P : Kind → Prop} : (∃ kind, P kind) ↔ P .person ∨ P .agent := by
  constructor
  · rintro ⟨kind, h⟩
    cases kind
    · exact Or.inl h
    · exact Or.inr h
  · rintro (h | h)
    · exact ⟨_, h⟩
    · exact ⟨_, h⟩

instance existsKind.decidable (P : Kind → Prop) [DecidablePred P] : Decidable (∃ kind, P kind) :=
  decidable_of_iff _ exists_kind_iff.symm

instance Registered.decidable (s : State) (k : Key) : Decidable (Registered s k) := by
  unfold Registered
  infer_instance

instance HasTeamCert.decidable (s : State) (o : Org) (t : Team) (k : Key) :
    Decidable (HasTeamCert s o t k) := by
  unfold HasTeamCert
  infer_instance

/-- A valid identity holds a certificate of its organisation. -/
theorem Valid.has_cert {s : State} {o : Org} {k : Key} {kind : Kind} (h : Valid s o k kind) :
    ∃ c, c ∈ s.certs ∧ c.subject = k ∧ c.org = o := by
  cases h with
  | person hp _ =>
    cases hp with
    | byRoot hc ho _ _ hs => exact ⟨_, hc, hs, ho⟩
    | byPerson hc ho _ _ hs _ => exact ⟨_, hc, hs, ho⟩
  | agentOfRoot hc ho _ _ hs _ => exact ⟨_, hc, hs, ho⟩
  | agentOf hc ho _ _ hs _ _ => exact ⟨_, hc, hs, ho⟩

theorem valid_somewhere_iff {s : State} {k : Key} :
    (∃ o kind, Valid s o k kind) ↔
      ∃ c, c ∈ s.certs ∧ (c.subject = k ∧ (Valid s c.org k .person ∨ Valid s c.org k .agent)) := by
  constructor
  · rintro ⟨o, kind, h⟩
    obtain ⟨c, hc, hs, ho⟩ := h.has_cert
    refine ⟨c, hc, hs, ?_⟩
    rw [ho]
    exact exists_kind_iff.1 ⟨kind, h⟩
  · rintro ⟨c, -, -, h⟩
    exact ⟨c.org, exists_kind_iff.2 h⟩

instance CanAct.decidable (s : State) (k : Key) : Decidable (CanAct s k) :=
  decidable_of_iff (¬ Registered s k ∨ ∃ c, c ∈ s.certs ∧
      (c.subject = k ∧ (Valid s c.org k .person ∨ Valid s c.org k .agent)))
    (by unfold CanAct; rw [valid_somewhere_iff])

instance InTeam.decidable (s : State) (o : Org) (t : Team) (k : Key) : Decidable (InTeam s o t k) := by
  unfold InTeam
  infer_instance

instance Admin.decidable (s : State) (o : Org) (k : Key) : Decidable (Admin s o k) := by
  unfold Admin
  infer_instance

instance Fresh.decidable (s : State) (k : Key) : Decidable (Fresh s k) := by
  unfold Fresh
  infer_instance

instance OneTeamIfLocal.decidable (s : State) (k : Key) : Decidable (OneTeamIfLocal s k) := by
  unfold OneTeamIfLocal
  infer_instance

theorem keepsAnAdmin_iff {s : State} {m : Membership} :
    KeepsAnAdmin s m ↔ (m.team = .admin →
      ∃ x, x ∈ s.members ∧ (x.org = m.org ∧ x.team = .admin ∧ x.member ≠ m.member ∧
        Admin s m.org x.member)) := by
  unfold KeepsAnAdmin
  constructor
  · intro h ht
    obtain ⟨k, hk, ha⟩ := h ht
    exact ⟨_, ha.1, rfl, rfl, hk, ha⟩
  · intro h ht
    obtain ⟨x, -, -, -, hne, ha⟩ := h ht
    exact ⟨_, hne, ha⟩

instance KeepsAnAdmin.decidable (s : State) (m : Membership) : Decidable (KeepsAnAdmin s m) :=
  decidable_of_iff _ keepsAnAdmin_iff.symm

instance MayIssue.decidable (a b : Kind) : Decidable (MayIssue a b) := by
  unfold MayIssue
  infer_instance

instance Satisfies.decidable (s : State) (o : Org) (approvals : List Key) :
    (a : Approver) → Decidable (Satisfies s o approvals a)
  | .anyPerson => by unfold Satisfies; infer_instance
  | .exactly k => by unfold Satisfies; infer_instance

instance Approved.decidable (s : State) (o : Org) (act : ActKind) (approvals : List Key) :
    Decidable (Approved s o act approvals) := by
  unfold Approved
  infer_instance

/-- An ask rule with a decision for every case. -/
class AskDecidable (ask : AskRule) where
  dec : ∀ s o act k, Decidable (ask s o act k)

instance AskDecidable.inst (ask : AskRule) [h : AskDecidable ask] (s : State) (o : Org)
    (act : ActKind) (k : Key) : Decidable (ask s o act k) := h.dec s o act k

theorem authorised_iff {ask : AskRule} {s : State} {key : OrgKey} {act : ActKind} {who : Party}
    {approvals : List Key} :
    Authorised ask s key act who approvals ↔
      (key ∉ s.held ∧ who = .controller key) ∨
      (key ∈ s.held ∧ match who with
        | .id k => ask s key.org act k ∧ Approved s key.org act approvals
        | _ => False) := by
  unfold Authorised
  cases who <;> simp

instance Authorised.decidable (ask : AskRule) [AskDecidable ask] (s : State) (key : OrgKey)
    (act : ActKind) (who : Party) (approvals : List Key) :
    Decidable (Authorised ask s key act who approvals) := by
  rw [authorised_iff]
  cases who <;> simp only <;> infer_instance

instance builtRule.askDecidable : AskDecidable builtRule where
  dec s o act k := by unfold builtRule; infer_instance

instance adminRule.askDecidable : AskDecidable adminRule where
  dec s o act k := by unfold adminRule; infer_instance

instance GrantLive.decidable (s : State) (g : Grant) : Decidable (GrantLive s g) := by
  unfold GrantLive
  infer_instance

end TrustWeb
