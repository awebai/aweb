import TrustWeb.Model

/-!
# Standing statements and the change feed (Design)

A layer beside the model; it changes nothing in it. A registry signs that a
fact of its record holds at a cut, until a deadline, depending on some handles.
Each change that ends a fact publishes, in an ordered feed, a handle the fact
depended on. A verifier admits a request on a statement from what it has
applied of the feed, its last barrier's time and its clock alone. Time and
delivery are predicates: the cuts, times and the verifier's applied point are
parameters, and the premises the real registry must meet are named.
-/

namespace TrustWeb

/-- A dependency handle the registry mints. -/
abbrev Handle := Nat

/-- A fact a registry attests: `team o t k`, that `k` can act in team `t` of
`o`; `identity o k kind`, that `k` is valid in `o` as a `kind`. -/
inductive Fact where
  | team (o : Org) (t : Team) (k : Key)
  | identity (o : Org) (k : Key) (kind : Kind)
  deriving DecidableEq, Repr

/-- The identity a fact is about. -/
def Fact.subject : Fact → Key
  | .team _ _ k => k
  | .identity _ k _ => k

/-- The fact holds in a record: `InTeam` for a team fact, `Valid` for an
identity fact. -/
def Fact.Holds (s : State) : Fact → Prop
  | .team o t k => InTeam s o t k
  | .identity o k kind => Valid s o k kind

/-- What a statement is for: ordinary standing, or current evidence for one
exact request (its digest), with a nonce that is used once. -/
inductive Purpose where
  | ordinary
  | current (digest nonce : Nat)
  deriving DecidableEq, Repr

/-- A statement the registry signs: `fact` holds at cut `cut`, it is good
until `expiry` (exclusive), and it depends on the handles `deps`. -/
structure Statement where
  fact : Fact
  cut : Nat
  expiry : Nat
  deps : List Handle
  purpose : Purpose
  deriving DecidableEq, Repr

/-- A registry: its record at each cut, the issuer time each cut committed
at, the handles a fact depends on at each cut, and the handles the change at
each cut retires (its feed entry). -/
structure Registry where
  record : Nat → State
  time : Nat → Nat
  handles : Nat → Fact → List Handle
  feed : Nat → List Handle

/-- The bounds: an ordinary statement's lifetime, current evidence's
lifetime, and the oldest a verifier's last applied barrier may be. -/
structure Bounds where
  life : Nat
  current : Nat
  feedAge : Nat

/-- The lifetime a purpose allows. -/
def Purpose.life (b : Bounds) : Purpose → Nat
  | .ordinary => b.life
  | .current _ _ => b.current

/-- The registry issued `st`: its fact holds in the record at its cut, its
handles are the fact's handles at that cut, and its expiry is at most the
cut's time plus the lifetime its purpose allows. -/
def Issued (R : Registry) (b : Bounds) (st : Statement) : Prop :=
  st.fact.Holds (R.record st.cut) ∧ st.deps = R.handles st.cut st.fact ∧
    st.expiry ≤ R.time st.cut + st.purpose.life b

/-- What a verifier decides from: the last cut of the feed it has applied,
the issuer time of its last applied barrier, an upper bound on the issuer's
time now, and the nonces of current evidence it has used. -/
structure Verifier where
  applied : Nat
  barrier : Nat
  now : Nat
  consumed : List Nat

/-- A request: who signed it, the fact it relies on, and its digest. -/
structure Request where
  signer : Key
  fact : Fact
  digest : Nat

/-- An entry the verifier has applied, after the statement's cut, retires one
of the statement's handles. -/
def Defeated (R : Registry) (v : Verifier) (st : Statement) : Prop :=
  ∃ j, st.cut < j ∧ j ≤ v.applied ∧ ∃ x, x ∈ R.feed j ∧ x ∈ st.deps

/-- An ordinary statement fits any request; current evidence fits only the
request with its digest, and only while its nonce is unused. -/
def Purpose.Fits (v : Verifier) (r : Request) : Purpose → Prop
  | .ordinary => True
  | .current d n => d = r.digest ∧ n ∉ v.consumed

/-- The verifier admits `r` on `st`: the statement is for the request's fact,
the request is signed by the fact's subject, the verifier has applied the
statement's cut, its clock is before the expiry and before the last barrier's
time plus the feed bound, no applied entry defeats the statement, and its
purpose fits. Nothing in it records which statements the verifier has seen. -/
def Admits (R : Registry) (b : Bounds) (v : Verifier) (r : Request) (st : Statement) : Prop :=
  st.fact = r.fact ∧ r.signer = st.fact.subject ∧ st.cut ≤ v.applied ∧
    v.now < st.expiry ∧ v.now < v.barrier + b.feedAge ∧ ¬ Defeated R v st ∧
    st.purpose.Fits v r

/-- The verifier after the effect admitted with a statement of this purpose:
current evidence's nonce is used. -/
def Purpose.consume (v : Verifier) : Purpose → Verifier
  | .ordinary => v
  | .current _ n => { v with consumed := n :: v.consumed }

/-- The feed premise: if a fact holds at cut `n` and not at a later cut `m`,
some change after `n` and at or before `m` retires one of its handles at `n`. -/
def FeedComplete (R : Registry) : Prop :=
  ∀ f n m, n ≤ m → f.Holds (R.record n) → ¬ f.Holds (R.record m) →
    ∃ j, n < j ∧ j ≤ m ∧ ∃ x, x ∈ R.feed j ∧ x ∈ R.handles n f

/-- The time premise: a later cut never committed at an earlier time. -/
def TimeMonotone (R : Registry) : Prop :=
  ∀ i j, i ≤ j → R.time i ≤ R.time j

/-- The barrier premise: the verifier's last applied barrier was observed no
later than the change after its applied cut committed. -/
def BarrierBefore (R : Registry) (v : Verifier) : Prop :=
  v.barrier ≤ R.time (v.applied + 1)

/-! ## The rules -/

/-- A statement creates no authority: the registry issues one only where its
fact holds at its cut. -/
theorem issued_fact_holds {R : Registry} {b : Bounds} {st : Statement}
    (h : Issued R b st) : st.fact.Holds (R.record st.cut) := h.1

/-- A statement creates no authority: a verifier admits a request only for
the statement's own fact, signed by that fact's subject, and, under the feed
premise, only if the fact holds in the record at the verifier's applied cut. -/
theorem admitted_fact_holds_at_applied {R : Registry} {b : Bounds} {v : Verifier}
    {r : Request} {st : Statement} (hfeed : FeedComplete R) (hst : Issued R b st)
    (ha : Admits R b v r st) :
    st.fact = r.fact ∧ r.signer = r.fact.subject ∧ r.fact.Holds (R.record v.applied) := by
  obtain ⟨hf, hs, hcut, -, -, hnd, -⟩ := ha
  refine ⟨hf, hf ▸ hs, ?_⟩
  rw [← hf]
  apply Classical.byContradiction
  intro hno
  obtain ⟨j, hj1, hj2, x, hx, hxd⟩ := hfeed st.fact st.cut v.applied hcut hst.1 hno
  exact hnd ⟨j, hj1, hj2, x, hx, hst.2.1 ▸ hxd⟩

/-- Expiry bounds a statement: a verifier admits on it only before its expiry,
so for an issued statement before its cut's time plus its lifetime. -/
theorem admitted_before_expiry {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} (hst : Issued R b st) (ha : Admits R b v r st) :
    v.now < st.expiry ∧ v.now < R.time st.cut + st.purpose.life b :=
  ⟨ha.2.2.2.1, Nat.lt_of_lt_of_le ha.2.2.2.1 hst.2.2⟩

/-- The expiry is exclusive: at it, nothing is admitted. -/
theorem not_admitted_at_expiry {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} (h : st.expiry ≤ v.now) : ¬ Admits R b v r st :=
  fun ha => Nat.lt_irrefl _ (Nat.lt_of_lt_of_le ha.2.2.2.1 h)

/-- An applied entry that retires one of a statement's handles defeats it,
on any presentation. -/
theorem defeated_not_admitted {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} (h : Defeated R v st) : ¬ Admits R b v r st :=
  fun ha => ha.2.2.2.2.2.1 h

/-- Under the feed premise, a statement whose fact has stopped holding at some
cut from its own up to the verifier's applied cut is not admitted. -/
theorem ended_fact_not_admitted {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} {m : Nat} (hfeed : FeedComplete R) (hst : Issued R b st)
    (hm1 : st.cut ≤ m) (hm2 : m ≤ v.applied) (hend : ¬ st.fact.Holds (R.record m)) :
    ¬ Admits R b v r st := by
  obtain ⟨j, hj1, hj2, x, hx, hxd⟩ := hfeed st.fact st.cut m hm1 hst.1 hend
  exact defeated_not_admitted ⟨j, hj1, Nat.le_trans hj2 hm2, x, hx, hst.2.1 ▸ hxd⟩

/-- A statement from a cut the verifier has not applied is not admitted. -/
theorem ahead_not_admitted {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} (h : v.applied < st.cut) : ¬ Admits R b v r st :=
  fun ha => Nat.lt_irrefl _ (Nat.lt_of_lt_of_le h ha.2.2.1)

/-- An applied feed point older than the bound refuses. -/
theorem stale_feed_not_admitted {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} (h : v.barrier + b.feedAge ≤ v.now) : ¬ Admits R b v r st :=
  fun ha => Nat.lt_irrefl _ (Nat.lt_of_lt_of_le ha.2.2.2.2.1 h)

/-- The removal bound: under the feed, time and barrier premises, once the
verifier's clock is at least the feed bound past the time of a cut at which an
issued statement's fact no longer holds, the statement is not admitted, whether
or not the verifier has applied that cut. -/
theorem removal_bound {R : Registry} {b : Bounds} {v : Verifier} {r : Request}
    {st : Statement} {m : Nat} (hfeed : FeedComplete R) (htime : TimeMonotone R)
    (hbar : BarrierBefore R v) (hst : Issued R b st) (hm : st.cut ≤ m)
    (hend : ¬ st.fact.Holds (R.record m)) (hnow : R.time m + b.feedAge ≤ v.now) :
    ¬ Admits R b v r st := by
  by_cases happ : m ≤ v.applied
  · exact ended_fact_not_admitted hfeed hst hm happ hend
  · have h1 : v.applied + 1 ≤ m := by omega
    have h2 := htime _ _ h1
    exact stale_feed_not_admitted (by unfold BarrierBefore at hbar; omega)

/-- Current evidence is bound to one exact request: it is admitted only for the
request with its digest. -/
theorem current_needs_its_request {R : Registry} {b : Bounds} {v : Verifier}
    {r : Request} {st : Statement} {d n : Nat} (hp : st.purpose = .current d n)
    (ha : Admits R b v r st) : r.digest = d := by
  have h := ha.2.2.2.2.2.2
  rw [hp] at h
  exact h.1.symm

/-- Current evidence is used once: after the effect it admitted, the same
evidence is admitted for no request. -/
theorem current_used_once {R : Registry} {b : Bounds} {v : Verifier} {r' : Request}
    {st : Statement} {d n : Nat} (hp : st.purpose = .current d n) :
    ¬ Admits R b (st.purpose.consume v) r' st := by
  intro ha
  have h := ha.2.2.2.2.2.2
  rw [hp] at h
  exact h.2 (by simp [Purpose.consume])

/-- Authority creation checks fresh: current evidence issued at the registry's
cut `head` needs its fact to hold there, so a change at or before `head` that
ended the fact (and nothing after it restored) leaves no evidence to issue. -/
theorem current_not_issued_where_fact_fails {R : Registry} {b : Bounds} {st : Statement}
    {head : Nat} (hcut : st.cut = head) (hend : ¬ st.fact.Holds (R.record head)) :
    ¬ Issued R b st :=
  fun h => hend (hcut ▸ h.1)

/-! ## Paired cases

One registry where identity 7 is in team 1 of organisation 0 at cut 0, is
removed at cut 1, and is back at cut 2 under a new handle. Each refused case
below has an admitted neighbour one change away. -/

/-- The record with nothing in it. -/
def emptyRecord : State := ⟨[], [], [], [], [], [], [], [], [], []⟩

/-- The record in which identity 7 holds a certificate of team 1 of
organisation 0, and nothing else. -/
def memberRecord : State := { emptyRecord with members := [⟨0, .named 1, 7⟩] }

/-- Nothing holds in the empty record. -/
theorem Fact.not_holds_empty (f : Fact) : ¬ f.Holds emptyRecord := by
  cases f with
  | team o t k =>
    intro h
    have := h.1
    simp [HasTeamCert, emptyRecord] at this
  | identity o k kind =>
    intro h
    cases h with
    | person hp _ => cases hp <;> simp_all [emptyRecord]
    | agentOfRoot hc => simp [emptyRecord] at hc
    | agentOf hc => simp [emptyRecord] at hc

/-- The example's fact: identity 7 can act in team 1 of organisation 0. -/
def exampleFact : Fact := .team 0 (.named 1) 7

theorem exampleFact_holds : exampleFact.Holds memberRecord := by
  refine ⟨by simp [HasTeamCert, memberRecord], Or.inl ?_⟩
  simp [Registered, memberRecord, emptyRecord]

/-- The example registry: identity 7 is a member at cut 0, removed at cut 1
(which retires handle 100) and back at cut 2 under handle 101. Cut 0 committed
at time 0, and every later cut at time 2000. -/
def exampleRegistry : Registry where
  record := fun n => if n = 1 then emptyRecord else memberRecord
  time := fun n => if n = 0 then 0 else 2000
  handles := fun n _ => if n < 2 then [100] else [101]
  feed := fun j => if j = 1 then [100] else []

/-- The example's bounds: 1800 for a statement, 10 for current evidence, 30
for the feed. -/
def exampleBounds : Bounds := ⟨1800, 10, 30⟩

theorem exampleRegistry_feedComplete : FeedComplete exampleRegistry := by
  intro f n m hnm hn hm
  by_cases h1 : n = 1
  · subst h1
    simp [exampleRegistry] at hn
    exact absurd hn (Fact.not_holds_empty f)
  · by_cases h2 : m = 1
    · subst h2
      have hn0 : n = 0 := by omega
      subst hn0
      exact ⟨1, by omega, by omega, 100, by simp [exampleRegistry], by simp [exampleRegistry]⟩
    · simp [exampleRegistry, h1, h2] at hn hm
      exact absurd hn hm

theorem exampleRegistry_timeMonotone : TimeMonotone exampleRegistry := by
  intro i j hij
  simp only [exampleRegistry]
  split <;> split <;> omega

/-- The example's statement: identity 7's team standing at cut 0, until 1800. -/
def exampleStatement : Statement := ⟨exampleFact, 0, 1800, [100], .ordinary⟩

/-- The statement issued again after identity 7 is back, at cut 2. -/
def exampleStatementAgain : Statement := ⟨exampleFact, 2, 3800, [101], .ordinary⟩

/-- A request signed by 7 that relies on the example's fact. -/
def exampleRequest : Request := ⟨7, exampleFact, 42⟩

theorem exampleStatement_issued : Issued exampleRegistry exampleBounds exampleStatement :=
  ⟨by simpa [exampleRegistry, exampleStatement] using exampleFact_holds,
   by simp [exampleRegistry, exampleStatement],
   by simp [exampleRegistry, exampleStatement, exampleBounds, Purpose.life]⟩

theorem exampleStatementAgain_issued :
    Issued exampleRegistry exampleBounds exampleStatementAgain :=
  ⟨by simpa [exampleRegistry, exampleStatementAgain] using exampleFact_holds,
   by simp [exampleRegistry, exampleStatementAgain],
   by simp [exampleRegistry, exampleStatementAgain, exampleBounds, Purpose.life]⟩

/-- Before the removal reaches it: a verifier that has applied only cut 0
admits the statement, although 7 was removed at cut 1. This is the window the
Design allows; it closes by `removal_bound`. -/
theorem admitted_before_removal_reaches_verifier :
    Admits exampleRegistry exampleBounds ⟨0, 0, 5, []⟩ exampleRequest exampleStatement := by
  refine ⟨rfl, rfl, by decide, by decide, by decide, ?_, trivial⟩
  rintro ⟨j, hj1, hj2, -⟩
  simp [exampleStatement] at hj1 hj2
  omega

/-- After the verifier applies the removal, the same statement is refused,
on its first presentation there as on any other. -/
theorem refused_after_removal_applied :
    ¬ Admits exampleRegistry exampleBounds ⟨1, 2000, 2001, []⟩ exampleRequest exampleStatement :=
  defeated_not_admitted ⟨1, by decide, by decide, 100, by simp [exampleRegistry],
    by simp [exampleStatement]⟩

/-- A verifier that has not applied the removal refuses once the feed bound
has passed since it committed. -/
theorem refused_at_removal_bound :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 0, 2030, []⟩ exampleRequest exampleStatement :=
  removal_bound (m := 1) exampleRegistry_feedComplete exampleRegistry_timeMonotone
    (by simp [BarrierBefore, exampleRegistry]) exampleStatement_issued (by decide)
    (by simpa [exampleRegistry, exampleStatement] using Fact.not_holds_empty exampleFact)
    (by simp [exampleRegistry, exampleBounds])

/-- A lost feed: with its last barrier 30 old, the verifier refuses the
statement it admitted at 5. -/
theorem refused_on_stale_feed :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 0, 30, []⟩ exampleRequest exampleStatement :=
  stale_feed_not_admitted (by simp [exampleBounds])

/-- The expiry boundary: admitted at 1799, refused at 1800. -/
theorem admitted_just_before_expiry :
    Admits exampleRegistry exampleBounds ⟨0, 1790, 1799, []⟩ exampleRequest exampleStatement := by
  refine ⟨rfl, rfl, by decide, by decide, by decide, ?_, trivial⟩
  rintro ⟨j, hj1, hj2, -⟩
  simp [exampleStatement] at hj1 hj2
  omega

theorem refused_at_expiry :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 1790, 1800, []⟩ exampleRequest exampleStatement :=
  not_admitted_at_expiry (by simp [exampleStatement])

/-- A proof ahead of the verifier: the statement from cut 2 is refused by a
verifier at cut 1. -/
theorem refused_when_ahead :
    ¬ Admits exampleRegistry exampleBounds ⟨1, 2000, 2001, []⟩ exampleRequest exampleStatementAgain :=
  ahead_not_admitted (by simp [exampleStatementAgain])

/-- After re-admission: a statement issued at cut 2 is admitted by a verifier at
cut 2, while the one from cut 0 stays refused there. -/
theorem readmitted_statement_admitted_old_refused :
    Admits exampleRegistry exampleBounds ⟨2, 2000, 2001, []⟩ exampleRequest exampleStatementAgain ∧
      ¬ Admits exampleRegistry exampleBounds ⟨2, 2000, 2001, []⟩ exampleRequest exampleStatement := by
  refine ⟨⟨rfl, rfl, by decide, by decide, by decide, ?_, trivial⟩,
    defeated_not_admitted ⟨1, by decide, by decide, 100, by simp [exampleRegistry],
      by simp [exampleStatement]⟩⟩
  rintro ⟨j, hj1, hj2, -⟩
  simp [exampleStatementAgain] at hj1 hj2
  omega

/-- The example's current evidence: for the request with digest 42, nonce 9,
issued at cut 0 with lifetime 10. -/
def exampleEvidence : Statement := ⟨exampleFact, 0, 10, [100], .current 42 9⟩

theorem exampleEvidence_issued : Issued exampleRegistry exampleBounds exampleEvidence :=
  ⟨by simpa [exampleRegistry, exampleEvidence] using exampleFact_holds,
   by simp [exampleRegistry, exampleEvidence],
   by simp [exampleRegistry, exampleEvidence, exampleBounds, Purpose.life]⟩

/-- Evidence issued before the removal is admitted for its exact request, once,
before the removal reaches the verifier and within its lifetime. -/
theorem evidence_admitted_once :
    Admits exampleRegistry exampleBounds ⟨0, 0, 5, []⟩ exampleRequest exampleEvidence ∧
      ¬ Admits exampleRegistry exampleBounds
        (exampleEvidence.purpose.consume ⟨0, 0, 5, []⟩) exampleRequest exampleEvidence := by
  refine ⟨⟨rfl, rfl, by decide, by decide, by decide, ?_, by simp [exampleEvidence, Purpose.Fits, exampleRequest]⟩,
    current_used_once (d := 42) (n := 9) rfl⟩
  rintro ⟨j, hj1, hj2, -⟩
  simp [exampleEvidence] at hj1 hj2
  omega

/-- The same evidence for a different request is refused. -/
theorem evidence_refused_for_other_request :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 0, 5, []⟩ ⟨7, exampleFact, 43⟩ exampleEvidence :=
  fun ha => by
    have := current_needs_its_request (d := 42) (n := 9) rfl ha
    simp at this

/-- After the removal, the registry issues no evidence at cut 1. -/
theorem evidence_not_issued_after_removal :
    ¬ Issued exampleRegistry exampleBounds { exampleEvidence with cut := 1 } :=
  current_not_issued_where_fact_fails rfl
    (by simpa [exampleRegistry, exampleEvidence] using Fact.not_holds_empty exampleFact)

/-- A statement for another team does not help: the request's fact must be the
statement's. -/
theorem refused_for_other_fact :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 0, 5, []⟩
      ⟨7, .team 0 (.named 2) 7, 42⟩ exampleStatement :=
  fun ha => by
    have := ha.1
    simp [exampleStatement, exampleFact] at this

/-- A request signed by another key does not help. -/
theorem refused_for_other_signer :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 0, 5, []⟩ ⟨8, exampleFact, 42⟩ exampleStatement :=
  fun ha => by
    have := ha.2.1
    simp [exampleStatement, exampleFact, Fact.subject] at this

end TrustWeb
