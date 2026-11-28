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

/-- A request: who signed it, the fact it relies on, its digest, and whether
it creates authority (a grant mint, a connect, an app install, an approval). -/
structure Request where
  signer : Key
  fact : Fact
  digest : Nat
  creates : Bool

/-- An entry the verifier has applied, at any cut up to its applied one,
retires one of the statement's handles. -/
def Defeated (R : Registry) (v : Verifier) (st : Statement) : Prop :=
  ∃ j, j ≤ v.applied ∧ ∃ x, x ∈ R.feed j ∧ x ∈ st.deps

/-- An ordinary statement fits only a request that creates no authority;
current evidence fits only a request that creates authority, with the
evidence's digest, while its nonce is unused. -/
def Purpose.Fits (v : Verifier) (r : Request) : Purpose → Prop
  | .ordinary => r.creates = false
  | .current d n => r.creates = true ∧ d = r.digest ∧ n ∉ v.consumed

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

/-- The registry issued current evidence `st` fresh, at its head `head`: it
issued `st`, `st` is current evidence, and `st`'s cut is `head`. -/
def IssuedAtHead (R : Registry) (b : Bounds) (head : Nat) (st : Statement) : Prop :=
  Issued R b st ∧ (∃ d n, st.purpose = .current d n) ∧ st.cut = head

/-- The issuer premise: the registry never gives a fact, at a cut, a handle
that an entry at or before that cut has retired. -/
def NoRetiredHandles (R : Registry) : Prop :=
  ∀ n f j, j ≤ n → ∀ x, x ∈ R.feed j → x ∉ R.handles n f

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
  obtain ⟨j, -, hj2, x, hx, hxd⟩ := hfeed st.fact st.cut v.applied hcut hst.1 hno
  exact hnd ⟨j, hj2, x, hx, hst.2.1 ▸ hxd⟩

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

/-- Under the issuer premise, only an entry after an issued statement's cut
defeats it, so checking every applied entry refuses no statement the registry
issued correctly for a reason older than its cut. -/
theorem defeat_is_after_cut {R : Registry} {b : Bounds} {v : Verifier} {st : Statement}
    (hno : NoRetiredHandles R) (hst : Issued R b st) (h : Defeated R v st) :
    ∃ j, st.cut < j ∧ j ≤ v.applied ∧ ∃ x, x ∈ R.feed j ∧ x ∈ st.deps := by
  obtain ⟨j, hj, x, hx, hd⟩ := h
  refine ⟨j, ?_, hj, x, hx, hd⟩
  apply Classical.byContradiction
  intro hle
  exact hno st.cut st.fact j (by omega) x hx (hst.2.1 ▸ hd)

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
  obtain ⟨j, -, hj2, x, hx, hxd⟩ := hfeed st.fact st.cut m hm1 hst.1 hend
  exact defeated_not_admitted ⟨j, Nat.le_trans hj2 hm2, x, hx, hst.2.1 ▸ hxd⟩

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

/-- Authority creation needs current evidence: a request that creates authority
is admitted only on current evidence with the request's digest, and never on
ordinary standing. -/
theorem creation_needs_current_evidence {R : Registry} {b : Bounds} {v : Verifier}
    {r : Request} {st : Statement} (hc : r.creates = true) (ha : Admits R b v r st) :
    ∃ d n, st.purpose = .current d n ∧ r.digest = d := by
  have h := ha.2.2.2.2.2.2
  cases hp : st.purpose with
  | ordinary => rw [hp] at h; simp [Purpose.Fits, hc] at h
  | current d n => rw [hp] at h; exact ⟨d, n, rfl, h.2.1.symm⟩

/-- Current evidence is used once: after the effect it admitted, the same
evidence is admitted for no request. -/
theorem current_used_once {R : Registry} {b : Bounds} {v : Verifier} {r' : Request}
    {st : Statement} {d n : Nat} (hp : st.purpose = .current d n) :
    ¬ Admits R b (st.purpose.consume v) r' st := by
  intro ha
  have h := ha.2.2.2.2.2.2
  rw [hp] at h
  exact h.2.2 (by simp [Purpose.consume])

/-- Authority creation checks fresh: a request that creates authority, admitted
on evidence the registry issued at its head, relies on a fact that held at that
head, and is admitted only before the head's time plus the evidence lifetime. -/
theorem creation_admitted_fresh {R : Registry} {b : Bounds} {v : Verifier}
    {r : Request} {st : Statement} {head : Nat} (hi : IssuedAtHead R b head st)
    (ha : Admits R b v r st) :
    r.fact.Holds (R.record head) ∧ v.now < R.time head + b.current := by
  obtain ⟨⟨hh, -, hexp⟩, ⟨d, n, hp⟩, hcut⟩ := hi
  refine ⟨ha.1 ▸ hcut ▸ hh, ?_⟩
  have := ha.2.2.2.1
  rw [hp] at hexp
  simp only [Purpose.life] at hexp
  rw [← hcut]
  omega

/-- A fresh request at a head where its fact does not hold gets no evidence. -/
theorem no_evidence_at_failed_head {R : Registry} {b : Bounds} {st : Statement}
    {head : Nat} (hend : ¬ st.fact.Holds (R.record head)) : ¬ IssuedAtHead R b head st :=
  fun ⟨h, _, hcut⟩ => hend (hcut ▸ h.1)

/-! ## Paired cases

One registry. Identity 7 is in team 1 of organisation 0 at cut 0 (time 0). It
is removed at cut 1 (time 4), which retires handle 100, and is back at cut 2
(time 6) under handle 101. Cut 3 (time 8) changes something else and retires
handle 555; later cuts commit at `n + 10000`. Every removal falls inside the
lifetimes, so the refused cases other than the expiry boundary are unexpired.
Each refused case has an admitted neighbour one change away. -/

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

/-- The example registry: cut 1 is the record with nothing in it, every other
cut is `memberRecord`; times 0, 4, 6, 8, then `n + 10000`; handle 100 at
cut 0, none at cut 1, and 101 from cut 2; the feed retires 100 at cut 1 and 555 at cut 3. -/
def exampleRegistry : Registry where
  record := fun n => if n = 1 then emptyRecord else memberRecord
  time := fun n => if n = 0 then 0 else if n = 1 then 4 else if n = 2 then 6 else if n = 3 then 8 else n + 10000
  handles := fun n _ => if n = 0 then [100] else if n = 1 then [] else [101]
  feed := fun j => if j = 1 then [100] else if j = 3 then [555] else []

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
  split <;> split <;> (try split) <;> (try split) <;> (try split) <;> (try split) <;>
    (try split) <;> (try split) <;> omega

/-- The example's statement: identity 7's team standing at cut 0, until 1800. -/
def exampleStatement : Statement := ⟨exampleFact, 0, 1800, [100], .ordinary⟩

/-- The statement issued again after identity 7 is back, at cut 2, until 1806. -/
def exampleStatementAgain : Statement := ⟨exampleFact, 2, 1806, [101], .ordinary⟩

/-- A request signed by 7 that relies on the example's fact and creates no
authority. -/
def exampleRequest : Request := ⟨7, exampleFact, 42, false⟩

/-- The same request, creating authority. -/
def exampleCreation : Request := ⟨7, exampleFact, 42, true⟩

theorem exampleStatement_issued : Issued exampleRegistry exampleBounds exampleStatement :=
  ⟨by simpa [exampleRegistry, exampleStatement] using exampleFact_holds,
   by simp [exampleRegistry, exampleStatement],
   by simp [exampleRegistry, exampleStatement, exampleBounds, Purpose.life]⟩

theorem exampleStatementAgain_issued :
    Issued exampleRegistry exampleBounds exampleStatementAgain :=
  ⟨by simpa [exampleRegistry, exampleStatementAgain] using exampleFact_holds,
   by simp [exampleRegistry, exampleStatementAgain],
   by simp [exampleRegistry, exampleStatementAgain, exampleBounds, Purpose.life]⟩

/-- A statement is not defeated if no feed entry up to the verifier's applied
cut retires one of its handles. -/
theorem example_not_defeated (v : Verifier) (st : Statement)
    (h : ∀ j, j ≤ v.applied → ∀ x, x ∈ exampleRegistry.feed j → x ∉ st.deps) :
    ¬ Defeated exampleRegistry v st :=
  fun ⟨j, hj, x, hx, hd⟩ => h j hj x hx hd

/-- After the removal committed, before it reaches the verifier: a verifier at
cut 0 admits the unexpired statement at time 7, although 7 was removed at cut
1, at time 4. This is the window the Design allows, and the removal bound
closes it. -/
theorem admitted_before_removal_reaches_verifier :
    Admits exampleRegistry exampleBounds ⟨0, 4, 7, []⟩ exampleRequest exampleStatement :=
  ⟨rfl, rfl, by decide, by decide, by decide,
    example_not_defeated ⟨0, 4, 7, []⟩ exampleStatement (by
      intro j hj x hx hd
      simp only [exampleRegistry] at hx
      by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> simp_all), rfl⟩

/-- At the same time, a verifier that has applied the removal refuses the same
statement, unexpired and with a fresh barrier, on its first presentation there
as on any other. -/
theorem refused_after_removal_applied :
    ¬ Admits exampleRegistry exampleBounds ⟨1, 4, 7, []⟩ exampleRequest exampleStatement :=
  defeated_not_admitted ⟨1, by decide, 100, by simp [exampleRegistry],
    by simp [exampleStatement]⟩

/-- The removal bound: a verifier still at cut 0, with the latest barrier the
premise allows, admits at time 33 and refuses at time 34, the feed bound after
the removal, while the statement is unexpired. -/
theorem admitted_just_before_removal_bound :
    Admits exampleRegistry exampleBounds ⟨0, 4, 33, []⟩ exampleRequest exampleStatement :=
  ⟨rfl, rfl, by decide, by decide, by decide,
    example_not_defeated ⟨0, 4, 33, []⟩ exampleStatement (by
      intro j hj x hx hd
      simp only [exampleRegistry] at hx
      by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> simp_all), rfl⟩

theorem refused_at_removal_bound :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 4, 34, []⟩ exampleRequest exampleStatement :=
  removal_bound (m := 1) exampleRegistry_feedComplete exampleRegistry_timeMonotone
    (by simp [BarrierBefore, exampleRegistry]) exampleStatement_issued (by decide)
    (by simpa [exampleRegistry, exampleStatement] using Fact.not_holds_empty exampleFact)
    (by simp [exampleRegistry, exampleBounds])

/-- A lost feed: with its last barrier at time 0, the verifier refuses at time
30 the unexpired statement it admits at time 7 with a barrier at time 4. -/
theorem refused_on_stale_feed :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 0, 30, []⟩ exampleRequest exampleStatement :=
  stale_feed_not_admitted (by simp [exampleBounds])

/-- The expiry boundary: the statement from cut 2, with expiry 1806, is admitted
at time 1805 and refused at time 1806, by a verifier at cut 3. -/
theorem admitted_just_before_expiry :
    Admits exampleRegistry exampleBounds ⟨3, 1790, 1805, []⟩ exampleRequest exampleStatementAgain :=
  ⟨rfl, rfl, by decide, by decide, by decide,
    example_not_defeated ⟨3, 1790, 1805, []⟩ exampleStatementAgain (by
      intro j hj x hx hd
      simp only [exampleRegistry] at hx
      by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> simp_all [exampleStatementAgain]), rfl⟩

theorem refused_at_expiry :
    ¬ Admits exampleRegistry exampleBounds ⟨3, 1790, 1806, []⟩ exampleRequest exampleStatementAgain :=
  not_admitted_at_expiry (by simp [exampleStatementAgain])

/-- A statement ahead of the verifier: the statement from cut 2 is refused by a
verifier at cut 1, and admitted at cut 2. -/
theorem refused_when_ahead :
    ¬ Admits exampleRegistry exampleBounds ⟨1, 4, 7, []⟩ exampleRequest exampleStatementAgain :=
  ahead_not_admitted (by simp [exampleStatementAgain])

/-- Re-admission: at cut 2 and time 8, the statement issued at cut 2 is
admitted, and the one from cut 0, unexpired, is refused by its retired
handle. -/
theorem readmitted_statement_admitted_old_refused :
    Admits exampleRegistry exampleBounds ⟨2, 6, 8, []⟩ exampleRequest exampleStatementAgain ∧
      ¬ Admits exampleRegistry exampleBounds ⟨2, 6, 8, []⟩ exampleRequest exampleStatement :=
  ⟨⟨rfl, rfl, by decide, by decide, by decide,
    example_not_defeated ⟨2, 6, 8, []⟩ exampleStatementAgain (by
      intro j hj x hx hd
      simp only [exampleRegistry] at hx
      by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> simp_all [exampleStatementAgain]), rfl⟩,
   defeated_not_admitted ⟨1, by decide, 100, by simp [exampleRegistry],
      by simp [exampleStatement]⟩⟩

/-- Continuity: cut 3, at time 8, changes something else and retires another
handle; at time 9 the statement from cut 2 stays admitted by a verifier that
has applied cut 3. -/
theorem continuity_keeps_statement :
    Admits exampleRegistry exampleBounds ⟨3, 8, 9, []⟩ exampleRequest exampleStatementAgain :=
  ⟨rfl, rfl, by decide, by decide, by decide,
    example_not_defeated ⟨3, 8, 9, []⟩ exampleStatementAgain (by
      intro j hj x hx hd
      simp only [exampleRegistry] at hx
      by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> simp_all [exampleStatementAgain]), rfl⟩

/-- The example's current evidence: for the request with digest 42, nonce 9,
issued at cut 0 with lifetime 10. -/
def exampleEvidence : Statement := ⟨exampleFact, 0, 10, [100], .current 42 9⟩

theorem exampleEvidence_issued_at_head :
    IssuedAtHead exampleRegistry exampleBounds 0 exampleEvidence :=
  ⟨⟨by simpa [exampleRegistry, exampleEvidence] using exampleFact_holds,
    by simp [exampleRegistry, exampleEvidence],
    by simp [exampleRegistry, exampleEvidence, exampleBounds, Purpose.life]⟩,
   ⟨42, 9, rfl⟩, rfl⟩

/-- Evidence issued at head 0, before the removal: at time 7, after the removal
committed and before it reaches the verifier, it is admitted once for its exact
creating request, and refused after its nonce is used. -/
theorem evidence_admitted_once :
    Admits exampleRegistry exampleBounds ⟨0, 4, 7, []⟩ exampleCreation exampleEvidence ∧
      ¬ Admits exampleRegistry exampleBounds
        (exampleEvidence.purpose.consume ⟨0, 4, 7, []⟩) exampleCreation exampleEvidence :=
  ⟨⟨rfl, rfl, by decide, by decide, by decide,
    example_not_defeated ⟨0, 4, 7, []⟩ exampleEvidence (by
      intro j hj x hx hd
      simp only [exampleRegistry] at hx
      by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> simp_all),
    by simp [exampleEvidence, Purpose.Fits, exampleCreation]⟩,
   current_used_once (d := 42) (n := 9) rfl⟩

/-- At the same time, a verifier that has applied the removal refuses it. -/
theorem evidence_refused_after_removal_applied :
    ¬ Admits exampleRegistry exampleBounds ⟨1, 4, 7, []⟩ exampleCreation exampleEvidence :=
  defeated_not_admitted ⟨1, by decide, 100, by simp [exampleRegistry],
    by simp [exampleEvidence]⟩

/-- The same evidence for a creating request with another digest is refused,
and ordinary standing is refused for the creating request. -/
theorem evidence_refused_for_other_request :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 4, 7, []⟩ ⟨7, exampleFact, 43, true⟩ exampleEvidence ∧
      ¬ Admits exampleRegistry exampleBounds ⟨0, 4, 7, []⟩ exampleCreation exampleStatement := by
  refine ⟨fun ha => ?_, fun ha => ?_⟩
  · obtain ⟨d, n, hp, hd⟩ := creation_needs_current_evidence rfl ha
    simp [exampleEvidence] at hp
    obtain ⟨rfl, -⟩ := hp
    simp at hd
  · obtain ⟨d, n, hp, -⟩ := creation_needs_current_evidence rfl ha
    simp [exampleStatement] at hp

/-- At head 1, after the removal, a fresh request gets no evidence; at head 0
it does (`exampleEvidence_issued_at_head`). -/
theorem no_evidence_after_removal :
    ¬ IssuedAtHead exampleRegistry exampleBounds 1 { exampleEvidence with cut := 1 } :=
  no_evidence_at_failed_head
    (by simpa [exampleRegistry, exampleEvidence] using Fact.not_holds_empty exampleFact)

/-- A statement for another team, or a request signed by another key, does not
help. -/
theorem refused_for_other_fact :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 4, 7, []⟩
      ⟨7, .team 0 (.named 2) 7, 42, false⟩ exampleStatement :=
  fun ha => by
    have := ha.1
    simp [exampleStatement, exampleFact] at this

theorem refused_for_other_signer :
    ¬ Admits exampleRegistry exampleBounds ⟨0, 4, 7, []⟩ ⟨8, exampleFact, 42, false⟩ exampleStatement :=
  fun ha => by
    have := ha.2.1
    simp [exampleStatement, exampleFact, Fact.subject] at this

theorem exampleRegistry_noRetiredHandles : NoRetiredHandles exampleRegistry := by
  intro n f j hjn x hx hh
  simp only [exampleRegistry] at hx hh
  by_cases h1 : j = 1 <;> by_cases h3 : j = 3 <;> by_cases hn0 : n = 0 <;> by_cases hn1 : n = 1 <;>
    simp_all <;> omega

/-- A restored or faulty issuer: the example's registry, except that from cut
2 it gives the fact handle 100 again, which cut 1 retired. -/
def reuseRegistry : Registry := { exampleRegistry with
  handles := fun n _ => if n = 1 then [] else [100] }

/-- The statement that issuer gives at cut 2, on the retired handle. -/
def reusedStatement : Statement := ⟨exampleFact, 2, 1806, [100], .ordinary⟩

/-- That registry meets the feed and time premises and issues the statement,
but breaks the issuer premise; a verifier at cut 2 refuses the statement by the
entry at cut 1, before its cut. Its neighbour is the re-admission with a new
handle (`readmitted_statement_admitted_old_refused`). -/
theorem reused_handle_refused :
    FeedComplete reuseRegistry ∧ TimeMonotone reuseRegistry ∧
      Issued reuseRegistry exampleBounds reusedStatement ∧ ¬ NoRetiredHandles reuseRegistry ∧
      ¬ Admits reuseRegistry exampleBounds ⟨2, 6, 8, []⟩ exampleRequest reusedStatement := by
  refine ⟨?_, exampleRegistry_timeMonotone, ⟨?_, ?_, ?_⟩, ?_, ?_⟩
  · intro f n m hnm hn hm
    by_cases h1 : n = 1
    · subst h1
      simp [reuseRegistry, exampleRegistry] at hn
      exact absurd hn (Fact.not_holds_empty f)
    · by_cases h2 : m = 1
      · subst h2
        have hn0 : n = 0 := by omega
        subst hn0
        exact ⟨1, by omega, by omega, 100, by simp [reuseRegistry, exampleRegistry],
          by simp [reuseRegistry]⟩
      · simp [reuseRegistry, exampleRegistry, h1, h2] at hn hm
        exact absurd hn hm
  · simpa [reuseRegistry, exampleRegistry, reusedStatement] using exampleFact_holds
  · simp [reuseRegistry, reusedStatement]
  · simp [reuseRegistry, exampleRegistry, reusedStatement, exampleBounds, Purpose.life]
  · intro h
    exact h 2 exampleFact 1 (by decide) 100 (by simp [reuseRegistry, exampleRegistry])
      (by simp [reuseRegistry])
  · exact defeated_not_admitted ⟨1, by decide, 100, by simp [reuseRegistry, exampleRegistry],
      by simp [reusedStatement]⟩

/-- A verifier is consistent with the registry's times: its clock is at or
after the time of its applied cut and of its barrier, and its barrier was
observed no later than the change after its applied cut. -/
def Consistent (R : Registry) (v : Verifier) : Prop :=
  R.time v.applied ≤ v.now ∧ v.barrier ≤ v.now ∧ BarrierBefore R v

/-- Every verifier the paired cases use is consistent with the example's times. -/
theorem example_verifiers_consistent :
    ∀ v ∈ [(⟨0, 4, 7, []⟩ : Verifier), ⟨1, 4, 7, []⟩, ⟨0, 4, 33, []⟩, ⟨0, 4, 34, []⟩,
      ⟨0, 0, 30, []⟩, ⟨3, 1790, 1805, []⟩, ⟨3, 1790, 1806, []⟩, ⟨2, 6, 8, []⟩,
      ⟨3, 8, 9, []⟩, ⟨0, 4, 7, [9]⟩], Consistent exampleRegistry v := by
  intro v hv
  simp at hv
  rcases hv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [Consistent, BarrierBefore, exampleRegistry]

end TrustWeb
