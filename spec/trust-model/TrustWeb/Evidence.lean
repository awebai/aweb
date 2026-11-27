import TrustWeb.Abilities

/-!
# Evidence of how a person was enrolled (planned)

A planned outcome, `controller_asserted_person`, says that a verified person
has enrolment evidence from its own domain's controller: it records who
vouched for the person. It carries no email verification, no fresh human
gesture and no permission. It is reported beside the shared verdict, which
does not change, and it does not change the outcome for agents below the
person.

Here the evidence is a list of assertions, kept outside the record. No act
reads it, so no act's premise and no verdict of the model (`Valid`,
`Person`, `AnswersFor`) depends on it. The results below hold the record, and
so the person's chain, fixed and vary the assertions.

Both routes that register a person directly under the root (the domain's
controller using the root key, or a hosted service holding it) add the same
kind of certificate: a person certificate issued by the root. The certificate
has no field for how the person was enrolled, so the chain alone cannot tell
the routes apart.

* **A10. Assertions.** An assertion in the list was signed by the party it
  names (the domain's authorised controller, or the hosted service after an
  email check) and is bound to that exact enrolment. The model does not
  check it.
-/

namespace TrustWeb

/-- Who vouched for a person's enrolment. -/
inductive Enrolment where
  /-- The organisation's domain controller asserted the enrolment. -/
  | controller
  /-- A hosted service asserted it after checking an email address. -/
  | hostedEmail
  deriving DecidableEq, Repr

/-- An authenticated assertion that `subject` of `org` was enrolled this way (A10). -/
structure Assertion where
  org : Org
  subject : Key
  enrolment : Enrolment
  deriving DecidableEq, Repr

/-- `controller_asserted_person`: `k` is a valid person of `o`, whoever issued
its certificate, and its own domain's authorised controller asserted its
enrolment, in an assertion bound to that exact enrolment (A10). -/
def ControllerAssertedPerson (s : State) (as : List Assertion) (o : Org) (k : Key) : Prop :=
  Valid s o k .person ∧ ⟨o, k, .controller⟩ ∈ as

/-- `k` is a valid person of `o`, and a hosted service asserted an email
enrolment for it. This is separate evidence. -/
def HostedEmailEnrolled (s : State) (as : List Assertion) (o : Org) (k : Key) : Prop :=
  Valid s o k .person ∧ ⟨o, k, .hostedEmail⟩ ∈ as

/-- `k` is a valid person of `o`, and no assertion is about its enrolment. -/
def EnrolmentUnspecified (s : State) (as : List Assertion) (o : Org) (k : Key) : Prop :=
  Valid s o k .person ∧ ∀ a, a ∈ as → a.org = o → a.subject ≠ k

/-- **The same chain, three kinds of evidence.** If `k` is a valid person of
`o`, then in that same record: with the controller's assertion alone, `k` is a
controller-asserted person and not email-enrolled; with the hosted service's
email assertion alone, `k` is email-enrolled and not a controller-asserted
person; with no assertion, its enrolment is unspecified and it is neither. -/
theorem enrolment_evidence_is_beside_the_chain {s : State} {o : Org} {k : Key}
    (hv : Valid s o k .person) :
    (ControllerAssertedPerson s [⟨o, k, .controller⟩] o k ∧
      ¬ HostedEmailEnrolled s [⟨o, k, .controller⟩] o k) ∧
    (HostedEmailEnrolled s [⟨o, k, .hostedEmail⟩] o k ∧
      ¬ ControllerAssertedPerson s [⟨o, k, .hostedEmail⟩] o k) ∧
    (EnrolmentUnspecified s [] o k ∧ ¬ ControllerAssertedPerson s [] o k ∧
      ¬ HostedEmailEnrolled s [] o k) := by
  refine ⟨⟨⟨hv, by simp⟩, fun h => by simpa using h.2⟩,
    ⟨⟨hv, by simp⟩, fun h => by simpa using h.2⟩,
    ⟨⟨hv, fun a ha => by simp at ha⟩, fun h => by simpa using h.2, fun h => by simpa using h.2⟩⟩

/-- **A controller-asserted person answers for itself.** If `k` is a
controller-asserted person of `o`, `k` answers for itself, as every valid
person does. -/
theorem controller_asserted_person_answers_for_itself {s : State} {as : List Assertion}
    {o : Org} {k : Key} (h : ControllerAssertedPerson s as o k) : AnswersFor s o k k :=
  .self h.1

/-- **The case is not vacuous.** Under any rule there is a record the system
reaches with a valid person in which the three kinds of evidence are as in
`enrolment_evidence_is_beside_the_chain`. -/
theorem enrolment_case_is_reachable (ask : AskRule) :
    ∃ s, Reachable ask s ∧ Valid s 0 1 .person ∧
      ControllerAssertedPerson s [⟨0, 1, .controller⟩] 0 1 ∧
      HostedEmailEnrolled s [⟨0, 1, .hostedEmail⟩] 0 1 ∧
      EnrolmentUnspecified s [] 0 1 := by
  obtain ⟨s, hr, _, hv, _⟩ := runs_without_key_holder ask
  have h := enrolment_evidence_is_beside_the_chain hv
  exact ⟨s, hr, hv, h.1.1, h.2.1.1, h.2.2.1⟩

end TrustWeb
