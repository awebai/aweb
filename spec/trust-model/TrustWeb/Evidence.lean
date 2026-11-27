import TrustWeb.Abilities

/-!
# Evidence of how a person was enrolled (planned)

Planned evidence of how a person was enrolled, kept as a list of assertions
outside the record.
-/

namespace TrustWeb

/-- How a person's enrolment was asserted. -/
inductive Enrolment where
  /-- By the organisation's domain controller. -/
  | controller
  /-- By a hosted service, for an email enrolment. -/
  | hostedEmail
  deriving DecidableEq, Repr

/-- An assertion that `subject` of `org` was enrolled this way. -/
structure Assertion where
  org : Org
  subject : Key
  enrolment : Enrolment
  deriving DecidableEq, Repr

/-- `k` is a valid person of `o`, and the list has the controller's assertion
for `k` in `o`. -/
def ControllerAssertedPerson (s : State) (as : List Assertion) (o : Org) (k : Key) : Prop :=
  Valid s o k .person ∧ ⟨o, k, .controller⟩ ∈ as

/-- `k` is a valid person of `o`, and the list has the hosted service's email
assertion for `k` in `o`. -/
def HostedEmailEnrolled (s : State) (as : List Assertion) (o : Org) (k : Key) : Prop :=
  Valid s o k .person ∧ ⟨o, k, .hostedEmail⟩ ∈ as

/-- `k` is a valid person of `o`, and no assertion in the list is about `k` in
`o`. -/
def EnrolmentUnspecified (s : State) (as : List Assertion) (o : Org) (k : Key) : Prop :=
  Valid s o k .person ∧ ∀ a, a ∈ as → a.org = o → a.subject ≠ k

/-- If `k` is a valid person of `o`, then in that same record: with the
controller's assertion alone, `k` is a controller-asserted person and not
email-enrolled; with the hosted service's email assertion alone, `k` is
email-enrolled and not a controller-asserted person; with no assertion, its
enrolment is unspecified and it is neither. -/
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

/-- If `k` is a controller-asserted person of `o`, `k` answers for itself in
`o`. -/
theorem controller_asserted_person_answers_for_itself {s : State} {as : List Assertion}
    {o : Org} {k : Key} (h : ControllerAssertedPerson s as o k) : AnswersFor s o k k :=
  .self h.1

/-- Under any rule there is a record the system reaches in which 1 is a valid
person of 0; with the controller's assertion alone 1 is a controller-asserted
person of 0, with the hosted service's email assertion alone it is
email-enrolled, and with no assertion its enrolment is unspecified. -/
theorem enrolment_case_is_reachable (ask : AskRule) :
    ∃ s, Reachable ask s ∧ Valid s 0 1 .person ∧
      ControllerAssertedPerson s [⟨0, 1, .controller⟩] 0 1 ∧
      HostedEmailEnrolled s [⟨0, 1, .hostedEmail⟩] 0 1 ∧
      EnrolmentUnspecified s [] 0 1 := by
  obtain ⟨s, hr, _, hv, _⟩ := runs_without_key_holder ask
  have h := enrolment_evidence_is_beside_the_chain hv
  exact ⟨s, hr, hv, h.1.1, h.2.1.1, h.2.2.1⟩

end TrustWeb
