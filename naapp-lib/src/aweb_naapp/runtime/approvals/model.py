"""The approval record and the values the primitive exchanges with an app."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from pgdbm.core import TransactionManager


class Assurance(StrEnum):
    """How strongly the approving human was authenticated, weakest first."""

    MEMBER_SESSION = "member_session"
    PASSKEY = "passkey"

    def satisfies(self, minimum: Assurance) -> bool:
        order = list(Assurance)
        return order.index(self) >= order.index(minimum)


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Purpose(StrEnum):
    """What an authenticator proof is for. A proof made for one purpose cannot
    serve another."""

    APPROVE = "approve"
    REJECT = "reject"
    VIEW = "view"


class Decision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"

    @property
    def purpose(self) -> Purpose:
        return Purpose(self.value)


class PresentationKind(StrEnum):
    LINK = "link"
    TASK = "task"


class DeliveryStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


class DispatchOutcome(StrEnum):
    """Where the one admitted dispatch stands. `completed` means a definite
    upstream response arrived, not that the operation succeeded."""

    DISPATCHING = "dispatching"
    COMPLETED = "completed"
    NOT_SENT = "not_sent"
    OUTCOME_UNKNOWN = "outcome_unknown"
    RECONCILED_COMPLETED = "reconciled_completed"
    RECONCILED_FAILED = "reconciled_failed"
    RECONCILED_UNKNOWN = "reconciled_unknown"


DISPATCHER_OUTCOMES = (
    DispatchOutcome.COMPLETED,
    DispatchOutcome.NOT_SENT,
    DispatchOutcome.OUTCOME_UNKNOWN,
)
RECONCILED_OUTCOMES = (
    DispatchOutcome.RECONCILED_COMPLETED,
    DispatchOutcome.RECONCILED_FAILED,
    DispatchOutcome.RECONCILED_UNKNOWN,
)
UNRECONCILED_OUTCOMES = (DispatchOutcome.DISPATCHING, DispatchOutcome.OUTCOME_UNKNOWN)


class Refusal(StrEnum):
    NOT_FOUND = "not_found"
    POLICY_UNKNOWN = "policy_unknown"
    NO_APPROVER = "no_approver"
    LINK_UNAVAILABLE = "link_unavailable"
    NOT_PENDING = "not_pending"
    NOT_APPROVED = "not_approved"
    EXPIRED = "expired"
    REVOKED = "revoked"
    REQUEST_MISMATCH = "request_mismatch"
    POLICY_CHANGED = "policy_changed"
    ASSURANCE_INSUFFICIENT = "assurance_insufficient"
    TASK_ANSWER_UNVERIFIED = "task_answer_unverified"
    PRESENTATION_UNSUPPORTED = "presentation_unsupported"
    AUTHENTICATOR_UNAVAILABLE = "authenticator_unavailable"
    AUTHENTICATION_FAILED = "authentication_failed"
    APPROVER_MISMATCH = "approver_mismatch"
    APPROVER_RETIRED = "approver_retired"
    PRESENTATION_MISMATCH = "presentation_mismatch"
    CONSUMED = "consumed"
    UNRECONCILED_DISPATCH = "unreconciled_dispatch"
    OPERATION_MISMATCH = "operation_mismatch"
    OUTCOME_INVALID = "outcome_invalid"
    OUTCOME_FINAL = "outcome_final"


class ApprovalRefused(Exception):
    def __init__(self, reason: Refusal) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True)
class ActionPolicy:
    """Owner-controlled policy for one kind of action.

    `approver_scope` names whose designated approver decides; `ttl` bounds how
    long an approval and its link stay usable. `link_reveals_request` says
    whether opening the link shows the request before the approver
    authenticates; by default it does only below passkey assurance.
    """

    policy_ref: str
    version: int
    min_assurance: Assurance
    ttl: timedelta
    approver_scope: str
    link_reveals_request: bool | None = None

    def reveals_request_on_link(self) -> bool:
        if self.link_reveals_request is not None:
            return self.link_reveals_request
        return self.min_assurance is not Assurance.PASSKEY


@dataclass(frozen=True)
class Approver:
    """The owner-designated human, with the contact the owner registered."""

    subject: str
    subject_type: str
    contact: str


@dataclass(frozen=True)
class Evidence:
    """What an authenticator verified: who approved, and how strongly."""

    assurance: Assurance
    subject: str
    subject_type: str
    evidence_ref: str


@dataclass(frozen=True)
class Approval:
    approval_id: str
    request_sha256: str
    request_ref: str
    policy_ref: str
    policy_version: int
    requested_by: str
    approver_subject: str
    approver_subject_type: str
    authenticator: Assurance | None
    auth_evidence_ref: str | None
    presentation_kind: PresentationKind
    presentation_ref: str | None
    task_answer_ref: str | None
    state: ApprovalState
    delivery_status: DeliveryStatus
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    revoked_at: datetime | None
    consumed_operation_id: str | None
    dispatch_outcome: DispatchOutcome | None
    response_status: str | None

    def state_at(self, now: datetime) -> ApprovalState:
        """The effective state. A consumed approval whose dispatch was never
        sent can still be revoked, which stops its transport retry."""
        if self.revoked_at is not None:
            return ApprovalState.REVOKED
        undecided_or_unused = self.state in (ApprovalState.PENDING, ApprovalState.APPROVED)
        if undecided_or_unused and now >= self.expires_at:
            return ApprovalState.EXPIRED
        return self.state


@dataclass(frozen=True)
class RequesterView:
    """What the requesting agent may see: no link, token or capability."""

    request_id: str
    approval_state: ApprovalState
    delivery_status: DeliveryStatus
    dispatch_outcome: DispatchOutcome | None


@dataclass(frozen=True)
class LinkedApproval:
    """The approver-facing read behind an approval link; it consumes nothing.
    `request` is None until the approver authenticates, unless the policy lets
    the link reveal it."""

    approval: Approval
    request: Mapping[str, Any] | None


@dataclass(frozen=True)
class TaskAnswerEvidence:
    """What the app verified about a task answer: the member-signed answer and
    its authoritative receipt, for this approval and decision."""

    task_answer_ref: str
    approval_id: str
    decision: Decision
    request_sha256: str


class TaskAnswerRejected(Exception):
    """The task answer or its receipt did not verify."""


class TaskAnswerVerifier(Protocol):
    async def verify(
        self, approval: Approval, decision: Decision, task_answer_ref: str
    ) -> TaskAnswerEvidence: ...


@dataclass(frozen=True)
class Admission:
    """The one admitted dispatch of an approval.

    `first` is False when an earlier admission of the same operation is being
    retrieved, which is not a new dispatch. The dispatcher sends only when
    `may_send` is True: on the first admission, or on a transport retry after
    `not_sent`.
    """

    approval_id: str
    operation_id: str
    first: bool
    may_send: bool
    dispatch_outcome: DispatchOutcome
    response_status: str | None


class PolicySource(Protocol):
    async def current(self, policy_ref: str) -> ActionPolicy | None: ...


class ApproverDirectory(Protocol):
    async def designated_approver(self, policy: ActionPolicy) -> Approver | None: ...

    async def is_current(self, approver_subject: str, policy: ActionPolicy) -> bool:
        """Whether this approver is still the current designation for the policy.
        An approval is only as good as its approver's current designation."""
        ...


class ApproverRetirement(Protocol):
    """Told when the owner retires an approver, inside the retiring transaction."""

    async def approver_retired(
        self, approver_subject: str, *, retired_by: str, tx: TransactionManager
    ) -> None: ...


class ApprovalDelivery(Protocol):
    """Sends an approval link to the designated approver's registered contact.

    The app turns the token into a URL on its own origin. The token goes nowhere
    else: not to the requester, not into logs, audit or task text.
    """

    async def deliver_approval_link(
        self, approver: Approver, link_token: str, approval: Approval
    ) -> DeliveryStatus: ...


class Authenticator(Protocol):
    """An adapter that proves which human acted, at one assurance level.

    Its challenge binds the approval, the purpose and, for a task presentation,
    the task answer reference, through `challenge_binding`.
    """

    assurance: Assurance

    async def challenge(
        self, approval: Approval, purpose: Purpose, task_answer_ref: str | None
    ) -> Mapping[str, Any]: ...

    async def verify(
        self,
        approval: Approval,
        purpose: Purpose,
        proof: Mapping[str, Any],
        task_answer_ref: str | None,
    ) -> Evidence: ...


class AuthenticationFailed(Exception):
    """The adapter could not verify the proof."""
