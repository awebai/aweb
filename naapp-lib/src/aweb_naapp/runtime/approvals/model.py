"""The approval record and the values the primitive exchanges with an app."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol


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


class Decision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


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
    long an approval and its link stay usable.
    """

    policy_ref: str
    version: int
    min_assurance: Assurance
    ttl: timedelta
    approver_scope: str


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
    """The approver-facing read behind an approval link; it consumes nothing."""

    approval: Approval
    request: Mapping[str, Any]


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


class ApprovalDelivery(Protocol):
    """Sends an approval link to the designated approver's registered contact.

    The app turns the token into a URL on its own origin. The token goes nowhere
    else: not to the requester, not into logs, audit or task text.
    """

    async def deliver_approval_link(
        self, approver: Approver, link_token: str, approval: Approval
    ) -> DeliveryStatus: ...


class Authenticator(Protocol):
    """An adapter that proves which human decided, at one assurance level."""

    assurance: Assurance

    async def challenge(self, approval: Approval, decision: Decision) -> Mapping[str, Any]: ...

    async def verify(
        self, approval: Approval, decision: Decision, proof: Mapping[str, Any]
    ) -> Evidence: ...


class AuthenticationFailed(Exception):
    """The adapter could not verify the proof."""
