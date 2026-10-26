"""Value-free reconciliation contracts; none of these objects grants authority.

Only ReconciliationPresentation contains a transient personal link. A caller
may release it after its postcommit exact-current-owner/S4/F6 check. Reads and
receipts never carry that token, request parameters, proofs or output bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from aweb_naapp.dispatch import State
from aweb_naapp.runtime.approvals import ApprovalState, DeliveryStatus
from aweb_naapp.runtime.installation import AdmittedInstallation

ReconciliationKind = Literal["broker", "run_job"]
ReconciliationOutcome = Literal["completed", "failed", "unknown-closed"]


@dataclass(frozen=True)
class ReconciliationResource:
    secret_id: str
    secret_ref: str | None
    version: int


@dataclass(frozen=True)
class ReconciliationOriginal:
    installation: AdmittedInstallation
    reconcile_ref: str
    request_id: str
    dispatch_id: UUID
    op_kind: ReconciliationKind
    requested_by: str
    resources: tuple[ReconciliationResource, ...]
    operation_id: str | None = None
    operation_digest: str | None = None
    job_id: str | None = None
    job_digest: str | None = None
    runner_id: str | None = None


@dataclass(frozen=True)
class ReconciliationView:
    original: ReconciliationOriginal
    state: State


@dataclass(frozen=True)
class ReconciliationControl:
    """The immutable real B2 control association, distinct from the send approval."""

    original: ReconciliationOriginal
    outcome: ReconciliationOutcome
    control_id: UUID
    approval_id: str
    approval_ref: str
    request_sha256: str
    policy_ref: str
    policy_version: int
    owner_scope: str
    owner_subject: str
    expires_at: datetime


@dataclass(frozen=True)
class ReconciliationControlStatus:
    control: ReconciliationControl
    original_state: State
    approval_state: ApprovalState
    delivery_status: DeliveryStatus


@dataclass(frozen=True)
class ReconciliationPresentation:
    """Only the explicit mint/present POST returns this after authority recheck."""

    status: ReconciliationControlStatus
    personal_token: str = field(repr=False)


@dataclass(frozen=True)
class ReconciliationReceipt:
    reconcile_ref: str
    request_id: str
    dispatch_id: UUID
    control_approval_id: str
    control_approval_ref: str
    state: Literal[State.RECONCILED_COMPLETED, State.RECONCILED_FAILED, State.RECONCILED_UNKNOWN]
