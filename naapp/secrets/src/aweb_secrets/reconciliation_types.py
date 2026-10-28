"""Value-free reconciliation contracts; none of these objects grants authority.

Only ReconciliationPresentation contains a transient personal link. A caller
may release it after its postcommit exact-current-owner/S4/F6 check. Reads and
receipts never carry that token, request parameters, proofs or output bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from aweb_naapp.dispatch import State
from aweb_naapp.runtime.approvals import ApprovalState, DeliveryStatus
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers
from pgdbm.core import TransactionManager

ReconciliationKind = Literal["broker", "run_job"]
ReconciliationOutcome = Literal["completed", "failed", "unknown-closed"]


class OwnerReconciliationFence(Protocol):
    """Console-owned authority for one exact S4 owner in one original tx.

    prepare caches the complete F6/OWNER/B3 union before exact LOGIN and S4
    holds; S13 only checks the returned shared handle. check takes no new
    locks and ends with live F6 and pure persisted session expiry. A new
    postcommit presentation transaction requires a new fence and handle.
    This credential-holding fence never spans Approvals.decide.
    """

    @property
    def scope(self) -> AdmittedInstallation: ...
    @property
    def owner_scope(self) -> str: ...
    @property
    def owner_subject(self) -> str: ...
    @property
    def expires_at(self) -> datetime: ...

    async def prepare(self, tx: TransactionManager) -> PreparedCurrentApprovers: ...

    async def check(self, tx: TransactionManager) -> None: ...


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
    repeat_state: State | None = None


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
    repeat_state: State | None = None


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
    state: Literal["reconciled_completed", "reconciled_failed", "reconciled_unknown"]
