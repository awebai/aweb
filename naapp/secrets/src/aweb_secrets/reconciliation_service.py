"""Caller-transaction owner controls and first settlement of an uncertain use.

The console prepares the one whole owner/B3/session union. This service only
checks its handle, consumes a separate outcome-bound APPROVE control, then
records original B2/S3 consequences. It never opens, sends, refreshes a grant,
looks up targets or rearms an approval. Delivery is an explicit postcommit call.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import uuid4

from aweb_naapp.dispatch import InvalidTransition, State
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approval,
    ApprovalRefused,
    Approvals,
    ApprovalState,
    Assurance,
    DispatchOutcome,
    PendingApproval,
    Refusal,
)
from aweb_naapp.runtime.approvals.dispatch_fence import DispatchAuthorityState
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    Passkeys,
    PreparedCurrentApprovers,
)
from pgdbm.core import TransactionManager

from aweb_secrets.broker_service import BrokerRequests
from aweb_secrets.owners import owner_scope
from aweb_secrets.reconciliation_control_audit import ReconciliationAudit
from aweb_secrets.reconciliation_policy import (
    CONTROL_TTL,
    reconciliation_policy_ref,
    reconciliation_request,
)
from aweb_secrets.reconciliation_reads import ReconciliationReads
from aweb_secrets.reconciliation_types import (
    OwnerReconciliationFence,
    ReconciliationControl,
    ReconciliationControlStatus,
    ReconciliationOriginal,
    ReconciliationOutcome,
    ReconciliationPresentation,
    ReconciliationReceipt,
)
from aweb_secrets.run_service import RunDispatch
from aweb_secrets.use_audit import UseApprovalAudit, UseAuditUnavailable

_STATES = {
    "completed": State.RECONCILED_COMPLETED,
    "failed": State.RECONCILED_FAILED,
    "unknown-closed": State.RECONCILED_UNKNOWN,
}
_REFUSALS = {
    "reconciliation_not_found": 404,
    "owner_required": 403,
    "reconciliation_invalid": 400,
    "reconciliation_conflict": 409,
}


class ReconciliationRefused(RuntimeError):
    def __init__(self, code: str) -> None:
        self.status = _REFUSALS[code]
        self.code = code
        super().__init__(code)


class _ControlAuthority:
    """B2 check-only adapter; caller already prepared the complete B3 union."""

    def __init__(
        self,
        tx: TransactionManager,
        control: ReconciliationControl,
        handle: PreparedCurrentApprovers,
        passkeys: Passkeys,
    ) -> None:
        self._tx, self._control, self._handle, self._passkeys = tx, control, handle, passkeys

    async def prepare(self, tx: TransactionManager, approvals: Sequence[Approval]) -> None:
        if tx is not self._tx or tuple(a.approval_id for a in approvals) != (
            self._control.approval_id,
        ):
            raise UseAuditUnavailable()

    async def read(self, tx: TransactionManager, approval: Approval) -> DispatchAuthorityState:
        if tx is not self._tx or approval.approval_id != self._control.approval_id:
            raise UseAuditUnavailable()
        current = await self._passkeys.check_current_approver(
            tx, self._handle, scope=self._control.owner_scope, subject=self._control.owner_subject
        )
        return DispatchAuthorityState(
            ActionPolicy(
                policy_ref=self._control.policy_ref,
                version=self._control.policy_version,
                min_assurance=Assurance.PASSKEY,
                ttl=CONTROL_TTL,
                approver_scopes=(self._control.owner_scope,),
                allow_requester_approval=True,
            ),
            current,
        )


class ReconciliationControls:
    def __init__(
        self,
        *,
        reads: ReconciliationReads,
        audit: ReconciliationAudit,
        approvals: Approvals,
        passkeys: Passkeys,
        use_audit: UseApprovalAudit,
        broker: BrokerRequests | None,
        runs: RunDispatch | None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._reads, self._audit, self._approvals, self._passkeys = (
            reads,
            audit,
            approvals,
            passkeys,
        )
        self._use_audit, self._broker, self._runs, self._clock = use_audit, broker, runs, clock

    def _backend(self, original: ReconciliationOriginal) -> BrokerRequests | RunDispatch:
        backend = self._broker if original.op_kind == "broker" else self._runs
        if backend is None:
            raise UseAuditUnavailable()
        return backend

    @staticmethod
    def _bound(control: ReconciliationControl, fence: OwnerReconciliationFence) -> None:
        if control.original.installation != fence.scope or (
            control.owner_scope,
            control.owner_subject,
        ) != (fence.owner_scope, fence.owner_subject):
            raise ReconciliationRefused("owner_required")

    async def _final(
        self,
        tx: TransactionManager,
        fence: OwnerReconciliationFence,
        handle: PreparedCurrentApprovers,
        *,
        expires_at: datetime,
    ) -> None:
        if not await self._passkeys.check_current_approver(
            tx, handle, scope=fence.owner_scope, subject=fence.owner_subject
        ):
            raise ApprovalRefused(Refusal.APPROVER_RETIRED)
        await fence.check(tx)
        # No await after this sample: every effect and audit wait precedes it.
        if self._clock() >= min(expires_at, fence.expires_at):
            raise ApprovalRefused(Refusal.EXPIRED)

    async def mint(
        self,
        tx: TransactionManager,
        *,
        reconcile_ref: str,
        outcome: ReconciliationOutcome,
        fence: OwnerReconciliationFence,
    ) -> PendingApproval:
        if not isinstance(outcome, str) or outcome not in _STATES:
            raise ReconciliationRefused("reconciliation_invalid")
        handle = await fence.prepare(tx)
        view = await self._reads.get(tx, scope=fence.scope, reconcile_ref=reconcile_ref)
        if view is None:
            raise ReconciliationRefused("reconciliation_not_found")
        self._backend(view.original)
        if view.state is not State.OUTCOME_UNKNOWN:
            raise ReconciliationRefused("reconciliation_conflict")
        owner = await tx.fetch_value(
            "SELECT principal_did FROM {{tables.owner_principals}} WHERE scope=$1 AND installation_id=$2 AND team_id=$3",
            fence.owner_scope,
            fence.scope.installation_id,
            fence.scope.team_id,
        )
        if (
            owner is None
            or owner_scope(fence.scope.installation_id, fence.scope.team_id, owner)
            != fence.owner_scope
        ):
            raise ReconciliationRefused("owner_required")
        request = reconciliation_request(
            view.original,
            control_id=uuid4(),
            outcome=outcome,
            owner_scope=fence.owner_scope,
            owner_subject=fence.owner_subject,
        )
        async with tx.transaction():
            pending = await self._approvals.mint(
                request=request,
                policy_ref=reconciliation_policy_ref(request),
                requested_by=owner,
                expires_at=min(self._clock() + CONTROL_TTL, fence.expires_at),
                tx=tx,
            )
            await self._final(tx, fence, handle, expires_at=pending.approval.expires_at)
        return pending

    async def status(
        self, tx: TransactionManager, *, scope: AdmittedInstallation, approval_id: str
    ) -> ReconciliationControlStatus | None:
        control = await self._audit.control(tx, scope=scope, approval_id=approval_id)
        if control is None:
            return None
        approval = await self._audit.approval_in(tx, approval_id)
        view = await self._reads.get(tx, scope=scope, reconcile_ref=control.original.reconcile_ref)
        if approval is None or view is None:
            raise UseAuditUnavailable()
        return ReconciliationControlStatus(
            control, view.state, approval.state_at(self._clock()), approval.delivery_status
        )

    async def present(
        self, tx: TransactionManager, *, pending: PendingApproval, fence: OwnerReconciliationFence
    ) -> ReconciliationPresentation:
        handle = await fence.prepare(tx)
        status = await self.status(tx, scope=fence.scope, approval_id=pending.approval.approval_id)
        if status is None:
            raise ReconciliationRefused("reconciliation_not_found")
        control = status.control
        self._bound(control, fence)
        if (
            len(pending.deliveries) != 1
            or status.original_state is not State.OUTCOME_UNKNOWN
            or (pending.approval.request_ref, pending.approval.request_sha256)
            != (control.approval_ref, control.request_sha256)
        ):
            raise ReconciliationRefused("reconciliation_conflict")
        [delivery] = pending.deliveries
        linked = await self._approvals.open_link(delivery.link_token)
        if (
            linked.approval.approval_id != control.approval_id
            or len(linked.approval.candidates) != 1
            or (linked.approval.candidates[0].scope, linked.approval.candidates[0].subject)
            != (fence.owner_scope, fence.owner_subject)
        ):
            raise ReconciliationRefused("owner_required")
        await self._final(tx, fence, handle, expires_at=control.expires_at)
        return ReconciliationPresentation(status, delivery.link_token)

    async def _proof(self, tx, control, approval):
        decided = approval.decided_by
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.reconciliation_control_proofs}} WHERE approval_id=$1 AND purpose='approve'",
            control.approval_id,
        )
        if (
            decided is None
            or decided.assurance is not Assurance.PASSKEY
            or row is None
            or (row["scope"], row["subject"], row["evidence_ref"])
            != (control.owner_scope, control.owner_subject, decided.evidence_ref)
            or (decided.scope, decided.subject) != (control.owner_scope, control.owner_subject)
        ):
            raise UseAuditUnavailable()
        try:
            commitment = await self._passkeys.evidence_commitment(
                decided.evidence_ref,
                context=PasskeyInstallationContext(
                    control.original.installation.app_id,
                    control.original.installation.team_id,
                    control.original.installation.installation_id,
                    control.original.installation.generation,
                ),
                scope=control.owner_scope,
                subject=control.owner_subject,
                purpose="approve",
                tx=tx,
            )
        except PasskeyProofUnavailable:
            raise UseAuditUnavailable() from None
        if commitment != row["commitment"]:
            raise UseAuditUnavailable()

    @staticmethod
    def _receipt(control: ReconciliationControl) -> ReconciliationReceipt:
        return ReconciliationReceipt(
            control.original.reconcile_ref,
            control.original.request_id,
            control.original.dispatch_id,
            control.approval_id,
            control.approval_ref,
            cast(
                Literal["reconciled_completed", "reconciled_failed", "reconciled_unknown"],
                _STATES[control.outcome].value,
            ),
        )

    @staticmethod
    def _payload(receipt: ReconciliationReceipt) -> dict[str, str]:
        return {
            "state": receipt.state,
            "request_id": receipt.request_id,
            "request_ref": receipt.reconcile_ref,
            "reconcile_ref": receipt.reconcile_ref,
            "control_approval_id": receipt.control_approval_id,
            "control_approval_ref": receipt.control_approval_ref,
        }

    async def settle(
        self, tx: TransactionManager, *, approval_id: str, fence: OwnerReconciliationFence
    ) -> ReconciliationReceipt:
        control = await self._audit.control(tx, scope=fence.scope, approval_id=approval_id)
        if control is None:
            raise ReconciliationRefused("reconciliation_not_found")
        self._bound(control, fence)
        backend = self._backend(control.original)
        handle = await fence.prepare(tx)
        originals = await self._use_audit.dispatch_approvals(tx, control.original.dispatch_id)
        await self._approvals.lock_many(tx, [approval_id, *(a.approval_id for a in originals)])
        receipt = self._receipt(control)
        result = self._payload(receipt)
        try:
            async with tx.transaction():
                row = await tx.fetch_one(
                    "SELECT state,result FROM {{tables.dispatches}} WHERE dispatch_id=$1",
                    control.original.dispatch_id,
                )
                if row is None:
                    raise UseAuditUnavailable()
                if row["state"] != State.OUTCOME_UNKNOWN:
                    stored = (
                        json.loads(row["result"])
                        if isinstance(row["result"], str)
                        else row["result"]
                    )
                    if row["state"] != receipt.state or stored != result:
                        raise ReconciliationRefused("reconciliation_conflict")
                    prior = await self._audit.approval_in(tx, approval_id)
                    if (
                        prior is None
                        or prior.state is not ApprovalState.CONSUMED
                        or prior.consumed_operation_id != str(control.control_id)
                        or prior.dispatch_outcome is not DispatchOutcome.COMPLETED
                    ):
                        raise UseAuditUnavailable()
                    await self._final(tx, fence, handle, expires_at=control.expires_at)
                    return receipt
                approval = await self._audit.approval_in(tx, approval_id)
                if approval is None:
                    raise UseAuditUnavailable()
                if approval.state is not ApprovalState.APPROVED:
                    raise ApprovalRefused(Refusal.NOT_APPROVED)
                await self._proof(tx, control, approval)
                request = reconciliation_request(
                    control.original,
                    control_id=control.control_id,
                    outcome=control.outcome,
                    owner_scope=control.owner_scope,
                    owner_subject=control.owner_subject,
                )
                admitted = await self._approvals.admit(
                    approval_id, request, str(control.control_id), tx=tx
                )
                if not admitted.may_send:
                    raise ReconciliationRefused("reconciliation_conflict")
                prepared = await self._approvals.prepare_dispatch(
                    tx,
                    approval_id,
                    request,
                    str(control.control_id),
                    authority=_ControlAuthority(tx, control, handle, self._passkeys),
                )
                await self._approvals.check_dispatch(tx, prepared)
                # Original consequence locks (including request advisory locks)
                # precede the original S3 lock. No publication gate is applied.
                for original in sorted(originals, key=lambda a: a.request_sha256):
                    await self._approvals.reconcile(
                        original.approval_id,
                        str(control.original.dispatch_id),
                        DispatchOutcome(receipt.state),
                        reconciled_by=fence.owner_subject,
                        tx=tx,
                    )
                await backend.reconcile(
                    tx, original=control.original, state=_STATES[control.outcome], result=result
                )
                await self._approvals.record_outcome(
                    approval_id,
                    str(control.control_id),
                    DispatchOutcome.COMPLETED,
                    tx=tx,
                )
                await self._final(
                    tx, fence, handle, expires_at=min(control.expires_at, prepared.expires_at)
                )
        except InvalidTransition:
            raise ReconciliationRefused("reconciliation_conflict") from None
        except ApprovalRefused as exc:
            if exc.reason is Refusal.OUTCOME_FINAL:
                raise ReconciliationRefused("reconciliation_conflict") from None
            raise
        return receipt
