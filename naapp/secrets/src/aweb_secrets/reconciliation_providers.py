"""Route outcome-bound owner controls to their own B2 providers (§11.2).

Control ceremonies retain local audit evidence; only settlement records the
original dispatch's consequences. They never enter the secret-use audit branch.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from aweb_naapp.runtime.approvals import ActionPolicy, Approver
from aweb_naapp.runtime.approvals.model import ApproverDirectory, PolicySource
from aweb_naapp.runtime.audit import AuditEvent, AuditSink
from pgdbm.core import TransactionManager

from aweb_secrets.reconciliation_control_audit import (
    ReconciliationAudit,
    is_reconciliation_control,
)
from aweb_secrets.reconciliation_policy import (
    POLICY_PREFIX,
    ReconciliationApprovers,
    ReconciliationPolicies,
)


class ReconciliationPolicyRouter:
    def __init__(self, *, standard: PolicySource, controls: ReconciliationPolicies) -> None:
        self._standard = standard
        self._controls = controls

    async def current(
        self, policy_ref: str, *, tx: TransactionManager | None = None
    ) -> ActionPolicy | None:
        provider = self._controls if policy_ref.startswith(POLICY_PREFIX + "|") else self._standard
        return await provider.current(policy_ref, tx=tx)


class ReconciliationApproverRouter:
    def __init__(self, *, standard: ApproverDirectory, controls: ReconciliationApprovers) -> None:
        self._standard = standard
        self._controls = controls

    async def candidates(
        self,
        policy: ActionPolicy,
        request: Mapping[str, Any],
        *,
        tx: TransactionManager | None = None,
    ) -> Sequence[Approver]:
        provider = (
            self._controls if policy.policy_ref.startswith(POLICY_PREFIX + "|") else self._standard
        )
        return await provider.candidates(policy, request, tx=tx)

    async def is_current(
        self, scope: str, subject: str, *, tx: TransactionManager | None = None
    ) -> bool:
        return await self._standard.is_current(scope, subject, tx=tx)


class ReconciliationAuditRouter:
    def __init__(self, *, standard: AuditSink, controls: ReconciliationAudit) -> None:
        self._standard = standard
        self._controls = controls

    async def emit(self, event: AuditEvent, transaction: TransactionManager) -> None:
        provider = self._controls if is_reconciliation_control(event) else self._standard
        await provider.emit(event, transaction)
