"""Required credential/change and use/run branches on the original caller tx."""

from aweb_naapp.runtime.audit import AuditEvent
from aweb_naapp.runtime.credential_audit import (
    CredentialAudit,
    GovernanceUnavailable,
    is_credential_event,
)
from pgdbm.core import TransactionManager

from aweb_secrets.use_audit import UseApprovalAudit, is_run_approval, is_use_approval


class SecretsAudit:
    def __init__(self, *, credentials: CredentialAudit, use: UseApprovalAudit) -> None:
        if credentials is None or use is None:
            raise ValueError("both production audit branches are required")
        self._credentials, self._use = credentials, use

    async def emit(self, event: AuditEvent, transaction: TransactionManager) -> None:
        if is_use_approval(event) or is_run_approval(event):
            # One shared branch; its explicit run opt-in rejects reserved run
            # events before any run-table read. No governance fallback.
            await self._use.emit(event, transaction)
        elif is_credential_event(event) or self._credentials.is_change_approval(event):
            await self._credentials.emit(event, transaction)
        else:
            raise GovernanceUnavailable()
