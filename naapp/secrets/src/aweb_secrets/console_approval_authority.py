"""Original F6, app, B3 and S4 authority for a console approval effect.

Decision preparation runs through B2's fence only after fresh verification.
Reconciliation also reuses this authority for mint/settle/presentation.
"""

from datetime import UTC, datetime

from aweb_naapp.console import ConsoleSession, KeyBoundConsoleSession, session_is_current
from aweb_naapp.roles import PrincipalKey, has_role, hold_role
from aweb_naapp.runtime.approvals import ApprovalDecisionFence
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers
from fastapi import HTTPException
from pgdbm.core import TransactionManager

from aweb_secrets.console import OwnerConsole
from aweb_secrets.owners import OWNER_ROLE, is_owner_scope, owner_scope


class ConsoleApprovalAuthority:
    def __init__(
        self,
        *,
        console: OwnerConsole,
        current: ConsoleSession,
        scope: AdmittedInstallation,
        require_owner: bool = True,
    ) -> None:
        self._console, self._current, self._scope = console, current, scope
        self._require_owner = require_owner or is_owner_scope(current.scope)
        self._tx: TransactionManager | None = None
        self._handle: PreparedCurrentApprovers | None = None
        self._owner: PrincipalKey | None = None

    @property
    def scope(self) -> AdmittedInstallation:
        return self._scope

    @property
    def owner_scope(self) -> str:
        return self._current.scope

    @property
    def owner_subject(self) -> str:
        return self._current.subject

    @property
    def expires_at(self) -> datetime:
        return self._current.expires_at

    async def _session(self, tx: TransactionManager, *, lock: bool = False) -> None:
        if not await session_is_current(tx, self._current, hold=lock):
            raise HTTPException(401, "console_session_required")

    async def prepare(self, tx: TransactionManager) -> PreparedCurrentApprovers:
        if self._tx is not None:
            # A handle never renews lost holds, even after rollback to a
            # savepoint on the same TransactionManager object.
            await self.check(tx)
            assert self._handle is not None
            return self._handle
        await self._console.fence.check(tx, self.scope)
        owner = None
        if self._require_owner:
            owner = await self._console.directory.owner_of(tx, self.owner_scope)
            if (
                owner is None
                or owner.team_id != self.scope.team_id
                or owner_scope(self.scope.installation_id, owner.team_id, owner.principal_did)
                != self.owner_scope
                or not await hold_role(tx, owner, OWNER_ROLE)
            ):
                raise HTTPException(403, "owner_required")
        else:
            await self._approver(tx)
        # The actual deciding pair is the complete B3 union. Preparation is
        # after its fresh assertion has committed, before any B2 effect lock.
        pairs = [(self.owner_scope, self.owner_subject)]
        handle = await self._console.prepare_session(tx, self._current, approver_pairs=pairs)
        if handle is None:
            handle = await self._console.passkeys.prepare_current_approvers(tx, pairs)
        signed = isinstance(self._current, KeyBoundConsoleSession)
        if not await self._console.passkeys.login_evidence_is_current(
            self.owner_scope,
            self.owner_subject,
            self._current.evidence_ref,
            tx=tx,
            hold=not signed,
        ):
            raise HTTPException(401, "console_session_required")
        await self._session(tx, lock=not signed)
        self._owner, self._handle, self._tx = owner, handle, tx
        # Also warm all final plain reads before any downstream B2/S3 locks.
        await self.check(tx)
        return handle

    async def check(self, tx: TransactionManager) -> None:
        if (
            self._tx is not tx
            or self._handle is None
            or not await self._console.passkeys.check_current_approver(
                tx, self._handle, scope=self.owner_scope, subject=self.owner_subject
            )
        ):
            raise HTTPException(401, "console_session_required")
        if self._require_owner:
            if self._owner is None or not await has_role(tx, self._owner, OWNER_ROLE):
                raise HTTPException(403, "owner_required")
        else:
            await self._approver(tx)
        await self._console.fence.check(tx, self.scope)
        await self._session(tx)
        # No awaited work follows the final live F6 and S4 deadline samples.
        if self.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "console_session_required")

    async def _approver(self, tx: TransactionManager) -> None:
        if not await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.approvers}} "
            "WHERE installation_id=$1 AND team_id=$2 AND scope=$3)",
            self.scope.installation_id,
            self.scope.team_id,
            self.owner_scope,
        ):
            raise HTTPException(403, "approver_required")

    def for_decision(self) -> ApprovalDecisionFence:
        return _DecisionFence(self)


class _DecisionFence:
    def __init__(self, authority: ConsoleApprovalAuthority) -> None:
        self._authority = authority

    async def prepare(self, tx: TransactionManager) -> None:
        await self._authority.prepare(tx)

    async def check(self, tx: TransactionManager) -> None:
        await self._authority.check(tx)
