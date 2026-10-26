"""Prepare one complete owner/B3/S4 union for a reconciliation transaction.

Create a fresh fence from the authenticated request session and authoritative
installation for each mint, settle or postcommit presentation transaction.
Never hold this fence across Approvals.decide: that separate fresh APPROVE
ceremony updates B3 credentials in its own transaction.
"""

from datetime import UTC, datetime

from aweb_naapp.console import ConsoleSession
from aweb_naapp.roles import PrincipalKey, has_role, hold_role
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers
from fastapi import HTTPException
from pgdbm.core import TransactionManager

from aweb_secrets.console import OwnerConsole
from aweb_secrets.owners import OWNER_ROLE, owner_scope


class ConsoleReconciliationFence:
    def __init__(
        self, *, console: OwnerConsole, current: ConsoleSession, scope: AdmittedInstallation
    ) -> None:
        self._console, self._current, self._scope = console, current, scope
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
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at"
            " FROM {{tables.console_sessions}} WHERE token_sha256=$1"
            + (" FOR SHARE" if lock else ""),
            self._current.token_sha256,
        )
        if (
            row is None
            or row["closed_at"] is not None
            or (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            != (
                self.owner_scope,
                self.owner_subject,
                self._current.evidence_ref,
                self.expires_at,
            )
            or self.expires_at <= datetime.now(UTC)
        ):
            raise HTTPException(401, "console_session_required")

    async def prepare(self, tx: TransactionManager) -> PreparedCurrentApprovers:
        if self._tx is not None:
            # A handle never renews lost holds, even after rollback to a
            # savepoint on the same TransactionManager object.
            await self.check(tx)
            assert self._handle is not None
            return self._handle
        await self._console.fence.check(tx, self.scope)
        owner = await self._console.directory.owner_of(tx, self.owner_scope)
        if (
            owner is None
            or owner.team_id != self.scope.team_id
            or owner_scope(self.scope.installation_id, owner.team_id, owner.principal_did)
            != self.owner_scope
            or not await hold_role(tx, owner, OWNER_ROLE)
        ):
            raise HTTPException(403, "owner_required")
        # The exact control owner is the entire authority union. Original send
        # approvers confer no authority to record an uncertain consequence.
        handle = await self._console.passkeys.prepare_current_approvers(
            tx, [(self.owner_scope, self.owner_subject)]
        )
        if not await self._console.passkeys.login_evidence_is_current(
            self.owner_scope, self.owner_subject, self._current.evidence_ref, tx=tx
        ):
            raise HTTPException(401, "console_session_required")
        await self._session(tx, lock=True)
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
        if self._owner is None or not await has_role(tx, self._owner, OWNER_ROLE):
            raise HTTPException(403, "owner_required")
        await self._session(tx)
        await self._console.fence.check(tx, self.scope)
        # No awaited work follows the final live F6 and S4 deadline samples.
        if self.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "console_session_required")
