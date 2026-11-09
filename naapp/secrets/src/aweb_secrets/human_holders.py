"""App-local owner holdings for the shared human handoff (acwd.4.5 slice 1).

This structural projection supplies no certificate, human classification, LOGIN
evidence or session. Those belong to the shared handoff/runtime. It reads the
existing owner, role and B3 records and pins them in the consumer's transaction.
The concrete shared handoff DTO/factory remains its owner's integration seam.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from aweb_naapp.roles import PrincipalKey, hold_role
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationDispatchFence,
    InstallationRefused,
)
from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers
from fastapi import HTTPException
from pgdbm.core import TransactionManager

from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.principal import is_principal

if TYPE_CHECKING:
    from aweb_secrets.console import OwnerConsole


class PublicScope(Protocol):
    @property
    def installation_id(self) -> str: ...

    @property
    def role(self) -> str: ...

    @property
    def principal(self) -> str: ...


@dataclass(frozen=True)
class OwnerPublicScope:
    installation_id: str
    role: str
    principal: str


@dataclass(frozen=True)
class OwnerCredentialTarget:
    """A registration destination; it grants no holding or session."""

    public_scope: OwnerPublicScope
    admitted: AdmittedInstallation
    b3_scope: str

    @property
    def team_id(self) -> str:
        return self.admitted.team_id


@dataclass(frozen=True)
class OwnerSessionTarget(OwnerCredentialTarget):
    """Existing app records only; shared/runtime adds verified remote evidence."""

    subject: str
    _role_assigned_at: datetime = field(repr=False)

    @property
    def holding_ref(self) -> tuple[AdmittedInstallation, OwnerPublicScope, str, datetime]:
        return self.admitted, self.public_scope, self.subject, self._role_assigned_at


@dataclass(frozen=True)
class PreparedOwnerHolding:
    """Local authority retained in one original tx, never a session or proof."""

    target: OwnerSessionTarget
    _authority: OwnerHoldingAuthority = field(repr=False)
    _tx: TransactionManager = field(repr=False)
    _fence: InstallationDispatchFence = field(repr=False)
    _approvers: PreparedCurrentApprovers = field(repr=False)


def _refused() -> HTTPException:
    return HTTPException(403, "owner_required")


class OwnerHoldingAuthority:
    def __init__(self, *, console: OwnerConsole) -> None:
        self._console = console

    @staticmethod
    def _scope(scope: PublicScope) -> OwnerPublicScope:
        try:
            installation_id, role, principal = scope.installation_id, scope.role, scope.principal
        except AttributeError:
            raise _refused() from None
        if (
            not isinstance(installation_id, str)
            or not installation_id
            or role != OWNER_ROLE
            or not is_principal(principal)
        ):
            raise _refused()
        return OwnerPublicScope(installation_id, role, principal)

    async def credential_target(self, public_scope: PublicScope) -> OwnerCredentialTarget:
        scope = self._scope(public_scope)
        # The root's sole lookup may refresh remote authority. No app lock yet.
        try:
            admitted = await self._console.installation(scope.installation_id)
        except LookupError:
            raise _refused() from None
        if admitted.installation_id != scope.installation_id:
            raise _refused()
        async with self._console.db.transaction() as tx:
            await self._console.fence.check(tx, admitted)
        return OwnerCredentialTarget(
            scope,
            admitted,
            owner_scope(admitted.installation_id, admitted.team_id, scope.principal),
        )

    async def session_target(self, public_scope: PublicScope) -> OwnerSessionTarget:
        destination = await self.credential_target(public_scope)
        approver = await self._console.passkeys.designated_approver(destination.b3_scope)
        if approver is None:
            raise _refused()
        async with self._console.db.transaction() as tx:
            await self._console.fence.check(tx, destination.admitted)
            assigned_at = await self._role_stamp(tx, destination)
        # This projection grants nothing; the caller must hold/recheck it before
        # release or effect. A changed B3 association cannot heal this subject.
        return OwnerSessionTarget(
            destination.public_scope,
            destination.admitted,
            destination.b3_scope,
            approver.subject,
            assigned_at,
        )

    async def _role_stamp(self, tx: TransactionManager, target: OwnerCredentialTarget) -> datetime:
        scope = self._scope(target.public_scope)
        admitted = target.admitted
        if scope.installation_id != admitted.installation_id or target.b3_scope != owner_scope(
            admitted.installation_id, admitted.team_id, scope.principal
        ):
            raise _refused()
        owner = await self._console.directory.owner_of(tx, target.b3_scope)
        if owner != PrincipalKey(admitted.team_id, scope.principal):
            raise _refused()
        row = await tx.fetch_one(
            "SELECT r.assigned_at FROM {{tables.owner_principals}} p"
            " JOIN {{tables.role_assignments}} r"
            " ON r.team_id=p.team_id AND r.principal_did=p.principal_did AND r.role=$5"
            " WHERE p.scope=$1 AND p.installation_id=$2 AND p.team_id=$3 AND p.principal_did=$4",
            target.b3_scope,
            admitted.installation_id,
            admitted.team_id,
            scope.principal,
            OWNER_ROLE,
        )
        if row is None:
            raise _refused()
        return row["assigned_at"]

    async def hold_session_target(
        self,
        tx: TransactionManager,
        target: OwnerSessionTarget,
        *,
        approvers: PreparedCurrentApprovers | None = None,
    ) -> PreparedOwnerHolding:
        """Prepare before B2/S3/session locks, after caller-specific app prelocks.

        Callers with a complete prepared B3 union pass it through; it is checked
        in the identical tx and no new B3 locks are acquired. Never call this
        across a fresh Approvals.decide ceremony or as a late check.
        """
        fence = self._console.fence.for_installation(target.admitted)
        await fence.prepare(tx)
        await fence.check(tx, target)
        owner = await self._console.directory.owner_of(tx, target.b3_scope)
        if owner is None or not await hold_role(tx, owner, OWNER_ROLE):
            raise _refused()
        if await self._role_stamp(tx, target) != target._role_assigned_at:
            raise _refused()
        if approvers is None:
            approvers = await self._console.passkeys.prepare_current_approvers(
                tx, [(target.b3_scope, target.subject)]
            )
        held = PreparedOwnerHolding(target, self, tx, fence, approvers)
        if not await self.check_session_target(tx, held):
            raise _refused()
        return held

    async def check_session_target(
        self, tx: TransactionManager, held: PreparedOwnerHolding
    ) -> bool:
        """SQL reads only, using held authority; no refresh, row lock or rearm."""
        if held._authority is not self or held._tx is not tx:
            return False
        target = held.target
        if not await self._console.passkeys.check_current_approver(
            tx, held._approvers, scope=target.b3_scope, subject=target.subject
        ):
            return False
        try:
            if await self._role_stamp(tx, target) != target._role_assigned_at:
                return False
            # The public bound F6 protocol reuses the prepare-time lock and
            # samples its SQL deadline after the other local reads/waits.
            await held._fence.check(tx, target)
        except (HTTPException, InstallationRefused):
            return False
        return True
