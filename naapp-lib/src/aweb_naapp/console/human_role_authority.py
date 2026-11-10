"""The console handoff's authority over one human role, on the shared holding
store (human-role-holders.md, Reading a holding).

A public scope (installation, role, principal) selects a holding and proves
nothing. Projection reads the current holding outside any effect transaction.
The hold takes the installation's fence, then the holding FOR SHARE, then
prepares B3 once for the complete pair union, and refuses unless the holding's
version (``held_since``) and credential subject are still the projected ones:
a revocation, a re-designation or a replacement in between refuses rather than
retargets. Check reuses the issued handle in its own transaction, by SQL only.

Membership and kind are not checked here; the shared handoff runs the
exact-principal check around every hold and check.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from weakref import ReferenceType, ref

from fastapi import HTTPException
from pgdbm.core import TransactionManager

from aweb_naapp import roles
from aweb_naapp.console.handoff_authority import PublicScope
from aweb_naapp.runtime.human_roles import HumanRoleHolding, HumanRoleHoldings
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationDispatchFence,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.passkeys import Passkeys, PreparedCurrentApprovers


def _not_held() -> HTTPException:
    return HTTPException(403, "role_not_held")


def _sign_in_again() -> HTTPException:
    return HTTPException(401, "console_session_required")


@dataclass(frozen=True)
class HumanRoleCredentialTarget:
    """A registration destination; it grants no holding or session."""

    public_scope: PublicScope
    admitted: AdmittedInstallation
    b3_scope: str

    @property
    def team_id(self) -> str:
        return self.admitted.team_id


@dataclass(frozen=True)
class HumanRoleSessionTarget(HumanRoleCredentialTarget):
    """The projected holding: its credential subject and its version."""

    subject: str
    held_since: datetime

    @property
    def holding_ref(self) -> tuple[AdmittedInstallation, PublicScope, str, datetime]:
        return self.admitted, self.public_scope, self.subject, self.held_since


@dataclass(frozen=True)
class PreparedHumanRoleHolding:
    """Authority held in one original transaction: never a session or proof."""

    target: HumanRoleSessionTarget
    _authority: HumanRoleHandoffAuthority = field(repr=False)
    _tx: TransactionManager = field(repr=False)
    _fence: InstallationDispatchFence = field(repr=False)
    _approvers: PreparedCurrentApprovers = field(repr=False)
    _pairs: tuple[tuple[str, str], ...] = field(repr=False)
    _issued_as: ReferenceType[PreparedHumanRoleHolding] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def approvers(self) -> PreparedCurrentApprovers:
        """The complete B3 union, for downstream consumers in this transaction."""
        return self._approvers

    @property
    def approver_pairs(self) -> tuple[tuple[str, str], ...]:
        return self._pairs


class HumanRoleHandoffAuthority:
    """The HandoffAuthority callbacks for ``role`` over the shared store."""

    def __init__(
        self,
        *,
        role: str,
        holdings: HumanRoleHoldings,
        fence: InstallationFence,
        passkeys: Passkeys,
    ) -> None:
        self.role = role
        self._holdings = holdings
        self._fence = fence
        self._passkeys = passkeys

    def _scope(self, scope: Any) -> PublicScope:
        try:
            installation_id, role, principal = scope.installation_id, scope.role, scope.principal
        except AttributeError:
            raise _not_held() from None
        if (
            not isinstance(installation_id, str)
            or not installation_id
            or role != self.role
            or not isinstance(principal, str)
            or not principal.startswith("did:aw:")
            or principal == "did:aw:"
        ):
            raise _not_held()
        return PublicScope(installation_id, role, principal)

    async def _installation(self, installation_id: str) -> AdmittedInstallation:
        """The admitted installation ``installation_id`` names: the fence's
        one record of it, refreshed outside any app lock."""
        rows = await self._fence.db.fetch_all(
            "SELECT team_id FROM {{tables.installation_fences}}"
            " WHERE app_id = $1 AND installation_id = $2",
            self._fence.app_id,
            installation_id,
        )
        if len(rows) != 1:
            raise _not_held()
        try:
            admitted = (await self._fence.permit(rows[0]["team_id"])).admitted
        except InstallationRefused as refused:
            # An inactive installation holds nothing; anything else, such as
            # an installation authority that cannot be reached, keeps its own
            # typed refusal rather than reading as a lost holding.
            if refused.code == "installation_inactive":
                raise _not_held() from None
            raise
        if admitted.installation_id != installation_id:
            raise _not_held()
        return admitted

    async def credential_target(self, public_scope: Any) -> HumanRoleCredentialTarget:
        scope = self._scope(public_scope)
        admitted = await self._installation(scope.installation_id)
        async with self._fence.db.transaction() as tx:
            await self._fence.check(tx, admitted)
        return HumanRoleCredentialTarget(
            scope,
            admitted,
            roles.holding_scope(
                admitted.installation_id, admitted.team_id, scope.role, scope.principal
            ),
        )

    async def session_target(self, public_scope: Any) -> HumanRoleSessionTarget:
        destination = await self.credential_target(public_scope)
        async with self._fence.db.transaction() as tx:
            await self._fence.check(tx, destination.admitted)
            held = await self._read(tx, destination)
        if held is None:
            raise _not_held()
        if held.subject is None:
            # The holding remains; no credential can sign in until a
            # replacement's cooling-off ends.
            raise _sign_in_again()
        return HumanRoleSessionTarget(
            destination.public_scope,
            destination.admitted,
            destination.b3_scope,
            held.subject,
            held.held_since,
        )

    async def _read(
        self, tx: TransactionManager, target: HumanRoleCredentialTarget
    ) -> HumanRoleHolding | None:
        held = await self._holdings.read_holding(
            tx,
            installation=target.admitted,
            role=target.public_scope.role,
            principal=target.public_scope.principal,
        )
        if held is not None and held.b3_scope != target.b3_scope:
            return None
        return held

    async def hold_session_target(
        self,
        tx: TransactionManager,
        target: HumanRoleSessionTarget | PreparedHumanRoleHolding,
        *,
        approver_pairs: Sequence[tuple[str, str]],
    ) -> PreparedHumanRoleHolding:
        """The fence, then the holding FOR SHARE, then one B3 preparation of
        the complete pair union, which must include the target's own pair.

        Repeated preparation passes the returned handle and its pairs; that
        only checks it and returns the identical object.
        """
        if isinstance(target, PreparedHumanRoleHolding):
            pairs = self._pair_union(target.target, approver_pairs)
            if pairs != target._pairs or not await self.check_session_target(tx, target):
                raise _not_held()
            return target
        if not isinstance(target, HumanRoleSessionTarget):
            raise _not_held()
        self._require_own(target)
        pairs = self._pair_union(target, approver_pairs)
        fence = self._fence.for_installation(target.admitted)
        await fence.prepare(tx)
        await fence.check(tx, target)
        scope = target.public_scope
        held = await self._holdings.hold_holding(
            tx, installation=target.admitted, role=scope.role, principal=scope.principal
        )
        if held is None or held.b3_scope != target.b3_scope or held.held_since != target.held_since:
            raise _not_held()
        approvers = await self._passkeys.prepare_current_approvers(tx, pairs)
        current = held.subject == target.subject and await self._passkeys.check_current_approver(
            tx, approvers, scope=target.b3_scope, subject=target.subject
        )
        # Sample the fence deadline after the last B3 wait, before refusing.
        await fence.check(tx, target)
        if not current:
            raise _sign_in_again()
        prepared = PreparedHumanRoleHolding(target, self, tx, fence, approvers, pairs)
        # A reconstructed dataclass must not turn copied fields into a handle
        # this authority issued. This is in-process identity, not a store.
        object.__setattr__(prepared, "_issued_as", ref(prepared))
        return prepared

    def _require_own(self, target: HumanRoleSessionTarget) -> None:
        """A target this authority could have projected: its selector names
        this role and the target's own admitted installation, and its B3 scope
        is that holding's. A target of another role's authority, sharing the
        store, is refused here rather than held."""
        scope = self._scope(target.public_scope)
        admitted = target.admitted
        if scope.installation_id != admitted.installation_id or target.b3_scope != (
            roles.holding_scope(
                admitted.installation_id, admitted.team_id, scope.role, scope.principal
            )
        ):
            raise _not_held()

    @staticmethod
    def _pair_union(
        target: HumanRoleSessionTarget, pairs: Sequence[tuple[str, str]]
    ) -> tuple[tuple[str, str], ...]:
        if not isinstance(pairs, Sequence) or isinstance(pairs, (str, bytes)):
            raise _not_held()
        if any(
            not isinstance(pair, (tuple, list))
            or len(pair) != 2
            or any(not isinstance(value, str) or not value for value in pair)
            for pair in pairs
        ):
            raise _not_held()
        union = tuple(sorted({(pair[0], pair[1]) for pair in pairs}))
        if (target.b3_scope, target.subject) not in union:
            raise _not_held()
        return union

    async def check_session_target(
        self, tx: TransactionManager, held: PreparedHumanRoleHolding
    ) -> bool:
        """SQL reads only, with the authority already held: no refresh, row
        lock or rearm."""
        if (
            not isinstance(held, PreparedHumanRoleHolding)
            or held._issued_as is None
            or held._issued_as() is not held
            or held._authority is not self
            or held._tx is not tx
        ):
            return False
        target = held.target
        if not await self._passkeys.check_current_approver(
            tx, held._approvers, scope=target.b3_scope, subject=target.subject
        ):
            return False
        current = await self._read(tx, target)
        if (
            current is None
            or current.held_since != target.held_since
            or current.subject != target.subject
        ):
            return False
        try:
            await held._fence.check(tx, target)
        except InstallationRefused:
            return False
        return True
