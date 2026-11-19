"""An app's one read of its human-role holdings (human-role-holders.md,
Reading a holding).

A holding joins the shared store's record (aweb_naapp.roles) to B3's approver
for its scope. The read runs in the caller's transaction by SQL only: no
registry read, no refresh, and no B3 lock. Membership and kind are the caller's
shared check (runtime.human_member), never this read's, so a holding whose
principal left the team still reads, and revoke can find it.

Lock order for a holder: the installation fence, then hold_holding for every
holding the transaction needs, then ONE sorted B3 preparation of every
(b3_scope, subject) pair (Passkeys.prepare_current_approvers), then the
caller's own rows. Writers lock the holding FOR UPDATE after the fence and
before any B3 row, so the two orders never cycle.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime

from pgdbm.core import TransactionManager

from aweb_naapp import roles
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import Passkeys


@dataclass(frozen=True)
class HumanRoleHolding:
    installation_id: str
    team_id: str
    role: str
    principal: str
    b3_scope: str
    # B3's subject for the credential that can log in; None while none can,
    # such as during a replacement's cooling-off. The holding still exists.
    subject: str | None
    held_since: datetime
    # The exact certificate retained for the holding; None for a holding
    # retained before certificates were, until a session handoff refreshes it.
    certificate: bytes | None


type _Read = Callable[..., Awaitable[roles.Holding | None]]


class HumanRoleHoldings:
    """The holdings of the roles an app declares with the human-role acts."""

    def __init__(self, *, roles: frozenset[str], passkeys: Passkeys) -> None:
        self._roles = roles
        self._passkeys = passkeys

    async def read_holding(
        self,
        tx: TransactionManager,
        *,
        installation: AdmittedInstallation,
        role: str,
        principal: str,
    ) -> HumanRoleHolding | None:
        """The current holding, or None: never designated, revoked, a role the
        app does not declare with the human-role acts, or a non-did:aw principal."""
        return await self._holding(tx, roles.read_holding, installation, role, principal)

    async def read_holding_of_scope(
        self, tx: TransactionManager, *, installation: AdmittedInstallation, b3_scope: str
    ) -> HumanRoleHolding | None:
        """The current holding whose B3 scope is ``b3_scope``, the same as
        read_holding gives for it, for a caller that holds only the scope. None
        when the scope names no current holding, another installation's or
        team's, or a role the app does not declare. There is no hold by scope:
        before an effect, hold_holding its principal and compare."""
        held = await roles.read_holding_of_scope(tx, b3_scope)
        if held is None or (held.installation_id, held.team_id) != (
            installation.installation_id,
            installation.team_id,
        ):
            return None
        return await self._human_holding(tx, held)

    async def hold_holding(
        self,
        tx: TransactionManager,
        *,
        installation: AdmittedInstallation,
        role: str,
        principal: str,
    ) -> HumanRoleHolding | None:
        """The same result as read_holding, with the holding held FOR SHARE until
        the transaction ends, so no holding writer commits under it. It takes no
        B3 row: the caller prepares B3 once, after all its holds."""
        return await self._holding(tx, roles.hold_holding, installation, role, principal)

    async def refresh_holding_certificate(
        self, tx: TransactionManager, *, holding: HumanRoleHolding, certificate: bytes
    ) -> bool:
        """Retain ``certificate`` for ``holding`` after a session handoff has
        verified it for this holding's team and principal and its login has
        committed. Run in its own transaction: the fence, then this, and no B3
        or session row. False, writing nothing, once the holding has changed."""
        return await roles.refresh_holding_certificate(
            tx,
            installation_id=holding.installation_id,
            team_id=holding.team_id,
            role=holding.role,
            principal=holding.principal,
            held_since=holding.held_since,
            certificate=certificate,
        )

    async def _holding(
        self,
        tx: TransactionManager,
        read: _Read,
        installation: AdmittedInstallation,
        role: str,
        principal: str,
    ) -> HumanRoleHolding | None:
        if role not in self._roles:
            return None
        try:
            held = await read(
                tx,
                installation_id=installation.installation_id,
                team_id=installation.team_id,
                role=role,
                principal=principal,
            )
        except ValueError:
            return None
        if held is None:
            return None
        return await self._human_holding(tx, held)

    async def _human_holding(
        self, tx: TransactionManager, held: roles.Holding
    ) -> HumanRoleHolding | None:
        if held.role not in self._roles:
            return None
        return HumanRoleHolding(
            installation_id=held.installation_id,
            team_id=held.team_id,
            role=held.role,
            principal=held.principal,
            b3_scope=held.b3_scope,
            subject=await self._passkeys.current_subject_in(tx, held.b3_scope),
            held_since=held.held_since,
            certificate=held.certificate,
        )
