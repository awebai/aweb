"""The readers of a team's log: the current holders of ``logs.reader``, humans
the owner names by a human-role act, who read only in a passkey session on
logs' console origin (audit-substrate.md §B5, human-role-holders.md).

A reader's B3 scope is its holding's: ``logs.reader.<40 hex>``, named by the
installation, the team and the principal, never by a contact. The holding
store keeps one record per scope; a console session holds only the scope, and
the directory answers from the store on every request: the holding must be
current, in logs' active installation, with a credential that can sign in.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.roles import (
    holding_record_of_scope,
    members_of,
    principal_key,
)
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.human_roles import HumanRoleHolding, HumanRoleHoldings
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    Passkeys,
    ProofContextResolver,
    ProofContextUnavailable,
    RetirementRefused,
    installation_context,
)
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_logs.ledger import Conflicted, LogsSigner, append_on

if TYPE_CHECKING:
    from aweb_naapp.runtime.credential_audit import CredentialAudit
    from aweb_naapp.runtime.team_auth import Principal

READER_ROLE = "logs.reader"
_SCOPE = re.compile(r"logs\.reader\.[0-9a-f]{40}")


def is_reader_scope(scope: str) -> bool:
    return _SCOPE.fullmatch(scope) is not None


class RemovalRefused(Exception):
    """A member's removal of a reader that team authority cannot make."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Reader:
    scope: str
    installation_id: str
    team_id: str
    principal: str


class ReaderDirectory:
    """The readers of this deployment: the current ``logs.reader`` holdings."""

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        app_id: str,
        passkeys: Callable[[], Passkeys],
    ) -> None:
        self.db = db
        self.app_id = app_id
        self._passkeys = passkeys

    async def reader(self, scope: str) -> Reader | None:
        """The reader ``scope`` admits now: the current holder of
        ``logs.reader`` whose holding B3 scope it is, in that holding's active
        installation, with a credential that can sign in. None for any other
        scope, a pre-ruling slot among them, and while a replaced credential
        is in its cooling-off."""
        if not is_reader_scope(scope):
            return None
        async with self.db.transaction() as tx:
            held = await self._held(tx, scope)
        if held is None or held.subject is None:
            return None
        return Reader(
            scope=scope,
            installation_id=held.installation_id,
            team_id=held.team_id,
            principal=held.principal,
        )

    async def _held(self, tx: TransactionManager, scope: str) -> HumanRoleHolding | None:
        """The current holding of ``scope`` in its own installation, provided
        that installation is still logs' active one; SQL reads only."""
        record = await holding_record_of_scope(tx, scope)
        if record is None or record.role != READER_ROLE:
            return None
        try:
            context = await installation_context(
                tx,
                app_id=self.app_id,
                team_id=record.team_id,
                installation_id=record.installation_id,
            )
        except ProofContextUnavailable:
            return None
        admitted = AdmittedInstallation(
            team_id=context.team_id,
            app_id=context.app_id,
            installation_id=context.installation_id,
            generation=context.generation,
        )
        return await self._holdings().read_holding_of_scope(
            tx, installation=admitted, b3_scope=scope
        )

    async def hold_holding(
        self, tx: TransactionManager, *, installation: AdmittedInstallation, principal: str
    ) -> HumanRoleHolding | None:
        """The current ``logs.reader`` holding of ``principal`` in
        ``installation``, held FOR SHARE until ``tx`` ends, so no holding
        writer commits under it; after the fence, before any B3 row."""
        return await self._holdings().hold_holding(
            tx, installation=installation, role=READER_ROLE, principal=principal
        )

    def _holdings(self) -> HumanRoleHoldings:
        return HumanRoleHoldings(roles=frozenset({READER_ROLE}), passkeys=self._passkeys())

    async def current_readers(self, *, installation_id: str, team_id: str) -> list[Reader]:
        """The readers of this installation and team who can sign in now, in
        scope order."""
        async with self.db.transaction() as tx:
            readers = await self.current_readers_in(
                tx, installation_id=installation_id, team_id=team_id
            )
        return sorted(readers, key=lambda reader: reader.scope)

    async def current_readers_in(
        self, tx: TransactionManager, *, installation_id: str, team_id: str
    ) -> list[Reader]:
        try:
            context = await installation_context(
                tx, app_id=self.app_id, team_id=team_id, installation_id=installation_id
            )
        except ProofContextUnavailable:
            return []
        admitted = AdmittedInstallation(
            team_id=context.team_id,
            app_id=context.app_id,
            installation_id=context.installation_id,
            generation=context.generation,
        )
        holdings = self._holdings()
        readers = []
        for member in await members_of(tx, team_id, READER_ROLE):
            held = await holdings.read_holding(
                tx, installation=admitted, role=READER_ROLE, principal=member.principal_did
            )
            if held is not None and held.subject is not None:
                readers.append(
                    Reader(
                        scope=held.b3_scope,
                        installation_id=held.installation_id,
                        team_id=held.team_id,
                        principal=held.principal,
                    )
                )
        return readers

    async def record(self, scope: str) -> Reader | None:
        """The ``logs.reader`` holding recorded for ``scope``, current or
        ended, as a reader of its installation and team. It admits nothing."""
        if not is_reader_scope(scope):
            return None
        held = await holding_record_of_scope(self.db, scope)
        if held is None or held.role != READER_ROLE:
            return None
        return Reader(
            scope=scope,
            installation_id=held.installation_id,
            team_id=held.team_id,
            principal=held.principal,
        )

    async def is_current_reader(self, scope: str) -> bool:
        """Whether ``scope`` admits a reader now (see :meth:`reader`): the
        console sessions' admission of a reader scope, at login and on every
        request."""
        return await self.reader(scope) is not None

    async def role_of(
        self, tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
    ) -> str | None:
        """The B3 role ``scope`` names in ``admitted``: a ``logs.reader``
        holding recorded for that installation and team, current or ended in
        this transaction, as when its revocation is recorded. It names the
        role only; admission reads the current holding."""
        record = await holding_record_of_scope(tx, scope)
        if (
            record is None
            or record.role != READER_ROLE
            or (record.installation_id, record.team_id)
            != (admitted.installation_id, admitted.team_id)
        ):
            return None
        return READER_ROLE

    def proof_context(self, *, app_id: str) -> ProofContextResolver:
        """B3's proof context of a reader scope: the installation its holding
        is recorded in, current or ended, which must still be the app's active
        installation of that team."""

        async def context(scope: str, *, tx: TransactionManager) -> PasskeyInstallationContext:
            record = await holding_record_of_scope(tx, scope)
            if record is None or record.role != READER_ROLE:
                raise ProofContextUnavailable()
            return await installation_context(
                tx, app_id=app_id, team_id=record.team_id, installation_id=record.installation_id
            )

        return context

    async def approver_retired(
        self, approver_subject: str, *, retired_by: str, tx: TransactionManager
    ) -> None:
        """A retired reader holds no approvals to revoke, and its console
        sessions end on their next request, which re-checks the holder."""

    def appender(self, signer: LogsSigner) -> Callable[[TransactionManager, UUID], Awaitable[None]]:
        """Append each governance event logs produces to the team's chain, in
        the transaction that enqueued it: the effect and its chain entry commit
        together or not at all.

        The entry's key evidence names logs' own producer key. It carries no
        admission until logs' own delivery of the same event arrives, which
        dedups and adds it.
        """

        async def append_own(tx: TransactionManager, event_id: UUID) -> None:
            row = await tx.fetch_one(
                "SELECT team_id, payload, signature FROM {{tables.outbox_events}}"
                " WHERE event_id = $1",
                event_id,
            )
            assert row is not None
            signing = bytes(row["payload"])
            event = verify(signing, row["signature"], team_id=row["team_id"])
            producer = event.fields["producer"]
            result = await append_on(
                tx,
                signer,
                event=event,
                signing_bytes=signing,
                signature=row["signature"],
                key_evidence={
                    "kid": event.producer_kid,
                    "did_key": event.producer_did_key,
                    "purposes": ["hook-event"],
                    "installation_id": producer["installation_id"],
                    "generation": producer["generation"],
                    "binding_ids": [],
                    "admissions": [],
                },
                received_at=datetime.now(UTC),
            )
            if isinstance(result, Conflicted):
                raise RuntimeError(f"the chain already holds other bytes for {event_id}")

        return append_own


class ReaderRemovals:
    """A team member removes a reader by team authority alone.

    The member's team-auth request names a current reader's scope. One
    transaction admits the installation, ends the holder's designation and
    records ``role.revoked`` with the member's team certificate as authority,
    which logs appends to its own chain. Team authority never removes the
    installation's last reader able to sign in, a current holder with an
    unrevoked passkey; only the owner's act can.
    """

    def __init__(
        self,
        directory: ReaderDirectory,
        *,
        fence: InstallationFence,
        passkeys: Passkeys,
        recorder: CredentialAudit,
    ) -> None:
        self.directory = directory
        self.fence = fence
        self.passkeys = passkeys
        self.recorder = recorder

    async def remove(self, *, principal: Principal, grant: Grant, scope: str) -> None:
        if principal.team_id != grant.team_id:
            raise RemovalRefused("reader_unknown", 404)
        reader = await self.directory.record(scope)
        if reader is None or reader.team_id != grant.team_id:
            raise RemovalRefused("reader_unknown", 404)
        await self.fence.refresh(grant.team_id)
        async with self.directory.db.transaction() as tx:
            # The fence first, then the holding, then B3: the order every
            # holder and holding writer takes. The holding is held, not
            # ended: containment retires the credential, and the holding
            # continues until the owner replaces it or revokes it.
            admitted = await self.fence.admit(tx, grant)
            if admitted.installation_id != reader.installation_id:
                raise RemovalRefused("reader_unknown", 404)
            held = await self.directory.hold_holding(
                tx, installation=admitted, principal=reader.principal
            )
            if held is None or held.b3_scope != scope:
                raise RemovalRefused("reader_unknown", 404)
            # The holding's approver, or the pending one while a replaced
            # credential is in its cooling-off.
            holder = await tx.fetch_value(
                "SELECT subject FROM {{tables.passkey_approvers}}"
                " WHERE scope = $1 AND superseded_at IS NULL",
                scope,
            )
            if holder is None:
                raise RemovalRefused("reader_unknown", 404)

            async def protect(guard: TransactionManager, _scope: str, _subject: str) -> None:
                # Admission holds the installation's fence row for update until
                # commit, and every holding writer holds it at least for share,
                # so this count sees every earlier removal or revocation
                # committed. Only a reader who can sign in protects.
                others = [
                    other
                    for other in await self.directory.current_readers_in(
                        guard,
                        installation_id=admitted.installation_id,
                        team_id=admitted.team_id,
                    )
                    if other.scope != scope
                ]
                if not others:
                    raise RetirementRefused("last_reader_protected")

            prepared = await self.recorder.prepare_containment(
                tx, admitted=admitted, principal=principal
            )
            with self.recorder.prepared(prepared):
                try:
                    await self.passkeys.retire_in(
                        tx,
                        scope=scope,
                        subject=holder,
                        authorized_by=principal_key(principal).principal_did,
                        protect=protect,
                    )
                except RetirementRefused as refused:
                    code = refused.reason
                    raise RemovalRefused(
                        code, 409 if code == "last_reader_protected" else 404
                    ) from None
            await self.fence.check(tx, admitted)
