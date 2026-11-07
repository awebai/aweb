"""The readers of a team's log: humans an owner act designates, who read only
in a passkey session on logs' console origin (audit-substrate.md §B5).

Each reader has a B3 scope of its own, a slot ``logs.reader.<32 hex>`` that
logs draws at random before the owner signs and binds to the installation,
the team and the hash of the contact the owner act must name. The scope is
public in the reader's governance events, so it is never derived from the
contact. The owner signs the exact slot; an act naming a slot for another
installation, team or contact, or an expired or already claimed one, claims
nothing. A pending slot grants nothing. A claimed slot is the reader's scope
for good, through enrolment, contact changes and recovery, and it says which
team its sessions read.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.owner_act import VerifiedOwnerAct
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, PreparedOwnerAct
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence
from aweb_naapp.runtime.passkeys import (
    DesignationRefused,
    PasskeyInstallationContext,
    Passkeys,
    ProofContextResolver,
    ProofContextUnavailable,
    contact_sha256,
    installation_context,
)
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_logs.ledger import Conflicted, LogsSigner, append_on

if TYPE_CHECKING:
    from aweb_naapp.runtime.credential_audit import CredentialAudit

READER_ROLE = "logs.reader"
SLOT_TTL = timedelta(hours=1)
_SCOPE = re.compile(r"logs\.reader\.[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def is_reader_scope(scope: str) -> bool:
    return _SCOPE.fullmatch(scope) is not None


class ReaderRefused(Exception):
    """No pending, unexpired slot issued for this installation, team and contact."""

    code = "owner_required"


@dataclass(frozen=True)
class Slot:
    scope: str
    expires_at: datetime


@dataclass(frozen=True)
class Pending:
    scope: str
    installation_id: str
    team_id: str
    contact_sha256: str


@dataclass(frozen=True)
class Reader:
    scope: str
    installation_id: str
    team_id: str


class ReaderDirectory:
    """The reader slots of this deployment, pending and claimed."""

    def __init__(self, db: AsyncDatabaseManager, *, slot_ttl: timedelta = SLOT_TTL) -> None:
        self.db = db
        self._slot_ttl = slot_ttl

    async def create_slot(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, contact_sha256: str
    ) -> Slot:
        """Issue, in the caller's transaction, a pending slot for the reader the
        owner will designate at this contact."""
        if not _SHA256.fullmatch(contact_sha256):
            raise ValueError("a reader's contact is named by its SHA-256")
        scope = f"{READER_ROLE}.{secrets.token_hex(16)}"
        expires_at = await tx.fetch_value(
            "INSERT INTO {{tables.readers}}"
            " (scope, installation_id, team_id, contact_sha256, expires_at)"
            " VALUES ($1, $2, $3, $4, NOW() + $5) RETURNING expires_at",
            scope,
            installation_id,
            team_id,
            contact_sha256,
            self._slot_ttl,
        )
        return Slot(scope=scope, expires_at=expires_at)

    async def claim(
        self,
        tx: TransactionManager,
        *,
        scope: str,
        installation_id: str,
        team_id: str,
        contact_sha256: str,
    ) -> Reader:
        """Claim, in the designating transaction, the pending slot the owner act names."""
        claimed = await tx.fetch_value(
            "UPDATE {{tables.readers}} SET claimed_at = NOW()"
            " WHERE scope = $1 AND installation_id = $2 AND team_id = $3"
            " AND contact_sha256 = $4 AND claimed_at IS NULL AND expires_at > NOW()"
            " RETURNING scope",
            scope,
            installation_id,
            team_id,
            contact_sha256,
        )
        if claimed is None:
            raise ReaderRefused("no pending slot for this act")
        return Reader(scope=scope, installation_id=installation_id, team_id=team_id)

    async def reader(self, scope: str) -> Reader | None:
        if not is_reader_scope(scope):
            return None
        row = await self.db.fetch_one(
            "SELECT scope, installation_id, team_id FROM {{tables.readers}}"
            " WHERE scope = $1 AND claimed_at IS NOT NULL",
            scope,
        )
        return Reader(**row) if row is not None else None

    async def readers(self, *, installation_id: str, team_id: str) -> list[Reader]:
        rows = await self.db.fetch_all(
            "SELECT scope, installation_id, team_id FROM {{tables.readers}}"
            " WHERE installation_id = $1 AND team_id = $2 AND claimed_at IS NOT NULL"
            " ORDER BY scope",
            installation_id,
            team_id,
        )
        return [Reader(**row) for row in rows]

    async def holder(self, scope: str) -> str | None:
        """The B3 subject currently designated for ``scope``, if any."""
        return await self.db.fetch_value(
            "SELECT subject FROM {{tables.passkey_approvers}}"
            " WHERE scope = $1 AND superseded_at IS NULL",
            scope,
        )

    async def current_readers(self, *, installation_id: str, team_id: str) -> list[Reader]:
        """The claimed slots of this installation and team that a holder
        currently fills."""
        rows = await self.db.fetch_all(
            "SELECT r.scope, r.installation_id, r.team_id FROM {{tables.readers}} r"
            " JOIN {{tables.passkey_approvers}} a ON a.scope = r.scope AND a.superseded_at IS NULL"
            " WHERE r.installation_id = $1 AND r.team_id = $2 AND r.claimed_at IS NOT NULL"
            " ORDER BY r.scope",
            installation_id,
            team_id,
        )
        return [Reader(**row) for row in rows]

    async def is_current_reader(self, scope: str) -> bool:
        """Whether ``scope`` is a claimed slot a holder currently fills: the
        console sessions' admission of a reader scope."""
        if not is_reader_scope(scope):
            return False
        current: bool = await self.db.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM {{tables.readers}} r"
            " JOIN {{tables.passkey_approvers}} a ON a.scope = r.scope AND a.superseded_at IS NULL"
            " WHERE r.scope = $1 AND r.claimed_at IS NOT NULL)",
            scope,
        )
        return current

    async def pending(self, scope: str) -> Pending | None:
        """The unexpired, unclaimed slot ``scope``, before any transaction."""
        if not is_reader_scope(scope):
            return None
        row = await self.db.fetch_one(
            "SELECT installation_id, team_id, contact_sha256 FROM {{tables.readers}}"
            " WHERE scope = $1 AND claimed_at IS NULL AND expires_at > NOW()",
            scope,
        )
        return Pending(scope=scope, **row) if row is not None else None

    async def role_of(
        self, tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
    ) -> str | None:
        """The B3 role ``scope`` holds in ``admitted``: a claimed slot of that
        installation and team is a reader."""
        claimed = await tx.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM {{tables.readers}} WHERE scope = $1"
            " AND installation_id = $2 AND team_id = $3 AND claimed_at IS NOT NULL)",
            scope,
            admitted.installation_id,
            admitted.team_id,
        )
        return READER_ROLE if claimed else None

    def proof_context(self, *, app_id: str) -> ProofContextResolver:
        """B3's proof context of a reader scope: the installation its claimed
        slot belongs to."""

        async def context(scope: str, *, tx: TransactionManager) -> PasskeyInstallationContext:
            row = await tx.fetch_one(
                "SELECT installation_id, team_id FROM {{tables.readers}}"
                " WHERE scope = $1 AND claimed_at IS NOT NULL",
                scope,
            )
            if row is None:
                raise ProofContextUnavailable()
            return await installation_context(
                tx, app_id=app_id, team_id=row["team_id"], installation_id=row["installation_id"]
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


class ReaderDesignations:
    """The owner designates a reader by an ``app-role.designate`` act naming a
    pending slot exactly: its installation, the slot as the role, and its
    contact's hash.

    One transaction consumes the act's nonce, claims the slot, designates the
    slot's B3 holder and records the governance event, which the recorder's
    ``after_enqueue`` appends to logs' own chain. An act that names anything
    else, or whose nonce was used, designates nobody.
    """

    def __init__(
        self,
        directory: ReaderDirectory,
        *,
        fence: InstallationFence,
        verifier: OwnerActVerifier,
        passkeys: Passkeys,
        recorder: CredentialAudit,
    ) -> None:
        self.directory = directory
        self.fence = fence
        self.verifier = verifier
        self.passkeys = passkeys
        self.recorder = recorder

    async def designate(
        self, *, signing: bytes, signature: str, scope: str, contact: str
    ) -> Reader:
        pending = await self.directory.pending(scope)
        if pending is None or pending.contact_sha256 != contact_sha256(contact):
            raise ReaderRefused("no pending slot for this act")
        admitted = (await self.fence.permit(pending.team_id)).admitted
        if admitted.installation_id != pending.installation_id:
            raise ReaderRefused("the slot belongs to another installation")
        expected = {
            "app_id": admitted.app_id,
            "installation_id": admitted.installation_id,
            "role": scope,
            "contact_sha256": pending.contact_sha256,
        }
        prepared = await self._prepare(signing, signature, admitted)
        context = await self.recorder.prepare_owner_act(
            admitted, signing=signing, signature=signature
        )
        with self.recorder.prepared(context):
            async with self.directory.db.transaction() as tx:
                await self.fence.check(tx, admitted)
                act = await self._consume(tx, prepared, expected)
                reader = await self.directory.claim(
                    tx,
                    scope=scope,
                    installation_id=admitted.installation_id,
                    team_id=admitted.team_id,
                    contact_sha256=pending.contact_sha256,
                )
                try:
                    designation = await self.passkeys.designate(
                        tx, scope=scope, contact=contact, evidence=act
                    )
                except DesignationRefused:
                    raise ReaderRefused("the slot cannot be designated") from None
                await self.fence.check(tx, admitted)
        await self.passkeys.deliver(designation)
        return reader

    async def revoke(self, *, signing: bytes, signature: str, scope: str) -> None:
        """End a reader's designation by an ``app-role.revoke`` act naming its
        scope and current holder. The slot stays claimed and holds no reader
        until the owner designates one again."""
        reader = await self.directory.reader(scope)
        holder = await self.directory.holder(scope) if reader is not None else None
        if reader is None or holder is None:
            raise ReaderRefused("no reader holds this scope")
        admitted = (await self.fence.permit(reader.team_id)).admitted
        if admitted.installation_id != reader.installation_id:
            raise ReaderRefused("the reader belongs to another installation")
        expected = {
            "app_id": admitted.app_id,
            "installation_id": admitted.installation_id,
            "role": scope,
            "subject_ref": holder,
        }
        prepared = await self._prepare(signing, signature, admitted)
        context = await self.recorder.prepare_owner_act(
            admitted, signing=signing, signature=signature
        )
        with self.recorder.prepared(context):
            async with self.directory.db.transaction() as tx:
                await self.fence.check(tx, admitted)
                act = await self._consume(tx, prepared, expected)
                try:
                    await self.passkeys.retire(tx, scope=scope, evidence=act)
                except DesignationRefused:
                    raise ReaderRefused("the reader cannot be revoked") from None
                await self.fence.check(tx, admitted)

    async def _prepare(
        self, signing: bytes, signature: str, admitted: AdmittedInstallation
    ) -> PreparedOwnerAct:
        try:
            return await self.verifier.prepare(signing, signature, team_id=admitted.team_id)
        except Refused:
            raise ReaderRefused("the act is not the owner's") from None

    async def _consume(
        self, tx: TransactionManager, prepared: PreparedOwnerAct, expected: dict[str, str]
    ) -> VerifiedOwnerAct:
        try:
            return await self.verifier.consume_in(tx, prepared, expected_subject=expected)
        except Refused:
            raise ReaderRefused("the act does not name this reader") from None
