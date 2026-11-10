"""Original assignment redaction snapshots; never a replacement credential read."""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_secrets_values.redaction import KnownValues
from pgdbm.core import TransactionManager

from .sealing import CustodyUnavailable, KeyProvider, SealContext, SealedValue, seal, unseal


def _context(scope: AdmittedInstallation, dispatch_id: UUID) -> SealContext:
    # Separate from ordinary sec_* values and the private backend credential.
    return SealContext(scope.installation_id, scope.team_id, f"run_redaction:{dispatch_id}", 1)


@dataclass(frozen=True, repr=False)
class SealedRunRedaction:
    scope: AdmittedInstallation
    dispatch_id: UUID
    deadline: datetime
    sealed: SealedValue


class RunRedaction:
    """Composition grants only RunDispatch this native-custody capability.

    Seal/open use provider I/O outside authority transactions. Retain/read/drop
    run in the caller transaction and bind the original installation and UUID.
    """

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider

    async def seal(
        self, scope: AdmittedInstallation, dispatch_id: UUID, known: KnownValues
    ) -> SealedValue:
        return await asyncio.to_thread(
            seal, self._provider, _context(scope, dispatch_id), known.snapshot()
        )

    async def retain(
        self,
        tx: TransactionManager,
        scope: AdmittedInstallation,
        dispatch_id: UUID,
        *,
        deadline: datetime,
        sealed: SealedValue,
    ) -> None:
        await tx.execute(
            "INSERT INTO {{tables.run_redaction_contexts}}"
            " (installation_id,team_id,dispatch_id,deadline,key_id,wrapped_key,nonce,ciphertext)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            scope.installation_id,
            scope.team_id,
            dispatch_id,
            deadline,
            sealed.key_id,
            sealed.wrapped_key,
            sealed.nonce,
            sealed.ciphertext,
        )

    async def read(
        self,
        tx: TransactionManager,
        scope: AdmittedInstallation,
        dispatch_id: UUID,
        *,
        now: datetime,
    ) -> SealedRunRedaction | None:
        # The persisted assignment's original deadline is authoritative. Neither
        # replay nor another worker can extend the snapshot lifetime.
        row = await tx.fetch_one(
            "SELECT r.* FROM {{tables.run_redaction_contexts}} r"
            " JOIN {{tables.dispatches}} d USING(dispatch_id)"
            " JOIN {{tables.run_deliveries}} v USING(dispatch_id)"
            " WHERE r.installation_id=$1 AND r.team_id=$2 AND r.dispatch_id=$3"
            " AND r.deadline=d.sweep_after AND r.deadline>$4 AND v.report_sha256 IS NULL",
            scope.installation_id,
            scope.team_id,
            dispatch_id,
            now,
        )
        if row is None:
            return None
        return SealedRunRedaction(
            scope,
            dispatch_id,
            row["deadline"],
            SealedValue(
                row["key_id"],
                bytes(row["wrapped_key"]),
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
            ),
        )

    async def open(self, snapshot: SealedRunRedaction) -> KnownValues:
        plaintext = await asyncio.to_thread(
            unseal, self._provider, _context(snapshot.scope, snapshot.dispatch_id), snapshot.sealed
        )
        try:
            return KnownValues.restore(plaintext.reveal())
        except ValueError:
            raise CustodyUnavailable("invalid original run redaction context") from None

    async def drop(
        self, tx: TransactionManager, scope: AdmittedInstallation, dispatch_id: UUID
    ) -> None:
        await tx.execute(
            "DELETE FROM {{tables.run_redaction_contexts}}"
            " WHERE installation_id=$1 AND team_id=$2 AND dispatch_id=$3",
            scope.installation_id,
            scope.team_id,
            dispatch_id,
        )
