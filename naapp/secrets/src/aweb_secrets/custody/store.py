"""Sealed secret versions at rest.

The console holds a :class:`SecretSealer`, which can only add a value. The
broker holds a :class:`SecretOpener`, which is the only way a stored value is
unsealed. The app's composition hands each its own; :class:`Custody` holds
both, with the operations that never reveal a value.

Lock order (decisions 43, 59, 65c, 78): installation fence, role hold,
replacement/reenable ancestry and grants where applicable, the complete approval
union and candidates, four-eyes setting, revision, then record writes. Within record
writes, lock the parent secrets row before custody rows: KEY SHARE for ingest,
UPDATE for reshaping. Existing ingest validates against the record re-read under
that lock; only initial-create drafts may have no parent yet. All callers run
at READ COMMITTED. Reshape checks retained custody history in a separate
statement after acquiring UPDATE, so an ingest it waited for is visible.
Initial drafts also pin their immutable shape in custody history. Confirmation
pins a zero-version custody row after creating the parent, so a concurrent
initial ingest and create serialize on the same key even before a parent is
visible. A zero-version pin may be reshaped; a sealed history may not.
Private backend-token staging locks its onepassword_credentials parent before
the reserved custody key. It creates no ordinary secret or active credential.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.secret import SecretRecord, sealed_shape

from .sealing import (
    CustodyUnavailable,
    KeyProvider,
    Plaintext,
    SealContext,
    SealedValue,
    seal,
    seal_canary,
    unseal,
)
from .values import decode_value

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_secrets_custody"
BACKEND_CREDENTIAL_ID = "bkc_onepassword"
_BACKEND_CREDENTIAL_SHAPE = {"v": 1, "purpose": "onepassword-service-account", "backend": "native"}


async def apply_custody_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


class SecretSealer:
    """Seals and stores new versions of a secret's value."""

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider

    async def ingest(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        secret_id: str,
        value: bytes,
        initial: SecretRecord | None = None,
    ) -> int:
        """Store ``value`` as the secret's next version, in the caller's transaction.

        Returns the version number. Allocating it locks the secret's row until
        the transaction ends, so concurrent ingests take turns. A disabled
        secret takes no new value. Sealing makes one call to the key provider
        while that lock is held, so with KMS the transaction's latency includes
        one KMS round trip, bounded by the client's timeouts.

        ``value`` is encoded with encode_value. Existing records are re-read
        under KEY SHARE and their current kind/backend/params govern validation.
        ``initial`` is only for an inert first-create draft with no record yet;
        if a parent exists, it always wins over that candidate."""
        row = await tx.fetch_one(
            "SELECT record FROM {{tables.secrets}}"
            " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3 FOR KEY SHARE",
            installation_id,
            team_id,
            secret_id,
        )
        if row is not None:
            record = SecretRecord.from_after(json.loads(row["record"]))
        elif initial is not None and initial.secret_id == secret_id:
            # The candidate belongs to a first-create draft; confirmation will
            # create its record. The existing-record path never trusts it.
            record = SecretRecord.from_after(initial.after)
        else:
            raise CustodyUnavailable("no secret record or initial-create candidate")
        if record.backend != "native":
            raise CustodyUnavailable("the secret does not use native custody")
        decode_value(record.kind, value)
        return await self._store_validated(
            tx,
            installation_id=installation_id,
            team_id=team_id,
            secret_id=secret_id,
            value=value,
            shape=sealed_shape(record),
        )

    async def _store_validated(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        secret_id: str,
        value: bytes,
        shape: dict,
    ) -> int:
        """Caller has locked the parent and validated the value/immutable shape."""
        allocated = await tx.fetch_one(
            """
            INSERT INTO {{tables.custody_secrets}}
                (installation_id, team_id, secret_id, last_version, immutable_shape)
            VALUES ($1, $2, $3, 1, $4)
            ON CONFLICT (installation_id, team_id, secret_id) DO UPDATE
                SET last_version = {{tables.custody_secrets}}.last_version + 1
                WHERE {{tables.custody_secrets}}.immutable_shape = EXCLUDED.immutable_shape
            RETURNING last_version, disabled_at
            """,
            installation_id,
            team_id,
            secret_id,
            json.dumps(shape),
        )
        if allocated is None:
            raise CustodyUnavailable("the sealed secret's immutable shape differs")
        if allocated["disabled_at"] is not None:
            raise CustodyUnavailable("the secret is disabled")
        version = int(allocated["last_version"])
        context = SealContext(
            installation_id=installation_id, team_id=team_id, secret_id=secret_id, version=version
        )
        sealed = await asyncio.to_thread(seal, self._provider, context, value)
        await tx.execute(
            """
            INSERT INTO {{tables.sealed_versions}}
                (installation_id, team_id, secret_id, version, key_id, wrapped_key, nonce, ciphertext)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            installation_id,
            team_id,
            secret_id,
            version,
            sealed.key_id,
            sealed.wrapped_key,
            sealed.nonce,
            sealed.ciphertext,
        )
        return version


class SecretOpener:
    """Unseals a stored version for one use. Only the broker path holds one."""

    def __init__(self, provider: KeyProvider, db: AsyncDatabaseManager) -> None:
        self._provider = provider
        self._db = db

    async def open(self, context: SealContext) -> Plaintext:
        if context.secret_id == BACKEND_CREDENTIAL_ID:
            raise CustodyUnavailable("backend credentials are not ordinary secret values")
        row = await self._db.fetch_one(
            """
            SELECT v.key_id, v.wrapped_key, v.nonce, v.ciphertext
            FROM {{tables.sealed_versions}} v
            JOIN {{tables.custody_secrets}} s USING (installation_id, team_id, secret_id)
            WHERE v.installation_id = $1 AND v.team_id = $2 AND v.secret_id = $3
                AND v.version = $4 AND s.disabled_at IS NULL
            """,
            context.installation_id,
            context.team_id,
            context.secret_id,
            context.version,
        )
        if row is None:
            raise CustodyUnavailable("no usable sealed value for that secret version")
        sealed = SealedValue(
            key_id=row["key_id"],
            wrapped_key=bytes(row["wrapped_key"]),
            nonce=bytes(row["nonce"]),
            ciphertext=bytes(row["ciphertext"]),
        )
        return await asyncio.to_thread(unseal, self._provider, context, sealed)


@dataclass(frozen=True)
class Description:
    """A secret's custody state: its latest stored version, never its value."""

    version: int | None
    updated_at: datetime | None
    state: Literal["active", "disabled"]


@dataclass(frozen=True)
class Health:
    ok: bool
    reason: str | None = None


class Custody:
    """The native KMS-sealed store of one deployment."""

    def __init__(self, provider: KeyProvider, db: AsyncDatabaseManager) -> None:
        self._provider = provider
        self._db = db
        self.sealer = SecretSealer(provider)
        self.opener = SecretOpener(provider, db)

    async def stage_backend_credential(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        value: bytes,
    ) -> SealContext:
        """Stage an inert native token for the caller's owner-console ceremony.

        Authorization/fence/role checks belong to that caller, as for ordinary
        ingest. This dedicated path accepts only the fixed private credential,
        creates no secret record and never sets active_version. Confirmation
        must bind the returned context to the exact scoped change before use.
        """
        decode_value("bearer", value)
        await tx.execute(
            "INSERT INTO {{tables.onepassword_credentials}}"
            " (installation_id, team_id, credential_id) VALUES ($1, $2, $3)"
            " ON CONFLICT (installation_id, team_id) DO UPDATE"
            " SET credential_id = EXCLUDED.credential_id",
            installation_id,
            team_id,
            BACKEND_CREDENTIAL_ID,
        )
        version = await self.sealer._store_validated(
            tx,
            installation_id=installation_id,
            team_id=team_id,
            secret_id=BACKEND_CREDENTIAL_ID,
            value=value,
            shape=_BACKEND_CREDENTIAL_SHAPE,
        )
        return SealContext(installation_id, team_id, BACKEND_CREDENTIAL_ID, version)

    async def backend_credential_matches(
        self, tx: TransactionManager, context: SealContext
    ) -> bool:
        """Whether this scoped private token version still exists for a draft.

        This performs no activation and takes no authority lock. Confirmation
        must recheck under its normal fence/role/preparation/write lock order.
        """
        if (
            context.secret_id != BACKEND_CREDENTIAL_ID
            or type(context.version) is not int
            or context.version <= 0
        ):
            return False
        return bool(
            await tx.fetch_value(
                "SELECT 1 FROM {{tables.onepassword_credentials}} p"
                " JOIN {{tables.custody_secrets}} c USING (installation_id, team_id)"
                " JOIN {{tables.sealed_versions}} v USING (installation_id, team_id, secret_id)"
                " WHERE p.installation_id=$1 AND p.team_id=$2"
                " AND c.secret_id=p.credential_id AND v.version=$3"
                " AND c.disabled_at IS NULL AND c.immutable_shape=$4::jsonb",
                context.installation_id,
                context.team_id,
                context.version,
                json.dumps(_BACKEND_CREDENTIAL_SHAPE),
            )
        )

    async def describe(
        self, *, installation_id: str, team_id: str, secret_id: str
    ) -> Description | None:
        row = await self._db.fetch_one(
            """
            SELECT s.disabled_at, v.version, v.created_at
            FROM {{tables.custody_secrets}} s
            LEFT JOIN LATERAL (
                SELECT version, created_at FROM {{tables.sealed_versions}}
                WHERE installation_id = s.installation_id AND team_id = s.team_id
                    AND secret_id = s.secret_id
                ORDER BY version DESC LIMIT 1
            ) v ON TRUE
            WHERE s.installation_id = $1 AND s.team_id = $2 AND s.secret_id = $3
            """,
            installation_id,
            team_id,
            secret_id,
        )
        if row is None:
            return None
        return Description(
            version=row["version"],
            updated_at=row["created_at"],
            state="disabled" if row["disabled_at"] is not None else "active",
        )

    async def shape_allows(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, record: SecretRecord
    ) -> bool:
        """Draft-time check only. Confirmation must atomically bind_shape."""
        row = await tx.fetch_one(
            "SELECT last_version, immutable_shape FROM {{tables.custody_secrets}}"
            " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3",
            installation_id,
            team_id,
            record.secret_id,
        )
        return (
            row is None
            or row["last_version"] == 0
            or (
                row["immutable_shape"] is not None
                and json.loads(row["immutable_shape"]) == sealed_shape(record)
            )
        )

    async def bind_shape(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, record: SecretRecord
    ) -> bool:
        """Pin a confirmed record after locking its parent. Initial ingest and
        initial creation take turns on this key, even with no visible parent.
        Only a history that never sealed a version may change its shape."""
        return bool(
            await tx.fetch_value(
                "INSERT INTO {{tables.custody_secrets}} AS c"
                " (installation_id, team_id, secret_id, last_version, immutable_shape)"
                " VALUES ($1, $2, $3, 0, $4)"
                " ON CONFLICT (installation_id, team_id, secret_id) DO UPDATE"
                " SET immutable_shape = EXCLUDED.immutable_shape"
                " WHERE c.last_version = 0 OR c.immutable_shape = EXCLUDED.immutable_shape"
                " RETURNING 1",
                installation_id,
                team_id,
                record.secret_id,
                json.dumps(sealed_shape(record)),
            )
        )

    async def value_matches(
        self, tx: TransactionManager, context: SealContext, record: SecretRecord
    ) -> bool:
        """Whether a live sealed version was ingested for this immutable shape."""
        return bool(
            await tx.fetch_value(
                "SELECT 1 FROM {{tables.custody_secrets}} c"
                " JOIN {{tables.sealed_versions}} v USING (installation_id, team_id, secret_id)"
                " WHERE c.installation_id = $1 AND c.team_id = $2 AND c.secret_id = $3"
                " AND v.version = $4 AND c.immutable_shape = $5::jsonb",
                context.installation_id,
                context.team_id,
                context.secret_id,
                context.version,
                json.dumps(sealed_shape(record)),
            )
        )

    async def ever_sealed(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, secret_id: str
    ) -> bool:
        """Whether any version of the secret was ever sealed, destroyed or not,
        whether or not any sealed versions survive. The caller must hold the
        parent secrets row FOR UPDATE before using this to authorize a reshape;
        this read alone cannot lock a custody row that does not yet exist."""
        return bool(
            await tx.fetch_value(
                "SELECT 1 FROM {{tables.custody_secrets}}"
                " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3"
                " AND last_version > 0",
                installation_id,
                team_id,
                secret_id,
            )
        )

    async def disable(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, secret_id: str
    ) -> None:
        """Refuse every open and ingest of the secret from now on."""
        await tx.execute(
            "UPDATE {{tables.custody_secrets}} SET disabled_at = NOW()"
            " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3"
            " AND disabled_at IS NULL",
            installation_id,
            team_id,
            secret_id,
        )

    async def enable(
        self, tx: TransactionManager, *, installation_id: str, team_id: str, secret_id: str
    ) -> None:
        """Restore custody access as part of the caller's confirmed reenable.

        This only clears the disabled marker. Destroyed versions stay destroyed,
        and retained version/shape history stays intact. The caller authorizes
        the widening act and updates the secret's record in this transaction.
        """
        await tx.execute(
            "UPDATE {{tables.custody_secrets}} SET disabled_at = NULL"
            " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3"
            " AND disabled_at IS NOT NULL",
            installation_id,
            team_id,
            secret_id,
        )

    async def destroy(self, tx: TransactionManager, context: SealContext) -> None:
        """Delete one version's wrapped data key and ciphertext from the live store.

        Copies in backups and the write-ahead log stay decryptable until they
        expire or the key-encryption key is retired."""
        await tx.execute(
            "DELETE FROM {{tables.sealed_versions}}"
            " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3 AND version = $4",
            context.installation_id,
            context.team_id,
            context.secret_id,
            context.version,
        )

    async def health(self) -> Health:
        """Whether a probe seals and unseals with the deployment's key provider."""
        try:
            await asyncio.to_thread(seal_canary, self._provider)
        except CustodyUnavailable as exc:
            return Health(ok=False, reason=str(exc))
        return Health(ok=True)
