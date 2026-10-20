"""Sealed secret versions at rest.

The console holds a :class:`SecretSealer`, which can only add a value. The
broker holds a :class:`SecretOpener`, which is the only way a stored value is
unsealed. No other object reads the sealed rows.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from .sealing import (
    CustodyUnavailable,
    KeyProvider,
    Plaintext,
    SealContext,
    SealedValue,
    seal,
    unseal,
)

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_secrets_custody"


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
    ) -> int:
        """Store ``value`` as the secret's next version, in the caller's transaction.

        Returns the version number. Two ingests racing for the same version
        cannot both commit: the second fails on the primary key."""
        version = int(
            await tx.fetch_value(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM {{tables.sealed_versions}}"
                " WHERE secret_id = $1",
                secret_id,
            )
        )
        context = SealContext(
            installation_id=installation_id, team_id=team_id, secret_id=secret_id, version=version
        )
        sealed = await asyncio.to_thread(seal, self._provider, context, value)
        await tx.execute(
            """
            INSERT INTO {{tables.sealed_versions}}
                (secret_id, version, key_id, wrapped_key, nonce, ciphertext)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
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
        row = await self._db.fetch_one(
            """
            SELECT key_id, wrapped_key, nonce, ciphertext FROM {{tables.sealed_versions}}
            WHERE secret_id = $1 AND version = $2
            """,
            context.secret_id,
            context.version,
        )
        if row is None:
            raise CustodyUnavailable("no sealed value for that secret version")
        sealed = SealedValue(
            key_id=row["key_id"],
            wrapped_key=bytes(row["wrapped_key"]),
            nonce=bytes(row["nonce"]),
            ciphertext=bytes(row["ciphertext"]),
        )
        return await asyncio.to_thread(unseal, self._provider, context, sealed)
