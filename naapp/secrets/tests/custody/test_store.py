"""Sealed versions at rest on real PostgreSQL."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_secrets.custody import (
    CustodyUnavailable,
    LocalKeyFileProvider,
    SealContext,
    SecretOpener,
    SecretSealer,
    apply_custody_migrations,
)

INSTALLATION = "installation-1"
TEAM = "team-1"


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_custody")
    await apply_custody_migrations(database)
    yield database


async def _ingest(db: AsyncDatabaseManager, sealer: SecretSealer, secret_id: str, value: bytes):
    async with db.transaction() as tx:
        return await sealer.ingest(
            tx, installation_id=INSTALLATION, team_id=TEAM, secret_id=secret_id, value=value
        )


def _context(secret_id: str, version: int) -> SealContext:
    return SealContext(
        installation_id=INSTALLATION, team_id=TEAM, secret_id=secret_id, version=version
    )


async def test_an_ingested_value_is_opened_by_the_opener(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider, canary: bytes
) -> None:
    version = await _ingest(db, SecretSealer(provider), "secret-1", canary)
    plaintext = await SecretOpener(provider, db).open(_context("secret-1", version))
    assert plaintext.reveal() == canary


async def test_no_stored_column_holds_the_value(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider, canary: bytes
) -> None:
    await _ingest(db, SecretSealer(provider), "secret-1", canary)
    rows = await db.fetch_all("SELECT * FROM {{tables.sealed_versions}}")
    assert rows
    for row in rows:
        for value in row.values():
            stored = value if isinstance(value, bytes) else str(value).encode()
            assert canary not in stored


async def test_versions_count_up_per_secret(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider
) -> None:
    sealer = SecretSealer(provider)
    assert await _ingest(db, sealer, "secret-1", b"a") == 1
    assert await _ingest(db, sealer, "secret-1", b"b") == 2
    assert await _ingest(db, sealer, "secret-2", b"c") == 1


async def test_an_ingest_rolls_back_with_its_transaction(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider
) -> None:
    class Abandoned(Exception):
        pass

    with pytest.raises(Abandoned):
        async with db.transaction() as tx:
            await SecretSealer(provider).ingest(
                tx, installation_id=INSTALLATION, team_id=TEAM, secret_id="secret-1", value=b"a"
            )
            raise Abandoned
    with pytest.raises(CustodyUnavailable):
        await SecretOpener(provider, db).open(_context("secret-1", 1))


@pytest.mark.parametrize("target", [("secret-2", 1), ("secret-1", 2)])
async def test_a_row_copied_to_another_secret_or_version_does_not_open(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider, canary: bytes, target
) -> None:
    await _ingest(db, SecretSealer(provider), "secret-1", canary)
    await db.execute(
        "INSERT INTO {{tables.custody_secrets}} (installation_id, team_id, secret_id, last_version)"
        " VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        INSTALLATION,
        TEAM,
        *target,
    )
    await db.execute(
        """
        INSERT INTO {{tables.sealed_versions}}
            (installation_id, team_id, secret_id, version, key_id, wrapped_key, nonce, ciphertext)
        SELECT installation_id, team_id, $1, $2, key_id, wrapped_key, nonce, ciphertext
        FROM {{tables.sealed_versions}} WHERE secret_id = 'secret-1' AND version = 1
        """,
        *target,
    )
    with pytest.raises(CustodyUnavailable):
        await SecretOpener(provider, db).open(_context(*target))


async def test_opening_under_another_team_is_refused(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider, canary: bytes
) -> None:
    version = await _ingest(db, SecretSealer(provider), "secret-1", canary)
    elsewhere = SealContext(
        installation_id=INSTALLATION, team_id="team-2", secret_id="secret-1", version=version
    )
    with pytest.raises(CustodyUnavailable):
        await SecretOpener(provider, db).open(elsewhere)


async def test_an_unknown_version_is_refused(
    db: AsyncDatabaseManager, provider: LocalKeyFileProvider
) -> None:
    with pytest.raises(CustodyUnavailable):
        await SecretOpener(provider, db).open(_context("secret-1", 1))


def test_the_sealer_cannot_open() -> None:
    assert not hasattr(SecretSealer, "open")
