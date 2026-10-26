"""Reader slots: the opaque scope an owner act designates a reader by, and the
team a designated reader reads."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.readers import ReaderDirectory, ReaderRefused, is_reader_scope

INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
TEAM = "demo:example.com"
CONTACT_SHA256 = hashlib.sha256(b"m@example.com").hexdigest()
OTHER_CONTACT_SHA256 = hashlib.sha256(b"q@example.com").hexdigest()


@pytest.mark.parametrize(
    "scope",
    ["logs.reader", "logs.reader.ABC", "secrets.owner." + "a" * 32, "logs.reader." + "a" * 31],
)
def test_only_reader_slot_scopes_are_reader_scopes(scope: str) -> None:
    assert not is_reader_scope(scope)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_readers")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


async def _slot(directory: ReaderDirectory, contact: str = CONTACT_SHA256) -> str:
    slot = await directory.create_slot(
        installation_id=INSTALLATION, team_id=TEAM, contact_sha256=contact
    )
    return slot.scope


async def _claim(
    db: AsyncDatabaseManager,
    directory: ReaderDirectory,
    scope: str,
    *,
    installation_id: str = INSTALLATION,
    team_id: str = TEAM,
    contact_sha256: str = CONTACT_SHA256,
) -> None:
    async with db.transaction() as tx:
        await directory.claim(
            tx,
            scope=scope,
            installation_id=installation_id,
            team_id=team_id,
            contact_sha256=contact_sha256,
        )


async def test_a_slot_is_random_and_says_nothing_about_its_contact(
    db: AsyncDatabaseManager,
) -> None:
    directory = ReaderDirectory(db)
    first, second = await _slot(directory), await _slot(directory)
    assert first != second
    assert is_reader_scope(first) and is_reader_scope(second)
    assert CONTACT_SHA256[:8] not in first


async def test_a_pending_slot_is_no_reader(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    scope = await _slot(directory)
    assert await directory.reader(scope) is None
    assert await directory.readers(installation_id=INSTALLATION, team_id=TEAM) == []


async def test_a_claimed_slot_is_a_reader_of_its_own_team(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    scope = await _slot(directory)
    await _claim(db, directory, scope)
    reader = await directory.reader(scope)
    assert reader is not None
    assert (reader.scope, reader.team_id, reader.installation_id) == (scope, TEAM, INSTALLATION)
    assert await directory.readers(installation_id=INSTALLATION, team_id=TEAM) == [reader]


@pytest.mark.parametrize(
    "claimed",
    [
        {"installation_id": OTHER_INSTALLATION},
        {"team_id": "other:example.com"},
        {"contact_sha256": OTHER_CONTACT_SHA256},
    ],
)
async def test_a_slot_is_claimed_only_for_what_it_was_issued_for(
    db: AsyncDatabaseManager, claimed: dict[str, str]
) -> None:
    directory = ReaderDirectory(db)
    scope = await _slot(directory)
    with pytest.raises(ReaderRefused):
        await _claim(db, directory, scope, **claimed)
    assert await directory.reader(scope) is None


async def test_an_unknown_or_expired_slot_is_never_claimed(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    with pytest.raises(ReaderRefused):
        await _claim(db, directory, "logs.reader." + "0" * 32)
    scope = await _slot(directory)
    await db.execute(
        "UPDATE {{tables.readers}} SET expires_at = NOW() - INTERVAL '1 second' WHERE scope = $1",
        scope,
    )
    with pytest.raises(ReaderRefused):
        await _claim(db, directory, scope)


async def test_a_slot_is_claimed_once(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    scope = await _slot(directory)
    await _claim(db, directory, scope)
    with pytest.raises(ReaderRefused):
        await _claim(db, directory, scope)


async def test_two_concurrent_claims_of_one_slot_leave_exactly_one(
    db: AsyncDatabaseManager,
) -> None:
    directory = ReaderDirectory(db)
    scope = await _slot(directory)
    results = await asyncio.gather(
        _claim(db, directory, scope), _claim(db, directory, scope), return_exceptions=True
    )
    assert sorted(type(result).__name__ for result in results) == ["NoneType", "ReaderRefused"]


async def test_a_claim_rolled_back_leaves_the_slot_pending(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    scope = await _slot(directory)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await directory.claim(
                tx,
                scope=scope,
                installation_id=INSTALLATION,
                team_id=TEAM,
                contact_sha256=CONTACT_SHA256,
            )
            raise RuntimeError("the designation failed")
    assert await directory.reader(scope) is None
    await _claim(db, directory, scope)
    assert await directory.reader(scope) is not None


async def test_a_slot_lives_for_its_ttl(db: AsyncDatabaseManager) -> None:
    slot = await ReaderDirectory(db, slot_ttl=timedelta(minutes=10)).create_slot(
        installation_id=INSTALLATION, team_id=TEAM, contact_sha256=CONTACT_SHA256
    )
    remaining = slot.expires_at - await db.fetch_value("SELECT NOW()")
    assert timedelta(minutes=9) < remaining <= timedelta(minutes=10)


async def test_a_contact_digest_must_be_a_sha256(db: AsyncDatabaseManager) -> None:
    with pytest.raises(ValueError):
        await ReaderDirectory(db).create_slot(
            installation_id=INSTALLATION, team_id=TEAM, contact_sha256="m@example.com"
        )
