"""Which team a reader reads, and the scope an owner act designates a reader by."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.readers import ReaderDirectory, is_reader_scope, reader_scope

INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
TEAM = "demo:example.com"
CONTACT_SHA256 = hashlib.sha256(b"m@example.com").hexdigest()


def test_a_reader_scope_names_its_installation_team_and_contact() -> None:
    scope = reader_scope(INSTALLATION, TEAM, CONTACT_SHA256)
    assert (
        scope
        == "logs.reader."
        + hashlib.sha256(f"{INSTALLATION}\n{TEAM}\n{CONTACT_SHA256}".encode()).hexdigest()[:40]
    )
    assert is_reader_scope(scope)
    assert reader_scope(OTHER_INSTALLATION, TEAM, CONTACT_SHA256) != scope
    assert reader_scope(INSTALLATION, "other:example.com", CONTACT_SHA256) != scope
    assert reader_scope(INSTALLATION, TEAM, "0" * 64) != scope


@pytest.mark.parametrize(
    "scope",
    ["logs.reader", "logs.reader.ABC", "secrets.owner." + "a" * 40, "logs.reader." + "a" * 39],
)
def test_only_derived_reader_scopes_are_reader_scopes(scope: str) -> None:
    assert not is_reader_scope(scope)


def test_a_contact_digest_must_be_a_sha256() -> None:
    with pytest.raises(ValueError):
        reader_scope(INSTALLATION, TEAM, "m@example.com")


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_readers")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


async def test_a_recorded_reader_reads_its_own_team(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    async with db.transaction() as tx:
        scope = await directory.record(
            tx, installation_id=INSTALLATION, team_id=TEAM, contact_sha256=CONTACT_SHA256
        )
    reader = await directory.reader(scope)
    assert reader is not None
    assert (reader.team_id, reader.installation_id) == (TEAM, INSTALLATION)
    assert await directory.reader(reader_scope(OTHER_INSTALLATION, TEAM, CONTACT_SHA256)) is None


async def test_recording_the_same_reader_again_keeps_one_row(db: AsyncDatabaseManager) -> None:
    directory = ReaderDirectory(db)
    for _ in range(2):
        async with db.transaction() as tx:
            await directory.record(
                tx, installation_id=INSTALLATION, team_id=TEAM, contact_sha256=CONTACT_SHA256
            )
    assert len(await directory.readers(installation_id=INSTALLATION, team_id=TEAM)) == 1


async def test_another_installations_reader_is_not_this_installations(
    db: AsyncDatabaseManager,
) -> None:
    directory = ReaderDirectory(db)
    async with db.transaction() as tx:
        await directory.record(
            tx, installation_id=OTHER_INSTALLATION, team_id=TEAM, contact_sha256=CONTACT_SHA256
        )
    assert await directory.readers(installation_id=INSTALLATION, team_id=TEAM) == []
