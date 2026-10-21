"""Migration of existing app pins and the shared transaction-level reader."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from pathlib import Path

import pytest
import pytest_asyncio
from pgdbm import AsyncMigrationManager

import aweb
from aweb.app_registry import get_installation_on, next_installation_generation_on

pytestmark = pytest.mark.asyncio
MIGRATION = "029_team_app_installation_identity.sql"
MIGRATIONS = Path(aweb.__file__).parent / "migrations" / "aweb"
TEAM = "demo:example.com"
OTHER_TEAM = "other:example.com"
ORIGIN = "https://fixture.example"
MANIFEST = json.dumps({
    "manifest_version": 1,
    "app": {"id": "fixture", "origin": ORIGIN, "version": "1.0.0"},
    "tools": [{"name": "list", "method": "GET", "path": "/v1/items", "scopes": ["fixture:read"]}],
}).encode()
DIGEST = "sha256:" + hashlib.sha256(MANIFEST).hexdigest()


async def migrate(db, path):
    await AsyncMigrationManager(
        db, migrations_path=str(path), module_name="aweb-aweb",
    ).apply_pending_migrations()


async def legacy_install(db, team_id):
    # Seed the shipped pre-F6 schema; the new install service is deliberately
    # not used to fabricate pre-migration evidence.
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, 'example.com', $2, 'did:key:team')",
        team_id, team_id.split(":")[0],
    )
    await db.execute(
        "INSERT INTO {{tables.app_registry_apps}} (app_id, origin) VALUES ('fixture', $1) ON CONFLICT DO NOTHING",
        ORIGIN,
    )
    await db.execute(
        """INSERT INTO {{tables.app_registry_entries}}
           (app_id, origin, digest, app_version, manifest_version)
           VALUES ('fixture', $1, $2, '1.0.0', 1) ON CONFLICT DO NOTHING""",
        ORIGIN, DIGEST,
    )
    await db.execute(
        """INSERT INTO {{tables.team_app_installs}}
           (team_id, app_id, origin, digest, app_version, manifest_version, granted_scopes, registered_from_manifest_bytes)
           VALUES ($1, 'fixture', $2, $3, '1.0.0', 1, ARRAY['fixture:read'], TRUE)""",
        team_id, ORIGIN, DIGEST,
    )


@pytest_asyncio.fixture
async def db(test_db_factory, tmp_path):
    db = await test_db_factory.create_db(suffix="installation_identity", schema="aweb")
    await db.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
    prior = tmp_path / "prior"
    prior.mkdir()
    for migration in sorted(MIGRATIONS.glob("*.sql")):
        if migration.name < MIGRATION:
            shutil.copyfile(migration, prior / migration.name)
    await migrate(db, prior)
    await legacy_install(db, TEAM)
    await legacy_install(db, OTHER_TEAM)
    await migrate(db, MIGRATIONS)
    return db


async def read(db, team_id=TEAM, **changes):
    async with db.transaction() as tx:
        return await get_installation_on(tx, team_id=team_id, app_id="fixture", **changes)


async def test_migration_keeps_pins_and_scopes_without_claiming_origin_verification(db):
    current = await read(db)
    assert current["installation_id"]
    assert current["generation"] == 1
    assert current["state"] == "pending_origin_verification"
    assert current["origin_verified"] is False
    assert current["origin"] == ORIGIN
    assert current["digest"] == DIGEST
    assert current["granted_scopes"] == ["fixture:read"]
    assert current["origin_verification_error"] is None
    assert await db.fetch_value(
        "SELECT manifest_bytes FROM {{tables.team_app_installs}} WHERE team_id = $1", TEAM,
    ) is None


async def test_id_is_stable_across_reapplying_migrations_and_unique_per_installation(db):
    first = await read(db)
    other = await read(db, OTHER_TEAM)
    assert first["installation_id"] != other["installation_id"]
    await migrate(db, MIGRATIONS)
    assert (await read(db))["installation_id"] == first["installation_id"]


async def test_reader_does_not_cross_teams_or_invent_an_installation(db):
    async with db.transaction() as tx:
        assert await get_installation_on(tx, team_id="absent:example.com", app_id="fixture") is None
        assert await get_installation_on(tx, team_id=TEAM, app_id="missing") is None


async def test_active_state_requires_verified_origin_and_pinned_bytes(db):
    import asyncpg
    from pgdbm.core import QueryError

    for changes in (
        "state = 'active'",
        "state = 'active', origin_verified = TRUE",
        "generation = 0",
    ):
        with pytest.raises((asyncpg.CheckViolationError, QueryError)):
            await db.execute("UPDATE {{tables.team_app_installs}} SET " + changes)
    assert (await read(db))["state"] == "pending_origin_verification"


async def test_exact_pinned_bytes_can_activate_without_changing_identity_generation_or_scopes(db):
    before = await read(db)
    # A trusted verifier supplies its origin-fetch evidence in this transaction.
    await db.execute(
        """UPDATE {{tables.team_app_installs}} SET manifest_bytes = $2,
           state = 'active', origin_verified = TRUE WHERE team_id = $1""", TEAM, MANIFEST,
    )
    after = await read(db)
    assert after["state"] == "active"
    assert after["origin_verified"] is True
    for field in ("installation_id", "generation", "granted_scopes", "origin", "digest"):
        assert after[field] == before[field]


async def test_bytes_that_disagree_with_the_pinned_digest_are_refused(db):
    import asyncpg
    from pgdbm.core import QueryError

    with pytest.raises((asyncpg.CheckViolationError, QueryError)):
        await db.execute(
            "UPDATE {{tables.team_app_installs}} SET manifest_bytes = $1 WHERE team_id = $2",
            b"different exact bytes", TEAM,
        )
    assert (await read(db))["digest"] == DIGEST


async def test_update_lock_serializes_lifecycle_mutations_on_the_current_install_row(db):
    locked = asyncio.Event()
    release = asyncio.Event()
    changed = asyncio.Event()

    async def reader():
        async with db.transaction() as tx:
            current = await get_installation_on(tx, team_id=TEAM, app_id="fixture", for_update=True)
            assert current["state"] == "pending_origin_verification"
            locked.set()
            await release.wait()

    async def lifecycle():
        await locked.wait()
        await db.execute(
            "UPDATE {{tables.team_app_installs}} SET state = 'uninstalled' WHERE team_id = $1 AND app_id = 'fixture'", TEAM,
        )
        changed.set()

    reader_task = asyncio.create_task(reader())
    writer_task = asyncio.create_task(lifecycle())
    try:
        await asyncio.wait_for(locked.wait(), 2)
        await asyncio.sleep(0.05)
        assert not changed.is_set()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(reader_task, writer_task), 3)
    assert (await read(db))["state"] == "uninstalled"


async def test_generation_counter_survives_two_complete_uninstalls_and_reinstallations(db):
    previous = await read(db)
    for expected in (2, 3):
        async with db.transaction() as tx:
            await get_installation_on(tx, team_id=TEAM, app_id="fixture", for_update=True)
            await tx.execute("DELETE FROM {{tables.team_app_installs}} WHERE team_id = $1", TEAM)
            generation = await next_installation_generation_on(tx, team_id=TEAM, app_id="fixture")
            assert generation == expected
            await tx.execute(
                """INSERT INTO {{tables.team_app_installs}}
                   (team_id, app_id, origin, digest, app_version, manifest_version, granted_scopes, generation)
                   VALUES ($1, 'fixture', $2, $3, '1.0.0', 1, ARRAY['fixture:read'], $4)""",
                TEAM, ORIGIN, DIGEST, generation,
            )
        current = await read(db)
        assert current["installation_id"] != previous["installation_id"]
        assert current["generation"] > previous["generation"]
        previous = current
    assert (await read(db, OTHER_TEAM))["generation"] == 1


async def test_generation_allocations_serialize_and_rollback_with_the_registry_transaction(db):
    async def allocate():
        async with db.transaction() as tx:
            return await next_installation_generation_on(tx, team_id=TEAM, app_id="fixture")

    assert sorted(await asyncio.gather(*(allocate() for _ in range(12)))) == list(range(2, 14))
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            assert await next_installation_generation_on(tx, team_id=TEAM, app_id="fixture") == 14
            raise RuntimeError("abort installation")
    assert await allocate() == 14


async def test_generation_counter_outlives_team_deletion_and_recreation_under_the_same_id(db):
    previous = await read(db)
    await db.execute("DELETE FROM {{tables.teams}} WHERE team_id = $1", TEAM)
    assert await read(db) is None
    async with db.transaction() as tx:
        await tx.execute(
            "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, 'example.com', 'demo', 'did:key:new-controller')",
            TEAM,
        )
        generation = await next_installation_generation_on(tx, team_id=TEAM, app_id="fixture")
        await tx.execute(
            """INSERT INTO {{tables.team_app_installs}}
               (team_id, app_id, origin, digest, app_version, manifest_version, granted_scopes, generation)
               VALUES ($1, 'fixture', $2, $3, '1.0.0', 1, ARRAY['fixture:read'], $4)""",
            TEAM, ORIGIN, DIGEST, generation,
        )
    current = await read(db)
    assert current["installation_id"] != previous["installation_id"]
    assert current["generation"] > previous["generation"]
