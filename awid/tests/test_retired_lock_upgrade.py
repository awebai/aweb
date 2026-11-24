"""Upgrade an actual RC migration ledger after its source files are retired.

The archived SQL is test input from the released candidate, not a migration
source. In particular, no INSERT fabricates an applied schema_migrations row.
"""

from __future__ import annotations

from pathlib import Path
from shutil import copyfile

import pytest
from pgdbm.migrations import AsyncMigrationManager

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = Path(__file__).parent / "fixtures" / "retired_lock_migrations"
MODULES = {
    "awid": (ROOT / "awid/src/awid_service/migrations", "awid-service", 15),
    "hooks": (ROOT / "naapp-contracts/src/aweb_naapp_contracts/hooks/migrations", "aweb_naapp_hooks", 2),

}


def stage(module: str, destination: Path, *, old: bool) -> Path:
    destination.mkdir()
    source, _, ceiling = MODULES[module]
    retired = {p.name for p in (ARCHIVE / module).glob("*.sql")}
    for path in source.glob("*.sql"):
        if path.name in retired:
            continue
        if not old or int(path.name.split("_", 1)[0]) <= ceiling:
            copyfile(path, destination / path.name)
    if old:
        for path in (ARCHIVE / module).glob("*.sql"):
            copyfile(path, destination / path.name)
    return destination


async def seed(db, module: str, *, retired: bool) -> None:
    if module == "awid":
        await db.execute(
            "INSERT INTO {{tables.teams}} (domain,name,team_did_key) "
            "VALUES('example.test','ordinary','did:key:ordinary')"
        )
        if retired:
            await db.execute(
                "INSERT INTO {{tables.team_protection}} "
                "(domain,name,service_id,service_did_key,generation) "
                "VALUES('example.test','ordinary','old-service','did:key:old-service',1)"
            )
    elif module == "hooks":
        await db.execute(
            "INSERT INTO {{tables.owner_act_nonces}} "
            "(scope,team_id,nonce,act_sha256,expires_at) "
            "VALUES('app','ordinary:example.test','used-once','digest',NOW()+interval '1 hour')"
        )
    if retired:
        await db.execute(
            "INSERT INTO {{tables.protected_effect_receipts}} "
            "(operation_id,team_id,service_id,operation,variant,artifact_sha256,header_sha256) "
            "VALUES('00000000-0000-4000-8000-000000000001','ordinary:example.test',"
            "'old-service','old-effect','default',$1,$1)",
            "a" * 64,
        )


async def assert_cleanup_and_preserved_authority(db, module: str) -> None:
    assert not await db.fetch_value("SELECT to_regclass('team_protection') IS NOT NULL")
    assert not await db.fetch_value("SELECT to_regclass('protected_effect_receipts') IS NOT NULL")
    if module == "awid":
        assert await db.fetch_value(
            "SELECT team_did_key FROM {{tables.teams}} WHERE name='ordinary'"
        ) == "did:key:ordinary"
        # The separate, released attestation feature is not the lock.
        for table in ("team_custodians", "member_custody", "member_person"):
            assert await db.fetch_value("SELECT to_regclass($1) IS NOT NULL", table)
    elif module == "hooks":
        assert await db.fetch_value(
            "SELECT nonce FROM {{tables.owner_act_nonces}} WHERE scope='app'"
        ) == "used-once"


@pytest.mark.asyncio
@pytest.mark.parametrize("module", MODULES)
async def test_old_applied_files_can_be_absent_while_cleanup_preserves_live_data(
    test_db_factory, tmp_path, module
):
    db = await test_db_factory.create_db(suffix="retired_" + module, schema=module)
    _, module_name, _ = MODULES[module]
    old = stage(module, tmp_path / "rc", old=True)
    old_runner = AsyncMigrationManager(db, migrations_path=str(old), module_name=module_name)
    await old_runner.apply_pending_migrations()
    original = await old_runner.get_applied_migrations()
    retired = {p.name for p in (ARCHIVE / module).glob("*.sql")}
    assert retired <= original.keys()
    await seed(db, module, retired=True)

    current = stage(module, tmp_path / "current", old=False)
    assert not retired.intersection(p.name for p in current.glob("*.sql"))
    runner = AsyncMigrationManager(db, migrations_path=str(current), module_name=module_name)
    # Real pgdbm must accept missing applied files, not treat them as modified.
    await runner.apply_pending_migrations()
    await assert_cleanup_and_preserved_authority(db, module)
    applied = await runner.get_applied_migrations()
    for name in retired:
        assert applied[name].checksum == original[name].checksum
    assert (await runner.apply_pending_migrations())["status"] == "up_to_date"


@pytest.mark.asyncio
@pytest.mark.parametrize("module", MODULES)
async def test_cleanup_is_also_safe_for_a_fresh_database(test_db_factory, tmp_path, module):
    db = await test_db_factory.create_db(suffix="fresh_" + module, schema=module)
    _, module_name, _ = MODULES[module]
    current = stage(module, tmp_path / "current", old=False)
    runner = AsyncMigrationManager(db, migrations_path=str(current), module_name=module_name)
    await runner.apply_pending_migrations()
    await seed(db, module, retired=False)
    await assert_cleanup_and_preserved_authority(db, module)
    assert (await runner.apply_pending_migrations())["status"] == "up_to_date"
