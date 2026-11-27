"""A host applies and checks every native migration module through one owner."""

import pytest
from pgdbm import AsyncMigrationManager

from aweb.db import DatabaseInfra


def test_complete_native_migration_inventory_is_packaged():
    from aweb.migrations import native_migration_modules

    inventory = native_migration_modules()
    assert [module.module_name for module in inventory] == [
        "aweb-aweb",
        "aweb_naapp_hooks",
    ]
    for module in inventory:
        assert module.migrations_path.is_dir()
        assert list(module.migrations_path.glob("*.sql")), module.module_name


@pytest.mark.asyncio
async def test_core_only_host_is_not_ready_until_owner_act_module_is_applied(
    shared_test_pool,
):
    from aweb.migrations import (
        AppliedNativeMigrations,
        PendingNativeMigrations,
        apply_native_migrations,
        native_migration_modules,
        pending_native_migrations,
    )

    infra = DatabaseInfra()
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=False)
    try:
        db = infra.get_manager("aweb")
        inventory = native_migration_modules()
        assert [module.module_name for module in inventory] == [
            "aweb-aweb",
            "aweb_naapp_hooks",
        ]
        fresh = await pending_native_migrations(db)
        assert isinstance(fresh, PendingNativeMigrations)
        assert not fresh.ready
        assert {item.module_name for item in fresh.pending} == {
            "aweb-aweb",
            "aweb_naapp_hooks",
        }

        # This is the old embedding behavior: apply core's directory only.
        await AsyncMigrationManager(
            db,
            migrations_path=str(inventory[0].migrations_path),
            module_name=inventory[0].module_name,
        ).apply_pending_migrations()
        core_only = await pending_native_migrations(db)
        assert not core_only.ready
        assert {item.module_name for item in core_only.pending} == {"aweb_naapp_hooks"}
        assert core_only.message.endswith(
            "Run apply_native_migrations(db) before serving traffic."
        )
        assert (
            await db.fetch_value("SELECT to_regclass('aweb.owner_act_nonces')") is None
        )

        applied = await apply_native_migrations(db)
        assert isinstance(applied, AppliedNativeMigrations)
        assert {item.module_name for item in applied.applied} == {"aweb_naapp_hooks"}
        assert (
            await db.fetch_value("SELECT to_regclass('aweb.owner_act_nonces')")
            is not None
        )
        assert (await pending_native_migrations(db)).ready
        assert (await apply_native_migrations(db)).applied == ()
    finally:
        await infra.close()


@pytest.mark.asyncio
async def test_native_initialization_satisfies_same_readiness_inventory(
    shared_test_pool,
):
    from aweb.migrations import pending_native_migrations

    infra = DatabaseInfra()
    await infra.initialize(shared_pool=shared_test_pool)
    try:
        ready = await pending_native_migrations(infra.get_manager("aweb"))
        assert ready.ready
        assert ready.pending == ()
    finally:
        await infra.close()


@pytest.mark.asyncio
async def test_changed_migration_receipt_fails_readiness_actionably(aweb_cloud_db):
    from aweb.migrations import NativeMigrationError, pending_native_migrations

    db = aweb_cloud_db.aweb_db
    # Model operator corruption of the receipt, without editing a frozen SQL file.
    await db.execute(
        "UPDATE {{tables.schema_migrations}} SET checksum='changed' "
        "WHERE module_name='aweb_naapp_hooks'",
    )
    with pytest.raises(NativeMigrationError) as refused:
        await pending_native_migrations(db)
    assert refused.value.module_name == "aweb_naapp_hooks"
    assert refused.value.operation == "check"
    assert str(refused.value).endswith(
        "Check the database connection and packaged migration files, then retry before serving traffic."
    )
    assert refused.value.__cause__ is not None
