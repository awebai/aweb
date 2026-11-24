"""Real pgdbm upgrade of both retired signers, including configurable schemas."""

from pathlib import Path
from shutil import copyfile

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = Path(__file__).parent / "fixtures/retired_signer_migrations"
SERVER_TABLES = (
    "protected_authorizer_bindings",
    "protected_requester_bindings",
    "protected_local_audit",
    "protected_operator_bootstraps",
    "protected_admission_policies",
    "protected_root_endorsements",
    "protected_root_admissions",
)
SHARED_TABLES = ("protected_signer_operations", "protected_signer_notice_reservations")
OLD_MODULES = {
    "server": "aweb_independent_protected_signer",
    "shared": "aweb_naapp_protected_signer",
}
CLEANUPS = (
    (ROOT / "server/src/aweb/migrations/aweb/053_drop_retired_signer.sql", "aweb-aweb"),
    (ARCHIVE / "passkeys/007_drop_retired_signer.sql", "aweb_naapp_passkeys"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_schema", ["protected_signer", "custom_signer"])
@pytest.mark.parametrize("installed", [False, True], ids=["fresh", "candidate-upgrade"])
async def test_cleanup_preserves_neighbours_and_reaches_legacy_schema(
    shared_test_pool, tmp_path, legacy_schema, installed
):
    active = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")
    legacy = AsyncDatabaseManager(pool=shared_test_pool, schema=legacy_schema)
    await active.execute("CREATE SCHEMA aweb")
    await active.execute(f'CREATE SCHEMA "{legacy_schema}"')
    # Same names without the retired module's ledger are not ours to drop.
    await active.execute("CREATE SCHEMA unrelated")
    await active.execute("CREATE TABLE unrelated.protected_local_audit (value text)")
    await active.execute("INSERT INTO unrelated.protected_local_audit VALUES ('kept')")
    await legacy.execute("CREATE TABLE {{tables.neighbour}} (proof bytea NOT NULL)")
    await legacy.execute(
        "INSERT INTO {{tables.neighbour}} VALUES ($1)", b"retained app proof"
    )
    old_records = {}
    if installed:
        for package, module in OLD_MODULES.items():
            runner = AsyncMigrationManager(
                legacy, migrations_path=str(ARCHIVE / package), module_name=module
            )
            await runner.apply_pending_migrations()
            old_records[package] = await runner.get_applied_migrations()
        for table in (*SERVER_TABLES, *SHARED_TABLES):
            assert await active.fetch_value(
                "SELECT to_regclass($1) IS NOT NULL", f"{legacy_schema}.{table}"
            )
        await legacy.execute(
            "INSERT INTO {{tables.protected_signer_operations}} "
            "(operation_id,handoff_id,requester,intent,request,digest,approval_id,candidate_links,expires_at) "
            "VALUES ('op','handoff','requester',$1,$1,'digest','approval','[]',NOW())",
            b"retired",
        )
        await legacy.execute(
            "INSERT INTO {{tables.protected_signer_notice_reservations}} "
            "VALUES ('op','service','authority','requester',1,false,NOW())"
        )
    for index, (source, module) in enumerate(CLEANUPS):
        staged = tmp_path / str(index)
        staged.mkdir()
        copyfile(source, staged / source.name)
        runner = AsyncMigrationManager(
            active, migrations_path=str(staged), module_name=module
        )
        await runner.apply_pending_migrations()
        assert (await runner.apply_pending_migrations())["status"] == "up_to_date"
        # Also exercise the SQL's IF EXISTS path independently of the ledger.
        await active.execute(source.read_text())
    for table in (*SERVER_TABLES, *SHARED_TABLES):
        assert not await active.fetch_value(
            "SELECT to_regclass($1) IS NOT NULL", f"{legacy_schema}.{table}"
        )
    assert (
        await legacy.fetch_value("SELECT proof FROM {{tables.neighbour}}")
        == b"retained app proof"
    )
    assert (
        await active.fetch_value("SELECT value FROM unrelated.protected_local_audit")
        == "kept"
    )
    for package, original in old_records.items():
        runner = AsyncMigrationManager(
            legacy,
            migrations_path=str(ARCHIVE / package),
            module_name=OLD_MODULES[package],
        )
        applied = await runner.get_applied_migrations()
        assert {k: v.checksum for k, v in applied.items()} == {
            k: v.checksum for k, v in original.items()
        }
