"""Logs' migrations on a database that already applied a later one (real PostgreSQL)."""

import shutil
from pathlib import Path

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH


async def migrate(db: AsyncDatabaseManager, path: Path) -> list[str]:
    applied = await AsyncMigrationManager(
        db, migrations_path=str(path), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    return [migration["filename"] for migration in applied["applied"]]


async def indexes(db: AsyncDatabaseManager) -> set[tuple[str, str]]:
    rows = await db.fetch_all(
        "SELECT tablename, indexname FROM pg_indexes WHERE schemaname = $1", db.schema
    )
    return {(row["tablename"], row["indexname"]) for row in rows}


@pytest.mark.parametrize("late", ["008_governance_index.sql", "009_retire_reader_slots.sql"])
async def test_a_database_missing_one_migration_reaches_the_complete_schema(
    test_db_factory, tmp_path: Path, late: str
) -> None:
    complete = await test_db_factory.create_db(suffix="logs_migrations_complete")
    await migrate(complete, MIGRATIONS_PATH)

    partial = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS_PATH, partial)
    (partial / late).unlink()
    upgraded = await test_db_factory.create_db(suffix="logs_migrations_upgraded")
    await migrate(upgraded, partial)
    assert await indexes(upgraded) != await indexes(complete)

    assert await migrate(upgraded, MIGRATIONS_PATH) == [late]
    assert await indexes(upgraded) == await indexes(complete)
    assert await migrate(upgraded, MIGRATIONS_PATH) == []
