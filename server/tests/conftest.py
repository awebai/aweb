"""Minimal pgdbm-backed fixtures for standalone aweb server tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest_asyncio
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb.db_config import build_database_config

pytest_plugins = ("pgdbm.fixtures.conftest",)

os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("AWEB_INTERNAL_AUTH_SECRET", "test-internal-auth-secret")


@pytest_asyncio.fixture
async def shared_test_pool(test_db_factory):
    db_manager = await test_db_factory.create_db(suffix="aweb_server")
    config = build_database_config(
        connection_string=db_manager.config.get_dsn(),
        min_connections=2,
        max_connections=5,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    try:
        yield pool
    finally:
        await pool.close()


@pytest_asyncio.fixture
async def aweb_cloud_db(shared_test_pool):
    """Standalone-compatible database managers for aweb/server schema tests."""

    temp_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await temp_manager.execute("CREATE SCHEMA IF NOT EXISTS server")
    await temp_manager.execute("CREATE SCHEMA IF NOT EXISTS aweb")

    oss_db = AsyncDatabaseManager(pool=shared_test_pool, schema="server")
    aweb_db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")

    import aweb

    aweb_path = Path(aweb.__file__).parent
    server_migrations = AsyncMigrationManager(
        oss_db,
        migrations_path=str(aweb_path / "migrations" / "server"),
        module_name="aweb-server",
        migrations_table="schema_migrations",
    )
    await server_migrations.apply_pending_migrations()

    aweb_migrations = AsyncMigrationManager(
        aweb_db,
        migrations_path=str(aweb_path / "migrations" / "aweb"),
        module_name="aweb-aweb",
        migrations_table="schema_migrations",
    )
    await aweb_migrations.apply_pending_migrations()

    class DatabaseManagers:
        def __init__(self, oss_db, aweb_db):
            self.oss_db = oss_db
            self.aweb_db = aweb_db

    yield DatabaseManagers(oss_db, aweb_db)
