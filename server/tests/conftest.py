"""Minimal pgdbm-backed fixtures for standalone aweb server tests."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest
import pytest_asyncio
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from awid.db_config import build_database_config
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations

pytest_plugins = ("pgdbm.fixtures.conftest",)

os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("AWEB_INTERNAL_AUTH_SECRET", "test-internal-auth-secret")
os.environ.setdefault("AWID_SERVICE_TOKEN", "aweb-server-tests-service-token-32-bytes")


@pytest_asyncio.fixture
async def shared_test_pool(test_db_factory):
    db_manager = await test_db_factory.create_db(suffix="aweb_server")
    # Pre-provision pgcrypto in public at the point the fresh database is
    # materialized (pgdbm creates test databases from template0, so no
    # template can carry it): migration 001's unqualified CREATE EXTENSION
    # then no-ops instead of resolving into the pinned pg_catalog and
    # colliding with the built-in gen_random_uuid.
    await db_manager.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
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
    """Database manager for the unified aweb schema tests."""

    temp_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await temp_manager.execute("CREATE SCHEMA IF NOT EXISTS aweb")

    aweb_db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")

    import aweb

    aweb_path = Path(aweb.__file__).parent
    aweb_migrations = AsyncMigrationManager(
        aweb_db,
        migrations_path=str(aweb_path / "migrations" / "aweb"),
        module_name="aweb-aweb",
        migrations_table="schema_migrations",
    )
    await aweb_migrations.apply_pending_migrations()
    await apply_owner_act_migrations(aweb_db)

    class DatabaseManagers:
        def __init__(self, aweb_db):
            self.oss_db = aweb_db
            self.aweb_db = aweb_db

    yield DatabaseManagers(aweb_db)


@pytest.fixture(scope="session")
def aw_cli_binary(tmp_path_factory):
    """One current-source CLI build for the real-service tests in this run."""
    configured = os.environ.get("AW_TEST_CLI_BINARY")
    if configured:
        # Preserve the explicit artifact override used by release harnesses.
        return Path(configured)
    binary = tmp_path_factory.mktemp("aw-cli") / ("aw.exe" if os.name == "nt" else "aw")
    repo = Path(__file__).resolve().parents[2]
    started = time.monotonic()
    build = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/aw"],
        cwd=repo / "cli/go", capture_output=True, text=True, timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    print(f"shared server-test CLI build: {time.monotonic() - started:.3f}s")
    return binary


@pytest.fixture
def source_cli_binary(aw_cli_binary, monkeypatch):
    monkeypatch.setenv("AW_TEST_CLI_BINARY", str(aw_cli_binary))
    return aw_cli_binary
