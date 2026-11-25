"""Minimal pgdbm-backed fixtures for standalone aweb server tests."""

from __future__ import annotations

import os
import runpy
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asyncpg import Pool

# xdist sets its worker identity before conftest imports. Bind services before
# pgdbm/plugin imports and test modules can capture a parent endpoint.
# This file is both tests.conftest and the CLI auth stack's top-level conftest.
# Resolve our sibling by file, independent of the caller's package search path.
runpy.run_path(str(Path(__file__).with_name("worker_services.py")))[
    "configure_worker_environment"
](os.environ)

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from pgdbm import AsyncDatabaseManager, DatabaseConfig  # noqa: E402

from awid.db_config import build_database_config  # noqa: E402
from aweb.migrations import apply_native_migrations  # noqa: E402

pytest_plugins = (
    "pgdbm.fixtures.conftest",
    "tests.real_stack",
    "tests.chat_coverage_support",
)


@pytest.fixture(scope="session")
def server_js_runtime():
    from tests.js_runtime_tree import (
        prepare_runtime_tree,
        remove_runtime_tree,
        runtime_repo,
    )

    source = Path(__file__).resolve().parents[2]
    root = runtime_repo(source)
    if root == source:
        yield root
        return
    prepare_runtime_tree(source, root)
    try:
        yield root
    finally:
        remove_runtime_tree(root)


os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("AWEB_INTERNAL_AUTH_SECRET", "test-internal-auth-secret")
os.environ.setdefault("AWID_SERVICE_TOKEN", "aweb-server-tests-service-token-32-bytes")


@dataclass(frozen=True)
class SharedTestDatabase:
    """The selected disposable database configuration and its one owned pool."""

    config: DatabaseConfig = field(repr=False)
    pool: Pool = field(repr=False)

    @property
    def dsn(self) -> str:
        return self.config.get_dsn()


@pytest_asyncio.fixture
async def shared_test_database(test_db_factory):
    db_manager = await test_db_factory.create_db(suffix="aweb_server")
    # Pre-provision pgcrypto in public at the point the fresh database is
    # materialized (pgdbm creates test databases from template0, so no
    # template can carry it): migration 001's unqualified CREATE EXTENSION
    # then no-ops instead of resolving into the pinned pg_catalog and
    # colliding with the built-in gen_random_uuid.
    await db_manager.execute(
        "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public"
    )
    config = build_database_config(
        connection_string=db_manager.config.get_dsn(),
        min_connections=2,
        max_connections=5,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    try:
        yield SharedTestDatabase(config=db_manager.config, pool=pool)
    finally:
        await pool.close()


@pytest_asyncio.fixture
async def shared_test_pool(shared_test_database):
    """Borrow the same pool; the selected database fixture owns its cleanup."""
    yield shared_test_database.pool


@dataclass(frozen=True)
class DatabaseManagers:
    aweb_db: AsyncDatabaseManager

    @property
    def oss_db(self) -> AsyncDatabaseManager:
        return self.aweb_db


@pytest_asyncio.fixture
async def pre_chat_coverage_db(chat_coverage_upgrade):
    return DatabaseManagers(chat_coverage_upgrade.infra.get_manager())


@pytest_asyncio.fixture
async def aweb_cloud_db(shared_test_pool):
    """Database manager for the unified aweb schema tests."""

    temp_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await temp_manager.execute("CREATE SCHEMA IF NOT EXISTS aweb")

    aweb_db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")

    await apply_native_migrations(aweb_db)

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
        cwd=repo / "cli/go",
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    print(f"shared server-test CLI build: {time.monotonic() - started:.3f}s")
    return binary


@pytest.fixture
def source_cli_binary(aw_cli_binary, monkeypatch):
    monkeypatch.setenv("AW_TEST_CLI_BINARY", str(aw_cli_binary))
    return aw_cli_binary
