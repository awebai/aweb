from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from aweb_naapp_testing.databases import TEST_SCHEMA, SchemaDatabases
from awid_service.testing import selected_test_database_config
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.testing import AsyncTestDatabase
from test_e2e_smoke import (  # noqa: F401
    aw_workspace,
    aw_workspace_factory,
    library,
    library_origin,
)

pytest_plugins = ("awid_service.testing_postgres",)

_MIGRATIONS = Path(__file__).resolve().parent.parent / "src" / "library" / "migrations"


@pytest_asyncio.fixture
async def migrated_db() -> AsyncIterator[AsyncDatabaseManager]:
    """A real Postgres database with library's migrations applied. Skips cleanly when
    no Postgres is reachable, so it runs in CI / the reviewer's real-DB pass and is a
    no-op in environments without a database."""
    test_database = AsyncTestDatabase(selected_test_database_config())
    try:
        await test_database.create_test_database()
    except Exception as exc:  # pragma: no cover - environment without Postgres
        if os.environ.get("LIBRARY_REQUIRE_TEST_DATABASE") == "1":
            raise RuntimeError("real Postgres is required for this test run") from exc
        pytest.skip(f"real Postgres not available: {exc}")

    try:
        async with test_database.get_test_db_manager(schema=TEST_SCHEMA) as db:
            migrations = AsyncMigrationManager(
                db, migrations_path=str(_MIGRATIONS), module_name="library"
            )
            await migrations.apply_pending_migrations()
            yield db
    finally:
        await test_database.drop_test_database()


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)
