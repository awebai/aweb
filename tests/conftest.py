from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig
from test_e2e_smoke import (  # noqa: F401
    aw_workspace,
    aw_workspace_factory,
    library,
    library_origin,
)

_MIGRATIONS = Path(__file__).resolve().parent.parent / "src" / "library" / "migrations"

_TEST_DB_CONFIG = DatabaseTestConfig(
    host=os.environ.get("TEST_DB_HOST", "localhost"),
    port=int(os.environ.get("TEST_DB_PORT", "5432")),
    user=os.environ.get("TEST_DB_USER", "postgres"),
    password=os.environ.get("TEST_DB_PASSWORD", "postgres"),
)


@pytest_asyncio.fixture
async def migrated_db() -> AsyncIterator[AsyncDatabaseManager]:
    """A real Postgres database with library's migrations applied. Skips cleanly when
    no Postgres is reachable, so it runs in CI / the reviewer's real-DB pass and is a
    no-op in environments without a database."""
    test_database = AsyncTestDatabase(_TEST_DB_CONFIG)
    try:
        await test_database.create_test_database()
    except Exception as exc:  # pragma: no cover - environment without Postgres
        pytest.skip(f"real Postgres not available: {exc}")

    try:
        async with test_database.get_test_db_manager() as db:
            migrations = AsyncMigrationManager(
                db, migrations_path=str(_MIGRATIONS), module_name="library"
            )
            await migrations.apply_pending_migrations()
            yield db
    finally:
        await test_database.drop_test_database()
