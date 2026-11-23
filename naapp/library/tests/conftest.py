from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

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

# A naapp runs in its own schema: the candidate gate's role carries
# production's search_path=pg_catalog, where an unqualified table resolves to
# no user schema at all.
TEST_SCHEMA = "naapp_test"


def named_database_config() -> DatabaseTestConfig:
    """The test server's address, which the environment must name.

    Without one, pgdbm's default is localhost:5432: on a developer's machine, a
    Postgres that is not the tests'."""
    unnamed = [name for name in ("TEST_DB_HOST", "TEST_DB_PORT") if not os.environ.get(name)]
    if unnamed:
        reason = f"no test database server named: set {' and '.join(unnamed)}"
        if os.environ.get("LIBRARY_REQUIRE_TEST_DATABASE") == "1":
            raise RuntimeError(reason)
        pytest.skip(reason)
    return DatabaseTestConfig(
        host=os.environ["TEST_DB_HOST"],
        port=int(os.environ["TEST_DB_PORT"]),
        user=os.environ.get("TEST_DB_USER", "postgres"),
        password=os.environ.get("TEST_DB_PASSWORD", "postgres"),
    )


@pytest_asyncio.fixture
async def migrated_db() -> AsyncIterator[AsyncDatabaseManager]:
    """A real Postgres database with library's migrations applied. Skips cleanly when
    no Postgres is reachable, so it runs in CI / the reviewer's real-DB pass and is a
    no-op in environments without a database."""
    test_database = AsyncTestDatabase(named_database_config())
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


class _SchemaDatabases:
    """pgdbm's test database factory, giving every database a schema unless the test names one.

    A copy of aweb_naapp_testing.databases.SchemaDatabases: Library's lock pins
    aweb-naapp from an external commit and cannot see the tree's testing
    package until aweb-acgh.5 moves it to in-repo path sources.
    """

    def __init__(self, factory: Any) -> None:
        self._factory = factory

    async def create_db(
        self, suffix: str | None = None, schema: str | None = None, **kwargs: Any
    ) -> AsyncDatabaseManager:
        # The factory reads the same variables itself; refuse before it defaults.
        named_database_config()
        return await self._factory.create_db(suffix, schema or TEST_SCHEMA, **kwargs)


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> _SchemaDatabases:
    return _SchemaDatabases(test_db_factory)
