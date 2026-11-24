from __future__ import annotations

import json
import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from aweb_naapp_testing.databases import TEST_SCHEMA, SchemaDatabases
from awid_service.testing import selected_test_database_config
from fastapi.testclient import TestClient
from manifest_config import TEST_GRANT_SEED_HEX
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.testing import AsyncTestDatabase
from test_e2e_smoke import (  # noqa: F401
    aw_workspace,
    library,
    library_origin,
    library_without_awid_service_token,
    workspaces,
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


@pytest_asyncio.fixture
async def database_url() -> AsyncIterator[str]:
    """A fresh, empty real Postgres database."""
    test_database = AsyncTestDatabase(selected_test_database_config())
    try:
        await test_database.create_test_database()
    except Exception as exc:  # pragma: no cover - environment without Postgres
        if os.environ.get("LIBRARY_REQUIRE_TEST_DATABASE") == "1":
            raise RuntimeError("real Postgres is required for this test run") from exc
        pytest.skip(f"real Postgres not available: {exc}")
    try:
        yield test_database.get_test_db_config().get_dsn()
    finally:
        await test_database.drop_test_database()


@pytest.fixture
def library_client(database_url: str) -> Iterator[TestClient]:
    """Library at its hosted origin, started on a real, empty database."""
    # library.api builds its runtime at import, after pytest_configure's key.
    from library.api import create_app
    from library.config import Settings

    settings = Settings(
        _env_file=None,
        database_url=database_url,
        db_schema=TEST_SCHEMA,
        public_origin="https://library.aweb.ai",
    )
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)


def pytest_configure(config: pytest.Config) -> None:
    # library.api constructs its real runtime at import, and the runtime reads
    # the installation grant-read key then. Give every test process a
    # disposable key file before that module is imported.
    directory = tempfile.TemporaryDirectory(prefix="library-test-key-")
    grant = Path(directory.name) / "grant-read.hex"
    grant.write_text(TEST_GRANT_SEED_HEX)
    grant.chmod(0o600)
    env = pytest.MonkeyPatch()
    env.setenv("LIBRARY_APP_KEY_FILES", json.dumps({"library:grant-read-1": str(grant)}))
    config.add_cleanup(directory.cleanup)
    config.add_cleanup(env.undo)
