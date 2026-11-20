from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from aweb_naapp.runtime.team_auth import Principal, record_observed_principal
from aweb_naapp_testing.databases import TEST_SCHEMA, SchemaDatabases
from fastapi.testclient import TestClient
from manifest_config import TEST_GRANT_SEED_HEX
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig
from test_e2e_smoke import (  # noqa: F401
    aw_workspace,
    library,
    library_origin,
    library_without_awid_service_token,
    workspaces,
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
    test_database = AsyncTestDatabase(_TEST_DB_CONFIG)
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


_ENGINEERING = Path(__file__).parent / "vectors" / "blueprints" / "engineering" / "source"
_PUBLISHER = Principal(
    team_id="default:publisher.example",
    did_key="did:key:z6MkPublisherMember",
    did_aw=None,
    address=None,
    alias="publisher",
    certificate_id="cert-publisher",
    team_did_key="did:key:z6MkPublisherTeam",
)


@pytest.fixture
def published_engineering(library_client: TestClient, database_url: str) -> TestClient:
    """Library with the engineering vector blueprint published by a team, through
    the product's own writers: the team is recorded as the runtime records an
    admitted member, then the blueprint is published as the import route does."""
    from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files
    from library.repository import publish_blueprint

    async def publish() -> None:
        db = AsyncDatabaseManager(
            DatabaseConfig(connection_string=database_url, schema=TEST_SCHEMA)
        )
        await db.connect()
        try:
            await record_observed_principal(db, _PUBLISHER)
            payload = {"files": collect_files(_ENGINEERING), "schema": BLUEPRINT_PAYLOAD_SCHEMA}
            await publish_blueprint(db, principal=_PUBLISHER, payload=payload)
        finally:
            await db.disconnect()

    asyncio.run(publish())
    return library_client
