from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig

from aweb_naapp.runtime.db import NaappDatabase
from aweb_naapp.runtime.settings import NaappSettings

_TEST_DB_CONFIG = DatabaseTestConfig(
    host=os.environ.get("TEST_DB_HOST", "localhost"),
    port=int(os.environ.get("TEST_DB_PORT", "5432")),
    user=os.environ.get("TEST_DB_USER", "postgres"),
    password=os.environ.get("TEST_DB_PASSWORD", "postgres"),
)


class ExampleSettings(NaappSettings):
    public_origin: str = "https://example.test"
    app_id: str = "example"


@pytest_asyncio.fixture
async def database_url() -> AsyncIterator[str]:
    """A fresh, empty real Postgres database."""
    test_database = AsyncTestDatabase(_TEST_DB_CONFIG)
    try:
        await test_database.create_test_database()
    except Exception as exc:  # pragma: no cover - environment without Postgres
        if os.environ.get("NAAPP_REQUIRE_TEST_DATABASE") == "1":
            raise RuntimeError("real Postgres is required for this test run") from exc
        pytest.skip(f"real Postgres not available: {exc}")
    try:
        yield test_database.get_test_db_config().get_dsn()
    finally:
        await test_database.drop_test_database()


def _migrations(tmp_path: Path) -> Path:
    path = tmp_path / "migrations"
    path.mkdir()
    (path / "001_initial.sql").write_text("CREATE TABLE things (id integer PRIMARY KEY);\n")
    return path


async def test_connect_applies_the_app_migrations_under_its_module(
    database_url: str, tmp_path: Path
) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(settings, module_name="example", migrations_path=_migrations(tmp_path))
    await database.connect()
    try:
        assert await database.db.fetch_value("SELECT to_regclass('things') IS NOT NULL")
        applied = await database.db.fetch_all("SELECT module_name, filename FROM schema_migrations")
        assert [(row["module_name"], row["filename"]) for row in applied] == [
            ("example", "001_initial.sql")
        ]
    finally:
        await database.disconnect()


async def test_reconnecting_applies_nothing_twice(database_url: str, tmp_path: Path) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    migrations = _migrations(tmp_path)
    for _ in range(2):
        database = NaappDatabase(settings, module_name="example", migrations_path=migrations)
        await database.connect()
        count = await database.db.fetch_value("SELECT count(*) FROM schema_migrations")
        await database.disconnect()
        assert count == 1


async def test_pool_follows_the_settings(database_url: str, tmp_path: Path) -> None:
    settings = ExampleSettings(
        _env_file=None,
        database_url=database_url,
        db_pool_min_connections=2,
        db_pool_max_connections=3,
    )
    database = NaappDatabase(settings, module_name="example", migrations_path=_migrations(tmp_path))
    await database.connect()
    try:
        stats = await database.db.get_pool_stats()
        assert (stats["min_size"], stats["max_size"]) == (2, 3)
    finally:
        await database.disconnect()
