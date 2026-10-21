"""Real PostgreSQL databases (pgdbm's test_db_factory), each in its own schema,
and real AWID routes on one of them (aweb_naapp_testing) for the tests that
verify team acts."""

from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from aweb_naapp_testing import Registry, awid_registry
from aweb_naapp_testing.databases import SchemaDatabases

pytest_plugins = ("pgdbm.fixtures.conftest",)


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    # AWID connects to this database by its DSN alone and keeps its tables in
    # its own explicit schema, so the test schema the factory adds goes unused.
    registry_db = await test_db_factory.create_db(suffix="naapp_awid")
    async with awid_registry(registry_db.config.get_dsn()) as running:
        yield running
