"""Real PostgreSQL databases (pgdbm's test_db_factory), and real AWID routes
on one of them (aweb_naapp_testing) for the tests that verify team acts."""

from collections.abc import AsyncIterator

import pytest_asyncio
from aweb_naapp_testing import Registry, awid_registry

pytest_plugins = ("pgdbm.fixtures.conftest",)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="naapp_awid")
    async with awid_registry(registry_db.config.get_dsn()) as running:
        yield running
