"""Real PostgreSQL databases for the tests (pgdbm's test_db_factory), and real
AWID routes on one of them."""

from collections.abc import AsyncIterator

import pytest_asyncio
from awid_service.testing import Registry, running_registry

pytest_plugins = ("pgdbm.fixtures.conftest",)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="secrets_awid")
    async with running_registry(registry_db.config.get_dsn()) as running:
        yield running
