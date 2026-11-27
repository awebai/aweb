"""Real PostgreSQL databases (pgdbm's test_db_factory), each in its own schema,
and real AWID routes on one of them (awid_service.testing) for the tests that
verify team acts."""

import os
import runpy
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

# xdist sets its worker identity before conftest imports. Bind this worker to
# its own Postgres and Redis (the server suite's plan) before pgdbm's plugin
# and test modules capture an endpoint.
runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "server/tests/worker_services.py")
)["configure_worker_environment"](os.environ)

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from aweb_naapp_testing.databases import SchemaDatabases  # noqa: E402
from awid_service.testing import Registry, running_registry  # noqa: E402

pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    # AWID connects to this database by its DSN alone and keeps its tables in
    # its own explicit schema, so the test schema the factory adds goes unused.
    registry_db = await test_db_factory.create_db(suffix="naapp_awid")
    async with running_registry(registry_db.config.get_dsn()) as running:
        yield running
