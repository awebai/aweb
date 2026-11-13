"""Real PostgreSQL databases for the logs tests (pgdbm's test_db_factory), each
in its own schema."""

from typing import Any

import pytest
from aweb_naapp_testing.databases import SchemaDatabases

pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)


@pytest.fixture
async def purges(test_db_factory: SchemaDatabases, db: Any) -> Any:
    """The purge ledger beside the test module's ``db``."""
    from .fixtures import purge_ledger

    return await purge_ledger(test_db_factory, db)


@pytest.fixture
async def purge_ledger_database(test_db_factory: SchemaDatabases) -> Any:
    """An empty database of its own for a Logs deployment's purge ledger."""
    return await test_db_factory.create_db(suffix="logs_purge_ledger")
