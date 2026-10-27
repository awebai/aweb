"""Real PostgreSQL databases for the logs tests (pgdbm's test_db_factory), each
in its own schema."""

from typing import Any

import pytest
from aweb_naapp_testing.databases import SchemaDatabases

pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)
