"""Real PostgreSQL databases for Folio's tests (pgdbm's test_db_factory)."""

from typing import Any

import pytest
from aweb_naapp_testing.databases import SchemaDatabases


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)
