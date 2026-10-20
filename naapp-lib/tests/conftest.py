"""Real PostgreSQL databases for the runtime tests (pgdbm's test_db_factory)."""

from typing import Any

import pytest
from pgdbm import AsyncDatabaseManager

pytest_plugins = ("pgdbm.fixtures.conftest",)

# A naapp runs in its own schema: the production role's search_path is
# pg_catalog, so an unqualified table resolves to no user schema at all.
TEST_SCHEMA = "naapp_test"


class _SchemaDatabases:
    """pgdbm's test database factory, giving every database a schema unless the test names one."""

    def __init__(self, factory: Any) -> None:
        self._factory = factory

    async def create_db(
        self, suffix: str | None = None, schema: str | None = None, **kwargs: Any
    ) -> AsyncDatabaseManager:
        return await self._factory.create_db(suffix, schema or TEST_SCHEMA, **kwargs)


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> _SchemaDatabases:
    return _SchemaDatabases(test_db_factory)
