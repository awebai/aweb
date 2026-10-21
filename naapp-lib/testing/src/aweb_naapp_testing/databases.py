"""Test databases that give each naapp test its own schema.

A naapp runs in its own schema: the candidate gate's role carries production's
search_path=pg_catalog, where an unqualified table resolves to no user schema
at all. With a schema configured, pgdbm pins the search_path to it on every
connection.
"""

from __future__ import annotations

from typing import Any

from pgdbm import AsyncDatabaseManager

TEST_SCHEMA = "naapp_test"


class SchemaDatabases:
    """pgdbm's test database factory, giving every database a schema unless the test names one."""

    def __init__(self, factory: Any) -> None:
        self._factory = factory

    async def create_db(
        self, suffix: str | None = None, schema: str | None = None, **kwargs: Any
    ) -> AsyncDatabaseManager:
        return await self._factory.create_db(suffix, schema or TEST_SCHEMA, **kwargs)
