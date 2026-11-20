"""Test databases that give each naapp test its own schema, and real
backups and restores of them.

A naapp runs in its own schema: the candidate gate's role carries production's
search_path=pg_catalog, where an unqualified table resolves to no user schema
at all. With a schema configured, pgdbm pins the search_path to it on every
connection.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
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


def _postgres_env(db: AsyncDatabaseManager, database: str) -> dict[str, str]:
    config = db.config
    return {
        **os.environ,
        "PGHOST": config.host,
        "PGPORT": str(config.port),
        "PGUSER": config.user,
        "PGPASSWORD": config.password,
        "PGDATABASE": database,
    }


async def back_up(db: AsyncDatabaseManager, path: Path) -> Path:
    """Write ``db``'s test database to ``path`` as a real ``pg_dump`` backup."""
    database = await db.fetch_value("SELECT current_database()")
    assert database.startswith("test_")
    # Inherit stderr so pytest shows tool failures (including version mismatches).
    await asyncio.to_thread(
        subprocess.run,
        ["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(path)],
        env=_postgres_env(db, database),
        check=True,
    )
    return path


async def restore(db: AsyncDatabaseManager, backup: Path) -> None:
    """Replace ``db``'s test database with ``backup`` by a real ``pg_restore``,
    reconnecting ``db`` to the restored database."""
    database = await db.fetch_value("SELECT current_database()")
    assert database.startswith("test_")
    await db.disconnect()
    await asyncio.to_thread(
        subprocess.run,
        [
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-acl",
            "--dbname",
            database,
            str(backup),
        ],
        env=_postgres_env(db, database),
        check=True,
    )
    await db.connect()
