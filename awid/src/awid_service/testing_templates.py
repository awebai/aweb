"""Worker-local PostgreSQL templates for ordinary tests with migrated schemas."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from pgdbm import AsyncDatabaseManager
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig

from awid.db_config import build_database_config

from .testing import require_selected_test_database, selected_test_database_config

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable

    from asyncpg import Pool

AWID_MIGRATION_DIRECTORY = Path(__file__).resolve().with_name("migrations")


def _migration_digest(modules: Iterable[tuple[str, Path]]) -> str:
    inventory = []
    for name, directory in modules:
        paths = sorted(directory.glob("*.sql"))
        if not paths:
            raise FileNotFoundError(f"No migration files for {name} in {directory}")
        inventory.append(
            (
                name,
                [
                    (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
                    for path in paths
                ],
            )
        )
    return hashlib.sha256(json.dumps(inventory).encode()).hexdigest()[:28]


@asynccontextmanager
async def _pool(database: AsyncTestDatabase):
    config = build_database_config(
        connection_string=database.get_test_db_config().get_dsn(),
        min_connections=2,
        max_connections=5,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    try:
        yield pool
    finally:
        await pool.close()


@dataclass(frozen=True)
class MigratedTestDatabase:
    name: str
    config: DatabaseTestConfig = field(repr=False)

    @asynccontextmanager
    async def clone(self):
        require_selected_test_database(self.config)
        database = AsyncTestDatabase(
            self.config.model_copy(update={"test_db_template": self.name})
        )
        try:
            await database.create_test_database(suffix="clone")
            async with _pool(database) as pool:
                yield pool
        finally:
            await database.drop_test_database()


@asynccontextmanager
async def migrated_test_database(
    shape: str,
    modules: Iterable[tuple[str, Path]],
    migrate: Callable[[Pool], Awaitable[None]],
):
    """Build once for the requesting worker and expose only disconnected templates."""
    config = selected_test_database_config()
    worker = os.environ.get("PYTEST_XDIST_WORKER", "serial")
    digest = _migration_digest(modules)
    suffix = f"{shape}_{worker}_{digest}"
    # pgdbm 0.5.0 inserts an eight-hex token and an underscore before the suffix.
    name_bytes = (
        len(config.test_db_prefix.encode("utf-8")) + 9 + len(suffix.encode("utf-8"))
    )
    if name_bytes > 63:
        raise ValueError(
            f"Database template name is {name_bytes} bytes; PostgreSQL allows 63"
        )

    database = AsyncTestDatabase(config)
    try:
        name = await database.create_test_database(suffix=suffix)
        async with _pool(database) as pool:
            await migrate(pool)
        yield MigratedTestDatabase(name, config)
    finally:
        await database.drop_test_database()
