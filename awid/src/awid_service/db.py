from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from pgdbm import AsyncDatabaseManager
from pgdbm.migrations import AsyncMigrationManager

from aweb.db_config import build_database_config

from .config import get_settings


class AwidDatabaseInfra:
    """Thin pgdbm wrapper that exposes the manager contract expected by `aweb` routes."""

    def __init__(self, *, schema: str = "awid") -> None:
        self.schema = schema
        self._shared_pool: Optional[Any] = None
        self._manager: Optional[AsyncDatabaseManager] = None
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._owns_pool = True

    async def initialize(
        self,
        *,
        shared_pool: Optional[Any] = None,
        run_migrations: bool = True,
    ) -> None:
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            if shared_pool is None:
                settings = get_settings()
                config = build_database_config(connection_string=settings.database_url)
                shared_pool = await AsyncDatabaseManager.create_shared_pool(config)
                self._owns_pool = True
            else:
                self._owns_pool = False

            self._shared_pool = shared_pool
            self._manager = AsyncDatabaseManager(pool=shared_pool, schema=self.schema)

            quoted_schema = self.schema.replace('"', '""')
            await self._manager.execute(f'CREATE SCHEMA IF NOT EXISTS "{quoted_schema}"')

            if run_migrations:
                import aweb

                aweb_path = Path(aweb.__file__).resolve().parent
                migrations = AsyncMigrationManager(
                    self._manager,
                    migrations_path=str(aweb_path / "migrations" / "aweb"),
                    module_name="awid-registry",
                    migrations_table="schema_migrations",
                )
                await migrations.apply_pending_migrations()

            self._initialized = True

    async def close(self) -> None:
        if self._shared_pool is not None and self._owns_pool:
            await self._shared_pool.close()

        self._shared_pool = None
        self._manager = None
        self._initialized = False
        self._owns_pool = True

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def get_manager(self, name: str = "aweb") -> AsyncDatabaseManager:
        if not self._initialized or self._manager is None:
            raise RuntimeError("AwidDatabaseInfra is not initialized")
        # The imported aweb routes and helpers are not consistent about the manager
        # name they request. This wrapper owns only one schema-bound manager, so
        # any requested name must resolve to that same manager.
        return self._manager
