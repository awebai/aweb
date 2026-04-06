from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from fastapi import Request
from pgdbm import AsyncDatabaseManager
from pgdbm.migrations import AsyncMigrationManager

from .config import get_settings
from .db_config import build_database_config

class DatabaseInfra:
    """
    Shared pgdbm infrastructure for the aweb server.

    Creates a single shared pool and a single database manager
    for the unified aweb schema.
    """

    def __init__(self) -> None:
        self._shared_pool: Optional[Any] = None
        self._manager: Optional[AsyncDatabaseManager] = None
        self._initialized: bool = False
        self._init_lock: asyncio.Lock = asyncio.Lock()
        self._owns_pool: bool = True

    async def initialize(
        self,
        *,
        shared_pool: Optional[Any] = None,
        run_migrations: bool = True,
    ) -> None:
        if self._initialized:
            return

        async with self._init_lock:
            # Double-check after acquiring lock (another coroutine may have initialized)
            if self._initialized:
                return  # type: ignore[unreachable]  # Valid double-checked locking

            if shared_pool is None:
                settings = get_settings()
                config = build_database_config(
                    connection_string=settings.database_url,
                    uses_transaction_pooler=settings.database_uses_transaction_pooler,
                    statement_cache_size=settings.database_statement_cache_size,
                )
                shared_pool = await AsyncDatabaseManager.create_shared_pool(config)
                self._owns_pool = True
            else:
                # Host application owns lifecycle of the pool.
                self._owns_pool = False

            self._shared_pool = shared_pool

            self._manager = AsyncDatabaseManager(
                pool=shared_pool,
                schema="aweb",
            )

            await self._manager.execute('CREATE SCHEMA IF NOT EXISTS "aweb"')

            if run_migrations:
                base_dir = Path(__file__).resolve().parent
                migrations_path = base_dir / "migrations" / "aweb"
                if migrations_path.is_dir():
                    mgr = AsyncMigrationManager(
                        self._manager,
                        migrations_path=str(migrations_path),
                        module_name="aweb-aweb",
                    )
                    await mgr.apply_pending_migrations()

            self._initialized = True

    async def close(self) -> None:
        if self._shared_pool is not None and self._owns_pool:
            await self._shared_pool.close()

        self._manager = None
        self._shared_pool = None
        self._initialized = False
        self._owns_pool = True

    @property
    def is_initialized(self) -> bool:
        """Check if the database infrastructure is initialized."""
        return self._initialized

    def get_manager(self, name: str = "aweb") -> AsyncDatabaseManager:
        if not self._initialized:
            raise RuntimeError(
                "DatabaseInfra is not initialized. Call 'await db_infra.initialize()' first."
            )
        assert self._manager is not None
        return self._manager


db_infra = DatabaseInfra()


def get_db_infra(request: Request) -> DatabaseInfra:
    """FastAPI dependency that returns the DatabaseInfra from app state.

    Works in both standalone and library modes since both set app.state.db.
    """
    return request.app.state.db
