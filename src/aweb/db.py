from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Request
from pgdbm import AsyncDatabaseManager, DatabaseConfig
from pgdbm.migrations import AsyncMigrationManager


class DatabaseInfra:
    """Shared pgdbm infrastructure for aweb.

    aweb supports the same dual-mode pattern as BeadHub:
    - Standalone service: it can create and own the shared pool
    - Embedded/library mode: it can reuse a pool owned by a parent app

    aweb data lives in the `aweb` schema (logical isolation).
    """

    def __init__(self) -> None:
        self._shared_pool: Optional[Any] = None
        self._managers: Dict[str, AsyncDatabaseManager] = {}
        self._initialized: bool = False
        self._init_lock: asyncio.Lock = asyncio.Lock()
        self._owns_pool: bool = True

    async def initialize(self, *, shared_pool: Optional[Any] = None) -> None:
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return  # type: ignore[unreachable]

            if shared_pool is None:
                database_url = _database_url_from_env()
                config = DatabaseConfig(connection_string=database_url)
                shared_pool = await AsyncDatabaseManager.create_shared_pool(config)
                self._owns_pool = True
            else:
                self._owns_pool = False

            self._shared_pool = shared_pool
            self._managers["aweb"] = AsyncDatabaseManager(pool=shared_pool, schema="aweb")

            base_dir = Path(__file__).resolve().parent
            migrations_root = base_dir / "migrations"

            for name, db in self._managers.items():
                await db.execute(f'CREATE SCHEMA IF NOT EXISTS "{db.schema}"')
                module_migrations = migrations_root / name
                if module_migrations.is_dir():
                    manager = AsyncMigrationManager(
                        db,
                        migrations_path=str(module_migrations),
                        module_name=f"aweb-{name}",
                    )
                    await manager.apply_pending_migrations()

            self._initialized = True

    async def close(self) -> None:
        if self._shared_pool is not None and self._owns_pool:
            await self._shared_pool.close()
        self._managers.clear()
        self._shared_pool = None
        self._initialized = False
        self._owns_pool = True

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def get_manager(self, name: str = "aweb") -> AsyncDatabaseManager:
        if not self._initialized:
            raise RuntimeError(
                "DatabaseInfra is not initialized. Call 'await db_infra.initialize()'."
            )
        manager = self._managers.get(name)
        if manager is None:
            available = ", ".join(sorted(self._managers.keys())) or "(none)"
            raise RuntimeError(
                f"Unknown database manager '{name}'. Available managers: {available}"
            )
        return manager


db_infra = DatabaseInfra()


def get_db_infra(request: Request) -> DatabaseInfra:
    """FastAPI dependency that returns aweb DatabaseInfra from app state."""
    return request.app.state.db


def _database_url_from_env() -> str:
    # Keep this local to avoid importing beadhub.config while the split is in progress.
    database_url = os.environ.get("AWEB_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL (or AWEB_DATABASE_URL) must be set to initialize aweb DB")
    return database_url
