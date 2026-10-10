from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from pgdbm import AsyncDatabaseManager, DatabaseConfig
from pgdbm.migrations import AsyncMigrationManager

from awid.db_config import build_database_config

from .config import get_settings

# The pgdbm protections that travel as startup parameters besides the search_path
# pin, which pgdbm verifies itself.
REQUIRED_SESSION_SETTINGS = (
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
    "jit",
)


class DatabaseSessionSettingsError(RuntimeError):
    """The database connection does not carry the session settings awid requires."""


def database_config_from_settings(settings: Any) -> DatabaseConfig:
    require = bool(getattr(settings, "database_require_session_settings", False))
    return build_database_config(
        connection_string=settings.database_url,
        statement_cache_size=getattr(settings, "database_statement_cache_size", None),
        uses_transaction_pooler=bool(getattr(settings, "database_uses_transaction_pooler", False)),
        pooler_max_connections=int(getattr(settings, "database_pooler_max_connections", 10)),
        shared_pool_search_path="pg_catalog" if require else None,
    )


async def verify_session_settings(pool: Any, config: DatabaseConfig) -> None:
    """Fail closed unless a pooled connection carries the timeouts awid requests.

    pgdbm sends them as startup parameters, which a transaction pooler may drop
    without error; role or database defaults survive the pooler.
    """
    requested = config.get_server_settings()
    names = [name for name in REQUIRED_SESSION_SETTINGS if name in requested]
    async with pool.acquire() as conn:
        role = await conn.fetchval("SELECT current_user")
        rows = await conn.fetch(
            "SELECT name, setting FROM pg_catalog.pg_settings WHERE name = ANY($1::text[])",
            names,
        )
    effective = {row["name"]: row["setting"] for row in rows}
    missing = [name for name in names if effective.get(name) != requested[name]]
    if not missing:
        return
    lines = [f"  {name}: requested {requested[name]!r}, connection has {effective.get(name)!r}" for name in missing]
    fixes = [f"  ALTER ROLE \"{role}\" SET {name} = '{requested[name]}';" for name in missing]
    raise DatabaseSessionSettingsError(
        "Database session settings were not applied; a connection pooler probably dropped "
        "the startup parameters:\n"
        + "\n".join(lines)
        + "\nSet them as role defaults, which every new server connection applies:\n"
        + "\n".join(fixes)
        + "\nThen refresh the pooler's server connections and confirm with "
        "SELECT name, setting, source FROM pg_settings."
    )


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
                config = database_config_from_settings(settings)
                shared_pool = await AsyncDatabaseManager.create_shared_pool(config)
                if getattr(settings, "database_require_session_settings", False):
                    try:
                        await verify_session_settings(shared_pool, config)
                    except BaseException:
                        await shared_pool.close()
                        raise
                self._owns_pool = True
            else:
                self._owns_pool = False

            self._shared_pool = shared_pool
            self._manager = AsyncDatabaseManager(pool=shared_pool, schema=self.schema)

            quoted_schema = self.schema.replace('"', '""')
            await self._manager.execute(f'CREATE SCHEMA IF NOT EXISTS "{quoted_schema}"')

            if run_migrations:
                import awid_service

                awid_path = Path(awid_service.__file__).resolve().parent
                migrations = AsyncMigrationManager(
                    self._manager,
                    migrations_path=str(awid_path / "migrations"),
                    module_name="awid-service",
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
