from __future__ import annotations

from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig

from aweb_naapp.runtime.settings import NaappSettings


class NaappDatabase:
    """Owns the pgdbm manager for a standalone naapp deployment and applies the
    app's migrations, tracked under its module name, when it connects."""

    def __init__(self, settings: NaappSettings, *, module_name: str, migrations_path: Path) -> None:
        self.settings = settings
        self.module_name = module_name
        self.migrations_path = migrations_path
        self.db = AsyncDatabaseManager(
            DatabaseConfig(
                connection_string=settings.database_url,
                schema=None,
                min_connections=settings.db_pool_min_connections,
                max_connections=settings.db_pool_max_connections,
                statement_cache_size=settings.db_statement_cache_size,
            )
        )

    async def connect(self) -> None:
        await self.db.connect()
        migrations = AsyncMigrationManager(
            self.db,
            migrations_path=str(self.migrations_path),
            module_name=self.module_name,
        )
        await migrations.apply_pending_migrations()

    async def disconnect(self) -> None:
        await self.db.disconnect()
