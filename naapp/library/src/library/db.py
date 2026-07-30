from __future__ import annotations

from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig

from library.config import Settings


class LibraryDatabase:
    """Owns the pgdbm manager for standalone library deployments."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
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
            migrations_path=str(Path(__file__).parent / "migrations"),
            module_name="library",
        )
        await migrations.apply_pending_migrations()

    async def disconnect(self) -> None:
        await self.db.disconnect()
