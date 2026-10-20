from __future__ import annotations

from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig

from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.settings import NaappSettings

_SHARED_MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_SHARED_MODULE = "aweb_naapp"


class NaappDatabase:
    """Owns the pgdbm manager for a standalone naapp deployment.

    On connect it applies the shared naapp migrations (module ``aweb_naapp``)
    and the outbox's, then the app's own, tracked under the app's module name,
    so an app's migrations can rely on the shared tables."""

    def __init__(self, settings: NaappSettings, *, module_name: str, migrations_path: Path) -> None:
        self.settings = settings
        self.module_name = module_name
        self.migrations_path = migrations_path
        self.db = AsyncDatabaseManager(
            DatabaseConfig(
                connection_string=settings.database_url,
                schema=settings.db_schema,
                min_connections=settings.db_pool_min_connections,
                max_connections=settings.db_pool_max_connections,
                statement_cache_size=settings.db_statement_cache_size,
            )
        )

    async def connect(self) -> None:
        await self.db.connect()
        await self._refuse_tables_in_another_schema()
        await self._apply(_SHARED_MIGRATIONS, _SHARED_MODULE)
        await apply_outbox_migrations(self.db)
        await self._apply(self.migrations_path, self.module_name)

    async def _apply(self, migrations_path: Path, module_name: str) -> None:
        migrations = AsyncMigrationManager(
            self.db, migrations_path=str(migrations_path), module_name=module_name
        )
        await migrations.apply_pending_migrations()

    async def _refuse_tables_in_another_schema(self) -> None:
        """Refuse to start when this app's migrations are recorded only in
        another schema, so a changed db_schema never creates a second, empty
        set of the app's tables."""
        schemas = await self.db.fetch_all(
            "SELECT table_schema FROM information_schema.tables"
            " WHERE table_name = 'schema_migrations' ORDER BY table_schema"
        )
        recorded = []
        for row in schemas:
            schema = row["table_schema"]
            quoted = '"' + schema.replace('"', '""') + '"'
            if await self.db.fetch_value(
                f"SELECT EXISTS (SELECT 1 FROM {quoted}.schema_migrations WHERE module_name = $1)",
                self.module_name,
            ):
                recorded.append(schema)
        configured = self.settings.db_schema
        if recorded and configured not in recorded:
            raise RuntimeError(
                f"the {self.module_name} tables are in schema {', '.join(recorded)}, "
                f"not the configured db_schema {configured}; refusing to create them again"
            )

    async def disconnect(self) -> None:
        await self.db.disconnect()
