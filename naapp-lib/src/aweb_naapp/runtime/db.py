from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig

from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.settings import NaappSettings

_SHARED_MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_SHARED_MODULE = "aweb_naapp"

# A store is a shared table set the app's own migrations may build on, applied
# by its own ``apply_*_migrations`` under its own module name, such as
# aweb_naapp.idempotency's or aweb_naapp.roles'.
Store = Callable[[AsyncDatabaseManager], Awaitable[None]]


class NaappDatabase:
    """Owns the pgdbm manager for a standalone naapp deployment.

    On connect it applies the shared naapp migrations (module ``aweb_naapp``)
    and the outbox's, then each store the app names, in order, then the app's
    own, tracked under the app's module name, so an app's migrations can rely
    on the shared tables and on its stores'. An app names exactly the stores
    it uses; there are none by default."""

    def __init__(
        self,
        settings: NaappSettings,
        *,
        module_name: str,
        migrations_path: Path,
        stores: Sequence[Store] = (),
    ) -> None:
        self.settings = settings
        self.module_name = module_name
        self.migrations_path = migrations_path
        self.stores = tuple(stores)
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
        await self._apply(_SHARED_MIGRATIONS, _SHARED_MODULE)
        await apply_outbox_migrations(self.db)
        for store in self.stores:
            await store(self.db)
        await self._apply(self.migrations_path, self.module_name)

    async def _apply(self, migrations_path: Path, module_name: str) -> None:
        migrations = AsyncMigrationManager(
            self.db, migrations_path=str(migrations_path), module_name=module_name
        )
        await migrations.apply_pending_migrations()

    async def disconnect(self) -> None:
        await self.db.disconnect()
