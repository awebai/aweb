from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from asyncpg import Pool
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig

from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.settings import NaappSettings

_SHARED_MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_SHARED_MODULE = "aweb_naapp"

# A store is a shared table set the app's own migrations may build on, applied
# by its own ``apply_*_migrations`` under its own module name, such as
# aweb_naapp.idempotency's or aweb_naapp.roles'. An app's own migrations never
# create a table with a store's table name: stores apply first, so an app's
# CREATE TABLE IF NOT EXISTS of that name would silently get the store's table.
Store = Callable[[AsyncDatabaseManager], Awaitable[None]]
SchemaCheck = Callable[[AsyncDatabaseManager], Awaitable[None]]


@dataclass(frozen=True, kw_only=True)
class ApplyMigrations:
    """Prepare the schema with the service's configured migration authority."""


@dataclass(frozen=True, kw_only=True)
class VerifyPreparedSchema:
    """Check an operator-prepared schema without runtime DDL (Antares390577b1)."""

    check: SchemaCheck


SchemaPreparation = ApplyMigrations | VerifyPreparedSchema


async def require_separate_database(
    content: AsyncDatabaseManager, ledger: AsyncDatabaseManager, *, ledger_name: str
) -> None:
    """Refuse a ``ledger`` that is not a database of its own beside ``content``.

    Enforce the separate-database contract used by Logs' purge ledger. A
    same-transaction ledger in an excluded protected schema has a different
    restore contract and does not call this check."""
    if content is ledger:
        raise ValueError(f"the {ledger_name} must be outside the content restore database")
    content_id = await content.fetch_value("SELECT current_database()")
    ledger_id = await ledger.fetch_value("SELECT current_database()")
    if content_id == ledger_id:
        raise ValueError(f"the {ledger_name} must use a separate database")


async def prepare_naapp_schema(
    db: AsyncDatabaseManager,
    *,
    module_name: str,
    migrations_path: Path,
    stores: Sequence[Store] = (),
) -> None:
    """Prepare shared stores then the app schema using one connected operator DB."""

    async def apply(path: Path, module: str) -> None:
        await AsyncMigrationManager(
            db, migrations_path=str(path), module_name=module
        ).apply_pending_migrations()

    await apply(_SHARED_MIGRATIONS, _SHARED_MODULE)
    await apply_outbox_migrations(db)
    for store in stores:
        await store(db)
    await apply(migrations_path, module_name)


class NaappDatabase:
    """Owns the pgdbm manager for a standalone naapp deployment.

    ApplyMigrations prepares shared, outbox, declared stores and app migrations
    in that order. VerifyPreparedSchema connects without DDL and invokes the
    required checker before the manager is published to runtime consumers.
    Each policy owns and closes the connections it creates."""

    def __init__(
        self,
        settings: NaappSettings,
        *,
        module_name: str,
        migrations_path: Path,
        stores: Sequence[Store] = (),
        schema_preparation: SchemaPreparation,
    ) -> None:
        if not isinstance(schema_preparation, (ApplyMigrations, VerifyPreparedSchema)):
            raise ValueError("Choose ApplyMigrations or VerifyPreparedSchema for this database.")
        self.settings = settings
        self.module_name = module_name
        self.migrations_path = migrations_path
        self.stores = tuple(stores)
        self.schema_preparation = schema_preparation
        self._pool: Pool | None = None
        self._config = DatabaseConfig(
            connection_string=settings.database_url,
            schema=settings.db_schema,
            min_connections=settings.db_pool_min_connections,
            max_connections=settings.db_pool_max_connections,
            statement_cache_size=settings.db_statement_cache_size,
        )
        self.db = AsyncDatabaseManager(self._config)

    async def connect(self) -> None:
        if self._pool is not None:
            raise RuntimeError("The runtime database is already connected.")
        if isinstance(self.schema_preparation, VerifyPreparedSchema):
            # The public external-pool path pins search_path without the
            # manager's CREATE SCHEMA connection initializer.
            pool = await AsyncDatabaseManager.create_shared_pool(self._config)
            try:
                self.db = AsyncDatabaseManager(pool=pool, schema=self.settings.db_schema)
                await self.schema_preparation.check(self.db)
            except BaseException:
                await pool.close()
                raise
            self._pool = pool
            return
        try:
            await self.db.connect()
            await prepare_naapp_schema(
                self.db,
                module_name=self.module_name,
                migrations_path=self.migrations_path,
                stores=self.stores,
            )
        except BaseException:
            await self.db.disconnect()
            raise

    async def disconnect(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        else:
            await self.db.disconnect()
