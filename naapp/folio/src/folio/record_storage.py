"""Lifecycle of Folio's shared page store and independent erasure ledger."""

import asyncio
import logging

from aweb_naapp.page_store import PageStore, RetentionPolicy, StoreError, apply_page_store_migrations
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from folio.config import Settings
from folio.record_collections import validate_record

logger = logging.getLogger(__name__)


class RecordStorage:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Policy comes only from the operator. An absent policy permits shared
        # read/export/delete semantics, while the store refuses content writes.
        self.retention = (
            RetentionPolicy(**settings.page_retention_policy)
            if settings.page_retention_policy is not None else None
        )
        self._store: PageStore | None = None
        self._ledger: AsyncDatabaseManager | None = None
        self._stop = asyncio.Event()
        self._maintenance: asyncio.Task | None = None

    def require_store(self) -> PageStore:
        if self._store is None:
            raise StoreError("records_unavailable", 503)
        return self._store

    async def connect(self, db: AsyncDatabaseManager) -> None:
        """Runtime store hook: migrations and restore fences precede traffic."""
        if self.settings.page_deletion_database_url is None:
            return
        ledger = AsyncDatabaseManager(DatabaseConfig(
            connection_string=self.settings.page_deletion_database_url,
            schema=self.settings.db_schema,
            min_connections=self.settings.db_pool_min_connections,
            max_connections=self.settings.db_pool_max_connections,
            statement_cache_size=self.settings.db_statement_cache_size,
        ))
        self._ledger = ledger
        try:
            await ledger.connect()
            await apply_page_store_migrations(db, ledger)
            store = PageStore(db, ledger=ledger, retention=self.retention,
                              record_validator=validate_record)
            await store.start()
            if self.retention is not None:
                await store.enforce_retention()
            self._store = store
            self._stop = asyncio.Event()
            if self.retention is not None:
                self._maintenance = asyncio.create_task(self._maintain())
        except BaseException:
            await self.disconnect()
            raise

    async def _maintain(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=3600)
            except TimeoutError:
                try:
                    await self.require_store().enforce_retention()
                except Exception:
                    logger.exception("Folio record retention maintenance failed")

    async def disconnect(self) -> None:
        self._stop.set()
        if self._maintenance is not None:
            await self._maintenance
            self._maintenance = None
        self._store = None
        if self._ledger is not None:
            ledger, self._ledger = self._ledger, None
            await ledger.disconnect()
