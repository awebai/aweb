"""Run production with the operator/runtime privilege split, never an admin DSN."""

import secrets
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import quote, urlsplit
from uuid import uuid4

import pytest
from aweb_naapp.runtime.db import prepared_pool_config
from aweb_naapp_testing.databases import SchemaDatabases
from pgdbm import AsyncDatabaseManager

from aweb_secrets.erasure import initialize_erasure_store


@asynccontextmanager
async def _prepared_database(
    factory, *, suffix: str, runtime_pool_limit: int
) -> AsyncIterator["PreparedDatabase"]:
    content_schema = "public"
    operator = await factory.create_db(suffix=suffix, schema=content_schema)
    role = "secrets_runtime_" + uuid4().hex
    password = secrets.token_urlsafe(32)
    async with operator.transaction() as tx:
        await tx.execute("SELECT set_config('aweb_test.role_password',$1,true)", password)
        await tx.execute(
            "DO $$ BEGIN EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L',"
            f" '{role}',current_setting('aweb_test.role_password')); END $$"
        )
    try:
        await initialize_erasure_store(
            operator, application_role=role, max_backup_age=timedelta(days=7)
        )
        parsed = urlsplit(operator.config.get_dsn())
        runtime_dsn = parsed._replace(
            netloc=(
                f"{quote(role, safe='')}:{quote(password, safe='')}@"
                + parsed.netloc.rsplit("@", 1)[-1]
            )
        ).geturl()
        configured = prepared_pool_config(
            operator.config.model_copy(
                update={
                    "connection_string": runtime_dsn,
                    "min_connections": 1,
                    "max_connections": runtime_pool_limit,
                    "server_settings": None,
                }
            ),
            content_schema=content_schema,
        )
        pool = await AsyncDatabaseManager.create_shared_pool(configured)
        try:
            yield PreparedDatabase(
                runtime=AsyncDatabaseManager(pool=pool, schema=content_schema), operator=operator
            )
        finally:
            await pool.close()
    finally:
        await operator.execute(f'DROP OWNED BY "{role}"')
        await operator.execute(f'DROP ROLE "{role}"')


@dataclass(kw_only=True, repr=False)
class PreparedDatabase:
    runtime: AsyncDatabaseManager
    operator: AsyncDatabaseManager


def _database_name(db: AsyncDatabaseManager) -> str:
    if db.config is None:
        raise ValueError("Use a database prepared by this fixture's operator.")
    return urlsplit(db.config.get_dsn()).path


@dataclass(kw_only=True, repr=False)
class PreparedDatabaseFactory:
    factory: SchemaDatabases
    stack: AsyncExitStack
    runtime_pool_limit: int = 2
    databases: dict[str, PreparedDatabase] = field(default_factory=dict)

    async def create_db(self, *, suffix: str) -> AsyncDatabaseManager:
        prepared = await self.stack.enter_async_context(
            _prepared_database(
                self.factory, suffix=suffix, runtime_pool_limit=self.runtime_pool_limit
            )
        )
        self.databases[_database_name(prepared.runtime)] = prepared
        return prepared.runtime

    @asynccontextmanager
    async def unavailable_erasure_storage(self, db: AsyncDatabaseManager) -> AsyncIterator[None]:
        """Refuse actual ledger INSERTs in this owned DB, preserving the live trigger."""
        prepared = self.databases[_database_name(db)]
        await prepared.operator.execute(
            "ALTER TABLE secrets_erasure.erasures ADD CONSTRAINT test_storage_unavailable"
            " CHECK (false) NOT VALID"
        )
        try:
            yield
        finally:
            await prepared.operator.execute(
                "ALTER TABLE secrets_erasure.erasures DROP CONSTRAINT test_storage_unavailable"
            )


@pytest.fixture
async def prepared_service_databases(test_db_factory) -> AsyncIterator[PreparedDatabaseFactory]:
    async with AsyncExitStack() as stack:
        yield PreparedDatabaseFactory(factory=test_db_factory, stack=stack)
