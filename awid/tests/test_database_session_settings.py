"""awid's database session settings behind a transaction pooler (PgBouncer, as on Neon).

pgdbm requests search_path, statement_timeout, lock_timeout,
idle_in_transaction_session_timeout and jit as startup parameters. A
transaction pooler may drop them, leaving the service without its timeouts.
These tests run awid's real startup against a real PgBouncer in transaction
mode (AWID_TEST_POOLER_URL) and against direct PostgreSQL.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from awid_service.config import get_settings
from awid_service.db import AwidDatabaseInfra, DatabaseSessionSettingsError, database_config_from_settings

POOLER_URL = os.environ.get("AWID_TEST_POOLER_URL", "")
needs_pooler = pytest.mark.skipif(
    not POOLER_URL, reason="set AWID_TEST_POOLER_URL to a PgBouncer in transaction mode (make test-awid-pooler)"
)

SESSION_DEFAULTS = {
    "search_path": "pg_catalog",
    "statement_timeout": "60s",
    "lock_timeout": "5s",
    "idle_in_transaction_session_timeout": "60s",
    "jit": "off",
}


def _with_database(url: str, database: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{database}"))


async def _create_database(defaults: dict[str, str] | None) -> str:
    """Create a fresh database through the pooler, so its server connections are new."""
    name = f"awid_pooler_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(POOLER_URL, statement_cache_size=0)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        for key, value in (defaults or {}).items():
            await admin.execute(f"ALTER DATABASE \"{name}\" SET {key} = '{value}'")
    finally:
        await admin.close()
    return name


async def _drop_database(name: str) -> None:
    admin = await asyncpg.connect(POOLER_URL, statement_cache_size=0)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await admin.close()


def _configure(monkeypatch, url: str, *, pooler: bool, require: bool) -> None:
    monkeypatch.setenv("AWID_DATABASE_URL", url)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("AWID_DATABASE_USES_TRANSACTION_POOLER", "true" if pooler else "false")
    monkeypatch.setenv("AWID_DATABASE_REQUIRE_SESSION_SETTINGS", "true" if require else "false")


def test_defaults_keep_the_unpinned_cached_configuration(monkeypatch):
    monkeypatch.setenv("AWID_DATABASE_URL", "postgresql://awid@localhost/awid")
    for name in (
        "AWID_DATABASE_USES_TRANSACTION_POOLER",
        "AWID_DATABASE_REQUIRE_SESSION_SETTINGS",
        "AWID_DATABASE_STATEMENT_CACHE_SIZE",
        "AWID_DATABASE_POOLER_MAX_CONNECTIONS",
    ):
        monkeypatch.delenv(name, raising=False)
    config = database_config_from_settings(get_settings())
    assert config.shared_pool_search_path is None
    assert config.statement_cache_size == 1000


def test_pooler_mode_disables_the_statement_cache_and_bounds_the_pool(monkeypatch):
    monkeypatch.setenv("AWID_DATABASE_URL", "postgresql://awid@localhost/awid")
    monkeypatch.setenv("AWID_DATABASE_USES_TRANSACTION_POOLER", "true")
    monkeypatch.setenv("AWID_DATABASE_POOLER_MAX_CONNECTIONS", "12")
    monkeypatch.setenv("AWID_DATABASE_REQUIRE_SESSION_SETTINGS", "true")
    config = database_config_from_settings(get_settings())
    assert config.statement_cache_size == 0
    assert config.max_connections == 12
    assert config.shared_pool_search_path == "pg_catalog"


@pytest.mark.asyncio
async def test_required_settings_accept_direct_postgres(monkeypatch, test_db_factory):
    db = await test_db_factory.create_db(suffix="awid_session_direct")
    _configure(monkeypatch, db.config.get_dsn(), pooler=False, require=True)
    infra = AwidDatabaseInfra(schema="awid")
    await infra.initialize(run_migrations=True)
    try:
        manager = infra.get_manager()
        assert await manager.fetch_value("SELECT current_setting('lock_timeout')") == "5s"
    finally:
        await infra.close()


@needs_pooler
@pytest.mark.asyncio
async def test_required_settings_refuse_a_pooler_that_drops_them(monkeypatch):
    name = await _create_database(defaults=None)
    try:
        _configure(monkeypatch, _with_database(POOLER_URL, name), pooler=True, require=True)
        infra = AwidDatabaseInfra(schema="awid")
        with pytest.raises(DatabaseSessionSettingsError) as refused:
            await infra.initialize(run_migrations=False)
        message = str(refused.value)
        for setting in ("statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "jit"):
            assert setting in message
        assert "ALTER ROLE" in message
    finally:
        await _drop_database(name)


@needs_pooler
@pytest.mark.asyncio
async def test_required_settings_accept_server_side_defaults_behind_the_pooler(monkeypatch):
    name = await _create_database(defaults=SESSION_DEFAULTS)
    try:
        _configure(monkeypatch, _with_database(POOLER_URL, name), pooler=True, require=True)
        infra = AwidDatabaseInfra(schema="awid")
        await infra.initialize(run_migrations=True)
        try:
            manager = infra.get_manager()
            assert await manager.fetch_value("SELECT count(*) FROM {{tables.dns_namespaces}}") == 0
            assert await manager.fetch_value("SHOW search_path") == "pg_catalog"
        finally:
            await infra.close()
    finally:
        await _drop_database(name)


async def _hold_server_connections(url: str, count: int) -> None:
    """Open `count` concurrent transactions through the pooler, forcing that many server connections."""
    connections = [await asyncpg.connect(url, statement_cache_size=0) for _ in range(count)]
    try:
        transactions = [conn.transaction() for conn in connections]
        for transaction in transactions:
            await transaction.start()
        await asyncio.gather(*(conn.fetchval("SELECT pg_backend_pid()") for conn in connections))
        for transaction in transactions:
            await transaction.rollback()
    finally:
        for conn in connections:
            await conn.close()


@needs_pooler
@pytest.mark.asyncio
async def test_required_settings_refuse_a_mix_of_old_and_new_server_connections(monkeypatch):
    # Rollout state between ALTER ROLE and the pooler's refresh: some server
    # connections predate the defaults, some carry them. The ones carrying them
    # are used most recently, so a single sample would see only those.
    name = await _create_database(defaults=None)
    url = _with_database(POOLER_URL, name)
    try:
        await _hold_server_connections(url, 4)
        admin = await asyncpg.connect(POOLER_URL, statement_cache_size=0)
        try:
            for key, value in SESSION_DEFAULTS.items():
                await admin.execute(f"ALTER DATABASE \"{name}\" SET {key} = '{value}'")
        finally:
            await admin.close()
        await _hold_server_connections(url, 8)

        _configure(monkeypatch, url, pooler=True, require=True)
        monkeypatch.setenv("AWID_DATABASE_POOLER_MAX_CONNECTIONS", "10")
        infra = AwidDatabaseInfra(schema="awid")
        with pytest.raises(DatabaseSessionSettingsError) as refused:
            await infra.initialize(run_migrations=False)
        assert "server connections" in str(refused.value)
    finally:
        await _drop_database(name)


@needs_pooler
@pytest.mark.asyncio
async def test_pooler_mode_serves_concurrent_varied_queries(monkeypatch):
    name = await _create_database(defaults=SESSION_DEFAULTS)
    try:
        _configure(monkeypatch, _with_database(POOLER_URL, name), pooler=True, require=True)
        infra = AwidDatabaseInfra(schema="awid")
        await infra.initialize(run_migrations=False)
        try:
            manager = infra.get_manager()

            async def worker(index: int) -> None:
                for step in range(40):
                    assert await manager.fetch_value(f"SELECT $1::int + {step % 25}", index) == index + step % 25

            await asyncio.gather(*(worker(index) for index in range(30)))
        finally:
            await infra.close()
    finally:
        await _drop_database(name)
