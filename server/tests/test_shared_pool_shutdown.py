"""Exercise both service pool owners against a real Postgres database."""

import asyncio

import asyncpg
import pytest

from aweb.db import DatabaseInfra
from awid_service.db import AwidDatabaseInfra


@pytest.mark.parametrize("infra_type", [DatabaseInfra, AwidDatabaseInfra])
@pytest.mark.asyncio
async def test_owned_pool_close_terminates_a_connection_still_checked_out(
    infra_type, test_db_factory, monkeypatch
):
    database = await test_db_factory.create_db(suffix="pool_shutdown")
    dsn = database.config.get_dsn()
    monkeypatch.setenv("AWEB_DATABASE_URL", dsn)
    monkeypatch.setenv("AWID_DATABASE_URL", dsn)
    infra = infra_type()
    await infra.initialize(run_migrations=False)

    async with infra.get_manager().acquire() as connection:
        assert await connection.fetchval("SELECT 1") == 1
        loop = asyncio.get_running_loop()
        started = loop.time()
        # Keep the real connection checked out throughout close. This is an
        # independent test watchdog, longer than the service's grace period.
        async with asyncio.timeout(8):
            await infra.close()
        assert 3 <= loop.time() - started < 8
        with pytest.raises(asyncpg.InterfaceError, match="connection has been released"):
            await connection.fetchval("SELECT 1")

    assert not infra.is_initialized


@pytest.mark.parametrize("infra_type", [DatabaseInfra, AwidDatabaseInfra])
@pytest.mark.asyncio
async def test_close_leaves_host_owned_pool_usable(infra_type, shared_test_pool):
    infra = infra_type()
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=False)

    async with shared_test_pool.acquire() as connection:
        async with asyncio.timeout(3):
            await infra.close()
        assert await connection.fetchval("SELECT 1") == 1

    assert not infra.is_initialized
    assert await shared_test_pool.fetchval("SELECT 1") == 1
