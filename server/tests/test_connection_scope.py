"""One pool connection per request, lent to one borrower at a time.

A session setting written with set_config(..., false) survives to the next
statement only when both run on one checkout: the pool's release resets it.
These tests use that, backend pids and session advisory locks to observe
which statements shared a connection, against a real Postgres.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from httpx import ASGITransport, AsyncClient

from aweb.connection_scope import ConnectionScopeMiddleware, DatabaseManager, connection_scope

_LOCK_KEY = 815_004


@pytest.fixture
def managers(shared_test_pool):
    return (
        DatabaseManager(pool=shared_test_pool, schema="aweb"),
        DatabaseManager(pool=shared_test_pool, schema="public"),
    )


async def _mark(db) -> None:
    await db.execute("SELECT set_config('application_name', 'lent', false)")


async def _marked(db) -> bool:
    return await db.fetch_value("SELECT current_setting('application_name')") == "lent"


async def _holds_session_lock(db) -> bool:
    return bool(
        await db.fetch_value(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND pid = pg_backend_pid()",
            _LOCK_KEY,
        )
    )


@pytest.mark.asyncio
async def test_statements_in_a_scope_share_one_checkout_across_managers(managers):
    aweb_db, public_db = managers
    async with connection_scope():
        await _mark(aweb_db)
        assert await _marked(public_db)
        pids = {await aweb_db.fetch_value("SELECT pg_backend_pid()") for _ in range(3)}
        async with public_db.transaction() as tx:
            pids.add(await tx.fetch_value("SELECT pg_backend_pid()"))
    assert len(pids) == 1


@pytest.mark.asyncio
async def test_statements_outside_a_scope_each_take_a_fresh_checkout(managers):
    aweb_db, _ = managers
    await _mark(aweb_db)
    assert not await _marked(aweb_db)


@pytest.mark.asyncio
async def test_a_manager_call_inside_a_transaction_still_runs_outside_it(managers):
    aweb_db, public_db = managers
    async with connection_scope():
        async with aweb_db.transaction() as tx:
            await tx.execute("CREATE TEMP TABLE scope_probe (n int) ON COMMIT DROP")
            outer_pid = await tx.fetch_value("SELECT pg_backend_pid()")
            inner_pid = await public_db.fetch_value("SELECT pg_backend_pid()")
            inner_sees_temp = await public_db.fetch_value("SELECT to_regclass('pg_temp.scope_probe') IS NOT NULL")
    assert inner_pid != outer_pid
    assert inner_sees_temp is False


@pytest.mark.asyncio
async def test_concurrent_branches_in_a_scope_use_separate_connections(managers):
    aweb_db, public_db = managers
    async with connection_scope():
        pids = await asyncio.gather(
            aweb_db.fetch_value("SELECT pg_backend_pid() FROM pg_sleep(0.1)"),
            public_db.fetch_value("SELECT pg_backend_pid() FROM pg_sleep(0.1)"),
            aweb_db.fetch_value("SELECT pg_backend_pid() FROM pg_sleep(0.1)"),
        )
    assert len(set(pids)) == 3


@pytest.mark.asyncio
async def test_a_cancelled_statement_discards_the_lent_connection(managers):
    aweb_db, public_db = managers
    async with connection_scope():
        await aweb_db.execute("SELECT pg_advisory_lock($1)", _LOCK_KEY)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(aweb_db.fetch_value("SELECT pg_sleep(5)"), timeout=0.2)
        assert await public_db.fetch_value("SELECT 1") == 1
        assert not await _holds_session_lock(public_db)
        await _mark(public_db)
        assert not await _marked(public_db)
    assert await public_db.fetch_value("SELECT pg_try_advisory_lock($1)", _LOCK_KEY)
    await public_db.execute("SELECT pg_advisory_unlock_all()")


@pytest.mark.asyncio
async def test_a_transaction_that_raises_discards_the_lent_connection(managers):
    aweb_db, public_db = managers
    async with connection_scope():
        with pytest.raises(RuntimeError, match="handler failed"):
            async with aweb_db.transaction() as tx:
                await tx.execute("SELECT pg_advisory_lock($1)", _LOCK_KEY)
                raise RuntimeError("handler failed")
        assert not await _holds_session_lock(public_db)
        await _mark(public_db)
        assert not await _marked(public_db)


@pytest.mark.asyncio
async def test_a_task_outliving_its_scope_uses_the_pool(managers):
    aweb_db, _ = managers
    scope_closed = asyncio.Event()

    async def after_close():
        await scope_closed.wait()
        return await aweb_db.fetch_value("SELECT pg_backend_pid()")

    async with connection_scope():
        lent_pid = await aweb_db.fetch_value("SELECT pg_backend_pid()")
        task = asyncio.create_task(after_close())
    scope_closed.set()
    later_pid = await task
    assert isinstance(later_pid, int)
    await _mark(aweb_db)
    assert not await _marked(aweb_db), lent_pid


def _app(db) -> FastAPI:
    app = FastAPI()

    @app.get("/plain")
    async def plain():
        await _mark(db)
        return {"marked": await _marked(db)}

    @app.get("/stream")
    async def stream():
        await _mark(db)
        marked_before_start = await _marked(db)

        async def body():
            await _mark(db)
            yield f"{marked_before_start},{await _marked(db)}"

        return StreamingResponse(body(), media_type="text/plain")

    app.add_middleware(ConnectionScopeMiddleware)
    return app


@pytest.mark.asyncio
async def test_a_request_shares_one_checkout_until_its_response_starts(managers):
    aweb_db, _ = managers
    async with AsyncClient(transport=ASGITransport(app=_app(aweb_db)), base_url="http://test") as client:
        plain = await client.get("/plain")
        stream = await client.get("/stream")
    assert plain.json() == {"marked": True}
    assert stream.text == "True,False"


class _UnusedRedis:
    pass


@pytest.mark.asyncio
async def test_an_aweb_app_request_shares_one_checkout(shared_test_pool, monkeypatch):
    from aweb.api import create_app
    from aweb.db import DatabaseInfra

    async def _noop_mount(_app, _db_infra, _redis, _registry_client):
        return None

    monkeypatch.setattr("aweb.api._mount_mcp_app", _noop_mount)
    db_infra = DatabaseInfra()
    await db_infra.initialize(shared_pool=shared_test_pool)
    app = create_app(db_infra=db_infra, redis=_UnusedRedis())
    app.state.db = db_infra

    @app.get("/probe")
    async def probe():
        db = app.state.db.get_manager("aweb")
        await _mark(db)
        return {"marked": await _marked(db)}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/probe")
    assert response.json() == {"marked": True}


@pytest.mark.asyncio
async def test_a_mounted_app_with_its_own_scope_middleware_joins_the_outer_scope(managers):
    aweb_db, _ = managers
    outer = FastAPI()
    outer.mount("/inner", _app(aweb_db))
    outer.add_middleware(ConnectionScopeMiddleware)

    @outer.middleware("http")
    async def mark_before_inner(request, call_next):
        await _mark(aweb_db)
        return await call_next(request)

    async with AsyncClient(transport=ASGITransport(app=outer), base_url="http://test") as client:
        response = await client.get("/inner/plain")
    assert response.json() == {"marked": True}


@pytest.mark.asyncio
async def test_an_idle_scope_parks_its_connection_for_the_next_statement(managers):
    aweb_db, _ = managers
    async with connection_scope():
        await _mark(aweb_db)
        assert await _marked(aweb_db)
        await asyncio.sleep(0.1)
        assert not await _marked(aweb_db)


@pytest_asyncio.fixture
async def small_pool(test_db_factory):
    from awid.db_config import build_database_config
    from pgdbm import AsyncDatabaseManager

    db = await test_db_factory.create_db(suffix="scope_small_pool")
    config = build_database_config(connection_string=db.config.get_dsn(), min_connections=1, max_connections=3)
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_requests_waiting_on_the_network_do_not_starve_the_pool(small_pool):
    db = DatabaseManager(pool=small_pool, schema="public")
    stalled_upstream = FastAPI()

    @stalled_upstream.get("/slow")
    async def slow():
        await asyncio.sleep(2)
        return {"ok": True}

    upstream = AsyncClient(transport=ASGITransport(app=stalled_upstream), base_url="http://upstream")
    app = FastAPI()

    @app.get("/stalled")
    async def stalled():
        await db.fetch_value("SELECT 1")
        await upstream.get("/slow")
        return {"value": await db.fetch_value("SELECT 2")}

    @app.get("/db")
    async def db_only():
        return {"value": await db.fetch_value("SELECT 3")}

    app.add_middleware(ConnectionScopeMiddleware)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        stalled_requests = [asyncio.create_task(client.get("/stalled")) for _ in range(10)]
        await asyncio.sleep(0.3)
        started = asyncio.get_running_loop().time()
        db_only_response = await client.get("/db")
        db_only_seconds = asyncio.get_running_loop().time() - started
        stalled_responses = await asyncio.gather(*stalled_requests)
    await upstream.aclose()

    assert db_only_response.json() == {"value": 3}
    assert db_only_seconds < 1.0
    assert [r.json() for r in stalled_responses] == [{"value": 2}] * 10


@pytest.mark.asyncio
async def test_an_exhausted_pool_fails_a_request_with_a_retryable_503(small_pool, monkeypatch):
    import aweb.connection_scope as connection_scope_module

    monkeypatch.setattr(connection_scope_module, "ACQUIRE_TIMEOUT_SECONDS", 0.3)
    db = DatabaseManager(pool=small_pool, schema="public")
    app = FastAPI()

    @app.get("/db")
    async def db_only():
        return {"value": await db.fetch_value("SELECT 1")}

    app.add_middleware(ConnectionScopeMiddleware)
    held = [await small_pool.acquire() for _ in range(3)]
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            started = asyncio.get_running_loop().time()
            response = await client.get("/db")
            seconds = asyncio.get_running_loop().time() - started
    finally:
        for connection in held:
            await small_pool.release(connection)

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "database_unavailable", "retryable": True}}
    assert response.headers["retry-after"] == "1"
    assert seconds < 1.0
