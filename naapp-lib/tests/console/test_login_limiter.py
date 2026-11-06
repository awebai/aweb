"""The console login limiter on real PostgreSQL, through a real ASGI app.

The limiter guards the login routes, which need no prior authentication. A
test route stands in for login_options so the limiter is exercised exactly as
the login routes call it.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import APIRouter, FastAPI, Request
from pgdbm import AsyncDatabaseManager

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleRoute,
    LoginLimiter,
    apply_console_migrations,
)

ORIGIN = "https://console.example"
SCOPE = "app.owner"


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_console_limits")
    await apply_console_migrations(database)
    yield database


def _app(limiter: LoginLimiter) -> FastAPI:
    router = APIRouter(route_class=ConsoleRoute)

    @router.post("/login/options")
    async def options(request: Request) -> dict[str, bool]:
        await limiter.admit(request, SCOPE)
        return {"issued": True}

    app = FastAPI()
    app.include_router(router)
    return app


def _client(limiter: LoginLimiter, peer: str) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=_app(limiter), client=(peer, 40000))
    return httpx.AsyncClient(transport=transport, base_url=ORIGIN)


class Clock:
    """The limiter's clock, moved by the test."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _limiter(db: AsyncDatabaseManager, **changes) -> LoginLimiter:
    settings = dict(client_identity=ClientIdentity(), limit=3, window=timedelta(minutes=1))
    settings.update(changes)
    return LoginLimiter(db, **settings)


async def _codes(client: httpx.AsyncClient, n: int, headers: list[dict[str, str]] | None = None):
    headers = headers or [{}] * n
    return [(await client.post("/login/options", headers=h)).status_code for h in headers]


async def test_a_flooding_client_is_throttled_while_another_logs_in(
    db: AsyncDatabaseManager,
) -> None:
    limiter = _limiter(db)
    async with (
        _client(limiter, "203.0.113.7") as flooder,
        _client(limiter, "198.51.100.9") as owner,
    ):
        assert await _codes(flooder, 5) == [200, 200, 200, 429, 429]
        assert await _codes(owner, 1) == [200]
        throttled = await flooder.post("/login/options")
    assert throttled.status_code == 429
    assert int(throttled.headers["retry-after"]) > 0
    assert throttled.headers["cache-control"] == "no-store"


async def test_a_forwarded_header_is_ignored_unless_configured_as_trusted(
    db: AsyncDatabaseManager,
) -> None:
    spoofed = [{"X-Forwarded-For": f"192.0.2.{n}"} for n in range(5)]
    async with _client(_limiter(db), "203.0.113.7") as client:
        assert await _codes(client, 5, spoofed) == [200, 200, 200, 429, 429]


async def test_a_trusted_proxy_header_names_the_client(db: AsyncDatabaseManager) -> None:
    limiter = _limiter(db, client_identity=ClientIdentity(trusted_header="X-Forwarded-For"))
    flood = [{"X-Forwarded-For": "1.1.1.1, 203.0.113.7"}] * 4
    async with _client(limiter, "10.0.0.2") as proxy:
        assert await _codes(proxy, 4, flood) == [200, 200, 200, 429]
        # The proxy appends the address it saw last; anything before it is the client's claim.
        other = [{"X-Forwarded-For": "203.0.113.7, 198.51.100.9"}]
        assert await _codes(proxy, 1, other) == [200]
        # Entries a client prepends are its own claims and change nothing.
        claimed = [{"X-Forwarded-For": f"192.0.2.{n}, 198.51.100.9"} for n in range(3)]
        assert await _codes(proxy, 3, claimed) == [200, 200, 429]


async def test_a_missing_trusted_header_falls_back_to_the_peer(db: AsyncDatabaseManager) -> None:
    limiter = _limiter(db, client_identity=ClientIdentity(trusted_header="X-Forwarded-For"))
    async with _client(limiter, "203.0.113.7") as client:
        assert await _codes(client, 4) == [200, 200, 200, 429]


async def test_login_volume_is_metered_per_scope(db: AsyncDatabaseManager) -> None:
    limiter = _limiter(db)
    async with (
        _client(limiter, "203.0.113.7") as flooder,
        _client(limiter, "198.51.100.9") as owner,
    ):
        await _codes(flooder, 5)
        await _codes(owner, 1)
    volume = await limiter.volume(SCOPE, since=timedelta(minutes=5))
    assert (volume.requests, volume.throttled) == (6, 2)
    assert (await limiter.volume("app.other", since=timedelta(minutes=5))).requests == 0


async def test_limits_must_be_positive(db: AsyncDatabaseManager) -> None:
    for changes in ({"limit": 0}, {"window": timedelta(0)}):
        with pytest.raises(ValueError):
            _limiter(db, **changes)


@pytest.mark.parametrize("slow_database", [False, True], ids=["normal", "slow-write"])
async def test_volume_older_than_its_retention_is_pruned(
    db: AsyncDatabaseManager, slow_database: bool
) -> None:
    if slow_database:
        # Real PostgreSQL latency: the bucket is stamped at transaction start,
        # while pruning runs in another statement after the write commits.
        await db.execute(
            "CREATE FUNCTION {{tables.slow_volume_write}}() RETURNS trigger LANGUAGE plpgsql AS "
            "$$ BEGIN PERFORM pg_sleep(1.1); RETURN NEW; END $$"
        )
        await db.execute(
            "CREATE TRIGGER slow_volume_write AFTER INSERT ON {{tables.console_login_volume}} "
            "FOR EACH ROW EXECUTE FUNCTION {{tables.slow_volume_write}}()"
        )
    retention = timedelta(days=1)
    limiter = _limiter(db, window=timedelta(seconds=1), volume_retention=retention)
    async with _client(limiter, "203.0.113.7") as client:
        assert await _codes(client, 1) == [200]
        # Age the fixture explicitly. A one-second retention can legitimately
        # expire even the current bucket while a slow request is in progress.
        await db.execute(
            "UPDATE {{tables.console_login_volume}} SET window_start = NOW() - interval '2 days'"
        )
        assert await _codes(client, 1) == [200]
    rows = await db.fetch_value("SELECT count(*) FROM {{tables.console_login_volume}}")
    assert rows == 1
    assert (await limiter.volume(SCOPE, since=retention)).requests == 1


async def test_volume_is_kept_for_thirty_days_by_default(db: AsyncDatabaseManager) -> None:
    async with _client(_limiter(db), "203.0.113.7") as client:
        await _codes(client, 1)
    await db.execute(
        "UPDATE {{tables.console_login_volume}} SET window_start = NOW() - interval '29 days'"
    )
    async with _client(_limiter(db), "198.51.100.9") as client:
        await _codes(client, 1)
    assert (await limiter_volume(db, timedelta(days=30))).requests == 2
    await db.execute(
        "UPDATE {{tables.console_login_volume}} SET window_start = NOW() - interval '31 days'"
        " WHERE window_start < NOW() - interval '1 day'"
    )
    async with _client(_limiter(db), "192.0.2.1") as client:
        await _codes(client, 1)
    assert (await limiter_volume(db, timedelta(days=30))).requests == 2


async def limiter_volume(db: AsyncDatabaseManager, since: timedelta):
    return await _limiter(db).volume(SCOPE, since=since)


async def test_volume_retention_must_be_positive(db: AsyncDatabaseManager) -> None:
    with pytest.raises(ValueError):
        _limiter(db, volume_retention=timedelta(0))


async def test_volume_cannot_be_read_past_its_retention(db: AsyncDatabaseManager) -> None:
    limiter = _limiter(db, volume_retention=timedelta(days=7))
    assert (await limiter.volume(SCOPE, since=timedelta(days=7))).requests == 0
    with pytest.raises(ValueError):
        await limiter.volume(SCOPE, since=timedelta(days=7, seconds=1))


# A login never waits on another transaction's lock to prune: a prune that skips
# locked rows, outside the login's own writes, cannot join a deadlock cycle.


async def _held(db: AsyncDatabaseManager, statement: str):
    """A transaction on another connection holding a lock on the rows `statement` selects."""
    tx_context = db.transaction()
    tx = await tx_context.__aenter__()
    await tx.execute(statement)
    return tx_context


async def test_a_login_does_not_wait_on_a_locked_old_volume_bucket(
    db: AsyncDatabaseManager,
) -> None:
    limiter = _limiter(db, volume_retention=timedelta(days=1))
    async with _client(limiter, "203.0.113.7") as client:
        await _codes(client, 1)
    await db.execute(
        "UPDATE {{tables.console_login_volume}} SET window_start = NOW() - interval '2 days'"
    )
    held = await _held(db, "SELECT * FROM {{tables.console_login_volume}} FOR UPDATE")
    try:
        async with _client(limiter, "198.51.100.9") as client:
            assert await asyncio.wait_for(_codes(client, 1), timeout=5) == [200]
    finally:
        await held.__aexit__(None, None, None)


async def _refuse_deletes(db: AsyncDatabaseManager, table: str) -> None:
    """Make every delete from `table` raise, as a lost connection or a lock error would."""
    await db.execute(
        "CREATE FUNCTION {{tables.refuse_delete}}() RETURNS trigger LANGUAGE plpgsql AS "
        "$$ BEGIN RAISE EXCEPTION 'prune refused'; END $$"
    )
    await db.execute(
        f"CREATE TRIGGER refuse_delete BEFORE DELETE ON {{{{tables.{table}}}}} "
        "FOR EACH ROW EXECUTE FUNCTION {{tables.refuse_delete}}()"
    )


# The per-client limit is the shared token bucket (aweb_naapp.ratelimit).


async def test_a_throttled_client_is_admitted_again_once_its_bucket_refills(
    db: AsyncDatabaseManager,
) -> None:
    clock = Clock()
    limiter = _limiter(db, limit=1, window=timedelta(minutes=1), clock=clock)
    async with _client(limiter, "203.0.113.7") as client:
        assert await _codes(client, 2) == [200, 429]
        clock.advance(timedelta(minutes=1))
        assert await _codes(client, 2) == [200, 429]


async def test_a_bucket_refills_continuously(db: AsyncDatabaseManager) -> None:
    clock = Clock()
    limiter = _limiter(db, limit=2, window=timedelta(minutes=1), clock=clock)
    async with _client(limiter, "203.0.113.7") as client:
        assert await _codes(client, 3) == [200, 200, 429]
        clock.advance(timedelta(seconds=29))
        throttled = await client.post("/login/options")
        clock.advance(timedelta(seconds=1))
        assert await _codes(client, 2) == [200, 429]
    assert throttled.status_code == 429
    assert throttled.headers["retry-after"] == "1"


async def _buckets(db: AsyncDatabaseManager) -> int:
    return int(await db.fetch_value("SELECT count(*) FROM {{tables.rate_buckets}}"))


async def test_full_buckets_are_swept_after_a_login(db: AsyncDatabaseManager) -> None:
    clock = Clock()
    limiter = _limiter(db, limit=5, window=timedelta(minutes=1), clock=clock)
    for n in range(4):
        async with _client(limiter, f"203.0.113.{n}") as client:
            await _codes(client, 1)
    assert await _buckets(db) == 4
    clock.advance(timedelta(minutes=1))
    async with _client(limiter, "198.51.100.9") as client:
        await _codes(client, 1)
    assert await _buckets(db) == 1


async def test_a_login_does_not_wait_on_a_locked_full_bucket(db: AsyncDatabaseManager) -> None:
    clock = Clock()
    limiter = _limiter(db, limit=5, window=timedelta(minutes=1), clock=clock)
    async with _client(limiter, "203.0.113.7") as client:
        await _codes(client, 1)
    clock.advance(timedelta(minutes=1))
    held = await _held(db, "SELECT * FROM {{tables.rate_buckets}} FOR UPDATE")
    try:
        async with _client(limiter, "198.51.100.9") as client:
            assert await asyncio.wait_for(_codes(client, 1), timeout=5) == [200]
    finally:
        await held.__aexit__(None, None, None)
    assert await _buckets(db) == 2


async def test_a_failing_sweep_does_not_fail_the_login(
    db: AsyncDatabaseManager, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    limiter = _limiter(db, limit=5, window=timedelta(minutes=1), clock=clock)
    async with _client(limiter, "203.0.113.7") as client:
        await _codes(client, 1)
    clock.advance(timedelta(minutes=1))
    await _refuse_deletes(db, "rate_buckets")
    with caplog.at_level("WARNING", logger="aweb_naapp.console"):
        async with _client(limiter, "198.51.100.9") as client:
            assert await _codes(client, 1) == [200]
    [record] = [r for r in caplog.records if r.name == "aweb_naapp.console"]
    assert "rate_buckets" in record.getMessage()
    assert "203.0.113.7" not in record.getMessage()


async def test_the_fixed_window_table_is_gone(db: AsyncDatabaseManager) -> None:
    present = await db.fetch_value(
        "SELECT to_regclass('{{tables.console_login_attempts}}') IS NOT NULL"
    )
    assert present is False


async def test_the_window_is_whole_seconds(db: AsyncDatabaseManager) -> None:
    with pytest.raises(ValueError):
        _limiter(db, window=timedelta(milliseconds=1500))
