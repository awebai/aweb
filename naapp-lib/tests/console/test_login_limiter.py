"""The console login limiter on real PostgreSQL, through a real ASGI app.

The limiter guards the login routes, which need no prior authentication. A
test route stands in for login_options so the limiter is exercised exactly as
the login routes call it.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta

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


async def test_the_window_resets(db: AsyncDatabaseManager) -> None:
    limiter = _limiter(db, limit=1, window=timedelta(seconds=1))
    async with _client(limiter, "203.0.113.7") as client:
        assert await _codes(client, 2) == [200, 429]
        await asyncio.sleep(1.1)
        assert await _codes(client, 1) == [200]


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


async def test_attempts_from_past_windows_are_pruned(db: AsyncDatabaseManager) -> None:
    limiter = _limiter(db, limit=5, window=timedelta(seconds=1))
    for n in range(4):
        async with _client(limiter, f"203.0.113.{n}") as client:
            await _codes(client, 1)
    await asyncio.sleep(1.1)
    async with _client(limiter, "198.51.100.9") as client:
        await _codes(client, 1)
    rows = await db.fetch_value("SELECT count(*) FROM {{tables.console_login_attempts}}")
    assert rows == 1
