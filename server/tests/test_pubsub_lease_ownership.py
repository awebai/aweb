"""Every PubSub stream returns its pooled Redis connection, on every path.

These run against real Redis and count the pool's checked-out connections.
redis-py's PubSub.aclose disconnects before it releases, so a cancellation
there, or one between connect and the caller taking ownership, strands a lease
that nothing returns.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress

import anyio
import pytest
from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from starlette.requests import Request

from aweb.events import stream_events_multi
from aweb.routes.dashboard import _sse_dashboard_events

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CYCLES = 10


def held(redis: Redis) -> int:
    return len(redis.connection_pool._in_use_connections)


async def settled(redis: Redis, expected: int, timeout: float = 2.0) -> int:
    """The held count once async finalizers have run, or the last count seen."""
    async with anyio.move_on_after(timeout):
        while held(redis) != expected:
            await asyncio.sleep(0.01)
    return held(redis)


@pytest.fixture
async def redis():
    async with Redis.from_url(REDIS_URL, decode_responses=True) as client:
        await client.ping()
        yield client


@pytest.fixture
def after_connect(monkeypatch):
    """Run a step right after PubSub.connect checks out its real connection."""
    step = {"action": None}
    original = PubSub.connect

    async def connect(self):
        await original(self)
        if step["action"] is not None:
            await step["action"]()

    monkeypatch.setattr(PubSub, "connect", connect)
    return step


def _streams(redis):
    def status():
        return stream_events_multi(redis, ["lease-ownership-workspace"], keepalive_seconds=1)

    def dashboard():
        # The first frames precede the dashboard's database snapshot.
        return _sse_dashboard_events(request=Request({"type": "http"}), db=None, redis=redis,
                                     team_id="lease-ownership:local")

    return {"status": status, "dashboard": dashboard}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["status", "dashboard"])
async def test_a_stream_closed_normally_returns_its_connection(redis, kind):
    for _ in range(CYCLES):
        stream = _streams(redis)[kind]()
        await anext(stream)
        assert held(redis) == 1
        await stream.aclose()
        assert held(redis) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["status", "dashboard"])
async def test_a_stream_closed_under_cancellation_returns_its_connection(redis, kind):
    for _ in range(CYCLES):
        stream = _streams(redis)[kind]()
        await anext(stream)
        assert held(redis) == 1
        # A client disconnect cancels the response's scope while it closes the stream.
        with anyio.CancelScope() as scope:
            scope.cancel()
            await stream.aclose()
    assert await settled(redis, 0) == 0


@pytest.mark.asyncio
async def test_a_status_stream_cancelled_while_acquiring_returns_its_connection(redis):
    for _ in range(CYCLES):
        stream = _streams(redis)["status"]()
        opening = asyncio.create_task(anext(stream))
        for _ in range(1000):
            await asyncio.sleep(0)
            if held(redis):
                break
        opening.cancel()
        with suppress(asyncio.CancelledError):
            await opening
        await stream.aclose()
    assert await settled(redis, 0) == 0


@pytest.mark.asyncio
async def test_a_status_stream_cancelled_after_connect_returns_its_connection(redis, after_connect):
    connected = asyncio.Event()

    async def pause():
        connected.set()
        await asyncio.sleep(0)

    after_connect["action"] = pause
    for _ in range(CYCLES):
        connected.clear()
        stream = _streams(redis)["status"]()
        opening = asyncio.create_task(anext(stream))
        await connected.wait()
        opening.cancel()
        with suppress(asyncio.CancelledError):
            await opening
        await stream.aclose()
    assert await settled(redis, 0) == 0


@pytest.mark.asyncio
async def test_a_status_stream_whose_subscribe_fails_after_connect_returns_its_connection(redis, after_connect):
    async def fail():
        raise RedisConnectionError("subscribe failed after the connection was checked out")

    after_connect["action"] = fail
    for _ in range(CYCLES):
        stream = _streams(redis)["status"]()
        with pytest.raises(RedisConnectionError):
            await anext(stream)
        await stream.aclose()
    assert await settled(redis, 0) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["cancel", "error"])
async def test_open_subscription_owns_its_connection_until_it_returns(redis, after_connect, boundary):
    from aweb.redis_subscriptions import open_subscription, release_subscription

    async def interrupt():
        if boundary == "cancel":
            raise asyncio.CancelledError
        raise RedisConnectionError("subscribe failed after the connection was checked out")

    after_connect["action"] = interrupt
    for _ in range(CYCLES):
        with pytest.raises(asyncio.CancelledError if boundary == "cancel" else RedisConnectionError):
            await open_subscription(redis, "lease-ownership-channel")
        assert held(redis) == 0
    after_connect["action"] = None
    pubsub = await open_subscription(redis, "lease-ownership-channel")
    assert held(redis) == 1
    with anyio.CancelScope() as scope:
        scope.cancel()
        await release_subscription(pubsub, "lease-ownership-channel")
    assert held(redis) == 0
    await release_subscription(None)
