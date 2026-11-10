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
import pytest_asyncio
from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from starlette.requests import Request

from aweb.events import stream_events_multi
from aweb.routes.dashboard import _sse_dashboard_events
from test_dashboard_privacy import privacy_app  # noqa: F401

CYCLES = 10


def held(redis: Redis) -> int:
    return len(redis.connection_pool._in_use_connections)


async def settled(redis: Redis, expected: int, timeout: float = 2.0) -> int:
    """The held count once async finalizers have run, or the last count seen."""
    with anyio.move_on_after(timeout):
        while held(redis) != expected:
            await asyncio.sleep(0.01)
    return held(redis)


@pytest_asyncio.fixture
async def redis():
    async with Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True) as client:
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


@pytest.mark.asyncio
async def test_a_chat_stream_whose_subscribe_fails_after_connect_returns_its_connection(privacy_app, after_connect):
    from test_agent_activity_http import _session, _stream

    env = privacy_app
    session_id = await _session(env, "alice", "bob")
    baseline = await settled(env.redis, 0)
    failures = []

    async def fail():
        failures.append(1)
        raise RedisConnectionError("subscribe failed after the connection was checked out")

    after_connect["action"] = fail
    # The stream falls back to database polling and retries its subscription until the deadline.
    async with _stream(env, "bob", session_id, seconds=2) as response:
        assert response.status_code == 200
        async for _ in response.aiter_lines():
            pass
    after_connect["action"] = None
    assert failures
    assert await settled(env.redis, baseline) == baseline


@pytest.mark.asyncio
async def test_a_subscription_whose_disconnect_fails_still_returns_its_connection(redis, monkeypatch, caplog):
    from redis.asyncio.connection import Connection

    from aweb.redis_subscriptions import open_subscription, release_subscription

    channel = "lease-ownership-disconnect-failure"
    pubsub = await open_subscription(redis, channel)
    assert held(redis) == 1
    original = Connection.disconnect

    async def disconnect(self, *args, **kwargs):
        # As when wait_closed times out: the socket is closed, then the timeout raises.
        await original(self, *args, **kwargs)
        raise TimeoutError("Timed out closing connection")

    monkeypatch.setattr(Connection, "disconnect", disconnect)
    with caplog.at_level("WARNING", logger="aweb.redis_subscriptions"):
        await release_subscription(pubsub, channel)
    monkeypatch.setattr(Connection, "disconnect", original)
    assert held(redis) == 0
    assert [r.getMessage() for r in caplog.records] == ["Redis pubsub close failed; returning its connection"]

    # The returned connection is reused and reconnects. The released PubSub, still
    # alive here, must not resubscribe through it or check out another connection.
    assert await redis.ping()
    assert await settled(redis, 0) == 0
    assert dict(await redis.pubsub_numsub(channel))[channel] == 0
    assert pubsub.channels == {}


@pytest.mark.asyncio
async def test_a_release_cancelled_by_asyncio_still_returns_its_connection(redis, monkeypatch):
    from redis.asyncio.connection import Connection

    from aweb.redis_subscriptions import open_subscription, release_subscription

    pubsub = await open_subscription(redis, "lease-ownership-channel")
    original = Connection.disconnect
    disconnecting = asyncio.Event()

    async def slow(self, *args, **kwargs):
        disconnecting.set()
        await asyncio.sleep(0.2)
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(Connection, "disconnect", slow)
    releasing = asyncio.create_task(release_subscription(pubsub, "lease-ownership-channel"))
    await disconnecting.wait()
    # A plain task cancellation, outside any AnyIO cancel scope.
    releasing.cancel()
    with suppress(asyncio.CancelledError):
        await releasing
    assert await settled(redis, 0) == 0
