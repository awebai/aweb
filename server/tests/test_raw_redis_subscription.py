"""Malformed bytes cannot poison the next frame or the serving Redis pool."""

import asyncio
import os
from uuid import uuid4

import anyio
import pytest
from redis.asyncio import Redis

from aweb.redis_subscriptions import raw_subscription


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_raw_frame_then_valid_frame_and_scoped_cleanup(cancelled):
    channel = f"raw-subscription:{uuid4()}"
    async with Redis.from_url(os.environ["REDIS_URL"], decode_responses=True) as serving:
        subscription = raw_subscription(serving, channel)
        pubsub = await subscription.__aenter__()
        pool = pubsub.connection_pool
        try:
            assert pool is not serving.connection_pool
            async with asyncio.timeout(5):
                while (await pubsub.get_message(timeout=1)) is None:
                    pass
            assert await serving.publish(channel, b"\xff") == 1
            assert await serving.publish(channel, '{"type":"healthy"}') == 1
            frames = []
            async with asyncio.timeout(5):
                while len(frames) < 2:
                    frame = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
                    if frame is not None:
                        frames.append(frame)
            assert [frame["data"] for frame in frames] == [b"\xff", b'{"type":"healthy"}']
            assert all(frame["channel"] == channel.encode() for frame in frames)
            # Existing callers still receive strings from the same serving pool.
            assert (await serving.pubsub_numsub(channel))[0] == (channel, 1)
            assert serving.connection_pool.get_encoder().decode_responses is True
        finally:
            with anyio.CancelScope() as scope:
                if cancelled:
                    scope.cancel()
                await subscription.__aexit__(None, None, None)
        assert not pool._in_use_connections
        assert all(not connection.is_connected for connection in pool._available_connections)
        assert (await serving.pubsub_numsub(channel))[0] == (channel, 0)
        assert await serving.ping()
