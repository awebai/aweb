"""PubSub subscriptions that always return their pooled Redis connection.

A PubSub checks a connection out of the shared pool when it first subscribes
and holds it until aclose(). redis-py's aclose() disconnects before it releases,
so a cancellation or an error during that disconnect leaves the connection
checked out for good. A PubSub that connects and then fails or is cancelled
before subscribe() returns has the same effect, since no caller holds it to
close it. Every stream that subscribes opens and releases through this module.
"""

from __future__ import annotations

import asyncio
import logging

import anyio
from redis.asyncio import Redis
from redis.asyncio.client import PubSub

logger = logging.getLogger(__name__)

# Releases outlive a cancelled caller; the loop holds only weak task references.
_releases: set[asyncio.Task] = set()


async def open_subscription(redis: Redis, *channels: str) -> PubSub:
    """A PubSub subscribed to channels, owned by the caller once this returns.

    If subscribing fails or is cancelled, its connection is released before the
    error propagates.
    """
    pubsub = redis.pubsub()
    try:
        await pubsub.subscribe(*channels)
    except BaseException:
        await release_subscription(pubsub)
        raise
    return pubsub


async def release_subscription(pubsub: PubSub | None, *channels: str) -> None:
    """Unsubscribe best-effort, then return the connection to the pool.

    The release runs in its own task, so neither AnyIO nor asyncio cancellation
    of the caller interrupts it, and it returns the connection even when the
    disconnect before it fails.
    """
    if pubsub is None:
        return
    try:
        if channels:
            try:
                await pubsub.unsubscribe(*channels)
            except Exception:
                pass
    finally:
        release = asyncio.ensure_future(_close(pubsub))
        _releases.add(release)
        release.add_done_callback(_releases.discard)
        with anyio.CancelScope(shield=True):
            await asyncio.shield(release)


async def _close(pubsub: PubSub) -> None:
    try:
        await pubsub.aclose()
    except Exception:
        logger.warning("Redis pubsub close failed; returning its connection", exc_info=True)
        # A PubSub whose constructor failed has no connection attribute.
        connection = getattr(pubsub, "connection", None)
        if connection is not None:
            pubsub.connection = None
            await pubsub.connection_pool.release(connection)
