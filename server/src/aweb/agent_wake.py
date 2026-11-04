"""Agent stream wakes: published by writers after commit, read by agent event streams.

A wake carries no content. It names a key and the kinds of state that may have
changed under it; the stream recomputes those kinds from Postgres, which stays
the only source of truth. Each key is the predicate the stream's snapshot
query filters on:

- ``did:{did}``: mail and chat addressed to an identity DID;
- ``agent:{agent_id}``: control signals and app events for one agent;
- ``team-room:{team_id}``: room notices of one team.

Writers record wakes with ``record_agent_wake`` inside an ``agent_wake_scope``
opened by the owner of the outermost transaction. The scope hands them to the
publisher only when it exits normally, after that transaction committed, so a
stream is never woken before the row it must read is visible.

The publisher bumps a counter per key and kind (``agent-mark:{kind}:{key}``)
and publishes on
``agent-wake:{key}`` in one pipeline, from its own task, so a Redis fault never
fails or delays the write. A failed publication is retried with backoff until
Redis accepts it. Streams compare the counters on their slow reconcile, which
recovers a wake lost while their subscriber was disconnected.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Generator, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

WAKE_MARK_TTL_SECONDS = 24 * 60 * 60
PUBLISH_RETRY_INITIAL_SECONDS = 1.0
PUBLISH_RETRY_MAX_SECONDS = 5.0
SUBSCRIBE_CONFIRM_TIMEOUT_SECONDS = 2.0
HUB_READ_TIMEOUT_SECONDS = 0.05
HUB_PING_INTERVAL_SECONDS = 15.0
HUB_RECONNECT_MAX_SECONDS = 5.0

WAKE_KINDS = frozenset({"mail", "chat", "control", "app", "room"})
_KINDS_BY_KEY_TYPE = {
    "did": ("mail", "chat"),
    "agent": ("control", "app"),
    "team-room": ("room",),
}


def did_wake_key(did: str) -> str:
    return f"did:{did}"


def agent_wake_key(agent_id: str) -> str:
    return f"agent:{agent_id}"


def team_room_wake_key(team_id: str) -> str:
    return f"team-room:{team_id}"


def wake_kinds_for_key(key: str) -> tuple[str, ...]:
    """The kinds of state a key can wake, in snapshot order."""
    return _KINDS_BY_KEY_TYPE.get(key.split(":", 1)[0], ())


def wake_channel(key: str) -> str:
    return f"agent-wake:{key}"


def wake_mark(key: str, kind: str) -> str:
    return f"agent-mark:{kind}:{key}"


def _merge(into: dict[str, set[str]], wakes: Mapping[str, Iterable[str]]) -> None:
    for key, kinds in wakes.items():
        into.setdefault(key, set()).update(kinds)


@dataclass
class _WakeScope:
    wakes: dict[str, set[str]] = field(default_factory=dict)


_current_scope: ContextVar[_WakeScope | None] = ContextVar("agent_wake_scope", default=None)


def record_agent_wake(key: str, kind: str) -> None:
    """Record that state under ``key`` changed, for publication after commit."""
    if kind not in WAKE_KINDS:
        raise ValueError(f"Unknown agent wake kind: {kind}")
    if not key:
        return
    scope = _current_scope.get()
    if scope is None:
        logger.warning("Agent wake %s (%s) recorded outside a wake scope; it is not published", key, kind)
        return
    scope.wakes.setdefault(key, set()).add(kind)


def record_did_wakes(dids: Iterable[str], kind: str) -> None:
    """Record a wake for each DID of one identity."""
    for did in dict.fromkeys(did for did in dids if did):
        record_agent_wake(did_wake_key(did), kind)


@contextlib.contextmanager
def agent_wake_scope(publisher: AgentWakePublisher | None) -> Generator[None]:
    """Collect wakes recorded inside; hand them to the publisher on normal exit.

    Open it around the outermost transaction. A nested scope records into the
    outermost one, so wakes are published once, after the outermost commit.
    Leaving by an exception publishes nothing. Without a publisher (no Redis)
    the wakes are dropped and streams rely on their reconcile.
    """
    if _current_scope.get() is not None:
        yield
        return
    scope = _WakeScope()
    token = _current_scope.set(scope)
    try:
        yield
    finally:
        _current_scope.reset(token)
    if publisher is not None and scope.wakes:
        publisher.submit(scope.wakes)


def agent_wake_publisher(state) -> AgentWakePublisher | None:
    """The process's publisher on an application state, if it runs one."""
    return getattr(state, "agent_wake_publisher", None)


class AgentWakePublisher:
    """Publishes wakes from one task per process, retrying until Redis accepts them."""

    def __init__(self, redis) -> None:
        self._redis = redis
        self._pending: dict[str, set[str]] = {}
        self._ready = asyncio.Event()
        self._task: asyncio.Task | None = None

    def submit(self, wakes: Mapping[str, Iterable[str]]) -> None:
        _merge(self._pending, wakes)
        self._ready.set()
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="agent-wake-publisher")

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _run(self) -> None:
        delay = PUBLISH_RETRY_INITIAL_SECONDS
        while True:
            await self._ready.wait()
            self._ready.clear()
            batch, self._pending = self._pending, {}
            if not batch:
                continue
            try:
                await self._send(batch)
            except asyncio.CancelledError:
                _merge(self._pending, batch)
                raise
            except Exception:
                _merge(self._pending, batch)
                logger.warning(
                    "Agent wake publication failed; retrying in %.0f s (%d keys pending)",
                    delay,
                    len(self._pending),
                    exc_info=True,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, PUBLISH_RETRY_MAX_SECONDS)
                self._ready.set()
                continue
            delay = PUBLISH_RETRY_INITIAL_SECONDS

    async def _send(self, wakes: Mapping[str, set[str]]) -> None:
        pipe = self._redis.pipeline(transaction=False)
        for key, kinds in wakes.items():
            for kind in kinds:
                pipe.incr(wake_mark(key, kind))
                pipe.expire(wake_mark(key, kind), WAKE_MARK_TTL_SECONDS)
            pipe.publish(wake_channel(key), json.dumps({"kinds": sorted(kinds)}))
        await pipe.execute()


async def read_wake_marks(redis, keys: Iterable[str]) -> dict[tuple[str, str], str | None]:
    """Return the change counter of every (key, kind) the keys can wake.

    One MGET. A missing counter reads as None; callers compare by inequality,
    so an expired or flushed counter can only cause an extra snapshot.
    """
    marks = [(key, kind) for key in dict.fromkeys(keys) for kind in wake_kinds_for_key(key)]
    if not marks:
        return {}
    values = await redis.mget([wake_mark(key, kind) for key, kind in marks])
    return {
        mark: (value.decode() if isinstance(value, bytes) else value)
        for mark, value in zip(marks, values, strict=True)
    }


@dataclass(frozen=True)
class AgentWakeBatch:
    kinds: frozenset[str]
    resync: bool


class AgentWakeSubscription:
    """One stream's view of the hub: the kinds woken since it last took them."""

    def __init__(self, keys: Iterable[str]) -> None:
        self.keys = tuple(dict.fromkeys(keys))
        self._kinds: set[str] = set()
        self._resync = False
        self._event = asyncio.Event()

    def _notify(self, kinds: Iterable[str]) -> None:
        self._kinds.update(kinds)
        self._event.set()

    def _notify_resync(self) -> None:
        self._resync = True
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()

    def take(self) -> AgentWakeBatch:
        batch = AgentWakeBatch(kinds=frozenset(self._kinds), resync=self._resync)
        self._kinds.clear()
        self._resync = False
        self._event.clear()
        return batch


class AgentWakeHub:
    """One Redis subscriber per process, shared by every agent event stream.

    Channels are reference-counted across streams. Only the reader task touches
    the PubSub connection; subscribe and unsubscribe requests are queued to it.
    After the connection is lost the reader reconnects, resubscribes every
    channel and then asks every stream to resync from Postgres.
    """

    def __init__(self, redis) -> None:
        self._redis = redis
        self._subscriptions: dict[str, set[AgentWakeSubscription]] = {}
        self._confirmed: set[str] = set()
        self._waiters: dict[str, list[asyncio.Future]] = {}
        self._requests: asyncio.Queue[tuple[str, list[str]]] = asyncio.Queue()
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="agent-wake-hub")

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    @contextlib.asynccontextmanager
    async def subscribe(self, keys: Iterable[str]):
        """Subscribe a stream to ``keys``; returns once the channels are live.

        If Redis does not confirm within a bound the stream proceeds anyway:
        the reader subscribes when Redis returns and then asks it to resync.
        """
        subscription = AgentWakeSubscription(keys)
        channels = [wake_channel(key) for key in subscription.keys]
        loop = asyncio.get_running_loop()
        waits: list[asyncio.Future] = []
        new_channels: list[str] = []
        for channel in channels:
            holders = self._subscriptions.setdefault(channel, set())
            if not holders:
                new_channels.append(channel)
            holders.add(subscription)
            if channel not in self._confirmed:
                waiter = loop.create_future()
                self._waiters.setdefault(channel, []).append(waiter)
                waits.append(waiter)
        if new_channels:
            self._requests.put_nowait(("subscribe", new_channels))
        try:
            if waits:
                await asyncio.wait(waits, timeout=SUBSCRIBE_CONFIRM_TIMEOUT_SECONDS)
            yield subscription
        finally:
            for waiter in waits:
                waiter.cancel()
            released = []
            for channel in channels:
                holders = self._subscriptions.get(channel)
                if holders is None:
                    continue
                holders.discard(subscription)
                if not holders:
                    del self._subscriptions[channel]
                    released.append(channel)
            if released:
                self._requests.put_nowait(("unsubscribe", released))

    async def _run(self) -> None:
        reconnect_delay = 0.5
        connected_before = False
        while True:
            pubsub = self._redis.pubsub()
            try:
                self._confirmed.clear()
                self._drain_requests()
                resync_pending = set(self._subscriptions) if connected_before else set()
                if self._subscriptions:
                    await pubsub.subscribe(*self._subscriptions)
                connected_before = True
                reconnect_delay = 0.5
                await self._read(pubsub, resync_pending)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning(
                    "Agent wake subscriber lost Redis; reconnecting in %.1f s",
                    reconnect_delay,
                    exc_info=True,
                )
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, HUB_RECONNECT_MAX_SECONDS)
            finally:
                with contextlib.suppress(Exception):
                    await pubsub.aclose()

    def _drain_requests(self) -> list[tuple[str, list[str]]]:
        requests = []
        while not self._requests.empty():
            requests.append(self._requests.get_nowait())
        return requests

    async def _read(self, pubsub, resync_pending: set[str]) -> None:
        loop = asyncio.get_running_loop()
        last_pong = loop.time()
        next_ping = loop.time() + HUB_PING_INTERVAL_SECONDS
        while True:
            for action, channels in self._drain_requests():
                if action == "subscribe":
                    wanted = [c for c in channels if c in self._subscriptions]
                    if wanted:
                        await pubsub.subscribe(*wanted)
                else:
                    gone = [c for c in channels if c not in self._subscriptions]
                    if gone:
                        await pubsub.unsubscribe(*gone)
                        self._confirmed.difference_update(gone)
            now = loop.time()
            if not pubsub.subscribed:
                # PING is only answered on the subscriber connection once it
                # is in subscribe mode; until then there is nothing to watch.
                last_pong = now
                next_ping = now + HUB_PING_INTERVAL_SECONDS
            elif now >= next_ping:
                if now - last_pong > 2 * HUB_PING_INTERVAL_SECONDS:
                    raise ConnectionError("agent wake subscriber missed its pong")
                await pubsub.ping()
                next_ping = now + HUB_PING_INTERVAL_SECONDS
            if pubsub.connection is None:
                # No channel was ever subscribed on this connection.
                await asyncio.sleep(HUB_READ_TIMEOUT_SECONDS)
                continue
            message = await pubsub.get_message(timeout=HUB_READ_TIMEOUT_SECONDS)
            if message is None:
                continue
            kind = _text(message.get("type"))
            if kind == "pong" or (kind == "message" and _text(message.get("data")) == "PONG"):
                last_pong = loop.time()
                continue
            channel = _text(message.get("channel"))
            if kind == "subscribe":
                self._confirmed.add(channel)
                for waiter in self._waiters.pop(channel, []):
                    if not waiter.done():
                        waiter.set_result(None)
                if resync_pending:
                    resync_pending.discard(channel)
                    if not resync_pending:
                        self._resync_all()
            elif kind == "message":
                self._dispatch(channel, _text(message.get("data")))

    def _dispatch(self, channel: str, data: str) -> None:
        holders = self._subscriptions.get(channel)
        if not holders:
            return
        try:
            kinds = [k for k in json.loads(data).get("kinds", []) if k in WAKE_KINDS]
        except (ValueError, AttributeError):
            kinds = []
        if not kinds:
            # An unreadable wake still means "something changed": resync.
            for subscription in holders:
                subscription._notify_resync()
            return
        for subscription in holders:
            subscription._notify(kinds)

    def _resync_all(self) -> None:
        for holders in self._subscriptions.values():
            for subscription in holders:
                subscription._notify_resync()


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode()
    return "" if value is None else str(value)
