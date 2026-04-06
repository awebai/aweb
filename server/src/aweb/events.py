"""Event publishing and streaming via Redis pub/sub."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class EventCategory(str, Enum):
    """Categories of events that can be streamed."""

    RESERVATION = "reservation"
    MESSAGE = "message"
    TASK = "task"
    CHAT = "chat"


@dataclass
class Event:
    """Base class for all events."""

    workspace_id: str
    type: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    project_slug: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @property
    def category(self) -> EventCategory:
        """Extract category from event type (e.g., 'message.delivered' -> 'message')."""
        return EventCategory(self.type.split(".")[0])


@dataclass
class ReservationAcquiredEvent(Event):
    """Event emitted when reservations are acquired."""

    type: str = field(default="reservation.acquired", init=False)
    paths: list[str] = field(default_factory=list)
    alias: str = ""
    ttl_seconds: int = 0
    reason: str | None = None
    exclusive: bool = True


@dataclass
class ReservationReleasedEvent(Event):
    """Event emitted when reservations are released."""

    type: str = field(default="reservation.released", init=False)
    paths: list[str] = field(default_factory=list)
    alias: str = ""


@dataclass
class ReservationRenewedEvent(Event):
    """Event emitted when reservation TTLs are extended."""

    type: str = field(default="reservation.renewed", init=False)
    paths: list[str] = field(default_factory=list)
    alias: str = ""
    ttl_seconds: int = 0


@dataclass
class MessageDeliveredEvent(Event):
    """Event emitted when a message is delivered to a workspace inbox."""

    type: str = field(default="message.delivered", init=False)
    message_id: str = ""
    from_workspace: str = ""
    from_alias: str = ""
    to_alias: str = ""
    subject: str = ""
    priority: str = "normal"


@dataclass
class MessageAcknowledgedEvent(Event):
    """Event emitted when a message is acknowledged."""

    type: str = field(default="message.acknowledged", init=False)
    message_id: str = ""
    from_alias: str = ""
    subject: str = ""


@dataclass
class ChatMessageEvent(Event):
    """Event emitted when a chat message is sent."""

    type: str = field(default="chat.message_sent", init=False)
    session_id: str = ""
    message_id: str = ""
    from_alias: str = ""
    to_aliases: list[str] = field(default_factory=list)
    preview: str = ""


@dataclass
class TaskStatusChangedEvent(Event):
    """Event emitted when a task's status changes."""

    type: str = field(default="task.status_changed", init=False)
    team_address: str = ""
    task_ref: str = ""
    old_status: str = ""
    new_status: str = ""
    title: str | None = None
    alias: str = ""


@dataclass
class TaskCreatedEvent(Event):
    """Event emitted when a task is created."""

    type: str = field(default="task.created", init=False)
    team_address: str = ""
    task_ref: str = ""
    title: str | None = None
    alias: str = ""


@dataclass
class TaskClaimedEvent(Event):
    """Event emitted when a workspace claims a task."""

    type: str = field(default="task.claimed", init=False)
    task_ref: str = ""
    alias: str = ""
    title: str | None = None


@dataclass
class TaskUnclaimedEvent(Event):
    """Event emitted when a workspace releases a task claim."""

    type: str = field(default="task.unclaimed", init=False)
    task_ref: str = ""
    alias: str = ""
    title: str | None = None


def _channel_name(workspace_id: str) -> str:
    """Generate Redis channel name for a workspace."""
    return f"events:{workspace_id}"


def chat_session_channel_name(session_id: str) -> str:
    """Generate Redis channel name for private chat session wake signals."""
    return f"chat-session:{session_id}"


async def publish_event(redis: Redis, event: Event) -> int:
    """Publish an event to the workspace's Redis pub/sub channel.

    Args:
        redis: Redis client
        event: Event to publish

    Returns:
        Number of subscribers that received the message
    """
    channel = _channel_name(event.workspace_id)
    message = event.to_json()
    count = await redis.publish(channel, message)
    logger.debug(f"Published {event.type} to {channel}, {count} subscribers")
    return count


async def publish_chat_session_signal(
    redis: Redis,
    *,
    session_id: str,
    signal_type: str,
    agent_id: str | None = None,
    message_id: str | None = None,
) -> int:
    """Publish a lightweight wake signal for an in-session chat SSE stream.

    The chat SSE route keeps Postgres as the source of truth and uses this
    pub/sub channel only as a wake hint to avoid tight DB polling.
    """
    channel = chat_session_channel_name(session_id)
    payload: dict[str, Any] = {
        "type": "chat.session_updated",
        "session_id": session_id,
        "signal_type": signal_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if agent_id:
        payload["agent_id"] = agent_id
    if message_id:
        payload["message_id"] = message_id
    count = await redis.publish(channel, json.dumps(payload))
    logger.debug("Published %s to %s, %s subscribers", signal_type, channel, count)
    return count

async def stream_events(
    redis: Redis,
    workspace_id: str,
    event_types: Optional[set[str]] = None,
    keepalive_seconds: int = 30,
) -> AsyncIterator[str]:
    """Stream events for a workspace as SSE-formatted strings.

    Args:
        redis: Redis client
        workspace_id: Workspace to stream events for
        event_types: Optional set of event categories to filter (e.g., {'message', 'task'})
                     If None, all events are streamed.
        keepalive_seconds: Seconds between keepalive comments

    Yields:
        SSE-formatted event strings (e.g., "data: {...}\\n\\n")
    """
    async for event in stream_events_multi(redis, [workspace_id], event_types, keepalive_seconds):
        yield event


async def stream_events_multi(
    redis: Redis,
    workspace_ids: list[str],
    event_types: Optional[set[str]] = None,
    keepalive_seconds: int = 30,
    check_disconnected: Optional[Callable[[], Awaitable[bool]]] = None,
) -> AsyncIterator[str]:
    """Stream events for multiple workspaces as SSE-formatted strings.

    Args:
        redis: Redis client
        workspace_ids: List of workspace IDs to stream events for
        event_types: Optional set of event categories to filter (e.g., {'message', 'task'})
                     If None, all events are streamed.
        keepalive_seconds: Seconds between keepalive comments
        check_disconnected: Optional async callback to check if client has disconnected.
                           When provided and returns True, the stream ends cleanly.

    Yields:
        SSE-formatted event strings (e.g., "data: {...}\\n\\n")
    """
    channels = [_channel_name(ws_id) for ws_id in workspace_ids]

    # Empty workspace list: send keepalives for a limited time.
    # This handles new projects with no workspaces yet while preventing
    # resource leaks if disconnect detection fails.
    if not channels:
        max_duration_seconds = 5 * 60  # 5 minutes
        max_keepalives = max_duration_seconds // keepalive_seconds
        keepalive_count = 0

        while keepalive_count < max_keepalives:
            # Check for client disconnect
            if check_disconnected and await check_disconnected():
                logger.debug("Client disconnected (empty workspace list)")
                return
            await asyncio.sleep(keepalive_seconds)
            yield ": keepalive\n\n"
            keepalive_count += 1

        logger.debug("Empty workspace stream reached max duration, closing")
        return

    loop = asyncio.get_running_loop()

    # Redis pub/sub has no message persistence. Events published while the
    # subscription is down (during reconnect or initial connect failure) are
    # silently lost. This is acceptable for SSE consumers because:
    # 1. The next successfully received event carries current state.
    # 2. Consumers that need at-least-once delivery should poll DB state as
    #    a catch-up mechanism (the per-agent wake stream in routes/events.py
    #    does this by polling Postgres directly).
    pubsub: PubSub | None = None
    reconnect_delay_seconds = 0.1
    max_reconnect_delay_seconds = 5.0
    next_reconnect_at: float | None = None

    async def _close_pubsub(ps: PubSub | None) -> None:
        if ps is None:
            return
        try:
            await ps.unsubscribe(*channels)
        except Exception:
            pass
        try:
            await ps.aclose()
        except Exception:
            pass

    async def _connect_pubsub() -> PubSub:
        ps: PubSub = redis.pubsub()
        await ps.subscribe(*channels)
        logger.debug(f"Subscribed to {len(channels)} channels")
        return ps

    try:
        pubsub = await _connect_pubsub()
        last_keepalive = loop.time()
        last_pubsub_ping = last_keepalive

        while True:
            # Check for client disconnect
            if check_disconnected and await check_disconnected():
                logger.debug(f"Client disconnected, ending stream for {len(channels)} channels")
                return

            now = loop.time()

            if pubsub is None:
                if next_reconnect_at is None or now >= next_reconnect_at:
                    try:
                        pubsub = await _connect_pubsub()
                        reconnect_delay_seconds = 0.1
                        next_reconnect_at = None
                        last_keepalive = now
                        last_pubsub_ping = now
                    except RedisError:
                        logger.warning(
                            "Redis pubsub reconnect failed; will retry",
                            exc_info=True,
                        )
                        next_reconnect_at = now + reconnect_delay_seconds
                        reconnect_delay_seconds = min(
                            max_reconnect_delay_seconds,
                            reconnect_delay_seconds * 2,
                        )

                if now - last_keepalive >= keepalive_seconds:
                    yield ": keepalive\n\n"
                    last_keepalive = now

                await asyncio.sleep(min(1.0, keepalive_seconds))
                continue

            try:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
            except RedisConnectionError:
                logger.info("Redis pubsub connection dropped; reconnecting", exc_info=True)
                await _close_pubsub(pubsub)
                pubsub = None
                next_reconnect_at = now + reconnect_delay_seconds
                reconnect_delay_seconds = min(
                    max_reconnect_delay_seconds,
                    reconnect_delay_seconds * 2,
                )
                message = None
            except RedisError:
                logger.warning("Redis pubsub error; reconnecting", exc_info=True)
                await _close_pubsub(pubsub)
                pubsub = None
                next_reconnect_at = now + reconnect_delay_seconds
                reconnect_delay_seconds = min(
                    max_reconnect_delay_seconds,
                    reconnect_delay_seconds * 2,
                )
                message = None

            current_time = loop.time()

            if message is not None and message["type"] == "message":
                data = message["data"]
                if isinstance(data, bytes):
                    data = data.decode("utf-8")

                # Parse event to check category filter
                try:
                    event_data = json.loads(data)
                    event_category = event_data.get("type", "").split(".")[0]

                    # Apply filter if specified
                    if event_types is None or event_category in event_types:
                        yield f"data: {data}\n\n"
                        last_keepalive = current_time
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in event: {data}")
                    continue

            # Send keepalive comment if needed
            if current_time - last_keepalive >= keepalive_seconds:
                if pubsub is not None and current_time - last_pubsub_ping >= keepalive_seconds:
                    try:
                        await pubsub.ping()
                        last_pubsub_ping = current_time
                    except RedisError:
                        logger.info("Redis pubsub ping failed; reconnecting", exc_info=True)
                        await _close_pubsub(pubsub)
                        pubsub = None
                        next_reconnect_at = current_time + reconnect_delay_seconds
                        reconnect_delay_seconds = min(
                            max_reconnect_delay_seconds,
                            reconnect_delay_seconds * 2,
                        )

                yield ": keepalive\n\n"
                last_keepalive = current_time

    except asyncio.CancelledError:
        logger.debug(f"Stream cancelled for {len(channels)} channels")
        raise
    finally:
        await _close_pubsub(pubsub)
        logger.debug(f"Unsubscribed from {len(channels)} channels")
