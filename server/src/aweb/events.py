"""Event publishing and streaming via Redis pub/sub."""

from __future__ import annotations

from aweb.reconnect import ReconnectBackoff

from aweb.messaging.kinds import ContentMode
from aweb.event_types import TransportEventType

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from redis.asyncio import Redis
from redis.asyncio.client import Pipeline, PubSub
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from aweb.redis_subscriptions import open_subscription, release_subscription

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
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

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

    type: str = field(default=TransportEventType.RESERVATION_ACQUIRED.value, init=False)
    paths: list[str] = field(default_factory=list)
    alias: str = ""
    ttl_seconds: int = 0
    reason: str | None = None
    exclusive: bool = True


@dataclass
class ReservationReleasedEvent(Event):
    """Event emitted when reservations are released."""

    type: str = field(default=TransportEventType.RESERVATION_RELEASED.value, init=False)
    paths: list[str] = field(default_factory=list)
    alias: str = ""


@dataclass
class ReservationRenewedEvent(Event):
    """Event emitted when reservation TTLs are extended."""

    type: str = field(default=TransportEventType.RESERVATION_RENEWED.value, init=False)
    paths: list[str] = field(default_factory=list)
    alias: str = ""
    ttl_seconds: int = 0


@dataclass
class MessageDeliveredEvent(Event):
    """Event emitted when a message is delivered to a workspace inbox."""

    type: str = field(default=TransportEventType.MAIL_DELIVERED.value, init=False)
    message_id: str = ""
    from_workspace: str = ""
    from_alias: str = ""
    to_alias: str = ""
    subject: str = ""
    priority: str = "normal"
    content_mode: str = ContentMode.PLAINTEXT
    encrypted: bool = False


@dataclass
class MessageAcknowledgedEvent(Event):
    """Event emitted when a message is acknowledged."""

    type: str = field(default=TransportEventType.MAIL_ACKNOWLEDGED.value, init=False)
    message_id: str = ""
    from_alias: str = ""
    subject: str = ""
    content_mode: str = ContentMode.PLAINTEXT
    encrypted: bool = False


@dataclass
class ChatMessageEvent(Event):
    """Event emitted when a chat message is sent."""

    type: str = field(default=TransportEventType.CHAT_MESSAGE_SENT.value, init=False)
    session_id: str = ""
    message_id: str = ""
    from_alias: str = ""
    to_aliases: list[str] = field(default_factory=list)
    preview: str = ""


@dataclass
class TaskStatusChangedEvent(Event):
    """Event emitted when a task's status changes."""

    type: str = field(default=TransportEventType.TASK_STATUS_CHANGED.value, init=False)
    team_id: str = ""
    task_ref: str = ""
    old_status: str = ""
    new_status: str = ""
    title: str | None = None
    alias: str = ""


@dataclass
class TaskCreatedEvent(Event):
    """Event emitted when a task is created."""

    type: str = field(default=TransportEventType.TASK_CREATED.value, init=False)
    team_id: str = ""
    task_ref: str = ""
    title: str | None = None
    alias: str = ""


@dataclass
class TaskClaimedEvent(Event):
    """Event emitted when a workspace claims a task."""

    type: str = field(default=TransportEventType.TASK_CLAIMED.value, init=False)
    task_ref: str = ""
    alias: str = ""
    title: str | None = None


@dataclass
class TaskUnclaimedEvent(Event):
    """Event emitted when a workspace releases a task claim."""

    type: str = field(default=TransportEventType.TASK_UNCLAIMED.value, init=False)
    task_ref: str = ""
    alias: str = ""
    title: str | None = None


@dataclass
class TeamEvent:
    """Minimal dashboard-facing event payload."""

    team_id: str
    type: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class TeamTaskCreatedEvent(TeamEvent):
    type: str = field(default=TransportEventType.TASK_CREATED.value, init=False)
    task_ref: str = ""
    alias: str = ""
    title: str = ""
    status: str = "open"
    assignee_alias: str | None = None


@dataclass
class TeamTaskStatusChangedEvent(TeamEvent):
    type: str = field(default=TransportEventType.TASK_STATUS_CHANGED.value, init=False)
    task_ref: str = ""
    alias: str = ""
    title: str = ""
    old_status: str = ""
    new_status: str = ""
    assignee_alias: str | None = None


@dataclass
class TeamTaskAssigneeChangedEvent(TeamEvent):
    type: str = field(
        default=TransportEventType.TASK_ASSIGNEE_CHANGED.value, init=False
    )
    task_ref: str = ""
    alias: str = ""
    title: str = ""
    old_assignee_alias: str | None = None
    assignee_alias: str | None = None


@dataclass
class TeamAgentStatusEvent(TeamEvent):
    """An agent's host-published reachability verdict changed (docs/agent-health.md)."""

    type: str = field(default=TransportEventType.AGENT_STATUS.value, init=False)
    agent_id: str = ""
    alias: str = ""
    reachable: str = ""
    reason_code: str | None = None
    reason_text: str | None = None
    fixing_by: str | None = None
    fixing_text: str | None = None
    observed_at: str = ""
    valid_until: str = ""


@dataclass
class TeamTaskClaimedEvent(TeamEvent):
    type: str = field(default=TransportEventType.TASK_CLAIMED.value, init=False)
    task_ref: str = ""
    alias: str = ""
    title: str = ""


@dataclass
class TeamTaskUnclaimedEvent(TeamEvent):
    type: str = field(default=TransportEventType.TASK_UNCLAIMED.value, init=False)
    task_ref: str = ""
    alias: str = ""
    title: str = ""


@dataclass
class TeamMessageSentEvent(TeamEvent):
    type: str = field(default=TransportEventType.MAIL_DELIVERED.value, init=False)
    message_id: str = ""
    from_alias: str = ""
    to_alias: str = ""
    subject: str = ""
    priority: str = "normal"
    content_mode: str = ContentMode.PLAINTEXT
    encrypted: bool = False


@dataclass
class TeamMessageAcknowledgedEvent(TeamEvent):
    type: str = field(default=TransportEventType.MAIL_ACKNOWLEDGED.value, init=False)
    alias: str = ""
    from_alias: str = ""
    subject: str = ""
    content_mode: str = ContentMode.PLAINTEXT
    encrypted: bool = False


@dataclass
class TeamChatMessageSentEvent(TeamEvent):
    type: str = field(default=TransportEventType.CHAT_MESSAGE_SENT.value, init=False)
    from_alias: str = ""
    to_aliases: list[str] = field(default_factory=list)
    preview: str = ""


@dataclass
class TeamReservationAcquiredEvent(TeamEvent):
    type: str = field(default=TransportEventType.RESERVATION_ACQUIRED.value, init=False)
    alias: str = ""
    paths: list[str] = field(default_factory=list)


@dataclass
class TeamReservationReleasedEvent(TeamEvent):
    type: str = field(default=TransportEventType.RESERVATION_RELEASED.value, init=False)
    alias: str = ""
    paths: list[str] = field(default_factory=list)


@dataclass
class TeamReservationRenewedEvent(TeamEvent):
    type: str = field(default=TransportEventType.RESERVATION_RENEWED.value, init=False)
    alias: str = ""
    paths: list[str] = field(default_factory=list)


@dataclass
class TeamAgentOnlineEvent(TeamEvent):
    type: str = field(default=TransportEventType.AGENT_ONLINE.value, init=False)
    alias: str = ""


@dataclass
class TeamAgentOfflineEvent(TeamEvent):
    type: str = field(default=TransportEventType.AGENT_OFFLINE.value, init=False)
    alias: str = ""


def _channel_name(workspace_id: str) -> str:
    """Generate Redis channel name for a workspace."""
    return f"events:{workspace_id}"


def team_events_channel_name(team_id: str) -> str:
    """Generate Redis channel name for dashboard team events."""
    return f"team-events:{team_id}"


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


def queue_team_event(pipeline: Pipeline, event: TeamEvent) -> None:
    """Queue the canonical team publication in a caller-owned MULTI transaction.

    The caller queues its presence snapshot alongside this event, then executes
    or retries WATCH/MULTI. Serialization happens before that Redis commit;
    queueing neither executes nor publishes outside the transaction.
    """
    pipeline.publish(team_events_channel_name(event.team_id), event.to_json())


async def publish_team_event(redis: Redis, event: TeamEvent) -> int:
    """Publish a dashboard-shaped event to the team pub/sub channel."""
    channel = team_events_channel_name(event.team_id)
    message = event.to_json()
    count = await redis.publish(channel, message)
    logger.debug("Published %s to %s, %s subscribers", event.type, channel, count)
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


async def stream_events_multi(
    redis: Redis,
    workspace_ids: list[str],
    event_types: Optional[set[str]] = None,
    keepalive_seconds: int = 30,
    check_disconnected: Optional[Callable[[], Awaitable[bool]]] = None,
    event_filter: Optional[Callable[[dict[str, Any]], bool]] = None,
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
        event_filter: Optional predicate for parsed event payloads that already
                      passed the category filter.

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
    backoff = ReconnectBackoff(initial_delay=0.1, maximum_delay=5.0)

    async def _close_pubsub(ps: PubSub | None) -> None:
        await release_subscription(ps, *channels)

    async def _connect_pubsub() -> PubSub:
        ps = await open_subscription(redis, *channels)
        logger.debug(f"Subscribed to {len(channels)} channels")
        return ps

    try:
        pubsub = await _connect_pubsub()
        last_keepalive = loop.time()
        last_pubsub_ping = last_keepalive

        while True:
            # Check for client disconnect
            if check_disconnected and await check_disconnected():
                logger.debug(
                    f"Client disconnected, ending stream for {len(channels)} channels"
                )
                return

            now = loop.time()

            if pubsub is None:
                if backoff.due(now):
                    try:
                        pubsub = await _connect_pubsub()
                        backoff.reset()
                        last_keepalive = now
                        last_pubsub_ping = now
                    except RedisError:
                        logger.warning(
                            "Redis pubsub reconnect failed; will retry",
                            exc_info=True,
                        )
                        backoff.schedule(now)

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
                logger.info(
                    "Redis pubsub connection dropped; reconnecting", exc_info=True
                )
                await _close_pubsub(pubsub)
                pubsub = None
                backoff.schedule(now)
                message = None
            except RedisError:
                logger.warning("Redis pubsub error; reconnecting", exc_info=True)
                await _close_pubsub(pubsub)
                pubsub = None
                backoff.schedule(now)
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
                        if event_filter is None or event_filter(event_data):
                            yield f"data: {data}\n\n"
                            last_keepalive = current_time
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in event: {data}")
                    continue

            # Send keepalive comment if needed
            if current_time - last_keepalive >= keepalive_seconds:
                if (
                    pubsub is not None
                    and current_time - last_pubsub_ping >= keepalive_seconds
                ):
                    try:
                        await pubsub.ping()
                        last_pubsub_ping = current_time
                    except RedisError:
                        logger.info(
                            "Redis pubsub ping failed; reconnecting", exc_info=True
                        )
                        await _close_pubsub(pubsub)
                        pubsub = None
                        backoff.schedule(current_time)

                yield ": keepalive\n\n"
                last_keepalive = current_time

    except asyncio.CancelledError:
        logger.debug(f"Stream cancelled for {len(channels)} channels")
        raise
    finally:
        await _close_pubsub(pubsub)
        logger.debug(f"Unsubscribed from {len(channels)} channels")
