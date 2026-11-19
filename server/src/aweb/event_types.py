"""Canonical names for standard mutations and published stream events.

docs/aw-hooks-sot.md:48-90 keeps the callback's (str, dict) integration seam.
These constants name standard events; they do not reject host-defined names
or make an unproduced event into a delivery guarantee.
"""

from enum import StrEnum


class MutationEventType(StrEnum):
    """Produced or explicitly handled mutations from the embedding contract."""

    AGENT_DELETED = "agent.deleted"
    AGENT_STATUS = "agent.status"
    MAIL_SENT = "message.sent"
    MAIL_ACKNOWLEDGED = "message.acknowledged"
    CHAT_MESSAGE_SENT = "chat.message_sent"
    ROOM_MESSAGE_SENT = "room.message_sent"
    RESERVATION_ACQUIRED = "reservation.acquired"
    RESERVATION_RELEASED = "reservation.released"
    RESERVATION_RENEWED = "reservation.renewed"
    TASK_CREATED = "task.created"
    TASK_UPDATED = "task.updated"
    TASK_STATUS_CHANGED = "task.status_changed"
    TASK_ASSIGNEE_CHANGED = "task.assignee_changed"
    TASK_DELETED = "task.deleted"
    TASK_COMMENT_ADDED = "task.comment_added"
    TASK_DEPENDENCY_ADDED = "task.dependency_added"
    TASK_DEPENDENCY_REMOVED = "task.dependency_removed"
    TASK_CLAIMED = "task.claimed"
    TASK_UNCLAIMED = "task.unclaimed"


class TransportEventType(StrEnum):
    """Stream names; hook translation decides which mutations publish them."""

    AGENT_STATUS = "agent.status"
    AGENT_ONLINE = "agent.online"
    AGENT_OFFLINE = "agent.offline"
    MAIL_DELIVERED = "message.delivered"
    MAIL_ACKNOWLEDGED = "message.acknowledged"
    CHAT_MESSAGE_SENT = "chat.message_sent"
    RESERVATION_ACQUIRED = "reservation.acquired"
    RESERVATION_RELEASED = "reservation.released"
    RESERVATION_RENEWED = "reservation.renewed"
    TASK_CREATED = "task.created"
    TASK_STATUS_CHANGED = "task.status_changed"
    TASK_ASSIGNEE_CHANGED = "task.assignee_changed"
    TASK_CLAIMED = "task.claimed"
    TASK_UNCLAIMED = "task.unclaimed"
