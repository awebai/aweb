"""Typed message mutation contexts and the existing public transport DTOs.

docs/aw-hooks-sot.md:92 (Typed producer contexts) distinguishes native chat from inbound federation
contexts. Their serializers preserve that distinction and nullable identity
projections. They neither authenticate a participant nor change callback,
transaction, failure or replay semantics.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Literal

from aweb.event_types import MutationEventType
from aweb.events import (
    ChatMessageEvent as ChatMessageEvent,
)
from aweb.events import (
    MessageAcknowledgedEvent as MessageAcknowledgedEvent,
)
from aweb.events import (
    MessageDeliveredEvent as MessageDeliveredEvent,
)
from aweb.events import (
    TeamChatMessageSentEvent as TeamChatMessageSentEvent,
)
from aweb.events import (
    TeamMessageAcknowledgedEvent as TeamMessageAcknowledgedEvent,
)
from aweb.events import (
    TeamMessageSentEvent as TeamMessageSentEvent,
)
from aweb.messaging.kinds import (
    ContentModeValue,
    MessageKind,
    MessagePriorityValue,
    MessageTransport,
    accepted_content_mode,
    accepted_message_priority,
)


def _require_named_value(value: object, *, expected: type[StrEnum], field: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(f"Pass a {expected.__name__} value for {field}.")


@dataclass(frozen=True, kw_only=True)
class MailSentContext:
    """Local or outbound mail callback fields, without a synthetic session."""

    event_type: ClassVar[MutationEventType] = MutationEventType.MAIL_SENT
    team_id: str | None
    from_agent_id: str | None
    from_did: str
    from_did_aw: str | None
    to_agent_id: str | None
    from_alias: str
    message_id: str
    conversation_id: str | None
    to_alias: str | None
    subject: str
    priority: MessagePriorityValue | None
    content_mode: ContentModeValue | None
    transport: MessageTransport = MessageTransport.LOCAL

    def __post_init__(self) -> None:
        _require_named_value(
            self.transport, expected=MessageTransport, field="transport"
        )
        object.__setattr__(self, "priority", accepted_message_priority(self.priority))
        object.__setattr__(
            self, "content_mode", accepted_content_mode(self.content_mode)
        )

    def to_context(self) -> dict[str, object]:
        """Build fresh callback data, keeping the optional federation key absent."""
        context: dict[str, object] = {
            "team_id": self.team_id,
            "from_agent_id": self.from_agent_id,
            "from_did": self.from_did,
            "from_did_aw": self.from_did_aw,
            "to_agent_id": self.to_agent_id,
            "from_alias": self.from_alias,
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "to_alias": self.to_alias,
            "subject": self.subject,
            "priority": self.priority,
            "content_mode": self.content_mode,
        }
        if self.transport is MessageTransport.FEDERATED:
            context["federated"] = True
        return context


@dataclass(frozen=True, kw_only=True)
class ChatMessageSentContext:
    """Native chat callback fields, including its recipient list and preview."""

    event_type: ClassVar[MutationEventType] = MutationEventType.CHAT_MESSAGE_SENT
    team_id: str | None
    session_id: str
    message_id: str
    from_agent_id: str | None
    from_alias: str
    from_did: str
    from_did_aw: str | None
    to_aliases: tuple[str, ...] | list[str]
    preview: str
    content_mode: ContentModeValue | None
    transport: MessageTransport = MessageTransport.LOCAL

    def __post_init__(self) -> None:
        _require_named_value(
            self.transport, expected=MessageTransport, field="transport"
        )
        object.__setattr__(
            self, "content_mode", accepted_content_mode(self.content_mode)
        )
        object.__setattr__(self, "to_aliases", tuple(self.to_aliases))

    def to_context(self) -> dict[str, object]:
        """Return callback-owned containers; mutating them cannot alter this DTO."""
        context: dict[str, object] = {
            "team_id": self.team_id,
            "session_id": self.session_id,
            "conversation_id": self.session_id,
            "message_id": self.message_id,
            "from_agent_id": self.from_agent_id,
            "from_alias": self.from_alias,
            "from_did": self.from_did,
            "from_did_aw": self.from_did_aw,
            "to_aliases": list(self.to_aliases),
            "preview": self.preview,
            "content_mode": self.content_mode,
        }
        if self.transport is MessageTransport.FEDERATED:
            context["federated"] = True
        return context


@dataclass(frozen=True, kw_only=True)
class FederatedMessageSentContext:
    """Inbound outbox fields; chat has a session and may lack native chat fields."""

    kind: Literal[MessageKind.MAIL, MessageKind.CHAT]
    team_id: str | None
    from_did: str
    from_did_aw: str | None
    to_agent_id: str | None
    from_alias: str
    message_id: str
    conversation_id: str
    to_alias: str | None
    subject: str
    priority: MessagePriorityValue | None
    content_mode: ContentModeValue | None

    def __post_init__(self) -> None:
        _require_named_value(self.kind, expected=MessageKind, field="kind")
        object.__setattr__(self, "priority", accepted_message_priority(self.priority))
        object.__setattr__(
            self, "content_mode", accepted_content_mode(self.content_mode)
        )

    @property
    def event_type(self) -> MutationEventType:
        """Choose the mutation name without assigning a team or actor."""
        if self.kind is MessageKind.MAIL:
            return MutationEventType.MAIL_SENT
        return MutationEventType.CHAT_MESSAGE_SENT

    def to_context(self) -> dict[str, object]:
        """Keep the existing shared inbound context, including its null mail session."""
        return {
            "team_id": self.team_id,
            "from_agent_id": None,
            "from_did": self.from_did,
            "from_did_aw": self.from_did_aw,
            "to_agent_id": self.to_agent_id,
            "from_alias": self.from_alias,
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "session_id": self.conversation_id
            if self.kind is MessageKind.CHAT
            else None,
            "to_alias": self.to_alias,
            "subject": self.subject,
            "priority": self.priority,
            "content_mode": self.content_mode,
            "federated": True,
        }


@dataclass(frozen=True, kw_only=True)
class MessageAcknowledgedContext:
    """Incoming acknowledgement callback identity and message metadata."""

    event_type: ClassVar[MutationEventType] = MutationEventType.MAIL_ACKNOWLEDGED
    team_id: str | None
    agent_id: str | None
    alias: str | None
    message_id: str
    from_alias: str | None
    subject: str
    content_mode: ContentModeValue | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "content_mode", accepted_content_mode(self.content_mode)
        )

    def to_context(self) -> dict[str, object]:
        """Return the acknowledgement context without manufacturing an actor."""
        return {
            "team_id": self.team_id,
            "agent_id": self.agent_id,
            "alias": self.alias,
            "message_id": self.message_id,
            "from_alias": self.from_alias,
            "subject": self.subject,
            "content_mode": self.content_mode,
        }


@dataclass(frozen=True, kw_only=True)
class RoomMessageSentContext:
    """Committed room-post metadata, without message content or recipients."""

    event_type: ClassVar[MutationEventType] = MutationEventType.ROOM_MESSAGE_SENT
    team_id: str
    room_id: str
    message_id: str
    from_agent_id: str
    from_did: str
    from_did_aw: str | None
    from_alias: str

    def to_context(self) -> dict[str, object]:
        """Return host accounting identifiers without disclosing the room body."""
        return {
            "team_id": self.team_id,
            "room_id": self.room_id,
            "message_id": self.message_id,
            "from_agent_id": self.from_agent_id,
            "from_did": self.from_did,
            "from_did_aw": self.from_did_aw,
            "from_alias": self.from_alias,
        }
