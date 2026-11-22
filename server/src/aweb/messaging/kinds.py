"""Message vocabularies shared by delivery and event producers."""

from enum import StrEnum
from typing import TypeAlias


class MessageKind(StrEnum):
    MAIL = "mail"
    CHAT = "chat"


class ContentMode(StrEnum):
    """Named modes from docs/aw-hooks-sot.md:92, not a received-value gate."""

    PLAINTEXT = "legacy_plaintext_v1"
    ENCRYPTED = "encrypted_v2"


class MessagePriority(StrEnum):
    """Mail priority values retained by the public send contract."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class MessageTransport(StrEnum):
    """Whether a message mutation carries the federation context field."""

    LOCAL = "local"
    FEDERATED = "federated"


# docs/aw-hooks-sot.md:92 keeps released input metadata open (Antares 03d344b5).
ContentModeValue: TypeAlias = ContentMode | str
MessagePriorityValue: TypeAlias = MessagePriority | str
_CONTENT_MODES = {mode.value: mode for mode in ContentMode}
_PRIORITIES = {priority.value: priority for priority in MessagePriority}


def accepted_content_mode(value: ContentModeValue | None) -> ContentModeValue:
    """Keep host defaults for absent modes; retain other accepted strings verbatim."""
    if value is None or value == "":
        return ContentMode.PLAINTEXT
    return _CONTENT_MODES.get(value, value)


def accepted_message_priority(
    value: MessagePriorityValue | None,
) -> MessagePriorityValue:
    """Keep the host's normal default without narrowing received priority text."""
    if value is None or value == "":
        return MessagePriority.NORMAL
    return _PRIORITIES.get(value, value)
