"""Message vocabularies shared by delivery and event producers."""

from enum import StrEnum


class MessageKind(StrEnum):
    MAIL = "mail"
    CHAT = "chat"
    ROOM = "room"


class ContentMode(StrEnum):
    """Stored/wire modes from docs/aw-hooks-sot.md:230-264."""

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
