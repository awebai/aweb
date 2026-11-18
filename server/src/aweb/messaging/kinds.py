"""Message kinds carried by the server's shared delivery owners."""

from enum import StrEnum


class MessageKind(StrEnum):
    MAIL = "mail"
    CHAT = "chat"
    ROOM = "room"
