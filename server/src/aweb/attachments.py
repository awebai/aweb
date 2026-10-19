"""Managed attachment wire types and embedding boundary.

The backend holds managed storage/custody, never authority conferred by an ID.
All provider errors use fixed codes; filenames/content must not enter logs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any, Literal, Protocol
from uuid import UUID
import unicodedata

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator
from awid.signing import canonical_json_bytes

MAX_FILE_BYTES = 5 * 1024 * 1024
MEDIA_TYPES = frozenset({"text/plain", "text/markdown", "text/csv", "application/json",
                         "application/pdf", "image/png", "image/jpeg", "image/webp"})
_UNSAFE = frozenset("\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c\u200b\u2060\ufeff")


class AttachmentError(Exception):
    """Safe provider failure. Only these fixed codes reach callers."""
    _STATUS = {"not_found": 404, "attachment_expired": 410, "attachment_deleted": 410,
               "attachment_unavailable": 503, "attachment_conflict": 409,
               "attachment_rate_limited": 429, "request_invalid": 422}

    def __init__(self, code: str, *, retry_after: int | None = None):
        self.code = code if code in self._STATUS else "attachment_unavailable"
        self.status_code = self._STATUS[self.code]
        self.retry_after = retry_after
        super().__init__(self.code)

    def http(self) -> HTTPException:
        return HTTPException(self.status_code, detail="Not found" if self.status_code == 404 else {"code": self.code},
                             headers={"Retry-After": str(max(1, min(self.retry_after, 3600)))}
                             if self.status_code == 429 and self.retry_after is not None else None)


class AttachmentRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    size: StrictInt = Field(ge=1, le=MAX_FILE_BYTES)
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("id")
    @classmethod
    def valid_id(cls, value):
        if str(UUID(value)) != value:
            raise ValueError("invalid attachment id")
        return value


class AttachmentDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    filename: str
    media_type: str
    size: StrictInt = Field(ge=1, le=MAX_FILE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: str

    @field_validator("id")
    @classmethod
    def valid_id(cls, value):
        return AttachmentRef.valid_id(value)

    @field_validator("filename")
    @classmethod
    def valid_filename(cls, value):
        if (not value or value != value.strip() or value in {".", ".."}
                or "/" in value or "\\" in value or len(value.encode("utf-8")) > 255
                or any(unicodedata.category(c) in {"Cc", "Cs"} or c in _UNSAFE for c in value)):
            raise ValueError("invalid attachment filename")
        return value

    @field_validator("media_type")
    @classmethod
    def valid_media_type(cls, value):
        if value not in MEDIA_TYPES:
            raise ValueError("invalid attachment media type")
        return value

    @field_validator("expires_at")
    @classmethod
    def valid_expiry(cls, value):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError("attachment expiry must be UTC")
        return value

    def ref(self) -> AttachmentRef:
        return AttachmentRef(id=self.id, size=self.size,
                             descriptor_sha256=sha256(canonical_json_bytes(self.model_dump())).hexdigest())


def descriptors(value: Any) -> list[AttachmentDescriptor]:
    try:
        if not isinstance(value, list) or len(value) > 4:
            raise ValueError()
        result = [AttachmentDescriptor.model_validate(item) for item in value]
        if len({item.id for item in result}) != len(result):
            raise ValueError()
        return result
    except (ValueError, TypeError, UnicodeError):
        raise AttachmentError("request_invalid") from None


def refs(value: Any) -> list[AttachmentRef]:
    try:
        if not isinstance(value, list) or len(value) > 4:
            raise ValueError()
        result = [AttachmentRef.model_validate(item) for item in value]
        if len({item.id for item in result}) != len(result):
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise AttachmentError("request_invalid") from None


def readable_attachments(value: Any) -> dict:
    """All-or-none projection; preserve independently decryptable text."""
    try:
        return {"attachments": [item.model_dump() for item in descriptors([] if value is None else value)],
                "attachments_available": True}
    except AttachmentError:
        return {"attachments": [], "attachments_available": False}


@dataclass(frozen=True)
class AttachmentBinding:
    kind: Literal["mail", "chat"]
    message_id: str
    conversation_id: str
    sender_did: str
    participant_dids: tuple[str, ...]
    sender_agent_id: str | None = None
    team_id: str | None = None


@dataclass(frozen=True)
class AttachmentParticipant:
    dids: tuple[str, ...]
    agent_id: str | None
    team_id: str | None


class AttachmentTransaction(Protocol):
    """pgdbm TransactionManager; schema views MUST reuse this connection."""
    @property
    def connection(self) -> Any: ...
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetch_one(self, query: str, *args: Any) -> Any: ...
    async def fetch_all(self, query: str, *args: Any) -> Any: ...


class AttachmentBackend(Protocol):
    async def bind(self, tx: AttachmentTransaction, *, binding: AttachmentBinding,
                   refs: list[AttachmentRef], message: dict) -> None:
        """Decrypt/validate staged commitments then bind once in tx; no network.

        Must prove ordered equality to authenticated inner descriptors, reject
        undecryptable custody and actor/recipient/conversation disagreement,
        enforce lifecycle/quota, and propagate failures. Only bind authority.
        """
        ...

    async def read(self, db: Any, *, binding: AttachmentBinding,
                   participant: AttachmentParticipant, ref: AttachmentRef) -> tuple[AttachmentDescriptor, bytes]:
        """Repeat message-content authority, lifecycle and participant rate bound.

        Return bounded managed plaintext and its immutable descriptor; never a
        URL. Raise only safe AttachmentError codes. No provider => unavailable.
        """
        ...
