"""Accepted chat inputs shared by HTTP, MCP and native embedding.

These are the existing route models, reexported there for Python callers.
"""

from __future__ import annotations

from aweb.messaging.kinds import ContentMode

from typing import Any
from uuid import UUID
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from aweb.messaging.alias_targets import validate_alias_selector
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference


def _parse_uuid(value: str, *, field: str) -> str:
    try:
        return str(UUID(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid {field} format") from exc


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None = None
    to_aliases: list[str] = Field(default_factory=list)
    to_dids: list[str] = Field(default_factory=list)
    to_addresses: list[str] = Field(default_factory=list)
    message: str
    content_mode: str = ContentMode.PLAINTEXT
    message_version: int = 1
    encrypted_envelope: dict[str, Any] | None = None
    leaving: bool = False
    hang_on: bool = False
    wait_seconds: int | None = None
    message_id: str | None = None
    reply_to: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None
    attachments: object = None
    attachment_refs: object = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_hosted_handle_targets(cls, data):
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        aliases: list[str] = []
        promoted_addresses: list[str] = []
        for value in normalized.get("to_aliases") or []:
            text = str(value or "").strip()
            address = normalize_hosted_handle_reference(text, require_agent=True)
            if text.startswith("@") and address != text and "/" in address:
                promoted_addresses.append(address)
            else:
                aliases.append(text)
        if promoted_addresses:
            normalized["to_aliases"] = aliases
            normalized["to_addresses"] = (
                list(normalized.get("to_addresses") or []) + promoted_addresses
            )
        if normalized.get("to_addresses"):
            normalized["to_addresses"] = [
                normalize_hosted_handle_reference(str(value), require_agent=True)
                for value in normalized.get("to_addresses") or []
            ]
        return normalized

    @field_validator("to_aliases", "to_dids", "to_addresses")
    @classmethod
    def _clean_targets(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values or []:
            value = (value or "").strip()
            if value:
                cleaned.append(value)
        return cleaned

    @field_validator("to_aliases")
    @classmethod
    def _validate_aliases(cls, values: list[str]) -> list[str]:
        return [validate_alias_selector(value, field="to_aliases") for value in values]

    @field_validator("to_addresses")
    @classmethod
    def _validate_addresses(cls, values: list[str]) -> list[str]:
        for value in values:
            if value.startswith("@"):
                raise ValueError("Invalid to_addresses format")
        return values

    @model_validator(mode="after")
    def _validate_targets(self) -> "CreateSessionRequest":
        if not self.to_aliases and not self.to_dids and not self.to_addresses:
            raise ValueError("Must provide to_aliases, to_dids, or to_addresses")
        if len(self.to_aliases) != len(set(self.to_aliases)):
            raise ValueError("to_aliases contains duplicates")
        if len(self.to_dids) != len(set(self.to_dids)):
            raise ValueError("to_dids contains duplicates")
        if len(self.to_addresses) != len(set(self.to_addresses)):
            raise ValueError("to_addresses contains duplicates")
        return self

    @model_validator(mode="after")
    def _validate_content_mode(self) -> "CreateSessionRequest":
        encrypted = (
            self.content_mode == ContentMode.ENCRYPTED
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if encrypted:
            if self.content_mode != ContentMode.ENCRYPTED:
                raise ValueError("content_mode must be encrypted_v2 for encrypted chat")
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted chat")
            if self.encrypted_envelope is None:
                raise ValueError("encrypted_envelope is required for encrypted chat")
        elif self.content_mode != ContentMode.PLAINTEXT or self.message_version != 1:
            raise ValueError("unsupported chat content mode")
        return self

    @field_validator("session_id", "message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None, info: ValidationInfo) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field=str(info.field_name or "message_id"))


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = ""
    content_mode: str = ContentMode.PLAINTEXT
    message_version: int = 1
    encrypted_envelope: dict[str, Any] | None = None
    leaving: bool = False
    hang_on: bool = False
    wait_seconds: int | None = Field(default=None, ge=0, le=600)
    reply_to: str | None = None
    message_id: str | None = None
    timestamp: str | None = None
    from_did: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=512)
    signed_payload: str | None = None
    attachments: object = None
    attachment_refs: object = None

    @model_validator(mode="after")
    def _validate_content_mode(self) -> "SendMessageRequest":
        encrypted = (
            self.content_mode == ContentMode.ENCRYPTED
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if encrypted:
            if self.content_mode != ContentMode.ENCRYPTED:
                raise ValueError("content_mode must be encrypted_v2 for encrypted chat")
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted chat")
            if self.encrypted_envelope is None:
                raise ValueError("encrypted_envelope is required for encrypted chat")
            return self
        if self.content_mode != ContentMode.PLAINTEXT or self.message_version != 1:
            raise ValueError("unsupported chat content mode")
        if not self.body:
            raise ValueError("body is required")
        return self

    @field_validator("message_id", "reply_to")
    @classmethod
    def _validate_message_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _parse_uuid(v, field="message_id")
