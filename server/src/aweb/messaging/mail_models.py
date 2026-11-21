"""Accepted mail inputs shared by HTTP, MCP and native embedding.

These are the existing route models, reexported there for Python callers.
"""

from __future__ import annotations

from aweb.messaging.kinds import ContentMode

from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from aweb.messaging.alias_targets import validate_alias_selector
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference

from aweb.messaging.kinds import MessagePriority


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1)
    to_did: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_stable_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_address: Optional[str] = Field(default=None, min_length=1, max_length=256)
    conversation_id: Optional[str] = None
    new_conversation: bool = (
        False  # Accepted no-op; conversation_id alone selects continuation.
    )
    subject: str = ""
    body: str = ""
    content_mode: Optional[str] = None
    message_version: Optional[int] = None
    encrypted_envelope: Optional[dict] = None
    priority: MessagePriority = MessagePriority.NORMAL
    message_id: Optional[str] = None
    timestamp: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    signature: Optional[str] = Field(default=None, max_length=512)
    signed_payload: Optional[str] = None
    attachments: object = None
    attachment_refs: object = None

    @model_validator(mode="after")
    def _validate_content_mode(self):
        is_encrypted = (
            self.content_mode == ContentMode.ENCRYPTED
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if is_encrypted:
            if self.content_mode != ContentMode.ENCRYPTED:
                raise ValueError(
                    "content_mode must be encrypted_v2 for encrypted messages"
                )
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted messages")
            if self.encrypted_envelope is None:
                raise ValueError(
                    "encrypted_envelope is required for encrypted messages"
                )
            if self.subject or self.body:
                raise ValueError(
                    "encrypted messages must not include plaintext subject or body"
                )
        elif self.body == "":
            raise ValueError("body is required for legacy plaintext mail")
        return self

    @model_validator(mode="before")
    @classmethod
    def _normalize_hosted_handle_targets(cls, data):
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        to_alias = str(normalized.get("to_alias") or "").strip()
        if to_alias.startswith("@"):
            address = normalize_hosted_handle_reference(to_alias, require_agent=True)
            if (
                address != to_alias
                and "/" in address
                and not normalized.get("to_address")
            ):
                normalized["to_address"] = address
                normalized.pop("to_alias", None)
        if normalized.get("to_address") is not None:
            normalized["to_address"] = normalize_hosted_handle_reference(
                str(normalized["to_address"]),
                require_agent=True,
            )
        return normalized

    @field_validator("to_agent_id")
    @classmethod
    def _validate_agent_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            return str(UUID(str(v).strip()))
        except ValueError as exc:
            raise ValueError("Invalid agent_id format") from exc

    @field_validator("to_alias")
    @classmethod
    def _validate_to_alias(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_alias_selector(v, field="to_alias")

    @field_validator("to_address")
    @classmethod
    def _validate_to_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip()
        if value.startswith("@"):
            raise ValueError("Invalid to_address format")
        return value

    @field_validator("message_id")
    @classmethod
    def _validate_message_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except ValueError as exc:
            raise ValueError("Invalid message_id format") from exc

    @field_validator("conversation_id")
    @classmethod
    def _validate_conversation_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except ValueError as exc:
            raise ValueError("Invalid conversation_id format") from exc
