"""Signed envelope contract for federated mail/chat delivery."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature

FEDERATION_ENVELOPE_VERSION = 1
FEDERATION_TIMESTAMP_SKEW_SECONDS = 300

MessageType = Literal["mail", "chat"]


class FederationEnvelopeError(ValueError):
    """Raised when a federated delivery envelope fails contract validation."""


class FederationEnvelope(BaseModel):
    """Canonical behavior-shaping payload signed for remote mail/chat delivery."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = FEDERATION_ENVELOPE_VERSION
    type: MessageType
    sender_did_aw: str = Field(..., min_length=1, max_length=256)
    sender_current_did_key: str = Field(..., min_length=1, max_length=256)
    sender_address: str | None = Field(default=None, min_length=1, max_length=256)
    sender_active_team_id: str | None = Field(default=None, min_length=1, max_length=512)
    sender_team_certificate: dict[str, Any] | None = None
    target_address: str = Field(..., min_length=1, max_length=256)
    target_did_aw: str = Field(..., min_length=1, max_length=256)
    target_current_did_key: str = Field(..., min_length=1, max_length=256)
    target_delivery_origin: str = Field(..., min_length=1, max_length=512)
    body: str
    message_id: str
    timestamp: str
    conversation_id: str | None = Field(default=None, min_length=1, max_length=64)
    subject: str | None = None
    priority: str | None = None

    @field_validator("sender_did_aw", "target_did_aw")
    @classmethod
    def _validate_did_aw(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("did:aw:"):
            raise ValueError("must be a did:aw")
        return value

    @field_validator("sender_current_did_key", "target_current_did_key")
    @classmethod
    def _validate_did_key(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("did:key:"):
            raise ValueError("must be a did:key")
        return value

    @field_validator("target_delivery_origin")
    @classmethod
    def _validate_delivery_origin(cls, value: str) -> str:
        return canonical_server_origin(value)

    @field_validator("message_id", "conversation_id")
    @classmethod
    def _validate_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(UUID(value.strip()))
        except Exception as exc:
            raise ValueError("must be a UUID") from exc

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: str) -> str:
        _parse_timestamp(value)
        return value


def canonical_federation_payload(envelope: FederationEnvelope | Mapping[str, Any]) -> bytes:
    """Return canonical bytes for the signed federation envelope."""
    model = (
        envelope
        if isinstance(envelope, FederationEnvelope)
        else FederationEnvelope.model_validate(envelope)
    )
    return canonical_json_bytes(model.model_dump(mode="json", exclude_none=True))


def verify_federation_envelope(
    envelope: FederationEnvelope | Mapping[str, Any],
    signature: str,
    *,
    expected: Mapping[str, Any | None] | None = None,
    now: datetime | None = None,
    max_skew_seconds: int = FEDERATION_TIMESTAMP_SKEW_SECONDS,
) -> FederationEnvelope:
    """Validate the envelope contract and sender signature.

    `expected` is for outer transport fields that must match the signed payload,
    such as the endpoint message type, resolved target address, message id, or
    target delivery origin.
    """
    model = (
        envelope
        if isinstance(envelope, FederationEnvelope)
        else FederationEnvelope.model_validate(envelope)
    )
    _enforce_timestamp_skew(model.timestamp, now=now, max_skew_seconds=max_skew_seconds)
    _enforce_expected_fields(model, expected or {})
    try:
        verify_did_key_signature(
            did_key=model.sender_current_did_key,
            payload=canonical_federation_payload(model),
            signature_b64=signature,
        )
    except Exception as exc:
        raise FederationEnvelopeError("Invalid federation envelope signature") from exc
    return model


def require_team_certificate_for_non_public_reachability(
    envelope: FederationEnvelope,
    *,
    reachability: str,
) -> None:
    """Require the carried team certificate when private awid reachability was used."""
    if reachability == "public":
        return
    if envelope.sender_team_certificate is None:
        raise FederationEnvelopeError("Federation envelope is missing sender_team_certificate")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError("Invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    if parsed.microsecond != 0:
        raise ValueError("timestamp must be second precision")
    return parsed.astimezone(timezone.utc)


def _enforce_timestamp_skew(value: str, *, now: datetime | None, max_skew_seconds: int) -> None:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    timestamp = _parse_timestamp(value)
    if abs((current - timestamp).total_seconds()) > max_skew_seconds:
        raise FederationEnvelopeError("Federation envelope timestamp outside accepted skew")


def _enforce_expected_fields(model: FederationEnvelope, expected: Mapping[str, Any | None]) -> None:
    payload = model.model_dump(mode="json", exclude_none=True)
    for field, expected_value in expected.items():
        actual = payload.get(field)
        if actual != expected_value:
            raise FederationEnvelopeError(f"Federation envelope {field} does not match")
