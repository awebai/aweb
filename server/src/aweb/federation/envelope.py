"""Federated mail/chat delivery envelope validation.

The federation transport envelope is not itself the sender-signed payload.
Self-custodial clients already sign the canonical mail/chat message payload
before handing it to their local server. The sender's server must preserve that
payload and signature when forwarding cross-server; it cannot manufacture a new
sender signature over a different federation wrapper.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from awid.log import canonical_server_origin
from awid.signing import verify_did_key_signature
from aweb.e2ee_messages import E2EEEnvelopeError, validate_e2ee_message_envelope
from aweb.messaging.signatures import (
    MessageSignatureShapeError,
    validate_ed25519_message_signature,
)

FEDERATION_ENVELOPE_VERSION = 1
FEDERATION_TIMESTAMP_SKEW_SECONDS = 300

MessageType = Literal["mail", "chat"]


class FederationEnvelopeError(ValueError):
    """Raised when a federated delivery envelope fails contract validation."""


class FederationEnvelope(BaseModel):
    """Transport wrapper around an existing sender-signed mail/chat payload."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = FEDERATION_ENVELOPE_VERSION
    type: MessageType
    sender_did_aw: str = Field(..., min_length=1, max_length=256)
    sender_current_did_key: str = Field(..., min_length=1, max_length=256)
    sender_address: str | None = Field(default=None, min_length=1, max_length=256)
    sender_delivery_origin: str | None = Field(default=None, min_length=1, max_length=512)
    # Deprecated v1 compatibility fields accepted only to tolerate old senders
    # during a bounded rollout window. They are intentionally ignored by all
    # routing, lookup, authorization, and delivery checks.
    sender_active_team_id: str | None = None
    sender_team_certificate: dict[str, Any] | None = None
    target_address_lookup_authorization: str | None = None
    target_address_lookup_timestamp: str | None = None
    target_address: str = Field(..., min_length=1, max_length=256)
    target_did_aw: str = Field(..., min_length=1, max_length=256)
    target_current_did_key: str = Field(..., min_length=1, max_length=256)
    target_delivery_origin: str = Field(..., min_length=1, max_length=512)
    body: str
    message_id: str
    timestamp: str
    signed_payload: str | None = None
    conversation_id: str | None = Field(default=None, min_length=1, max_length=64)
    subject: str | None = None
    priority: str | None = None
    content_mode: str | None = None
    message_version: int | None = None
    encrypted_envelope: dict[str, Any] | None = None
    wait_seconds: int | None = None
    reply_to: str | None = Field(default=None, min_length=1, max_length=64)
    sender_leaving: bool = False
    hang_on: bool = False

    @field_validator("sender_did_aw", "target_did_aw")
    @classmethod
    def _validate_routing_did(cls, value: str) -> str:
        value = value.strip()
        if not (value.startswith("did:aw:") or value.startswith("did:key:")):
            raise ValueError("must be a did:aw or did:key")
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

    @field_validator("sender_delivery_origin")
    @classmethod
    def _validate_optional_delivery_origin(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return canonical_server_origin(value)

    @field_validator("message_id", "conversation_id", "reply_to")
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
    def _validate_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _parse_timestamp(value)
        return value


class FederatedDeliveryRequest(BaseModel):
    """Request body sent from one aweb server to another."""

    model_config = ConfigDict(extra="forbid")

    envelope: FederationEnvelope
    signature: str = Field(..., min_length=1, max_length=512)


def verify_federation_envelope(
    envelope: FederationEnvelope | Mapping[str, Any],
    signature: str,
    *,
    expected: Mapping[str, Any | None] | None = None,
    now: datetime | None = None,
    max_skew_seconds: int = FEDERATION_TIMESTAMP_SKEW_SECONDS,
) -> FederationEnvelope:
    """Validate the transport envelope and the preserved sender signature.

    `expected` is for outer transport fields that must match the signed payload,
    such as the endpoint message type, resolved target address, message id, or
    target delivery origin.
    """
    model = (
        envelope
        if isinstance(envelope, FederationEnvelope)
        else FederationEnvelope.model_validate(envelope)
    )
    enforce_message_timestamp_skew(
        _parse_timestamp(model.timestamp),
        now=now,
        max_skew_seconds=max_skew_seconds,
        label="Federation envelope timestamp",
    )
    _enforce_expected_fields(model, expected or {})
    if _is_encrypted_v2(model):
        signed_sender_address = _enforce_encrypted_payload_binding(model, signature, now=now)
        return model.model_copy(update={"sender_address": signed_sender_address})
    if not model.signed_payload:
        raise FederationEnvelopeError("Federation signed_payload is required")
    signed_sender_address = _enforce_signed_payload_binding(model)
    try:
        validate_ed25519_message_signature(signature)
    except MessageSignatureShapeError as exc:
        raise FederationEnvelopeError(str(exc)) from exc
    try:
        verify_did_key_signature(
            did_key=model.sender_current_did_key,
            payload=model.signed_payload.encode("utf-8"),
            signature_b64=signature,
        )
    except Exception as exc:
        raise FederationEnvelopeError("Invalid federation message signature") from exc
    return model.model_copy(update={"sender_address": signed_sender_address})


def _is_encrypted_v2(model: FederationEnvelope) -> bool:
    return (
        model.content_mode == "encrypted_v2"
        or model.message_version == 2
        or model.encrypted_envelope is not None
    )


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


def enforce_message_timestamp_skew(
    timestamp: datetime,
    *,
    now: datetime | None = None,
    max_skew_seconds: int = FEDERATION_TIMESTAMP_SKEW_SECONDS,
    label: str = "timestamp",
) -> None:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if abs((current - timestamp).total_seconds()) > max_skew_seconds:
        raise FederationEnvelopeError(f"{label} outside accepted skew")


def _enforce_expected_fields(model: FederationEnvelope, expected: Mapping[str, Any | None]) -> None:
    payload = model.model_dump(mode="json", exclude_none=True)
    for field, expected_value in expected.items():
        actual = payload.get(field)
        if actual != expected_value:
            raise FederationEnvelopeError(f"Federation envelope {field} does not match")


def _signed_payload_json(model: FederationEnvelope) -> dict[str, Any]:
    try:
        payload = json.loads(model.signed_payload)
    except Exception as exc:
        raise FederationEnvelopeError("Federation signed_payload must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise FederationEnvelopeError("Federation signed_payload must be a JSON object")
    return payload


def _expect_signed_value(payload: Mapping[str, Any], field: str, expected: Any) -> None:
    actual = payload.get(field)
    if actual != expected:
        raise FederationEnvelopeError(f"Federation signed_payload {field} does not match")


def _expect_signed_value_in(payload: Mapping[str, Any], field: str, allowed: tuple[Any, ...]) -> None:
    actual = payload.get(field)
    if not any(actual == value for value in allowed):
        raise FederationEnvelopeError(f"Federation signed_payload {field} does not match")


def _enforce_signed_payload_binding(model: FederationEnvelope) -> str | None:
    payload = _signed_payload_json(model)
    _expect_signed_value(payload, "type", model.type)
    _expect_signed_value(payload, "body", model.body)
    _expect_signed_value(payload, "from_did", model.sender_current_did_key)
    _expect_signed_value(payload, "message_id", model.message_id)
    _expect_signed_value(payload, "timestamp", model.timestamp)
    # First-contact federation signs the routable address. Continuations may
    # sign the already-vetted recipient identity while the envelope still carries
    # target_address as the transport route.
    _expect_signed_value_in(
        payload,
        "to",
        (model.target_address, model.target_did_aw, model.target_current_did_key),
    )
    # Local signed-message validation accepts to_did as either the stable
    # did:aw or the current did:key. Federation must preserve that same signed
    # payload vocabulary while the envelope still carries the resolved current
    # key for routing/freshness checks.
    signed_to_did = str(payload.get("to_did") or "").strip()
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if signed_to_did:
        _expect_signed_value_in(
            payload,
            "to_did",
            (model.target_current_did_key, model.target_did_aw),
        )
    elif signed_to_stable_id != model.target_did_aw:
        raise FederationEnvelopeError("Federation signed_payload to_did does not match")
    if model.target_did_aw.startswith("did:aw:"):
        if signed_to_stable_id != model.target_did_aw:
            raise FederationEnvelopeError("Federation signed_payload to_stable_id does not match")
    elif payload.get("to_stable_id") not in (None, "", model.target_did_aw):
        raise FederationEnvelopeError("Federation signed_payload to_stable_id does not match")
    if model.sender_did_aw.startswith("did:aw:"):
        _expect_signed_value(payload, "from_stable_id", model.sender_did_aw)
    elif payload.get("from_stable_id") not in (None, "", model.sender_did_aw):
        raise FederationEnvelopeError("Federation signed_payload from_stable_id does not match")
    signed_sender = str(payload.get("from") or "").strip() or None
    if model.sender_address is not None and signed_sender != model.sender_address:
        raise FederationEnvelopeError("Federation signed_payload from does not match")
    signed_sender_address = (
        signed_sender
        if signed_sender is not None and "/" in signed_sender
        else None
    )
    if model.conversation_id is not None:
        _expect_signed_value(payload, "conversation_id", model.conversation_id)
    elif payload.get("conversation_id"):
        raise FederationEnvelopeError("Federation signed_payload conversation_id does not match")
    if model.type == "mail":
        _expect_signed_value(payload, "subject", model.subject or "")
        signed_priority = payload.get("priority") or "normal"
        if signed_priority != (model.priority or "normal"):
            raise FederationEnvelopeError("Federation signed_payload priority does not match")
    if model.type == "chat":
        if payload.get("wait_seconds") != model.wait_seconds:
            raise FederationEnvelopeError("Federation signed_payload wait_seconds does not match")
        if (payload.get("reply_to") or None) != model.reply_to:
            raise FederationEnvelopeError("Federation signed_payload reply_to does not match")
        if bool(payload.get("sender_leaving")) != model.sender_leaving:
            raise FederationEnvelopeError("Federation signed_payload sender_leaving does not match")
        if bool(payload.get("hang_on")) != model.hang_on:
            raise FederationEnvelopeError("Federation signed_payload hang_on does not match")
    return signed_sender_address


def _enforce_encrypted_payload_binding(
    model: FederationEnvelope,
    signature: str,
    *,
    now: datetime | None,
) -> str | None:
    if model.content_mode != "encrypted_v2":
        raise FederationEnvelopeError("Federation encrypted content_mode must be encrypted_v2")
    if model.message_version != 2:
        raise FederationEnvelopeError("Federation encrypted message_version must be 2")
    if not isinstance(model.encrypted_envelope, dict):
        raise FederationEnvelopeError("Federation encrypted_envelope must be an object")
    if model.encrypted_envelope.get("signature") != signature:
        raise FederationEnvelopeError("Federation encrypted signature does not match envelope signature")
    if (model.subject or "") != "":
        raise FederationEnvelopeError("Federation encrypted subject must be empty")
    if model.body != "":
        raise FederationEnvelopeError("Federation encrypted body must be empty")
    if model.signed_payload is not None:
        raise FederationEnvelopeError("Federation encrypted signed_payload must be absent")
    if (model.timestamp or "") != str(model.encrypted_envelope.get("created_at") or ""):
        raise FederationEnvelopeError("Federation encrypted timestamp does not match envelope created_at")
    try:
        validate_e2ee_message_envelope(
            model.encrypted_envelope,
            kind=model.type,
            message_id=model.message_id,
            conversation_id=model.conversation_id or "",
            sender_did=model.sender_current_did_key,
            sender_stable_id=model.sender_did_aw if model.sender_did_aw.startswith("did:aw:") else None,
            recipients=[
                {
                    "did": model.target_current_did_key,
                    "stable_id": model.target_did_aw if model.target_did_aw.startswith("did:aw:") else None,
                    "address": model.target_address,
                }
            ],
            now=now,
        )
    except E2EEEnvelopeError as exc:
        raise FederationEnvelopeError(str(exc)) from exc
    sender = model.encrypted_envelope.get("from")
    signed_sender_address = (
        str(sender.get("address") or "").strip() or None
        if isinstance(sender, dict)
        else None
    )
    if model.sender_address is not None and signed_sender_address != model.sender_address:
        raise FederationEnvelopeError("Federation encrypted sender address does not match")
    return signed_sender_address
