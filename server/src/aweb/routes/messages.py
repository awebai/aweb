from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aweb.deps import get_db
from aweb.config import get_settings
from aweb.e2ee_messages import (
    E2EEEnvelopeError,
    encrypted_message_storage_metadata,
    validate_e2ee_mail_envelope,
)
from aweb.federation.envelope import (
    FederationEnvelope,
    FederationEnvelopeError,
    verify_federation_envelope,
)
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_mail
from aweb.hooks import fire_mutation_hook
from aweb.identity_metadata import lookup_identity_metadata_by_did
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    derive_team_address,
    get_agent_by_namespace_alias,
    namespace_exists,
    resolve_alias_target,
    team_exists,
    validate_alias_selector,
)
from aweb.messaging.address_auth import (
    local_recipient_visible_to_auth,
    requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.conversations import (
    create_conversation,
    find_active_one_to_one_conversation_between,
    get_conversation,
    touch_conversation_activity,
)
from aweb.messaging.contacts import upsert_successful_identity_contact
from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.mail_routing import (
    MailContinuationContext,
    explicit_mail_target_matches_participant,
    mail_continuation_context,
    participant_is_remote,
    recipient_for_conversation_participant,
    remote_recipient_from_participant,
    with_requested_address as _with_requested_address,
)
from aweb.messaging.messages import (
    MessagePriority,
    authorize_message_delivery,
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
    resolve_agent_by_did,
    utc_iso as _utc_iso,
)
from aweb.messaging.verification import (
    message_verification_status,
    require_conversation_not_legacy_bound,
)
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ServiceError, ValidationError

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


async def _resolve_message_alias(db, auth: MessagingAuth, raw_alias: str) -> dict | None:
    target = resolve_alias_target(auth.team_id, raw_alias, field="to_alias")
    if "~" in str(raw_alias or "") and not await team_exists(db, target.team_id):
        raise HTTPException(status_code=404, detail=f"Unknown team: {target.team_id}")
    return await get_agent_by_alias(db, team_id=target.team_id, alias=target.alias)


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1)
    to_did: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_stable_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    to_address: Optional[str] = Field(default=None, min_length=1, max_length=256)
    conversation_id: Optional[str] = None
    subject: str = ""
    body: str = ""
    content_mode: Optional[str] = None
    message_version: Optional[int] = None
    encrypted_envelope: Optional[dict] = None
    priority: MessagePriority = "normal"
    message_id: Optional[str] = None
    timestamp: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    signature: Optional[str] = Field(default=None, max_length=512)
    signed_payload: Optional[str] = None

    @model_validator(mode="after")
    def _validate_content_mode(self):
        is_encrypted = (
            self.content_mode == "encrypted_v2"
            or self.message_version == 2
            or self.encrypted_envelope is not None
        )
        if is_encrypted:
            if self.content_mode != "encrypted_v2":
                raise ValueError("content_mode must be encrypted_v2 for encrypted messages")
            if self.message_version != 2:
                raise ValueError("message_version must be 2 for encrypted messages")
            if self.encrypted_envelope is None:
                raise ValueError("encrypted_envelope is required for encrypted messages")
            if self.subject or self.body:
                raise ValueError("encrypted messages must not include plaintext subject or body")
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
            if address != to_alias and "/" in address and not normalized.get("to_address"):
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
        except Exception:
            raise ValueError("Invalid agent_id format")

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
        except Exception:
            raise ValueError("Invalid message_id format")

    @field_validator("conversation_id")
    @classmethod
    def _validate_conversation_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid conversation_id format")


class SendMessageResponse(BaseModel):
    message_id: str
    conversation_id: Optional[str] = None
    status: str
    delivered_at: str


class InboxMessage(BaseModel):
    message_id: str
    conversation_id: Optional[str] = None
    from_agent_id: Optional[str] = None
    from_alias: str
    to_alias: str
    subject: Optional[str] = None
    body: Optional[str] = None
    content_mode: str = "legacy_plaintext_v1"
    message_version: int = 1
    encrypted_envelope: Optional[dict] = None
    priority: MessagePriority
    read_at: Optional[str]
    created_at: str
    from_did: Optional[str] = None
    to_did: Optional[str] = None
    from_stable_id: Optional[str] = None
    to_stable_id: Optional[str] = None
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    signature: Optional[str] = None
    signed_payload: Optional[str] = None
    verification_status: Optional[str] = None


class InboxResponse(BaseModel):
    messages: list[InboxMessage]


class AckResponse(BaseModel):
    message_id: str
    acknowledged_at: str


async def _inbox_response_from_rows(db, rows) -> InboxResponse:
    identity_map = await lookup_identity_metadata_by_did(
        db,
        [
            str(value).strip()
            for row in rows
            for value in (row.get("from_did"), row.get("to_did"))
            if value
        ],
    )

    messages = []
    for r in rows:
        from_did = (r.get("from_did") or "").strip()
        to_did = (r.get("to_did") or "").strip()
        content_mode = str(r.get("content_mode") or "legacy_plaintext_v1")
        encrypted_envelope = r.get("encrypted_envelope")
        if isinstance(encrypted_envelope, str):
            encrypted_envelope = json.loads(encrypted_envelope)
        messages.append(
            InboxMessage(
                message_id=str(r["message_id"]),
                conversation_id=(str(r["conversation_id"]) if r.get("conversation_id") else None),
                from_agent_id=(str(r["from_agent_id"]) if r.get("from_agent_id") else None),
                from_alias=r["from_alias"],
                to_alias=r["to_alias"],
                subject=(r["subject"] if content_mode == "legacy_plaintext_v1" else ""),
                body=(r["body"] if content_mode == "legacy_plaintext_v1" else ""),
                content_mode=content_mode,
                message_version=int(r.get("message_version") or 1),
                encrypted_envelope=(dict(encrypted_envelope) if encrypted_envelope is not None else None),
                priority=r["priority"],
                read_at=r["read_at"].isoformat() if r.get("read_at") else None,
                created_at=r["created_at"].isoformat(),
                from_did=from_did or None,
                to_did=to_did or None,
                from_stable_id=(identity_map.get(from_did, {}).get("stable_id") or None),
                to_stable_id=(identity_map.get(to_did, {}).get("stable_id") or None),
                from_address=(r.get("from_address") or identity_map.get(from_did, {}).get("address") or None),
                to_address=(identity_map.get(to_did, {}).get("address") or None),
                signature=r.get("signature"),
                signed_payload=r.get("signed_payload"),
                verification_status=message_verification_status(dict(r)),
            )
        )

    return InboxResponse(messages=messages)


@router.get("/conversations/{conversation_id}", response_model=InboxResponse)
async def get_mail_conversation(
    request: Request,
    conversation_id: str,
    db=Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> InboxResponse:
    del request
    aweb_db = db.get_manager("aweb")
    actor_dids = auth_dids(auth)
    if not actor_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    try:
        conv_uuid = UUID(conversation_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid conversation_id format")

    conversation = await aweb_db.fetch_one(
        """
        SELECT conversation_id, conversation_type
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        conv_uuid,
    )
    if conversation:
        if conversation["conversation_type"] != "mail":
            raise HTTPException(status_code=422, detail="Conversation is not a mail conversation")
        participant = await aweb_db.fetch_one(
            """
            SELECT 1
            FROM {{tables.conversation_participants}}
            WHERE conversation_id = $1
              AND did = ANY($2::text[])
            LIMIT 1
            """,
            conv_uuid,
            actor_dids,
        )
        if not participant:
            raise HTTPException(status_code=403, detail="Authenticated identity is not a participant in this conversation")
        rows = await aweb_db.fetch_all(
            """
            SELECT m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
                   m.subject, m.body, m.priority, m.read_at, m.created_at,
                   m.from_did, m.to_did, m.signature, m.signed_payload, m.conversation_id,
                   m.content_mode, m.message_version, m.encrypted_envelope
            FROM {{tables.messages}} m
            WHERE m.conversation_id = $1
            ORDER BY m.created_at ASC, m.message_id ASC
            LIMIT $2
            """,
            conv_uuid,
            limit,
        )
        return await _inbox_response_from_rows(db, rows)

    legacy_rows = await aweb_db.fetch_all(
        """
        SELECT m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.to_did, m.signature, m.signed_payload, m.conversation_id,
               m.content_mode, m.message_version, m.encrypted_envelope
        FROM {{tables.messages}} m
        WHERE m.message_id = $1
          AND (m.from_did = ANY($2::text[]) OR m.to_did = ANY($2::text[]))
        ORDER BY m.created_at ASC, m.message_id ASC
        LIMIT $3
        """,
        conv_uuid,
        actor_dids,
        limit,
    )
    if legacy_rows:
        raise HTTPException(
            status_code=404,
            detail="This is a legacy mail without a conversation; use --message-id",
        )
    raise HTTPException(status_code=404, detail="Conversation not found")


def _parse_signed_timestamp(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid timestamp format")
    if dt.tzinfo is None:
        raise HTTPException(status_code=422, detail="timestamp must be timezone-aware")
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond != 0:
        raise HTTPException(status_code=422, detail="timestamp must be second precision")
    return dt


def _validate_signed_mail_payload(
    *,
    signed_payload: str | None,
    recipient: dict | None,
    to_agent_id: str | None,
    to_alias: str | None,
    requested_to_alias: str | None,
    from_alias: str | None,
    from_address: str | None,
    from_stable_id: str | None,
    priority: MessagePriority,
    subject: str,
    body: str,
    from_did: str,
    message_id: str,
    timestamp: str,
    conversation_id: str | None = None,
) -> None:
    if signed_payload is None:
        return
    try:
        payload = json.loads(signed_payload)
    except Exception:
        raise HTTPException(status_code=422, detail="signed_payload must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="signed_payload must be a JSON object")
    if payload.get("type") != "mail":
        raise HTTPException(status_code=422, detail="signed_payload type must be mail")
    allowed_from_values = {
        value
        for value in (
            str(from_alias or "").strip(),
            str(from_address or "").strip(),
            str(from_did or "").strip(),
            str(from_stable_id or "").strip(),
        )
        if value
    }
    signed_from = str(payload.get("from") or "").strip()
    if signed_from and signed_from not in allowed_from_values:
        raise HTTPException(status_code=422, detail="signed_payload from must match the authenticated sender")
    recipient_alias = (recipient or {}).get("alias") or ""
    recipient_address = (recipient or {}).get("address") or ""
    recipient_stable_id = (recipient or {}).get("did_aw") or ""
    recipient_current_did = (recipient or {}).get("did_key") or ""
    alias_values = (
        ()
        if "~" in str(requested_to_alias or "")
        else (str(to_alias or "").strip(), str(recipient_alias).strip())
    )
    allowed_to_values = {
        value
        for value in (
            str(to_agent_id or "").strip(),
            str(requested_to_alias or "").strip(),
            str(recipient_address).strip(),
            str(recipient_stable_id).strip(),
            str(recipient_current_did).strip(),
            *alias_values,
        )
        if value
    }
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to not in allowed_to_values:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    signed_to_did = str(payload.get("to_did") or "").strip()
    if signed_to_did and signed_to_did not in {
        str(recipient_stable_id).strip(),
        str(recipient_current_did).strip(),
    }:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if signed_to_stable_id and signed_to_stable_id != str(recipient_stable_id).strip():
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    if (payload.get("priority") or "normal") != priority:
        raise HTTPException(status_code=422, detail="signed_payload priority must match the mail message")
    if payload.get("subject", "") != subject:
        raise HTTPException(status_code=422, detail="signed_payload subject must match the mail subject")
    if payload.get("body") != body:
        raise HTTPException(status_code=422, detail="signed_payload body must match the mail body")
    if payload.get("from_did") != from_did:
        raise HTTPException(status_code=422, detail="signed_payload from_did must match the authenticated sender")
    signed_from_stable_id = str(payload.get("from_stable_id") or "").strip()
    if signed_from_stable_id and signed_from_stable_id != str(from_stable_id or "").strip():
        raise HTTPException(
            status_code=422,
            detail="signed_payload from_stable_id must match the authenticated sender",
        )
    if payload.get("message_id") != message_id:
        raise HTTPException(status_code=422, detail="signed_payload message_id must match the mail message")
    if payload.get("timestamp") != timestamp:
        raise HTTPException(status_code=422, detail="signed_payload timestamp must match the mail message")
    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if conversation_id is not None:
        if not signed_conversation_id:
            raise HTTPException(status_code=422, detail="signed_payload conversation_id is required")
        if signed_conversation_id != conversation_id:
            raise HTTPException(status_code=422, detail="signed_payload conversation_id must match")
    elif signed_conversation_id:
        raise HTTPException(status_code=422, detail="signed_payload conversation_id must match")


def _external_recipient_from_address(address: str, resolution) -> dict:
    _, name = address.split("/", 1)
    delivery = getattr(resolution, "delivery", None)
    return {
        "agent_id": None,
        "team_id": None,
        "alias": name,
        "address": address,
        "did_aw": resolution.did_aw.strip(),
        "did_key": (getattr(resolution, "current_did_key", "") or "").strip(),
        "delivery_origin": (getattr(delivery, "origin", "") or "").strip(),
        "external": True,
    }


def _raise_bare_did_first_contact_unsupported() -> None:
    raise HTTPException(
        status_code=422,
        detail="Bare did:aw first-contact is unsupported; use to_address=domain/name or continue an existing conversation",
    )


def _sender_address(auth: MessagingAuth) -> str | None:
    return (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias) or None


def _recipient_transport_hint(payload: SendMessageRequest) -> str:
    if payload.to_address is not None:
        return "to_address"
    if payload.to_stable_id is not None:
        return "to_stable_id"
    if payload.to_did is not None:
        return "to_did"
    if payload.to_agent_id is not None:
        return "to_agent_id"
    if payload.to_alias is not None:
        return "to_alias"
    return "mail"


def _recipient_conversation_address(recipient: dict | None, payload: SendMessageRequest) -> str | None:
    address = str((recipient or {}).get("address") or "").strip()
    if address:
        return address
    requested_address = str(payload.to_address or "").strip()
    if requested_address:
        return requested_address
    return derive_team_address(
        str((recipient or {}).get("team_id") or ""),
        str((recipient or {}).get("alias") or ""),
    ) or None


async def _local_recipient_from_address(db, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _recipient_identity_matches(left: dict | None, right: dict | None) -> bool:
    if left is None or right is None:
        return False
    left_agent_id = str(left.get("agent_id") or "").strip()
    right_agent_id = str(right.get("agent_id") or "").strip()
    if left_agent_id and left_agent_id == right_agent_id:
        return True
    for field in ("did_aw", "did_key"):
        left_value = str(left.get(field) or "").strip()
        right_value = str(right.get(field) or "").strip()
        if left_value and right_value and left_value == right_value:
            return True
    return False


def _signed_payload_matches_address_binding(
    payload: dict | None,
    *,
    address: str,
    recipient: dict,
) -> bool:
    if not isinstance(payload, dict) or payload.get("type") != "mail":
        return False
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to != address:
        return False
    recipient_stable_id = str(recipient.get("did_aw") or "").strip()
    recipient_current_did = str(recipient.get("did_key") or "").strip()
    signed_to_did = str(payload.get("to_did") or "").strip()
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if not signed_to_did and not signed_to_stable_id:
        return False
    if signed_to_did and signed_to_did not in {recipient_stable_id, recipient_current_did}:
        return False
    if signed_to_stable_id and signed_to_stable_id != recipient_stable_id:
        return False
    return bool(recipient_stable_id or recipient_current_did)


def _signed_payload_conversation_id(signed_payload: str | None) -> str:
    if not signed_payload:
        return ""
    try:
        payload = json.loads(signed_payload)
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("conversation_id") or "").strip()


def _require_remote_mail_signature(payload: SendMessageRequest) -> None:
    if not payload.signature or not payload.signed_payload:
        raise HTTPException(
            status_code=422,
            detail="Federated mail delivery requires a sender-signed payload",
        )
    if not payload.from_did or not payload.from_did.strip():
        raise HTTPException(
            status_code=422,
            detail="from_did is required for federated mail delivery",
        )
    if not payload.message_id or not payload.timestamp or not payload.conversation_id:
        raise HTTPException(
            status_code=422,
            detail="message_id, timestamp, and conversation_id are required for federated mail delivery",
        )


def _validate_encrypted_payload(
    payload: SendMessageRequest,
    *,
    auth: MessagingAuth,
    sender_did: str,
    recipient: dict | None,
    recipient_did: str,
) -> dict | None:
    if payload.content_mode != "encrypted_v2":
        return None
    if payload.message_id is None or payload.conversation_id is None:
        raise HTTPException(
            status_code=422,
            detail="message_id and conversation_id are required for encrypted mail",
        )
    recipient_address = _recipient_conversation_address(recipient, payload)
    try:
        validate_e2ee_mail_envelope(
            payload.encrypted_envelope or {},
            message_id=payload.message_id,
            conversation_id=payload.conversation_id,
            sender_did=(auth.did_key or sender_did).strip(),
            sender_stable_id=(auth.did_aw or "").strip() or None,
            recipient_did=recipient_did,
            recipient_stable_id=str((recipient or {}).get("did_aw") or "").strip() or None,
            recipient_address=recipient_address,
        )
    except E2EEEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return encrypted_message_storage_metadata(payload.encrypted_envelope or {})


def _remote_delivery_origin(recipient: dict | None) -> str:
    return str((recipient or {}).get("delivery_origin") or "").strip()


def _local_public_origin(request: Request) -> str:
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    if configured:
        return configured
    return get_settings().public_origin


def _concrete_contact_address(recipient: dict | None) -> str:
    address = str((recipient or {}).get("address") or "").strip()
    return address if "/" in address else ""


async def record_successful_contact_side_effect(
    db,
    *,
    owner_did: str,
    sender_team_id: str | None,
    recipient: dict | None,
) -> bool:
    recipient_address = _concrete_contact_address(recipient)
    if not recipient_address:
        return False
    recipient_team_id = str((recipient or {}).get("team_id") or "").strip()
    sender_team = str(sender_team_id or "").strip()
    if sender_team and recipient_team_id and sender_team == recipient_team_id:
        return False
    return await upsert_successful_identity_contact(
        db,
        owner_did=owner_did,
        contact_address=recipient_address,
        label=str((recipient or {}).get("alias") or recipient_address),
    )


async def _deliver_remote_mail_and_project_locally(
    request: Request,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    recipient: dict,
    recipient_did: str,
    to_agent_id: str | None,
    to_alias: str | None,
    created_at: datetime | None,
    msg_uuid: UUID | None,
) -> SendMessageResponse:
    if payload.content_mode == "encrypted_v2":
        raise HTTPException(status_code=422, detail="Federated E2E mail delivery is not implemented yet")
    delivery_origin = _remote_delivery_origin(recipient)
    if not delivery_origin:
        raise HTTPException(
            status_code=424,
            detail="Recipient address has no federated delivery origin",
        )
    _require_remote_mail_signature(payload)
    sender_routing_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_routing_did:
        raise HTTPException(
            status_code=422,
            detail="Federated mail delivery requires a sender identity",
        )
    sender_current_did = payload.from_did.strip()
    if sender_current_did not in set(auth_dids(auth)):
        raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
    target_current_did = str(recipient.get("did_key") or "").strip()
    target_stable_id = str(recipient.get("did_aw") or recipient_did or "").strip()
    target_address = str(recipient.get("address") or payload.to_address or target_stable_id or "").strip()
    if not target_current_did or not target_stable_id or not target_address:
        raise HTTPException(
            status_code=422,
            detail="Federated mail delivery requires a resolved target identity",
        )
    try:
        envelope = FederationEnvelope(
            type="mail",
            sender_did_aw=sender_routing_did,
            sender_current_did_key=sender_current_did,
            sender_address=sender_address,
            sender_delivery_origin=_local_public_origin(request),
            target_address=target_address,
            target_did_aw=target_stable_id,
            target_current_did_key=target_current_did,
            target_delivery_origin=delivery_origin,
            body=payload.body,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            signed_payload=payload.signed_payload,
            conversation_id=payload.conversation_id,
            subject=payload.subject,
            priority=payload.priority,
        )
        verify_federation_envelope(
            envelope,
            payload.signature,
            expected={
                "type": "mail",
                "target_address": target_address,
                "target_did_aw": target_stable_id,
                "target_current_did_key": target_current_did,
                "target_delivery_origin": envelope.target_delivery_origin,
                "message_id": payload.message_id,
                "conversation_id": payload.conversation_id,
            },
        )
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        remote = await deliver_federated_mail(
            delivery_origin=delivery_origin,
            envelope=envelope,
            signature=payload.signature,
            transport=getattr(request.app.state, "federation_mail_transport", None),
        )
    except FederatedMailDeliveryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    conversation_id = str(remote.get("conversation_id") or payload.conversation_id or "").strip()
    message_id = str(remote.get("message_id") or payload.message_id or "").strip()
    delivered_at = str(remote.get("delivered_at") or (payload.timestamp or "")).strip()
    if conversation_id != payload.conversation_id:
        raise HTTPException(status_code=502, detail="Federated mail response conversation_id mismatch")
    if message_id != payload.message_id:
        raise HTTPException(status_code=502, detail="Federated mail response message_id mismatch")

    aweb_db = db.get_manager("aweb")
    existing_projection = await aweb_db.fetch_one(
        """
        SELECT message_id, conversation_id, created_at
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        msg_uuid,
    ) if msg_uuid is not None else None
    if existing_projection:
        return SendMessageResponse(
            message_id=str(existing_projection["message_id"]),
            conversation_id=str(existing_projection["conversation_id"]),
            status=str(remote.get("status") or "delivered"),
            delivered_at=delivered_at or _utc_iso(existing_projection["created_at"]),
        )

    try:
        existing_conversation = await aweb_db.fetch_one(
            """
            SELECT conversation_id
            FROM {{tables.conversations}}
            WHERE conversation_id = $1
            """,
            UUID(conversation_id),
        )
        if existing_conversation:
            conversation = {"conversation_id": str(existing_conversation["conversation_id"])}
        else:
            conversation = await create_conversation(
                db,
                conversation_type="mail",
                created_by_did=sender_did,
                conversation_id=conversation_id,
                initiator={
                    "did": sender_did,
                    "agent_id": auth.agent_id,
                    "alias": auth.alias or sender_address or sender_did,
                    "address": sender_address,
                    "transport_hint": "sender",
                },
                recipients=[
                    {
                        "did": recipient_did,
                        "agent_id": to_agent_id,
                        "alias": to_alias or recipient.get("alias") or recipient_did,
                        "address": target_address,
                        "delivery_origin": delivery_origin,
                        "current_did_key": target_current_did,
                        "transport_hint": _recipient_transport_hint(payload),
                    }
                ],
                team_id=auth.team_id,
            )
        local_message_id, local_created_at = await deliver_message(
            db,
            registry_client=registry_client,
            recipient_agent=recipient,
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_alias=auth.alias,
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            from_did=sender_did,
            to_did=recipient_did,
            sender_address=sender_address,
            subject=payload.subject,
            body=payload.body,
            priority=payload.priority,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            created_at=created_at,
            message_id=msg_uuid,
            conversation_id=conversation["conversation_id"],
            skip_policy_check=True,
        )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await record_successful_contact_side_effect(
        db,
        owner_did=sender_routing_did,
        sender_team_id=auth.team_id,
        recipient=recipient,
    )

    await fire_mutation_hook(
        request,
        "message.sent",
        {
            "team_id": auth.team_id,
            "from_agent_id": auth.agent_id,
            "from_did": sender_did,
            "from_did_aw": sender_routing_did if sender_routing_did.startswith("did:aw:") else None,
            "to_agent_id": to_agent_id,
            "from_alias": auth.alias or sender_did,
            "message_id": message_id or str(local_message_id),
            "conversation_id": conversation_id or conversation["conversation_id"],
            "to_alias": to_alias,
            "subject": payload.subject,
            "priority": payload.priority,
            "federated": True,
        },
    )

    return SendMessageResponse(
        message_id=message_id or str(local_message_id),
        conversation_id=conversation_id or conversation["conversation_id"],
        status=str(remote.get("status") or "delivered"),
        delivered_at=delivered_at or _utc_iso(local_created_at),
    )


async def _bound_recipient_from_address(
    db,
    *,
    registry_client,
    auth: MessagingAuth,
    address: str,
    expected_recipient: dict | None = None,
    signed_payload: str | None = None,
    signature: str | None = None,
) -> dict | None:
    if "/" not in address:
        raise HTTPException(status_code=422, detail="to_address must be domain/name")
    domain, name = address.split("/", 1)
    if registry_client is not None:
        resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolved is not None and resolved.did_aw:
            bound_recipient = await resolve_agent_by_did(db, resolved.did_aw)
            if bound_recipient is not None:
                return bound_recipient
    local_recipient = await _local_recipient_from_address(db, domain=domain, name=name)
    if requires_registry_address_binding(local_recipient):
        if local_recipient_visible_to_auth(local_recipient, auth):
            return local_recipient
        if registry_client is None:
            return local_recipient
        if (
            expected_recipient is not None
            and _recipient_identity_matches(local_recipient, expected_recipient)
            and _signed_payload_matches_address_binding(
                verified_signed_payload_json(
                    signed_payload=signed_payload,
                    signature=signature,
                    did_key=auth.did_key,
                ),
                address=address,
                recipient=local_recipient,
            )
        ):
            return local_recipient
        raise HTTPException(status_code=404, detail="Recipient address not found")
    return local_recipient


async def _send_mail_conversation_continuation(
    request: Request,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    conversation_id: str,
) -> SendMessageResponse:
    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    created_at = None

    try:
        continuation = await mail_continuation_context(
            db,
            conversation_id=conversation_id,
            sender_did=sender_did,
            equivalent_dids=auth_dids(auth),
        )
        recipient_participant = continuation.recipient_participant
        if participant_is_remote(recipient_participant):
            return await _send_federated_mail_conversation_continuation(
                request,
                payload,
                db,
                auth=auth,
                registry_client=registry_client,
                sender_address=sender_address,
                sender_did=sender_did,
                continuation=continuation,
            )
        recipient = await recipient_for_conversation_participant(db, recipient_participant)
        if payload.signature is not None:
            if payload.from_did is None or not payload.from_did.strip():
                raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
            from_did = payload.from_did.strip()
            if from_did not in set(auth_dids(auth)):
                raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
            if payload.message_id is None or payload.timestamp is None:
                raise HTTPException(
                    status_code=422,
                    detail="message_id and timestamp are required when signature is provided",
                )
            _validate_signed_mail_payload(
                signed_payload=payload.signed_payload,
                recipient=recipient,
                to_agent_id=payload.to_agent_id,
                to_alias=recipient_participant.get("alias"),
                requested_to_alias=payload.to_alias,
                from_alias=auth.alias,
                from_address=sender_address,
                from_stable_id=auth.did_aw,
                priority=payload.priority,
                subject=payload.subject,
                body=payload.body,
                from_did=from_did,
                message_id=payload.message_id,
                timestamp=payload.timestamp,
                conversation_id=conversation_id,
            )
            created_at = _parse_signed_timestamp(payload.timestamp)
        encrypted_metadata = _validate_encrypted_payload(
            payload,
            auth=auth,
            sender_did=sender_did,
            recipient=recipient,
            recipient_did=recipient_participant["did"],
        )
        message_id, created_at = await deliver_message(
            db,
            registry_client=registry_client,
            recipient_agent=recipient,
            team_id=continuation.conversation.get("team_id") or auth.team_id,
            from_agent_id=auth.agent_id,
            from_alias=auth.alias,
            to_agent_id=recipient_participant.get("agent_id"),
            to_alias=recipient_participant.get("alias"),
            from_did=sender_did,
            to_did=recipient_participant["did"],
            sender_address=sender_address,
            subject=payload.subject,
            body=payload.body,
            priority=payload.priority,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            content_mode=payload.content_mode or "legacy_plaintext_v1",
            message_version=payload.message_version or 1,
            encrypted_envelope=payload.encrypted_envelope,
            encrypted_metadata=encrypted_metadata,
            created_at=created_at,
            message_id=msg_uuid,
            conversation_id=conversation_id,
            sender_verified_team_id=auth.verified_team_id,
            sender_verified_dids=auth_dids(auth),
            stored_route_continuation=True,
        )
        await touch_conversation_activity(db, conversation_id=conversation_id)
    except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await fire_mutation_hook(
        request,
        "message.sent",
        {
            "team_id": auth.team_id,
            "from_agent_id": auth.agent_id,
            "from_did": sender_did,
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_agent_id": recipient_participant.get("agent_id"),
            "from_alias": auth.alias or sender_did,
            "message_id": str(message_id),
            "conversation_id": conversation_id,
            "to_alias": recipient_participant.get("alias"),
            "subject": payload.subject,
            "priority": payload.priority,
        },
    )

    return SendMessageResponse(
        message_id=str(message_id),
        conversation_id=conversation_id,
        status="delivered",
        delivered_at=_utc_iso(created_at),
    )


async def _send_federated_mail_conversation_continuation(
    request: Request,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    continuation: MailContinuationContext,
) -> SendMessageResponse:
    recipient_participant = continuation.recipient_participant
    try:
        recipient = await remote_recipient_from_participant(registry_client, recipient_participant)
    except (ValidationError, ServiceError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    created_at = _parse_signed_timestamp(payload.timestamp) if payload.timestamp else None
    return await _deliver_remote_mail_and_project_locally(
        request,
        payload,
        db,
        auth=auth,
        registry_client=registry_client,
        sender_address=sender_address,
        sender_did=sender_did,
        recipient=recipient,
        recipient_did=recipient_participant["did"],
        to_agent_id=None,
        to_alias=recipient_participant.get("alias"),
        created_at=created_at,
        msg_uuid=msg_uuid,
    )


async def _existing_mail_conversation_for_target(
    db,
    *,
    auth: MessagingAuth,
    sender_did: str,
    sender_address: str | None,
    payload: SendMessageRequest,
) -> dict | None:
    target_did = ""
    target_agent_id = None
    target_address = None

    if payload.to_stable_id is not None and payload.to_stable_id.strip():
        target_did = payload.to_stable_id.strip()
        recipient = await resolve_agent_by_did(db, target_did)
        if recipient is not None:
            target_agent_id = recipient.get("agent_id")
            target_address = (recipient.get("address") or "").strip() or None
    elif payload.to_did is not None and payload.to_did.strip():
        target_did = payload.to_did.strip()
        recipient = await resolve_agent_by_did(db, target_did)
        if recipient is not None:
            target_did = (recipient.get("did_aw") or recipient.get("did_key") or target_did).strip()
            target_agent_id = recipient.get("agent_id")
            target_address = (recipient.get("address") or "").strip() or None
    elif payload.to_address is not None and payload.to_address.strip():
        target_address = payload.to_address.strip()
        if "/" in target_address:
            domain, name = target_address.split("/", 1)
            recipient = await _local_recipient_from_address(db, domain=domain, name=name)
            if recipient is not None:
                target_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
                target_agent_id = recipient.get("agent_id")
                target_address = (recipient.get("address") or "").strip() or target_address
    elif payload.to_agent_id is not None and payload.to_agent_id.strip():
        target_agent_id = payload.to_agent_id.strip()
        recipient = await get_agent_by_id(
            db, team_id=auth.team_id, agent_id=target_agent_id,
        ) if auth.team_id else await get_agent_by_id(db, agent_id=target_agent_id)
        if recipient is not None:
            target_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            target_address = (recipient.get("address") or "").strip() or None
    elif payload.to_alias is not None and payload.to_alias.strip():
        recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
        if recipient is None:
            return None
        target_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        target_agent_id = recipient.get("agent_id")
        target_address = (recipient.get("address") or "").strip() or None

    if not (target_did or target_agent_id or target_address):
        return None

    try:
        return await find_active_one_to_one_conversation_between(
            db,
            conversation_type="mail",
            did_a=sender_did,
            did_key_a=auth.did_key,
            agent_id_a=auth.agent_id,
            address_a=sender_address,
            did_b=target_did,
            agent_id_b=target_agent_id,
            address_b=target_address,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.post("", response_model=SendMessageResponse)
async def send_message(
    request: Request, payload: SendMessageRequest, db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> SendMessageResponse:
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    sender_address = _sender_address(auth)
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    has_explicit_recipient = any(
        value is not None
        for value in (
            payload.to_agent_id,
            payload.to_alias,
            payload.to_did,
            payload.to_stable_id,
            payload.to_address,
        )
    )

    if payload.conversation_id is not None and not has_explicit_recipient:
        return await _send_mail_conversation_continuation(
            request,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            conversation_id=payload.conversation_id,
        )

    if has_explicit_recipient:
        requested_continuation = None
        if payload.conversation_id is not None:
            requested_conversation = await get_conversation(db, conversation_id=payload.conversation_id)
            if requested_conversation is not None:
                try:
                    requested_continuation = await mail_continuation_context(
                        db,
                        conversation_id=payload.conversation_id,
                        sender_did=sender_did,
                        equivalent_dids=auth_dids(auth),
                    )
                except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
                    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
                if not explicit_mail_target_matches_participant(
                    requested_continuation.recipient_participant,
                    to_agent_id=payload.to_agent_id,
                    to_alias=payload.to_alias,
                    to_did=payload.to_did,
                    to_stable_id=payload.to_stable_id,
                    to_address=payload.to_address,
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="conversation_id recipient does not match the requested recipient",
                    )
                if not participant_is_remote(requested_continuation.recipient_participant):
                    return await _send_mail_conversation_continuation(
                        request,
                        payload,
                        db,
                        auth=auth,
                        registry_client=registry_client,
                        sender_address=sender_address,
                        sender_did=sender_did,
                        conversation_id=payload.conversation_id,
                    )
                return await _send_federated_mail_conversation_continuation(
                    request,
                    payload,
                    db,
                    auth=auth,
                    registry_client=registry_client,
                    sender_address=sender_address,
                    sender_did=sender_did,
                    continuation=requested_continuation,
                )

        if requested_continuation is None:
            existing_conversation = await _existing_mail_conversation_for_target(
                db,
                auth=auth,
                sender_did=sender_did,
                sender_address=sender_address,
                payload=payload,
            )
            if existing_conversation is not None:
                existing_conversation_id = existing_conversation["conversation_id"]
                if payload.conversation_id is not None and payload.conversation_id != existing_conversation_id:
                    raise HTTPException(
                        status_code=409,
                        detail="Existing active conversation found; continue that conversation instead",
                    )
                if payload.conversation_id is None:
                    if payload.signature is not None and _signed_payload_conversation_id(
                        payload.signed_payload
                    ) != existing_conversation_id:
                        raise HTTPException(
                            status_code=409,
                            detail="Signed message must bind the existing conversation_id",
                        )
                    return await _send_mail_conversation_continuation(
                        request,
                        payload,
                        db,
                        auth=auth,
                        registry_client=registry_client,
                        sender_address=sender_address,
                        sender_did=sender_did,
                        conversation_id=existing_conversation_id,
                    )
                try:
                    existing_continuation = await mail_continuation_context(
                        db,
                        conversation_id=existing_conversation_id,
                        sender_did=sender_did,
                        equivalent_dids=auth_dids(auth),
                    )
                except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
                    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
                if not participant_is_remote(existing_continuation.recipient_participant):
                    return await _send_mail_conversation_continuation(
                        request,
                        payload,
                        db,
                        auth=auth,
                        registry_client=registry_client,
                        sender_address=sender_address,
                        sender_did=sender_did,
                        conversation_id=existing_conversation_id,
                    )

    recipient = None
    recipient_did: str | None = None
    to_agent_id: str | None = payload.to_agent_id
    to_alias: str | None = None

    if payload.to_address is None and payload.to_stable_id is not None:
        recipient_did = payload.to_stable_id.strip()
        recipient = await resolve_agent_by_did(db, recipient_did)
        if recipient is None:
            if recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_did is not None and payload.to_did.strip():
            bound_recipient = await resolve_agent_by_did(db, payload.to_did.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_did must match the to_stable_id recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_stable_id recipient")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_stable_id recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
                expected_recipient=recipient,
                signed_payload=payload.signed_payload,
                signature=payload.signature,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_stable_id recipient")
            recipient = _with_requested_address(recipient, address)
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is None and payload.to_did is not None:
        requested_recipient_did = payload.to_did.strip()
        recipient = await resolve_agent_by_did(db, requested_recipient_did)
        if recipient is None:
            if requested_recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_did recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_did recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
                expected_recipient=recipient,
                signed_payload=payload.signed_payload,
                signature=payload.signature,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_did recipient")
            recipient = _with_requested_address(recipient, address)
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or requested_recipient_did).strip()
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is not None:
        address = payload.to_address.strip()
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_address must be domain/name")
        domain, name = address.split("/", 1)
        if registry_client is not None:
            resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await resolve_agent_by_did(db, recipient_did)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)

        if recipient is None:
            recipient = await _local_recipient_from_address(db, domain=domain, name=name)
            if recipient is None:
                if await namespace_exists(db, domain):
                    raise HTTPException(status_code=404, detail="Recipient agent not found")
                if registry_client is None:
                    raise HTTPException(status_code=503, detail="AWID registry unavailable")
                raise HTTPException(status_code=404, detail="Recipient address not found")
            if registry_client is not None and requires_registry_address_binding(recipient):
                if not (
                    local_recipient_visible_to_auth(recipient, auth)
                    or _signed_payload_matches_address_binding(
                        verified_signed_payload_json(
                            signed_payload=payload.signed_payload,
                            signature=payload.signature,
                            did_key=auth.did_key,
                        ),
                        address=address,
                        recipient=recipient,
                    )
                ):
                    raise HTTPException(status_code=404, detail="Recipient address not found")
            recipient = _with_requested_address(recipient, address)
            recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            if not recipient_did:
                raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            if recipient.get("external"):
                if payload.to_alias.strip() != recipient["alias"]:
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
            else:
                bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
                if not _recipient_identity_matches(bound_recipient, recipient):
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if recipient.get("external") or payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_address recipient")
        if payload.to_stable_id is not None and payload.to_stable_id.strip():
            if payload.to_stable_id.strip() != str(recipient.get("did_aw") or "").strip():
                raise HTTPException(status_code=422, detail="to_stable_id must match the to_address recipient")
        if payload.to_did is not None and payload.to_did.strip():
            candidate_dids = {
                str(recipient.get("did_aw") or "").strip(),
                str(recipient.get("did_key") or "").strip(),
            }
            if payload.to_did.strip() not in candidate_dids:
                raise HTTPException(status_code=422, detail="to_did must match the to_address recipient")
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias") or address
    elif to_agent_id is not None:
        recipient = await get_agent_by_id(
            db, team_id=auth.team_id, agent_id=to_agent_id,
        ) if auth.team_id else await get_agent_by_id(db, agent_id=to_agent_id)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_agent_id recipient")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_alias = recipient.get("alias")
    elif payload.to_alias is not None:
        recipient = await _resolve_message_alias(db, auth, payload.to_alias)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient["alias"]
    else:
        raise HTTPException(status_code=422, detail="Must provide to_did, to_address, to_agent_id, or to_alias")

    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    created_at = None
    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
        from_did = payload.from_did.strip()
        if from_did not in set(auth_dids(auth)):
            raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        _validate_signed_mail_payload(
            signed_payload=payload.signed_payload,
            recipient=recipient,
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            requested_to_alias=payload.to_alias,
            from_alias=auth.alias,
            from_address=sender_address,
            from_stable_id=auth.did_aw,
            priority=payload.priority,
            subject=payload.subject,
            body=payload.body,
            from_did=from_did,
            message_id=payload.message_id,
            timestamp=payload.timestamp,
            conversation_id=payload.conversation_id,
        )
        created_at = _parse_signed_timestamp(payload.timestamp)

    if (recipient or {}).get("external"):
        return await _deliver_remote_mail_and_project_locally(
            request,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            recipient=recipient,
            recipient_did=recipient_did or "",
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            created_at=created_at,
            msg_uuid=msg_uuid,
        )

    try:
        if not (recipient or {}).get("external"):
            await authorize_message_delivery(
                db,
                recipient_agent=recipient,
                sender_did=sender_did,
                sender_address=sender_address,
                sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id,
                sender_verified_dids=auth_dids(auth),
            )
        encrypted_metadata = _validate_encrypted_payload(
            payload,
            auth=auth,
            sender_did=sender_did,
            recipient=recipient,
            recipient_did=recipient_did or "",
        )
        # If an explicit recipient is present, conversation_id is a caller-chosen
        # initial id. Continuations use conversation_id without recipient fields.
        conversation = await create_conversation(
            db,
            conversation_type="mail",
            created_by_did=sender_did,
            conversation_id=payload.conversation_id,
            initiator={
                "did": sender_did,
                "agent_id": auth.agent_id,
                "alias": auth.alias or sender_address or sender_did,
                "address": sender_address,
                "transport_hint": "sender",
            },
            recipients=[
                {
                    "did": recipient_did or "",
                    "agent_id": to_agent_id,
                    "alias": to_alias or (recipient or {}).get("alias") or recipient_did or "",
                    "address": _recipient_conversation_address(recipient, payload),
                    "current_did_key": (recipient or {}).get("did_key"),
                    "transport_hint": _recipient_transport_hint(payload),
                }
            ],
            team_id=auth.team_id,
        )
        message_id, created_at = await deliver_message(
            db,
            registry_client=registry_client,
            recipient_agent=recipient,
            team_id=auth.team_id,
            from_agent_id=auth.agent_id,
            from_alias=auth.alias,
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            from_did=sender_did,
            to_did=recipient_did or "",
            sender_address=sender_address,
            subject=payload.subject,
            body=payload.body,
            priority=payload.priority,
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            content_mode=payload.content_mode or "legacy_plaintext_v1",
            message_version=payload.message_version or 1,
            encrypted_envelope=payload.encrypted_envelope,
            encrypted_metadata=encrypted_metadata,
            created_at=created_at,
            message_id=msg_uuid,
            conversation_id=conversation["conversation_id"],
            skip_policy_check=True,
        )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await record_successful_contact_side_effect(
        db,
        owner_did=(auth.did_aw or sender_did).strip(),
        sender_team_id=auth.team_id,
        recipient=recipient,
    )

    await fire_mutation_hook(
        request,
        "message.sent",
        {
            "team_id": auth.team_id,
            "from_agent_id": auth.agent_id,
            "from_did": sender_did,
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_agent_id": to_agent_id,
            "from_alias": auth.alias or sender_did,
            "message_id": str(message_id),
            "conversation_id": conversation["conversation_id"],
            "to_alias": to_alias,
            "subject": payload.subject,
            "priority": payload.priority,
        },
    )

    return SendMessageResponse(
        message_id=str(message_id),
        conversation_id=conversation["conversation_id"],
        status="delivered",
        delivered_at=_utc_iso(created_at),
    )


@router.get("/inbox", response_model=InboxResponse)
async def get_inbox(
    request: Request,
    db=Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    unread_only: bool = Query(default=False),
    message_id: str | None = Query(default=None),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> InboxResponse:
    aweb_db = db.get_manager("aweb")
    inbox_dids = auth_dids(auth)
    if not inbox_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    where_clause = "WHERE m.to_did = ANY($1::text[])"
    params: list = [inbox_dids]

    if message_id is not None and message_id.strip():
        try:
            params.append(UUID(message_id.strip()))
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid message_id format")
        where_clause += f" AND m.message_id = ${len(params)}"
    elif unread_only:
        where_clause += " AND m.read_at IS NULL"

    rows = await aweb_db.fetch_all(
        f"""
        SELECT m.message_id, m.from_agent_id, m.from_alias, m.from_address, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.to_did, m.signature, m.signed_payload, m.conversation_id,
               m.content_mode, m.message_version, m.encrypted_envelope
        FROM {{{{tables.messages}}}} m
        {where_clause}
        ORDER BY m.created_at DESC
        LIMIT ${len(params) + 1}
        """,
        *params,
        limit,
    )

    return await _inbox_response_from_rows(db, rows)


@router.post("/{message_id}/ack", response_model=AckResponse)
async def ack_message(
    request: Request, message_id: str, db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
) -> AckResponse:

    try:
        msg_uuid = UUID(message_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    inbox_dids = auth_dids(auth)
    if not inbox_dids:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    result = await aweb_db.fetch_one(
        """
        UPDATE {{tables.messages}}
        SET read_at = $1
        WHERE message_id = $2 AND to_did = ANY($3::text[])
          AND read_at IS NULL
        RETURNING message_id, from_alias, subject
        """,
        now,
        msg_uuid,
        inbox_dids,
    )

    if not result:
        # Either already read or not found — check existence
        existing = await aweb_db.fetch_one(
            """
            SELECT message_id, read_at, from_alias, subject FROM {{tables.messages}}
            WHERE message_id = $1 AND to_did = ANY($2::text[])
            """,
            msg_uuid,
            inbox_dids,
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Message not found")

    if result:
        await fire_mutation_hook(
            request,
            "message.acknowledged",
            {
                "team_id": auth.team_id,
                "agent_id": auth.agent_id,
                "alias": auth.alias,
                "message_id": str(msg_uuid),
                "from_alias": result["from_alias"],
                "subject": result["subject"] or "",
            },
        )

    return AckResponse(
        message_id=str(msg_uuid),
        acknowledged_at=now.isoformat(),
    )
