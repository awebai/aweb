from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import asyncpg.exceptions
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.address_scope import (
    format_local_address,
    get_project_scope,
    parse_recipient_ref,
    resolve_local_recipient,
)
from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.awid.custody import sign_on_behalf
from aweb.awid.did import validate_stable_id
from aweb.awid.replacement import get_sender_delivery_metadata
from aweb.awid.stable_id import ensure_agent_stable_ids
from aweb.messaging.contacts import get_contact_addresses, is_address_in_contacts
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.messaging.messages import (
    MessagePriority,
    deliver_message,
    get_agent_row_any,
    get_agent_row,
    utc_iso as _utc_iso,
)
from aweb.messaging.rotation import acknowledge_rotation, get_pending_announcements

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


def _parse_signed_timestamp(value: str) -> datetime:
    """Parse an RFC3339 timestamp for signed payloads (UTC, second precision)."""
    value = (value or "").strip()
    if not value:
        raise HTTPException(status_code=422, detail="timestamp must not be empty")
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


def _mail_signature_fields(
    *,
    from_address: str,
    message_id: UUID,
    to_address: str,
    to_did: str | None,
    subject: str,
    body: str,
    created_at: datetime,
    from_stable_id: str | None,
    to_stable_id: str | None,
) -> dict[str, str]:
    fields: dict[str, str] = {
        "from": from_address,
        "from_did": "",
        "message_id": str(message_id),
        "to": to_address,
        "to_did": to_did or "",
        "type": "mail",
        "subject": subject,
        "body": body,
        "timestamp": _utc_iso(created_at),
    }
    if from_stable_id:
        fields["from_stable_id"] = from_stable_id
    if to_stable_id:
        fields["to_stable_id"] = to_stable_id
    return fields


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1, max_length=320)
    subject: str = ""
    body: str
    priority: MessagePriority = "normal"
    thread_id: Optional[str] = None
    message_id: Optional[str] = None
    timestamp: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    from_stable_id: Optional[str] = Field(default=None, max_length=256)
    to_did: Optional[str] = Field(default=None, max_length=256)
    to_stable_id: Optional[str] = Field(default=None, max_length=256)
    signature: Optional[str] = Field(default=None, max_length=512)
    signing_key_id: Optional[str] = Field(default=None, max_length=256)
    signed_payload: Optional[str] = None

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
        v = v.strip()
        if not v:
            raise ValueError("to_alias must not be empty")
        parse_recipient_ref(v)
        return v

    @field_validator("thread_id")
    @classmethod
    def _validate_thread_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid thread_id format")

    @field_validator("message_id")
    @classmethod
    def _validate_message_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid message_id format")

    @field_validator("from_stable_id", "to_stable_id")
    @classmethod
    def _validate_stable_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        return validate_stable_id(v)


class SendMessageResponse(BaseModel):
    message_id: str
    status: str
    delivered_at: str


class RotationAnnouncement(BaseModel):
    old_did: str
    new_did: str
    timestamp: str
    old_key_signature: str


class ReplacementAnnouncement(BaseModel):
    address: str
    old_did: str
    new_did: str
    controller_did: str
    timestamp: str
    controller_signature: str


class InboxMessage(BaseModel):
    message_id: str
    from_agent_id: str
    from_alias: str
    from_address: str
    subject: str
    body: str
    priority: MessagePriority
    thread_id: Optional[str]
    read_at: Optional[str]
    created_at: str
    from_did: Optional[str] = None
    from_stable_id: Optional[str] = None
    to_did: Optional[str] = None
    to_stable_id: Optional[str] = None
    to_address: str
    signature: Optional[str] = None
    signing_key_id: Optional[str] = None
    signed_payload: Optional[str] = None
    rotation_announcement: Optional[RotationAnnouncement] = None
    replacement_announcement: Optional[ReplacementAnnouncement] = None
    is_contact: bool = False


class InboxResponse(BaseModel):
    messages: list[InboxMessage]


class AckResponse(BaseModel):
    message_id: str
    acknowledged_at: str


@router.post("", response_model=SendMessageResponse)
async def send_message(
    request: Request, payload: SendMessageRequest, db=Depends(get_db)
) -> SendMessageResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    sender = await get_agent_row(db, project_id=project_id, agent_id=actor_id)
    if sender is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    sender_scope = await get_project_scope(db, project_id=project_id)

    to_agent_id: str | None = payload.to_agent_id
    recipient_project_id: str = project_id
    recipient_project_slug: str = sender_scope.project_slug
    recipient_ref: str | None = payload.to_alias
    if to_agent_id is None and payload.to_alias is not None:
        resolved = await resolve_local_recipient(
            db,
            sender_project_id=project_id,
            sender_agent_id=actor_id,
            ref=payload.to_alias,
        )
        to_agent_id = resolved.agent_id
        recipient_project_id = resolved.project_id
        recipient_project_slug = resolved.project_slug

    if to_agent_id is None:
        raise HTTPException(status_code=422, detail="Must provide to_agent_id or to_alias")
    if payload.to_alias is None:
        recipient = await get_agent_row_any(db, agent_id=to_agent_id)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        recipient_project_id = str(recipient["project_id"])
        recipient_scope = await get_project_scope(db, project_id=recipient_project_id)
        if recipient_scope.project_id != sender_scope.project_id and (
            not sender_scope.owner_ref
            or not recipient_scope.owner_ref
            or recipient_scope.owner_type != sender_scope.owner_type
            or recipient_scope.owner_ref != sender_scope.owner_ref
        ):
            raise HTTPException(status_code=404, detail="Agent not found")
        recipient_project_slug = recipient_scope.project_slug
        recipient_ref = format_local_address(
            base_project_slug=sender_scope.project_slug,
            target_project_slug=recipient_project_slug,
            alias=recipient["alias"],
        )

    # Enforce access_mode: contacts_only agents reject non-contacts.
    from aweb.messaging.contacts import check_access

    sender_from_address = format_local_address(
        base_project_slug=recipient_project_slug,
        target_project_slug=sender_scope.project_slug,
        alias=sender["alias"],
    )
    allowed = await check_access(
        db,
        target_project_id=recipient_project_id,
        target_agent_id=to_agent_id,
        sender_project_id=project_id,
        sender_address=sender_from_address,
        sender_owner_type=sender_scope.owner_type,
        sender_owner_ref=sender_scope.owner_ref,
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Recipient only accepts messages from contacts")

    # Check if recipient is retired
    aweb_db = db.get_manager("aweb")
    recip_status = await aweb_db.fetch_one(
        """
        SELECT status, successor_agent_id
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(to_agent_id),
        UUID(recipient_project_id),
    )
    if recip_status and recip_status["status"] == "retired":
        successor_alias = None
        succ_id = recip_status["successor_agent_id"]
        if succ_id:
            succ = await aweb_db.fetch_one(
                "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1 AND deleted_at IS NULL",
                succ_id,
            )
            if succ:
                successor_alias = succ["alias"]
        return JSONResponse(
            status_code=410,
            content={
                "detail": "Agent is retired",
                "successor_alias": successor_alias,
                "successor_agent_id": str(succ_id) if succ_id is not None else None,
            },
        )

    # Server-side custodial signing: sign before INSERT so the message is
    # never observable without its signature.
    msg_from_did = payload.from_did
    msg_from_stable_id = payload.from_stable_id
    msg_to_stable_id = payload.to_stable_id
    msg_signature = payload.signature
    msg_signing_key_id = payload.signing_key_id
    msg_signed_payload = payload.signed_payload
    created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    if payload.signature is not None:
        if payload.from_did is None or not payload.from_did.strip():
            raise HTTPException(
                status_code=422, detail="from_did is required when signature is provided"
            )
        if payload.message_id is None or payload.timestamp is None:
            raise HTTPException(
                status_code=422,
                detail="message_id and timestamp are required when signature is provided",
            )
        created_at = _parse_signed_timestamp(payload.timestamp)
        pre_message_id = uuid_mod.UUID(payload.message_id)

    stable_ids = await ensure_agent_stable_ids(aweb_db, agent_ids=[actor_id, to_agent_id])
    sender_stable_id = stable_ids.get(actor_id)
    recipient_stable_id = stable_ids.get(to_agent_id)

    if payload.from_stable_id is not None and payload.from_stable_id != sender_stable_id:
        raise HTTPException(
            status_code=403, detail="from_stable_id does not match sender stable_id"
        )
    if payload.to_stable_id is not None and payload.to_stable_id != recipient_stable_id:
        raise HTTPException(
            status_code=403, detail="to_stable_id does not match recipient stable_id"
        )

    ns_row = await aweb_db.fetch_one(
        """
        SELECT p.slug AS sender_project_slug, rp.slug AS recipient_project_slug
        FROM {{tables.projects}} p
        JOIN {{tables.projects}} rp ON rp.project_id = $2
        WHERE p.project_id = $1 AND p.deleted_at IS NULL AND rp.deleted_at IS NULL
        """,
        UUID(project_id),
        UUID(recipient_project_id),
    )
    if not ns_row:
        raise HTTPException(status_code=404, detail="Project not found")

    from_address = format_local_address(
        base_project_slug=ns_row["recipient_project_slug"],
        target_project_slug=ns_row["sender_project_slug"],
        alias=sender["alias"],
    )
    to_address = recipient_ref or ""
    msg_from_stable_id = sender_stable_id
    msg_to_stable_id = recipient_stable_id
    message_fields = _mail_signature_fields(
        from_address=from_address,
        message_id=pre_message_id,
        to_address=to_address,
        to_did=payload.to_did,
        subject=payload.subject,
        body=payload.body,
        created_at=created_at,
        from_stable_id=msg_from_stable_id,
        to_stable_id=msg_to_stable_id,
    )

    if payload.signature is None:
        sign_result = await sign_on_behalf(
            actor_id,
            message_fields,
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id, msg_signed_payload = sign_result

    try:
        message_id, created_at = await deliver_message(
            db,
            project_id=project_id,
            from_agent_id=actor_id,
            from_alias=sender["alias"],
            to_agent_id=to_agent_id,
            recipient_project_id=recipient_project_id,
            subject=payload.subject,
            body=payload.body,
            priority=payload.priority,
            thread_id=payload.thread_id,
            from_did=msg_from_did,
            from_stable_id=msg_from_stable_id,
            to_did=payload.to_did,
            to_stable_id=msg_to_stable_id,
            signature=msg_signature,
            signing_key_id=msg_signing_key_id,
            signed_payload=msg_signed_payload,
            created_at=created_at,
            message_id=pre_message_id,
        )
    except Exception as e:
        # message_id is client-controllable for self-custodial signing, so surface
        # idempotency/replay conflicts as 409.
        if isinstance(e, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise

    # Sending a message to an agent implicitly acknowledges their rotation
    aweb_db = db.get_manager("aweb")
    await acknowledge_rotation(aweb_db, from_agent_id=UUID(actor_id), to_agent_id=UUID(to_agent_id))

    hook_context = {
        "message_id": str(message_id),
        "from_agent_id": actor_id,
        "to_agent_id": to_agent_id,
        "subject": payload.subject,
    }
    await fire_mutation_hook(request, "message.sent", hook_context)

    return SendMessageResponse(
        message_id=str(message_id),
        status="delivered",
        delivered_at=_utc_iso(created_at),
    )


@router.get("/inbox", response_model=InboxResponse)
async def inbox(
    request: Request,
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=500),
    db=Depends(get_db),
) -> InboxResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    # Ensure the inbox owner exists in this project.
    owner = await get_agent_row(db, project_id=project_id, agent_id=actor_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_agent_id, from_alias, subject, body, priority, thread_id, read_at, created_at,
               from_did, from_stable_id, to_did, to_stable_id, signature, signing_key_id, signed_payload,
               project_id, recipient_project_id
        FROM {{tables.messages}}
        WHERE recipient_project_id = $1
          AND to_agent_id = $2
          AND ($3::bool IS FALSE OR read_at IS NULL)
        ORDER BY created_at DESC
        LIMIT $4
        """,
        UUID(project_id),
        UUID(actor_id),
        bool(unread_only),
        int(limit),
    )

    # Look up pending rotation announcements for message senders
    sender_ids = list({r["from_agent_id"] for r in rows})
    announcements = await get_pending_announcements(
        aweb_db, sender_ids=sender_ids, recipient_id=UUID(actor_id)
    )
    sender_delivery = await get_sender_delivery_metadata(aweb_db, sender_ids=sender_ids)

    contact_addrs = await get_contact_addresses(db, project_id=project_id)
    project_ids = {
        str(r["project_id"]) for r in rows
    } | {
        str(r["recipient_project_id"]) for r in rows
    }
    project_slugs: dict[str, str] = {}
    if project_ids:
        slug_rows = await aweb_db.fetch_all(
            """
            SELECT project_id, slug
            FROM {{tables.projects}}
            WHERE project_id = ANY($1::uuid[])
            """,
            [UUID(project_id) for project_id in project_ids],
        )
        project_slugs = {str(r["project_id"]): r["slug"] for r in slug_rows}

    messages = []
    for r in rows:
        sender_project_slug = project_slugs.get(str(r["project_id"]), "")
        recipient_project_slug = project_slugs.get(str(r["recipient_project_id"]), "")
        from_alias = r["from_alias"]
        local_from_address = format_local_address(
            base_project_slug=recipient_project_slug,
            target_project_slug=sender_project_slug,
            alias=from_alias,
        )
        sender_meta = sender_delivery.get(str(r["from_agent_id"]), {})
        from_address = sender_meta.get("from_address") or local_from_address
        to_address = format_local_address(
            base_project_slug=sender_project_slug,
            target_project_slug=recipient_project_slug,
            alias=owner["alias"],
        )
        ann_data = announcements.get(str(r["from_agent_id"]))
        ann = RotationAnnouncement(**ann_data) if ann_data else None
        replacement_data = sender_meta.get("replacement_announcement")
        replacement = ReplacementAnnouncement(**replacement_data) if replacement_data else None
        messages.append(
            InboxMessage(
                message_id=str(r["message_id"]),
                from_agent_id=str(r["from_agent_id"]),
                from_alias=r["from_alias"],
                from_address=from_address,
                subject=r["subject"],
                body=r["body"],
                priority=r["priority"],
                thread_id=str(r["thread_id"]) if r["thread_id"] is not None else None,
                read_at=_utc_iso(r["read_at"]) if r["read_at"] is not None else None,
                created_at=_utc_iso(r["created_at"]),
                from_did=r["from_did"],
                from_stable_id=r.get("from_stable_id"),
                to_did=r["to_did"],
                to_stable_id=r.get("to_stable_id"),
                to_address=to_address,
                signature=r["signature"],
                signing_key_id=r["signing_key_id"],
                signed_payload=r.get("signed_payload"),
                rotation_announcement=ann,
                replacement_announcement=replacement,
                is_contact=is_address_in_contacts(
                    from_address,
                    contact_addrs,
                ),
            )
        )

    return InboxResponse(messages=messages)


@router.post("/{message_id}/ack", response_model=AckResponse)
async def acknowledge(
    request: Request,
    message_id: str,
    db=Depends(get_db),
) -> AckResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    try:
        message_uuid = UUID(message_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    # Ensure the actor exists in-project.
    actor = await get_agent_row(db, project_id=project_id, agent_id=actor_id)
    if actor is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT to_agent_id, read_at
        FROM {{tables.messages}}
        WHERE recipient_project_id = $1 AND message_id = $2
        """,
        UUID(project_id),
        message_uuid,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Message not found")
    if str(row["to_agent_id"]) != actor_id:
        raise HTTPException(status_code=403, detail="Not authorized to acknowledge this message")

    await aweb_db.execute(
        """
        UPDATE {{tables.messages}}
        SET read_at = COALESCE(read_at, NOW())
        WHERE recipient_project_id = $1 AND message_id = $2
        """,
        UUID(project_id),
        message_uuid,
    )

    # Read back the read_at timestamp for a stable response.
    updated = await aweb_db.fetch_one(
        """
        SELECT read_at
        FROM {{tables.messages}}
        WHERE recipient_project_id = $1 AND message_id = $2
        """,
        UUID(project_id),
        message_uuid,
    )
    acknowledged_at = (
        _utc_iso(updated["read_at"])
        if updated and updated["read_at"]
        else _utc_iso(datetime.now(timezone.utc))
    )

    await fire_mutation_hook(
        request,
        "message.acknowledged",
        {
            "message_id": str(message_uuid),
            "agent_id": actor_id,
        },
    )

    return AckResponse(message_id=str(message_uuid), acknowledged_at=acknowledged_at)
