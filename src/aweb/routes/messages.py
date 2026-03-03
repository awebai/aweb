from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth, validate_agent_alias
from aweb.contacts_service import get_contact_addresses, is_address_in_contacts
from aweb.custody import sign_on_behalf
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.messages_service import (
    MessagePriority,
    deliver_message,
    get_agent_row,
)
from aweb.messages_service import utc_iso as _utc_iso
from aweb.rotation_announcements import acknowledge_rotation, get_pending_announcements
from aweb.routes import format_agent_address
from aweb.stable_id import ensure_agent_stable_ids, validate_stable_id

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


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1, max_length=64)
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
        return validate_agent_alias(v)

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
    rotation_announcement: Optional[RotationAnnouncement] = None
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

    to_agent_id: str | None = payload.to_agent_id
    if to_agent_id is None and payload.to_alias is not None:
        aweb_db = db.get_manager("aweb")
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id
            FROM {{tables.agents}}
            WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
            """,
            UUID(project_id),
            payload.to_alias,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Agent not found")
        to_agent_id = str(row["agent_id"])

    if to_agent_id is None:
        raise HTTPException(status_code=422, detail="Must provide to_agent_id or to_alias")

    # Check if recipient is retired
    aweb_db = db.get_manager("aweb")
    recip_status = await aweb_db.fetch_one(
        """
        SELECT status, successor_agent_id
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(to_agent_id),
        UUID(project_id),
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

    stable_ids = await ensure_agent_stable_ids(
        aweb_db, project_id=project_id, agent_ids=[actor_id, to_agent_id]
    )
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

    if payload.signature is None:
        proj_row = await aweb_db.fetch_one(
            "SELECT slug FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
            UUID(project_id),
        )
        project_slug = proj_row["slug"] if proj_row else ""
        recip_row = await aweb_db.fetch_one(
            "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1 AND deleted_at IS NULL",
            UUID(to_agent_id),
        )
        to_address = f"{project_slug}/{recip_row['alias']}" if recip_row else ""
        msg_from_stable_id = sender_stable_id
        msg_to_stable_id = recipient_stable_id
        message_fields: dict[str, str] = {
            "from": f"{project_slug}/{sender['alias']}",
            "from_did": "",
            "message_id": str(pre_message_id),
            "to": to_address,
            "to_did": payload.to_did or "",
            "type": "mail",
            "subject": payload.subject,
            "body": payload.body,
            "timestamp": _utc_iso(created_at),
        }
        if msg_from_stable_id:
            message_fields["from_stable_id"] = msg_from_stable_id
        if msg_to_stable_id:
            message_fields["to_stable_id"] = msg_to_stable_id
        sign_result = await sign_on_behalf(
            actor_id,
            message_fields,
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id = sign_result

    try:
        message_id, created_at = await deliver_message(
            db,
            project_id=project_id,
            from_agent_id=actor_id,
            from_alias=sender["alias"],
            to_agent_id=to_agent_id,
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
            created_at=created_at,
            message_id=pre_message_id,
        )
    except Exception as e:
        # message_id is client-controllable for self-custodial signing, so surface
        # idempotency/replay conflicts as 409.
        import asyncpg.exceptions

        if isinstance(e, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="message_id already exists")
        raise

    # Sending a message to an agent implicitly acknowledges their rotation
    aweb_db = db.get_manager("aweb")
    await acknowledge_rotation(aweb_db, from_agent_id=UUID(actor_id), to_agent_id=UUID(to_agent_id))

    await fire_mutation_hook(
        request,
        "message.sent",
        {
            "message_id": str(message_id),
            "from_agent_id": actor_id,
            "to_agent_id": to_agent_id,
            "subject": payload.subject,
        },
    )

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
               from_did, from_stable_id, to_did, to_stable_id, signature, signing_key_id
        FROM {{tables.messages}}
        WHERE project_id = $1
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

    proj_row = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
        UUID(project_id),
    )
    project_slug = proj_row["slug"] if proj_row else ""
    inbox_owner_address = format_agent_address(project_slug, owner["alias"])

    contact_addrs = await get_contact_addresses(db, project_id=project_id)

    messages = []
    for r in rows:
        ann_data = announcements.get(str(r["from_agent_id"]))
        ann = RotationAnnouncement(**ann_data) if ann_data else None
        messages.append(
            InboxMessage(
                message_id=str(r["message_id"]),
                from_agent_id=str(r["from_agent_id"]),
                from_alias=r["from_alias"],
                from_address=format_agent_address(project_slug, r["from_alias"]),
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
                to_address=inbox_owner_address,
                signature=r["signature"],
                signing_key_id=r["signing_key_id"],
                rotation_announcement=ann,
                is_contact=is_address_in_contacts(
                    format_agent_address(project_slug, r["from_alias"]),
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
        WHERE project_id = $1 AND message_id = $2
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
        WHERE project_id = $1 AND message_id = $2
        """,
        UUID(project_id),
        message_uuid,
    )

    # Read back the read_at timestamp for a stable response.
    updated = await aweb_db.fetch_one(
        """
        SELECT read_at
        FROM {{tables.messages}}
        WHERE project_id = $1 AND message_id = $2
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
