from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth, validate_agent_alias
from aweb.custody import sign_on_behalf
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.messages_service import MessagePriority, deliver_message, get_agent_row
from aweb.rotation_announcements import acknowledge_rotation, get_pending_announcements

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


def _utc_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601, UTC, second precision with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1, max_length=64)
    subject: str = ""
    body: str
    priority: MessagePriority = "normal"
    thread_id: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    to_did: Optional[str] = Field(default=None, max_length=256)
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
    subject: str
    body: str
    priority: MessagePriority
    thread_id: Optional[str]
    read_at: Optional[str]
    created_at: str
    from_did: Optional[str] = None
    to_did: Optional[str] = None
    signature: Optional[str] = None
    signing_key_id: Optional[str] = None
    rotation_announcement: Optional[RotationAnnouncement] = None


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

    # Server-side custodial signing: sign before INSERT so the message is
    # never observable without its signature.
    msg_from_did = payload.from_did
    msg_signature = payload.signature
    msg_signing_key_id = payload.signing_key_id
    created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    if payload.signature is None:
        aweb_db = db.get_manager("aweb")
        proj_row = await aweb_db.fetch_one(
            "SELECT slug FROM {{tables.projects}} WHERE project_id = $1",
            UUID(project_id),
        )
        project_slug = proj_row["slug"] if proj_row else ""
        recip_row = await aweb_db.fetch_one(
            "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1 AND deleted_at IS NULL",
            UUID(to_agent_id),
        )
        to_address = f"{project_slug}/{recip_row['alias']}" if recip_row else ""
        sign_result = await sign_on_behalf(
            actor_id,
            {
                "from": f"{project_slug}/{sender['alias']}",
                "from_did": "",
                "message_id": str(pre_message_id),
                "to": to_address,
                "to_did": payload.to_did or "",
                "type": "mail",
                "subject": payload.subject,
                "body": payload.body,
                "timestamp": _utc_iso(created_at),
            },
            db,
        )
        if sign_result is not None:
            msg_from_did, msg_signature, msg_signing_key_id = sign_result

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
        to_did=payload.to_did,
        signature=msg_signature,
        signing_key_id=msg_signing_key_id,
        created_at=created_at,
        message_id=pre_message_id,
    )

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
               from_did, to_did, signature, signing_key_id
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

    messages = []
    for r in rows:
        ann_data = announcements.get(str(r["from_agent_id"]))
        ann = RotationAnnouncement(**ann_data) if ann_data else None
        messages.append(
            InboxMessage(
                message_id=str(r["message_id"]),
                from_agent_id=str(r["from_agent_id"]),
                from_alias=r["from_alias"],
                subject=r["subject"],
                body=r["body"],
                priority=r["priority"],
                thread_id=str(r["thread_id"]) if r["thread_id"] is not None else None,
                read_at=_utc_iso(r["read_at"]) if r["read_at"] is not None else None,
                created_at=_utc_iso(r["created_at"]),
                from_did=r["from_did"],
                to_did=r["to_did"],
                signature=r["signature"],
                signing_key_id=r["signing_key_id"],
                rotation_announcement=ann,
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
