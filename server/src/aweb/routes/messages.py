from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.messaging.messages import (
    MessagePriority,
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
    utc_iso as _utc_iso,
)
from aweb.team_auth_deps import get_team_identity

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1, max_length=64)
    subject: str = ""
    body: str
    priority: MessagePriority = "normal"
    message_id: Optional[str] = None
    from_did: Optional[str] = Field(default=None, max_length=256)
    signature: Optional[str] = Field(default=None, max_length=512)
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

    @field_validator("message_id")
    @classmethod
    def _validate_message_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return str(UUID(str(v).strip()))
        except Exception:
            raise ValueError("Invalid message_id format")


class SendMessageResponse(BaseModel):
    message_id: str
    status: str
    delivered_at: str


class InboxMessage(BaseModel):
    message_id: str
    from_agent_id: str
    from_alias: str
    to_alias: str
    subject: str
    body: str
    priority: MessagePriority
    read_at: Optional[str]
    created_at: str
    from_did: Optional[str] = None
    signature: Optional[str] = None
    signed_payload: Optional[str] = None


class InboxResponse(BaseModel):
    messages: list[InboxMessage]


class AckResponse(BaseModel):
    message_id: str
    acknowledged_at: str


@router.post("", response_model=SendMessageResponse)
async def send_message(
    request: Request, payload: SendMessageRequest, db=Depends(get_db)
) -> SendMessageResponse:
    identity = await get_team_identity(request, db)

    # Resolve recipient
    to_agent_id: str | None = payload.to_agent_id
    to_alias: str | None = None

    if to_agent_id is not None:
        recipient = await get_agent_by_id(
            db, team_address=identity.team_address, agent_id=to_agent_id,
        )
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        to_alias = recipient["alias"]

    elif payload.to_alias is not None:
        recipient = await get_agent_by_alias(
            db, team_address=identity.team_address, alias=payload.to_alias,
        )
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient["alias"]

    else:
        raise HTTPException(status_code=422, detail="Must provide to_agent_id or to_alias")

    msg_uuid = UUID(payload.message_id) if payload.message_id else None

    message_id, created_at = await deliver_message(
        db,
        team_address=identity.team_address,
        from_agent_id=identity.agent_id,
        from_alias=identity.alias,
        to_agent_id=to_agent_id,
        to_alias=to_alias,
        subject=payload.subject,
        body=payload.body,
        priority=payload.priority,
        from_did=payload.from_did,
        signature=payload.signature,
        signed_payload=payload.signed_payload,
        message_id=msg_uuid,
    )

    await fire_mutation_hook(
        request,
        "message_sent",
        {
            "team_address": identity.team_address,
            "alias": identity.alias,
            "message_id": str(message_id),
            "to_alias": to_alias,
            "subject": payload.subject,
        },
    )

    return SendMessageResponse(
        message_id=str(message_id),
        status="delivered",
        delivered_at=_utc_iso(created_at),
    )


@router.get("/inbox", response_model=InboxResponse)
async def get_inbox(
    request: Request,
    db=Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    unread_only: bool = Query(default=False),
) -> InboxResponse:
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    where_clause = "WHERE m.team_address = $1 AND m.to_agent_id = $2"
    params: list = [identity.team_address, UUID(identity.agent_id)]

    if unread_only:
        where_clause += " AND m.read_at IS NULL"

    rows = await aweb_db.fetch_all(
        f"""
        SELECT m.message_id, m.from_agent_id, m.from_alias, m.to_alias,
               m.subject, m.body, m.priority, m.read_at, m.created_at,
               m.from_did, m.signature, m.signed_payload
        FROM {{{{tables.messages}}}} m
        {where_clause}
        ORDER BY m.created_at DESC
        LIMIT $3
        """,
        *params,
        limit,
    )

    messages = []
    for r in rows:
        messages.append(InboxMessage(
            message_id=str(r["message_id"]),
            from_agent_id=str(r["from_agent_id"]),
            from_alias=r["from_alias"],
            to_alias=r["to_alias"],
            subject=r["subject"],
            body=r["body"],
            priority=r["priority"],
            read_at=r["read_at"].isoformat() if r.get("read_at") else None,
            created_at=r["created_at"].isoformat(),
            from_did=r.get("from_did"),
            signature=r.get("signature"),
            signed_payload=r.get("signed_payload"),
        ))

    return InboxResponse(messages=messages)


@router.post("/{message_id}/ack", response_model=AckResponse)
async def ack_message(
    request: Request, message_id: str, db=Depends(get_db)
) -> AckResponse:
    identity = await get_team_identity(request, db)

    try:
        msg_uuid = UUID(message_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)

    result = await aweb_db.fetch_one(
        """
        UPDATE {{tables.messages}}
        SET read_at = $1
        WHERE message_id = $2 AND team_address = $3 AND to_agent_id = $4
          AND read_at IS NULL
        RETURNING message_id
        """,
        now,
        msg_uuid,
        identity.team_address,
        UUID(identity.agent_id),
    )

    if not result:
        # Either already read or not found — check existence
        existing = await aweb_db.fetch_one(
            """
            SELECT message_id, read_at FROM {{tables.messages}}
            WHERE message_id = $1 AND team_address = $2 AND to_agent_id = $3
            """,
            msg_uuid,
            identity.team_address,
            UUID(identity.agent_id),
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Message not found")

    return AckResponse(
        message_id=str(msg_uuid),
        acknowledged_at=now.isoformat(),
    )
