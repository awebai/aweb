from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.deps import get_db
from aweb.messages_service import MessagePriority, deliver_message, get_agent_row

router = APIRouter(prefix="/v1/messages", tags=["aweb-mail"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_agent_id: Optional[str] = Field(default=None, min_length=1)
    to_alias: Optional[str] = Field(default=None, min_length=1, max_length=64)
    subject: str = ""
    body: str
    priority: MessagePriority = "normal"
    thread_id: Optional[str] = None

    @field_validator("to_agent_id")
    @classmethod
    def _validate_agent_id(cls, v: str) -> str:
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


class SendMessageResponse(BaseModel):
    message_id: str
    status: str
    delivered_at: str


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


class InboxResponse(BaseModel):
    messages: list[InboxMessage]


class AckResponse(BaseModel):
    message_id: str
    acknowledged_at: str


@router.post("", response_model=SendMessageResponse)
async def send_message(request: Request, payload: SendMessageRequest, db=Depends(get_db)) -> SendMessageResponse:
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
    )
    return SendMessageResponse(
        message_id=str(message_id),
        status="delivered",
        delivered_at=created_at.isoformat(),
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
        SELECT message_id, from_agent_id, from_alias, subject, body, priority, thread_id, read_at, created_at
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

    return InboxResponse(
        messages=[
            InboxMessage(
                message_id=str(r["message_id"]),
                from_agent_id=str(r["from_agent_id"]),
                from_alias=r["from_alias"],
                subject=r["subject"],
                body=r["body"],
                priority=r["priority"],
                thread_id=str(r["thread_id"]) if r["thread_id"] is not None else None,
                read_at=r["read_at"].isoformat() if r["read_at"] is not None else None,
                created_at=r["created_at"].isoformat(),
            )
            for r in rows
        ]
    )


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
    acknowledged_at = updated["read_at"].isoformat() if updated and updated["read_at"] else _now_iso()

    return AckResponse(message_id=str(message_uuid), acknowledged_at=acknowledged_at)
