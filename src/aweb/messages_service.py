from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import HTTPException

MessagePriority = Literal["low", "normal", "high", "urgent"]


def _parse_uuid(v: str, *, field_name: str) -> UUID:
    v = str(v).strip()
    if not v:
        raise HTTPException(status_code=422, detail=f"Missing {field_name}")
    try:
        return UUID(v)
    except Exception:
        raise HTTPException(status_code=422, detail=f"Invalid {field_name} format")


async def get_agent_row(db, *, project_id: str, agent_id: str) -> dict | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, project_id, alias, deleted_at
        FROM {{tables.agents}}
        WHERE agent_id = $1
        """,
        _parse_uuid(agent_id, field_name="agent_id"),
    )
    if not row:
        return None
    if str(row["project_id"]) != project_id:
        return None
    if row.get("deleted_at") is not None:
        return None
    return dict(row)


async def deliver_message(
    db,
    *,
    project_id: str,
    from_agent_id: str,
    from_alias: str,
    to_agent_id: str,
    subject: str,
    body: str,
    priority: MessagePriority,
    thread_id: str | None,
    from_did: str | None = None,
    to_did: str | None = None,
    signature: str | None = None,
    signing_key_id: str | None = None,
    created_at: datetime | None = None,
    message_id: UUID | None = None,
) -> tuple[UUID, datetime]:
    project_uuid = _parse_uuid(project_id, field_name="project_id")
    from_uuid = _parse_uuid(from_agent_id, field_name="from_agent_id")
    to_uuid = _parse_uuid(to_agent_id, field_name="to_agent_id")
    thread_uuid = _parse_uuid(thread_id, field_name="thread_id") if thread_id is not None else None

    sender = await get_agent_row(db, project_id=str(project_uuid), agent_id=str(from_uuid))
    if sender is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if sender["alias"] != from_alias:
        raise HTTPException(status_code=422, detail="from_alias does not match canonical alias")

    recipient = await get_agent_row(db, project_id=str(project_uuid), agent_id=str(to_uuid))
    if recipient is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if created_at is None:
        created_at = datetime.now(timezone.utc)
    if message_id is None:
        message_id = uuid_mod.uuid4()

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}}
            (message_id, project_id, from_agent_id, to_agent_id, from_alias, subject, body, priority, thread_id,
             from_did, to_did, signature, signing_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING message_id, created_at
        """,
        message_id,
        project_uuid,
        from_uuid,
        to_uuid,
        from_alias,
        subject,
        body,
        priority,
        thread_uuid,
        from_did,
        to_did,
        signature,
        signing_key_id,
        created_at,
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to create message")

    return UUID(str(row["message_id"])), row["created_at"]
