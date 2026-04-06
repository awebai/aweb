from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from aweb.service_errors import NotFoundError, ServiceError, ValidationError

MessagePriority = Literal["low", "normal", "high", "urgent"]


def utc_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601, UTC, second precision with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_uuid(v: str, *, field_name: str) -> UUID:
    v = str(v).strip()
    if not v:
        raise ValidationError(f"Missing {field_name}")
    try:
        return UUID(v)
    except Exception:
        raise ValidationError(f"Invalid {field_name} format")


async def get_agent_by_id(db, *, team_address: str, agent_id: str) -> dict | None:
    """Look up an agent by agent_id within a team."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_address, alias, did_key, status, deleted_at
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND team_address = $2 AND deleted_at IS NULL
        """,
        _parse_uuid(agent_id, field_name="agent_id"),
        team_address,
    )
    if not row:
        return None
    return dict(row)


async def get_agent_by_alias(db, *, team_address: str, alias: str) -> dict | None:
    """Look up an agent by alias within a team."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_address, alias, did_key, status, deleted_at
        FROM {{tables.agents}}
        WHERE team_address = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_address,
        alias,
    )
    if not row:
        return None
    return dict(row)


async def deliver_message(
    db,
    *,
    team_address: str,
    from_agent_id: str,
    from_alias: str,
    to_agent_id: str,
    to_alias: str,
    subject: str,
    body: str,
    priority: MessagePriority,
    from_did: str | None = None,
    signature: str | None = None,
    signed_payload: str | None = None,
    created_at: datetime | None = None,
    message_id: UUID | None = None,
) -> tuple[UUID, datetime]:
    """Deliver a message within a team.

    Validates that both sender and recipient exist in the team,
    then inserts the message row.
    """
    from_uuid = _parse_uuid(from_agent_id, field_name="from_agent_id")
    to_uuid = _parse_uuid(to_agent_id, field_name="to_agent_id")

    sender = await get_agent_by_id(db, team_address=team_address, agent_id=str(from_uuid))
    if sender is None:
        raise NotFoundError("Sender agent not found")
    if sender["alias"] != from_alias:
        raise ValidationError("from_alias does not match canonical alias")

    recipient = await get_agent_by_id(db, team_address=team_address, agent_id=str(to_uuid))
    if recipient is None:
        raise NotFoundError("Recipient agent not found")

    if created_at is None:
        created_at = datetime.now(timezone.utc)
    if message_id is None:
        message_id = uuid_mod.uuid4()

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}}
            (message_id, team_address, from_agent_id, to_agent_id,
             from_alias, to_alias, subject, body, priority,
             from_did, signature, signed_payload, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING message_id, created_at
        """,
        message_id,
        team_address,
        from_uuid,
        to_uuid,
        from_alias,
        to_alias,
        subject,
        body,
        priority,
        from_did,
        signature,
        signed_payload,
        created_at,
    )
    if not row:
        raise ServiceError("Failed to create message")

    return UUID(str(row["message_id"])), row["created_at"]
