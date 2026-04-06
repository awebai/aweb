"""MCP tools for async mail messaging."""

from __future__ import annotations

import json
from typing import cast
from uuid import UUID

from aweb.mcp.auth import get_auth
from aweb.messaging.messages import (
    MessagePriority,
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
    utc_iso as _utc_iso,
)

VALID_PRIORITIES: set[str] = set(MessagePriority.__args__)  # type: ignore[attr-defined]


async def send_mail(
    db_infra,
    *,
    to: str,
    subject: str = "",
    body: str,
    priority: str = "normal",
) -> str:
    """Send an async message to an alias within the team."""
    auth = get_auth()
    if priority not in VALID_PRIORITIES:
        return json.dumps(
            {"error": f"Invalid priority. Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"}
        )

    recipient_alias = (to or "").strip()
    if not recipient_alias:
        return json.dumps({"error": "Recipient is required"})

    recipient = await get_agent_by_alias(
        db_infra, team_address=auth.team_address, alias=recipient_alias,
    )
    if recipient is None:
        return json.dumps({"error": f"Agent '{recipient_alias}' not found"})

    try:
        message_id, created_at = await deliver_message(
            db_infra,
            team_address=auth.team_address,
            from_agent_id=auth.agent_id,
            from_alias=auth.alias,
            to_agent_id=str(recipient["agent_id"]),
            to_alias=recipient["alias"],
            subject=subject,
            body=body,
            priority=cast(MessagePriority, priority),
        )
    except Exception as exc:
        detail = getattr(exc, "detail", None)
        return json.dumps({"error": detail or str(exc)})

    return json.dumps(
        {
            "message_id": str(message_id),
            "status": "delivered",
            "delivered_at": _utc_iso(created_at),
            "to": recipient_alias,
        }
    )


async def check_inbox(
    db_infra,
    *,
    unread_only: bool = True,
    limit: int = 50,
    include_bodies: bool = True,
) -> str:
    """List inbox messages for the authenticated agent."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    owner = await get_agent_by_id(
        db_infra, team_address=auth.team_address, agent_id=auth.agent_id,
    )
    if owner is None:
        return json.dumps({"error": "Agent not found"})

    try:
        limit_value = max(1, min(int(limit), 500))
    except Exception:
        return json.dumps({"error": "limit must be an integer"})

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_agent_id, from_alias, to_alias,
               subject, body, priority, read_at, created_at,
               from_did, signature, signed_payload
        FROM {{tables.messages}}
        WHERE team_address = $1
          AND to_agent_id = $2
          AND ($3::bool IS FALSE OR read_at IS NULL)
        ORDER BY created_at DESC
        LIMIT $4
        """,
        auth.team_address,
        UUID(auth.agent_id),
        bool(unread_only),
        limit_value,
    )

    # Auto-acknowledge unread messages
    unread_message_ids = [r["message_id"] for r in rows if r["read_at"] is None]
    if unread_message_ids:
        await aweb_db.execute(
            """
            UPDATE {{tables.messages}}
            SET read_at = COALESCE(read_at, NOW())
            WHERE team_address = $1
              AND to_agent_id = $2
              AND message_id = ANY($3::uuid[])
            """,
            auth.team_address,
            UUID(auth.agent_id),
            unread_message_ids,
        )

    messages = []
    for r in rows:
        read_at = _utc_iso(r["read_at"]) if r["read_at"] is not None else None
        msg: dict = {
            "message_id": str(r["message_id"]),
            "from_agent_id": str(r["from_agent_id"]),
            "from_alias": r["from_alias"],
            "to_alias": r["to_alias"],
            "subject": r["subject"],
            "priority": r["priority"],
            "read": read_at is not None or r["message_id"] in unread_message_ids,
            "read_at": read_at,
            "created_at": _utc_iso(r["created_at"]),
        }
        if include_bodies:
            msg["body"] = r["body"]
        if r["from_did"]:
            msg["from_did"] = r["from_did"]
        if r["signature"]:
            msg["signature"] = r["signature"]
        if r["signed_payload"]:
            msg["signed_payload"] = r["signed_payload"]
        messages.append(msg)

    return json.dumps({"messages": messages})
