"""MCP tools for async mail messaging."""

from __future__ import annotations

import json
from typing import cast
from uuid import UUID

from aweb.mcp.auth import get_auth
from aweb.messages_service import MessagePriority, deliver_message, get_agent_row

VALID_PRIORITIES: set[str] = set(MessagePriority.__args__)  # type: ignore[attr-defined]


async def send_mail(
    db_infra, *, to_alias: str, subject: str = "", body: str, priority: str = "normal"
) -> str:
    """Send an async message to another agent in the same project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if priority not in VALID_PRIORITIES:
        return json.dumps(
            {"error": f"Invalid priority. Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"}
        )

    # Resolve sender
    sender = await get_agent_row(db_infra, project_id=auth.project_id, agent_id=auth.agent_id)
    if sender is None:
        return json.dumps({"error": "Sender agent not found"})

    # Resolve recipient by alias
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id
        FROM {{tables.agents}}
        WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        UUID(auth.project_id),
        to_alias,
    )
    if not row:
        return json.dumps({"error": f"Agent '{to_alias}' not found in project"})

    to_agent_id = str(row["agent_id"])

    message_id, created_at = await deliver_message(
        db_infra,
        project_id=auth.project_id,
        from_agent_id=auth.agent_id,
        from_alias=sender["alias"],
        to_agent_id=to_agent_id,
        subject=subject,
        body=body,
        priority=cast(MessagePriority, priority),
        thread_id=None,
    )

    return json.dumps(
        {
            "message_id": str(message_id),
            "status": "delivered",
            "delivered_at": created_at.isoformat(),
        }
    )


async def check_inbox(db_infra, *, unread_only: bool = True) -> str:
    """List inbox messages for the authenticated agent."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_agent_id, from_alias, subject, body, priority, thread_id, read_at, created_at
        FROM {{tables.messages}}
        WHERE project_id = $1
          AND to_agent_id = $2
          AND ($3::bool IS FALSE OR read_at IS NULL)
        ORDER BY created_at DESC
        LIMIT 50
        """,
        UUID(auth.project_id),
        UUID(auth.agent_id),
        bool(unread_only),
    )

    messages = []
    for r in rows:
        messages.append(
            {
                "message_id": str(r["message_id"]),
                "from_alias": r["from_alias"],
                "subject": r["subject"],
                "body": r["body"],
                "priority": r["priority"],
                "read": r["read_at"] is not None,
                "created_at": r["created_at"].isoformat(),
            }
        )

    return json.dumps({"messages": messages})


async def ack_message(db_infra, *, message_id: str) -> str:
    """Acknowledge (mark as read) a message."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    try:
        message_uuid = UUID(message_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid message_id format"})

    row = await aweb_db.fetch_one(
        """
        SELECT read_at
        FROM {{tables.messages}}
        WHERE project_id = $1 AND message_id = $2 AND to_agent_id = $3
        """,
        UUID(auth.project_id),
        message_uuid,
        UUID(auth.agent_id),
    )
    if not row:
        return json.dumps({"error": "Message not found"})

    await aweb_db.execute(
        """
        UPDATE {{tables.messages}}
        SET read_at = COALESCE(read_at, NOW())
        WHERE project_id = $1 AND message_id = $2 AND to_agent_id = $3
        """,
        UUID(auth.project_id),
        message_uuid,
        UUID(auth.agent_id),
    )

    return json.dumps({"message_id": str(message_uuid), "status": "acknowledged"})
