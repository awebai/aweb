"""MCP tools for async mail messaging."""

from __future__ import annotations

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import cast
from uuid import UUID

from aweb.mcp.auth import get_auth
from aweb.messaging.contacts import check_access, get_contact_addresses, is_address_in_contacts
from aweb.messaging.messages import MessagePriority, deliver_message, get_agent_by_id as get_agent_row
from aweb.messaging.messages import utc_iso as _utc_iso
from aweb.service_errors import ServiceError

VALID_PRIORITIES: set[str] = set(MessagePriority.__args__)  # type: ignore[attr-defined]


async def _project_slug_map(db_infra, *, project_ids: set[str]) -> dict[str, str]:
    if not project_ids:
        return {}

    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT project_id, slug
        FROM {{tables.projects}}
        WHERE project_id = ANY($1::uuid[]) AND deleted_at IS NULL
        """,
        [UUID(project_id) for project_id in sorted(project_ids)],
    )
    return {str(row["project_id"]): row["slug"] for row in rows}


async def send_mail(
    db_infra,
    *,
    registry_client,
    to: str,
    subject: str = "",
    body: str,
    priority: str = "normal",
    thread_id: str = "",
) -> str:
    """Send an async message to an alias, scoped address, or namespace address."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if priority not in VALID_PRIORITIES:
        return json.dumps(
            {"error": f"Invalid priority. Must be one of: {', '.join(sorted(VALID_PRIORITIES))}"}
        )

    sender = await get_agent_row(db_infra, project_id=auth.project_id, agent_id=auth.agent_id)
    if sender is None:
        return json.dumps({"error": "Sender agent not found"})

    recipient_ref = (to or "").strip()
    if not recipient_ref:
        return json.dumps({"error": "Recipient is required"})

    try:
        recipient = await resolve_local_recipient(
            db_infra,
            sender_project_id=auth.project_id,
            sender_agent_id=auth.agent_id,
            ref=recipient_ref,
            registry_client=registry_client,
        )
    except Exception as exc:
        detail = getattr(exc, "detail", None)
        return json.dumps({"error": detail or str(exc)})

    sender_scope = await get_project_scope(db_infra, project_id=auth.project_id)
    recipient_scope = await get_project_scope(db_infra, project_id=recipient.project_id)
    sender_from_address = format_local_address(
        base_project_slug=recipient_scope.project_slug,
        target_project_slug=sender_scope.project_slug,
        alias=sender["alias"],
    )
    allowed = await check_access(
        db_infra,
        target_project_id=recipient.project_id,
        target_agent_id=recipient.agent_id,
        sender_project_id=auth.project_id,
        sender_address=sender_from_address,
    )
    if not allowed:
        return json.dumps({"error": "Recipient only accepts messages from contacts"})

    retired = await aweb_db.fetch_one(
        """
        SELECT status, successor_agent_id
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(recipient.agent_id),
        UUID(recipient.project_id),
    )
    if retired and retired["status"] == "retired":
        successor_alias = None
        succ_id = retired["successor_agent_id"]
        if succ_id:
            succ = await aweb_db.fetch_one(
                "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1 AND deleted_at IS NULL",
                succ_id,
            )
            if succ:
                successor_alias = succ["alias"]
        return json.dumps(
            {
                "error": "Agent is retired",
                "successor_alias": successor_alias,
                "successor_agent_id": str(succ_id) if succ_id is not None else None,
            }
        )

    stable_ids = await ensure_agent_stable_ids(
        aweb_db, agent_ids=[auth.agent_id, recipient.agent_id]
    )
    msg_from_did = None
    msg_from_stable_id = stable_ids.get(auth.agent_id)
    msg_to_stable_id = stable_ids.get(recipient.agent_id)
    msg_signature = None
    msg_signing_key_id = None
    msg_signed_payload = None
    created_at = datetime.now(timezone.utc)
    pre_message_id = uuid_mod.uuid4()

    sign_result = await sign_on_behalf(
        auth.agent_id,
        {
            "from": sender_from_address,
            "from_did": "",
            "from_stable_id": msg_from_stable_id or "",
            "message_id": str(pre_message_id),
            "to": recipient_ref,
            "to_did": "",
            "to_stable_id": msg_to_stable_id or "",
            "type": "mail",
            "subject": subject,
            "body": body,
            "timestamp": _utc_iso(created_at),
        },
        db_infra,
    )
    if sign_result is not None:
        msg_from_did, msg_signature, msg_signing_key_id, msg_signed_payload = sign_result

    try:
        message_id, created_at = await deliver_message(
            db_infra,
            project_id=auth.project_id,
            from_agent_id=auth.agent_id,
            from_alias=sender["alias"],
            to_agent_id=recipient.agent_id,
            recipient_project_id=recipient.project_id,
            subject=subject,
            body=body,
            priority=cast(MessagePriority, priority),
            thread_id=thread_id or None,
            from_did=msg_from_did,
            from_stable_id=msg_from_stable_id,
            to_stable_id=msg_to_stable_id,
            signature=msg_signature,
            signing_key_id=msg_signing_key_id,
            signed_payload=msg_signed_payload,
            created_at=created_at,
            message_id=pre_message_id,
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    await acknowledge_rotation(
        aweb_db,
        from_agent_id=UUID(auth.agent_id),
        to_agent_id=UUID(recipient.agent_id),
    )

    return json.dumps(
        {
            "message_id": str(message_id),
            "status": "delivered",
            "delivered_at": _utc_iso(created_at),
            "to": recipient_ref,
            "thread_id": thread_id or None,
        }
    )


async def check_inbox(
    db_infra,
    *,
    registry_client=None,
    unread_only: bool = True,
    limit: int = 50,
    include_bodies: bool = True,
) -> str:
    """List inbox messages for the authenticated agent."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    owner = await get_agent_row(db_infra, project_id=auth.project_id, agent_id=auth.agent_id)
    if owner is None:
        return json.dumps({"error": "Agent not found"})

    try:
        limit_value = max(1, min(int(limit), 500))
    except Exception:
        return json.dumps({"error": "limit must be an integer"})

    rows = await aweb_db.fetch_all(
        """
        SELECT message_id, from_agent_id, from_alias, subject, body, priority, thread_id, read_at, created_at,
               from_did, from_stable_id, to_did, to_stable_id, signature, signing_key_id,
               signed_payload, project_id, recipient_project_id
        FROM {{tables.messages}}
        WHERE recipient_project_id = $1
          AND to_agent_id = $2
          AND ($3::bool IS FALSE OR read_at IS NULL)
        ORDER BY created_at DESC
        LIMIT $4
        """,
        UUID(auth.project_id),
        UUID(auth.agent_id),
        bool(unread_only),
        limit_value,
    )

    sender_ids = list({r["from_agent_id"] for r in rows})
    announcements = await get_pending_announcements(
        aweb_db, sender_ids=sender_ids, recipient_id=UUID(auth.agent_id)
    )
    sender_delivery = await get_sender_delivery_metadata(
        aweb_db,
        sender_ids=sender_ids,
        registry_client=registry_client,
    )
    contact_addrs = await get_contact_addresses(db_infra, project_id=auth.project_id)
    slug_by_project_id = await _project_slug_map(
        db_infra,
        project_ids={
            str(r["project_id"])
            for r in rows
        }
        | {
            str(r["recipient_project_id"])
            for r in rows
        },
    )

    unread_message_ids = [r["message_id"] for r in rows if r["read_at"] is None]
    acknowledged_at_by_id: dict[str, str] = {}
    if unread_message_ids:
        await aweb_db.execute(
            """
            UPDATE {{tables.messages}}
            SET read_at = COALESCE(read_at, NOW())
            WHERE recipient_project_id = $1
              AND to_agent_id = $2
              AND message_id = ANY($3::uuid[])
            """,
            UUID(auth.project_id),
            UUID(auth.agent_id),
            unread_message_ids,
        )
        acknowledged_rows = await aweb_db.fetch_all(
            """
            SELECT message_id, read_at
            FROM {{tables.messages}}
            WHERE recipient_project_id = $1
              AND to_agent_id = $2
              AND message_id = ANY($3::uuid[])
            """,
            UUID(auth.project_id),
            UUID(auth.agent_id),
            unread_message_ids,
        )
        acknowledged_at_by_id = {
            str(row["message_id"]): _utc_iso(row["read_at"])
            for row in acknowledged_rows
            if row["read_at"] is not None
        }

    messages = []
    for r in rows:
        message_id = str(r["message_id"])
        read_at = acknowledged_at_by_id.get(message_id) or (
            _utc_iso(r["read_at"]) if r["read_at"] is not None else None
        )
        sender_project_id = str(r["project_id"])
        recipient_project_id = str(r["recipient_project_id"])
        sender_project_slug = slug_by_project_id.get(sender_project_id)
        recipient_project_slug = slug_by_project_id.get(recipient_project_id)
        if not sender_project_slug or not recipient_project_slug:
            return json.dumps({"error": "Project not found"})
        local_from_address = format_local_address(
            base_project_slug=recipient_project_slug,
            target_project_slug=sender_project_slug,
            alias=r["from_alias"],
        )
        sender_meta = sender_delivery.get(str(r["from_agent_id"]), {})
        from_address = sender_meta.get("from_address") or local_from_address
        to_address = format_local_address(
            base_project_slug=sender_project_slug,
            target_project_slug=recipient_project_slug,
            alias=owner["alias"],
        )
        msg: dict = {
            "message_id": message_id,
            "from_agent_id": str(r["from_agent_id"]),
            "from_alias": r["from_alias"],
            "from_address": from_address,
            "subject": r["subject"],
            "priority": r["priority"],
            "thread_id": str(r["thread_id"]) if r["thread_id"] is not None else None,
            "read": read_at is not None,
            "read_at": read_at,
            "created_at": _utc_iso(r["created_at"]),
            "to_address": to_address,
            "is_contact": is_address_in_contacts(from_address, contact_addrs),
        }
        if include_bodies:
            msg["body"] = r["body"]
        if r["from_did"]:
            msg["from_did"] = r["from_did"]
        if r["from_stable_id"]:
            msg["from_stable_id"] = r["from_stable_id"]
        if r["to_did"]:
            msg["to_did"] = r["to_did"]
        if r["to_stable_id"]:
            msg["to_stable_id"] = r["to_stable_id"]
        if r["signature"]:
            msg["signature"] = r["signature"]
        if r["signing_key_id"]:
            msg["signing_key_id"] = r["signing_key_id"]
        if r["signed_payload"]:
            msg["signed_payload"] = r["signed_payload"]
        announcement = announcements.get(str(r["from_agent_id"]))
        if announcement:
            msg["rotation_announcement"] = announcement
        messages.append(msg)

    return json.dumps({"messages": messages})
