"""Shared, non-consuming next-call mail/chat/room nudges for MCP factories."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from mcp.types import CallToolResult, TextContent

from aweb.mcp.auth import get_auth, primary_auth_did
from aweb.mcp.tools.room import room_notice_count
from aweb.messaging.mail_attribution import incoming_mail_sql

logger = logging.getLogger(__name__)


async def append_pending_nudge(result: Any, db_infra: Any) -> Any:
    """Append fixed count-only text to a completed FastMCP tool result.

    Call after dispatch, while MCPAuthMiddleware still binds the request's
    actor. Supported inputs are the SDK's CallToolResult, content sequence,
    structured dict, and (content, structuredContent) return shapes. Existing
    content, structured data, error state and metadata retain their wire form.
    Unavailable count components are omitted; no known pending work returns the
    input itself. Room authority/counts come from the shared room-read adapter.
    This is an active-call hint, never an idle wake or a delivery receipt.
    """
    if isinstance(result, CallToolResult) and result.isError:
        return result
    if not isinstance(result, (CallToolResult, dict, Sequence)) or isinstance(result, (str, bytes)):
        return result
    try:
        auth = get_auth()
    except RuntimeError:
        return result
    if not auth.team_id or not auth.agent_id:
        return result
    participant_did = primary_auth_did(auth)
    if not participant_did:
        return result

    mail = chat = None
    try:
        counts = await db_infra.get_manager("aweb").fetch_one(
            f"""
            WITH actor AS MATERIALIZED (
                SELECT agent_id
                FROM {{{{tables.agents}}}}
                WHERE team_id = $1 AND agent_id = $2
                  AND deleted_at IS NULL AND status = 'active'
            ),
            mine AS MATERIALIZED (
                SELECT p.session_id, p.did, p.current_did_key
                FROM {{{{tables.chat_participants}}}} p CROSS JOIN actor a
                WHERE p.did = ANY($3::text[])
            )
            SELECT
                (SELECT COUNT(*) FROM {{{{tables.messages}}}} m
                 WHERE m.read_at IS NULL
                   AND {incoming_mail_sql('$3')}) AS unread_mail,
                (SELECT COUNT(*) FROM mine p
                 JOIN {{{{tables.chat_messages}}}} m ON m.session_id = p.session_id
                 WHERE m.from_did <> p.did
                   AND m.from_did IS DISTINCT FROM p.current_did_key
                   AND NOT EXISTS (
                       SELECT 1 FROM {{{{tables.chat_message_reads}}}} r
                       WHERE r.session_id = m.session_id AND r.did = p.did
                         AND r.message_id = m.message_id
                   )) AS unread_chat_messages
            FROM actor a
            """,
            auth.team_id,
            UUID(auth.agent_id),
            [participant_did],
        )
        if counts is not None:
            mail = counts["unread_mail"]
            chat = counts["unread_chat_messages"]
            if type(mail) is not int or type(chat) is not int or mail < 0 or chat < 0:
                raise ValueError("Invalid pending message counts")
    except Exception:
        # Counting is best effort; never replace a successful tool result or
        # invent an empty mailbox when the lookup failed. Cancellation propagates.
        logger.exception("MCP pending message count lookup failed")
        mail = chat = None

    room = None
    try:
        room = await room_notice_count(db_infra)
        if room is not None and (type(room) is not int or room < 0):
            raise ValueError("Invalid pending room post count")
    except Exception:
        logger.exception("MCP room notice count lookup failed")
        room = None

    pending = []
    instructions = []
    if mail:
        pending.append(f"{mail} unread mail message{'s' if mail != 1 else ''}")
        instructions.append("Read mail with check_mail.")
    if chat:
        pending.append(f"{chat} unread chat message{'s' if chat != 1 else ''}")
        instructions.append("Read chats with check_chats and read_chat, "
                            "then mark them read with mark_chat_read.")
    if room:
        pending.append(f"{room} new team room post{'s' if room != 1 else ''}")
        instructions.append("Read the room with room_read.")
    if not pending:
        return result
    if len(pending) == 1:
        waiting = pending[0]
        if mail:
            instructions = [f"Read {'it' if mail == 1 else 'them'} with check_mail."]
        elif chat:
            pronoun = "it" if chat == 1 else "them"
            instructions = [f"Read {pronoun} with check_chats and read_chat, "
                            f"then mark {pronoun} read with mark_chat_read."]
    else:
        waiting = ", ".join(pending[:-1]) + (", and " if len(pending) > 2 else " and ") + pending[-1]
    text = f"[aweb] You have {waiting}. {' '.join(instructions)}"
    nudge = TextContent(type="text", text=text)
    if isinstance(result, CallToolResult):
        return result.model_copy(update={"content": [*result.content, nudge]})
    # Match mcp.server.lowlevel.Server.call_tool normalization, including its
    # text mirror for structured-only returns. Never merge into structured data.
    if isinstance(result, tuple) and len(result) == 2:
        content, structured = result
    elif isinstance(result, dict):
        content = [TextContent(type="text", text=json.dumps(result, indent=2))]
        structured = result
    else:
        content, structured = result, None
    return CallToolResult(content=[*content, nudge], structuredContent=structured, isError=False)
