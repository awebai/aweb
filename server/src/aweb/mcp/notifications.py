"""Shared, non-consuming next-call mail/chat nudges for MCP factories."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from mcp.types import CallToolResult, TextContent

from aweb.mcp.auth import get_auth

logger = logging.getLogger(__name__)


async def append_pending_nudge(result: Any, db_infra: Any) -> Any:
    """Append fixed count-only text to a completed FastMCP tool result.

    Call after dispatch, while MCPAuthMiddleware still binds the request's
    actor. Supported inputs are the SDK's CallToolResult, content sequence,
    structured dict, and (content, structuredContent) return shapes. Existing
    content, structured data, error state and metadata retain their wire form.
    No-pending, unscoped, failed and unavailable lookups return the input itself.
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

    try:
        counts = await db_infra.get_manager("aweb").fetch_one(
            """
            WITH actor AS MATERIALIZED (
                SELECT agent_id, did_key,
                       CASE WHEN did_aw_verified_key = did_key
                            THEN NULLIF(did_aw, '') END AS did_aw
                FROM {{tables.agents}}
                WHERE team_id = $1 AND agent_id = $2
                  AND deleted_at IS NULL AND status = 'active'
            ),
            mine AS MATERIALIZED (
                SELECT DISTINCT ON (p.session_id) p.session_id, p.did
                FROM {{tables.chat_participants}} p CROSS JOIN actor a
                WHERE p.did = a.did_key OR p.did = a.did_aw OR p.agent_id = a.agent_id
                ORDER BY p.session_id,
                         CASE WHEN p.did = a.did_aw THEN 0
                              WHEN p.did = a.did_key THEN 1 ELSE 2 END, p.did
            )
            SELECT
                (SELECT COUNT(*) FROM {{tables.messages}} m
                 WHERE m.read_at IS NULL
                   AND (m.to_did = a.did_key OR m.to_did = a.did_aw)) AS unread_mail,
                (SELECT COUNT(*) FROM mine p
                 JOIN {{tables.chat_messages}} m ON m.session_id = p.session_id
                 WHERE m.from_did <> p.did
                   AND NOT EXISTS (
                       SELECT 1 FROM {{tables.chat_message_reads}} r
                       WHERE r.session_id = m.session_id AND r.did = p.did
                         AND r.message_id = m.message_id
                   )) AS unread_chat_messages
            FROM actor a
            """,
            auth.team_id,
            UUID(auth.agent_id),
        )
        if counts is None:
            return result
        mail = counts["unread_mail"]
        chat = counts["unread_chat_messages"]
        if type(mail) is not int or type(chat) is not int or mail < 0 or chat < 0:
            raise ValueError("Invalid pending message counts")
    except Exception:
        # Counting is best effort; never replace a successful tool result or
        # invent an empty mailbox when the lookup failed. Cancellation propagates.
        logger.exception("MCP pending message count lookup failed")
        return result
    if mail == 0 and chat == 0:
        return result

    mail_waiting = f"{mail} unread mail message{'s' if mail != 1 else ''}"
    chat_waiting = f"{chat} unread chat message{'s' if chat != 1 else ''}"
    if mail and chat:
        text = (f"[aweb] You have {mail_waiting} and {chat_waiting}. "
                "Read mail with check_mail. Read chats with check_chats and read_chat, "
                "then mark them read with mark_chat_read.")
    elif mail:
        text = (f"[aweb] You have {mail_waiting}. "
                f"Read {'it' if mail == 1 else 'them'} with check_mail.")
    else:
        pronoun = "it" if chat == 1 else "them"
        text = (f"[aweb] You have {chat_waiting}. "
                f"Read {pronoun} with check_chats and read_chat, "
                f"then mark {pronoun} read with mark_chat_read.")
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
