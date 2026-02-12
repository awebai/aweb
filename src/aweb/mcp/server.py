"""aweb MCP server factory.

Creates an MCP-over-Streamable-HTTP ASGI app that exposes aweb coordination
primitives as MCP tools.  Designed to be mounted alongside the REST API::

    from aweb.mcp import create_mcp_app
    mcp_app = create_mcp_app(db_infra=infra, redis=redis)
    fastapi_app.mount("/mcp", mcp_app)
"""

from __future__ import annotations

from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from redis.asyncio import Redis

from aweb.db import DatabaseInfra
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.mcp.tools.agents import heartbeat as _heartbeat_impl
from aweb.mcp.tools.agents import list_agents as _list_agents_impl
from aweb.mcp.tools.chat import chat_history as _chat_history_impl
from aweb.mcp.tools.chat import chat_pending as _chat_pending_impl
from aweb.mcp.tools.chat import chat_read as _chat_read_impl
from aweb.mcp.tools.chat import chat_send as _chat_send_impl
from aweb.mcp.tools.identity import whoami as _whoami_impl
from aweb.mcp.tools.mail import ack_message as _ack_message_impl
from aweb.mcp.tools.mail import check_inbox as _check_inbox_impl
from aweb.mcp.tools.mail import send_mail as _send_mail_impl


def _register_tools(mcp: FastMCP, db_infra: DatabaseInfra, redis: Optional[Redis]) -> None:
    """Register all aweb MCP tools on the server."""

    # -- Identity --

    @mcp.tool(
        name="whoami",
        description=(
            "Show the current agent's identity on the aweb network, "
            "including alias, project, and agent type."
        ),
    )
    async def whoami() -> str:
        return await _whoami_impl(db_infra)

    # -- Mail --

    @mcp.tool(
        name="send_mail",
        description=(
            "Send an async message to another agent. The recipient will see "
            "the message next time they check their inbox."
        ),
    )
    async def send_mail(
        to_alias: str,
        body: str,
        subject: str = "",
        priority: str = "normal",
    ) -> str:
        return await _send_mail_impl(
            db_infra, to_alias=to_alias, subject=subject, body=body, priority=priority
        )

    @mcp.tool(
        name="check_inbox",
        description="Check the agent's inbox for messages from other agents.",
    )
    async def check_inbox(unread_only: bool = True) -> str:
        return await _check_inbox_impl(db_infra, unread_only=unread_only)

    @mcp.tool(
        name="ack_message",
        description="Acknowledge (mark as read) a message by its ID.",
    )
    async def ack_message(message_id: str) -> str:
        return await _ack_message_impl(db_infra, message_id=message_id)

    # -- Agents --

    @mcp.tool(
        name="list_agents",
        description="List all agents in the current project with online status.",
    )
    async def list_agents() -> str:
        return await _list_agents_impl(db_infra, redis)

    @mcp.tool(
        name="heartbeat",
        description="Send a heartbeat to maintain agent presence (online status).",
    )
    async def heartbeat() -> str:
        return await _heartbeat_impl(db_infra, redis)

    # -- Chat --

    @mcp.tool(
        name="chat_send",
        description=(
            "Send a real-time chat message. Provide to_alias for a new conversation "
            "or session_id to reply in an existing one. Set wait=true to block until "
            "the other agent replies (recommended for conversations)."
        ),
    )
    async def chat_send(
        message: str,
        to_alias: str = "",
        session_id: str = "",
        wait: bool = False,
        wait_seconds: int = 120,
        leaving: bool = False,
        hang_on: bool = False,
    ) -> str:
        return await _chat_send_impl(
            db_infra,
            redis,
            message=message,
            to_alias=to_alias,
            session_id=session_id,
            wait=wait,
            wait_seconds=wait_seconds,
            leaving=leaving,
            hang_on=hang_on,
        )

    @mcp.tool(
        name="chat_pending",
        description="List conversations with unread messages waiting for you.",
    )
    async def chat_pending() -> str:
        return await _chat_pending_impl(db_infra, redis)

    @mcp.tool(
        name="chat_history",
        description="Get message history for a chat session.",
    )
    async def chat_history(
        session_id: str,
        unread_only: bool = False,
        limit: int = 50,
    ) -> str:
        return await _chat_history_impl(
            db_infra, session_id=session_id, unread_only=unread_only, limit=limit
        )

    @mcp.tool(
        name="chat_read",
        description="Mark chat messages as read up to a given message ID.",
    )
    async def chat_read(session_id: str, up_to_message_id: str) -> str:
        return await _chat_read_impl(
            db_infra, session_id=session_id, up_to_message_id=up_to_message_id
        )


def create_mcp_app(
    *,
    db_infra: DatabaseInfra,
    redis: Optional[Redis] = None,
) -> Any:
    """Create an MCP ASGI app for aweb tools.

    The returned app handles Streamable HTTP transport and can be mounted on
    any ASGI framework (FastAPI, Starlette, etc.)::

        fastapi_app.mount("/mcp", create_mcp_app(db_infra=infra))

    The MCP endpoint will be at the mount path (e.g. ``/mcp``).
    """
    mcp = FastMCP(
        "aweb",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )

    _register_tools(mcp, db_infra, redis)

    # streamable_http_app() returns a Starlette app with the MCP endpoint
    # at streamable_http_path. We wrap it with auth middleware.
    inner = mcp.streamable_http_app()
    return MCPAuthMiddleware(inner, db_infra)
