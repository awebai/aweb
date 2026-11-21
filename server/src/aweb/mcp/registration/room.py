"""Native room tool registration."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.room import (
    room_pending as _room_pending_impl,
)
from aweb.mcp.tools.room import (
    room_post as _room_post_impl,
)
from aweb.mcp.tools.room import (
    room_read as _room_read_impl,
)
from aweb.messaging.room import ROOM_DISCLOSURE

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native room tools with the serving dependencies."""

    @mcp.tool(
        name="room_pending",
        description="Check your pending team room notices without acknowledging mail or chat. Read posts with room_read.",
    )
    async def room_pending() -> str:
        """Check your pending team room notices without acknowledging mail or chat. Read posts with room_read."""
        return await _room_pending_impl(dependencies.db_infra)

    @mcp.tool(
        name="room_read",
        description="Read the shared team room, oldest first. All current members can read retained history, including posts made before they joined. Explicit read only; follow next_cursor when has_more is true.",
    )
    async def room_read(after: str | None = None, limit: int = 50) -> str:
        """Read the shared team room, oldest first. All current members can read retained history, including posts made before they joined. Explicit read only; follow next_cursor when has_more is true."""
        return await _room_read_impl(dependencies.db_infra, after=after, limit=limit)

    @mcp.tool(
        name="room_post",
        description="Post a signed announcement to the shared team room. "
        + ROOM_DISCLOSURE
        + " Hosted MCP signs as the authenticated actor. Self-custodial callers supply signed_post. E2E rooms are unsupported. Other current members receive one notice per post; no reply is expected.",
    )
    async def room_post(
        body: str = "",
        subject: str = "",
        e2ee: bool = False,
        signed_post: dict[str, Any] | None = None,
    ) -> str:
        """Post a signed announcement using the native shared-room contract."""
        return await _room_post_impl(
            dependencies.db_infra,
            hosted_signer=dependencies.hosted_signer,
            body=body,
            subject=subject,
            e2ee=e2ee,
            signed_post=signed_post,
        )
