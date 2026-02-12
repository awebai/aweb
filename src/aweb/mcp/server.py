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
from aweb.mcp.tools.identity import whoami as _whoami_impl


def _register_tools(mcp: FastMCP, db_infra: DatabaseInfra) -> None:
    """Register all aweb MCP tools on the server."""

    @mcp.tool(
        name="whoami",
        description=(
            "Show the current agent's identity on the aweb network, "
            "including alias, project, and agent type."
        ),
    )
    async def whoami() -> str:
        return await _whoami_impl(db_infra)


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

    _register_tools(mcp, db_infra)

    # streamable_http_app() returns a Starlette app with the MCP endpoint
    # at streamable_http_path. We wrap it with auth middleware.
    inner = mcp.streamable_http_app()
    return MCPAuthMiddleware(inner, db_infra)
