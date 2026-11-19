"""Native agents tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.agents import heartbeat as _heartbeat_impl
from aweb.mcp.tools.agents import list_agents as _list_agents_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native agents tools with the serving dependencies."""

    @mcp.tool(
        name="list_agents",
        description="List all agents in the current team with online status.",
    )
    async def list_agents() -> str:
        """List all agents in the current team with online status."""
        return await _list_agents_impl(
            dependencies.db_infra,
            dependencies.redis,
            registry_client=dependencies.registry_client,
        )

    @mcp.tool(
        name="heartbeat",
        description="Send a heartbeat to maintain agent presence (online status).",
    )
    async def heartbeat() -> str:
        """Send a heartbeat to maintain agent presence (online status)."""
        return await _heartbeat_impl(dependencies.db_infra, dependencies.redis)
