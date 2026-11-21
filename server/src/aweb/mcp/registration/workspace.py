"""Native workspace tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.workspace import workspace_status as _workspace_status_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native workspace tools with the serving dependencies."""

    @mcp.tool(
        name="workspace_status",
        description="Show self/team coordination status for the current agent.",
    )
    async def workspace_status(limit: int = 15) -> str:
        """Show self/team coordination status for the current agent."""
        return await _workspace_status_impl(
            dependencies.db_infra,
            dependencies.redis,
            registry_client=dependencies.registry_client,
            limit=limit,
        )
