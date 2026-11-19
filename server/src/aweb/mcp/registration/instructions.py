"""Native instructions tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.team_instructions import (
    instructions_history as _instructions_history_impl,
)
from aweb.mcp.tools.team_instructions import (
    instructions_show as _instructions_show_impl,
)

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native instructions tools with the serving dependencies."""

    @mcp.tool(
        name="instructions_show",
        description="Show the active shared team instructions or a requested instructions version.",
    )
    async def instructions_show(team_instructions_id: str = "") -> str:
        """Show the active shared team instructions or a requested instructions version."""
        return await _instructions_show_impl(
            dependencies.db_infra, team_instructions_id=team_instructions_id
        )

    @mcp.tool(
        name="instructions_history",
        description="List recent shared team instructions versions.",
    )
    async def instructions_history(limit: int = 20) -> str:
        """List recent shared team instructions versions."""
        return await _instructions_history_impl(dependencies.db_infra, limit=limit)
