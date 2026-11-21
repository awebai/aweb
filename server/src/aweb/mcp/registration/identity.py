"""Native identity tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.identity import whoami as _whoami_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native identity tools with the serving dependencies."""

    @mcp.tool(
        name="whoami",
        description="Show the authenticated agent identity and team scope.",
    )
    async def whoami() -> str:
        """Show the authenticated agent identity and team scope."""
        return await _whoami_impl(dependencies.db_infra)
