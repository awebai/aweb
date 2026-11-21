"""Native roles tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.team_roles import roles_list as _roles_list_impl
from aweb.mcp.tools.team_roles import roles_show as _roles_show_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native roles tools with the serving dependencies."""

    @mcp.tool(
        name="roles_show",
        description="Show the active team roles bundle and the current agent's selected role.",
    )
    async def roles_show(only_selected: bool = False) -> str:
        """Show the active team roles bundle and the current agent's selected role."""
        return await _roles_show_impl(
            dependencies.db_infra, only_selected=only_selected
        )

    @mcp.tool(
        name="roles_list",
        description="List available roles from the active team roles bundle.",
    )
    async def roles_list() -> str:
        """List available roles from the active team roles bundle."""
        return await _roles_list_impl(dependencies.db_infra)
