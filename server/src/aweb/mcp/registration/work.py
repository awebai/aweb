"""Native work tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.work import work_active as _work_active_impl
from aweb.mcp.tools.work import work_blocked as _work_blocked_impl
from aweb.mcp.tools.work import work_ready as _work_ready_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native work tools with the serving dependencies."""

    @mcp.tool(
        name="work_ready",
        description="List ready tasks that are not already claimed by another workspace.",
    )
    async def work_ready() -> str:
        """List ready tasks that are not already claimed by another workspace."""
        return await _work_ready_impl(dependencies.db_infra)

    @mcp.tool(
        name="work_active", description="List active in-progress work across the team."
    )
    async def work_active() -> str:
        """List active in-progress work across the team."""
        return await _work_active_impl(
            dependencies.db_infra,
            dependencies.redis,
            registry_client=dependencies.registry_client,
        )

    @mcp.tool(
        name="work_blocked", description="List blocked tasks in the current team."
    )
    async def work_blocked() -> str:
        """List blocked tasks in the current team."""
        return await _work_blocked_impl(dependencies.db_infra)
