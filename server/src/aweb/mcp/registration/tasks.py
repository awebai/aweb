"""Native tasks tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from aweb.mcp.tools.tasks import task_claim as _task_claim_impl
from aweb.mcp.tools.tasks import task_close as _task_close_impl
from aweb.mcp.tools.tasks import task_comment_add as _task_comment_add_impl
from aweb.mcp.tools.tasks import task_comment_list as _task_comment_list_impl
from aweb.mcp.tools.tasks import task_create as _task_create_impl
from aweb.mcp.tools.tasks import task_get as _task_get_impl
from aweb.mcp.tools.tasks import task_list as _task_list_impl
from aweb.mcp.tools.tasks import task_ready as _task_ready_impl
from aweb.mcp.tools.tasks import task_reopen as _task_reopen_impl
from aweb.mcp.tools.tasks import task_update as _task_update_impl

from .dependencies import ToolDependencies


def register_tools(mcp: FastMCP, dependencies: ToolDependencies) -> None:
    """Register the native tasks tools with the serving dependencies."""

    @mcp.tool(name="task_create", description="Create a task in the current team.")
    async def task_create(
        title: str,
        description: str = "",
        notes: str = "",
        priority: int = 2,
        task_type: str = "task",
        labels: list[str] | None = None,
        parent_task_id: str = "",
        assignee: str = "",
    ) -> str:
        """Create a task in the current team."""
        return await _task_create_impl(
            dependencies.db_infra,
            title=title,
            description=description,
            notes=notes,
            priority=priority,
            task_type=task_type,
            labels=labels,
            parent_task_id=parent_task_id,
            assignee=assignee,
        )

    @mcp.tool(name="task_list", description="List tasks in the current team.")
    async def task_list(
        status: str = "",
        assignee: str = "",
        task_type: str = "",
        priority: int = -1,
        labels: list[str] | None = None,
    ) -> str:
        """List tasks in the current team."""
        return await _task_list_impl(
            dependencies.db_infra,
            status=status,
            assignee=assignee,
            task_type=task_type,
            priority=priority,
            labels=labels,
        )

    @mcp.tool(name="task_ready", description="List ready tasks in the current team.")
    async def task_ready(unclaimed_only: bool = True) -> str:
        """List ready tasks in the current team."""
        return await _task_ready_impl(
            dependencies.db_infra, unclaimed_only=unclaimed_only
        )

    @mcp.tool(name="task_get", description="Get a task by ref or UUID.")
    async def task_get(ref: str) -> str:
        """Get a task by ref or UUID."""
        return await _task_get_impl(dependencies.db_infra, ref=ref)

    @mcp.tool(name="task_close", description="Close a task by ref or UUID.")
    async def task_close(ref: str) -> str:
        """Close a task by ref or UUID."""
        return await _task_close_impl(dependencies.db_infra, ref=ref)

    @mcp.tool(
        name="task_update",
        description="Update task fields such as status, title, notes, assignee, or labels.",
    )
    async def task_update(
        ref: str,
        status: str = "",
        title: str = "",
        description: str = "",
        notes: str = "",
        task_type: str = "",
        priority: int = -1,
        labels: list[str] | None = None,
        assignee: str = "",
    ) -> str:
        """Update task fields such as status, title, notes, assignee, or labels."""
        return await _task_update_impl(
            dependencies.db_infra,
            ref=ref,
            status=status,
            title=title,
            description=description,
            notes=notes,
            task_type=task_type,
            priority=priority,
            labels=labels,
            assignee=assignee,
        )

    @mcp.tool(name="task_reopen", description="Reopen a closed task.")
    async def task_reopen(ref: str) -> str:
        """Reopen a closed task."""
        return await _task_reopen_impl(dependencies.db_infra, ref=ref)

    @mcp.tool(
        name="task_claim",
        description="Claim a task by marking it in progress for the current agent.",
    )
    async def task_claim(ref: str) -> str:
        """Claim a task by marking it in progress for the current agent."""
        return await _task_claim_impl(dependencies.db_infra, ref=ref)

    @mcp.tool(name="task_comment_add", description="Add a comment to a task.")
    async def task_comment_add(ref: str, body: str) -> str:
        """Add a comment to a task."""
        return await _task_comment_add_impl(dependencies.db_infra, ref=ref, body=body)

    @mcp.tool(name="task_comment_list", description="List comments on a task.")
    async def task_comment_list(ref: str) -> str:
        """List comments on a task."""
        return await _task_comment_list_impl(dependencies.db_infra, ref=ref)
