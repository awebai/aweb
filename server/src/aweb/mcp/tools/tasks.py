"""MCP tools for project task coordination."""

from __future__ import annotations

import json

from aweb.coordination.tasks_service import (
    add_comment,
    create_task,
    get_task,
    list_comments,
    list_ready_tasks,
    list_tasks,
    update_task,
)
from aweb.mcp.auth import get_auth
from aweb.service_errors import ConflictError, NotFoundError, ValidationError


async def task_create(
    db_infra,
    *,
    title: str,
    description: str = "",
    notes: str = "",
    priority: int = 2,
    task_type: str = "task",
    labels: list[str] | None = None,
    parent_task_id: str = "",
    assignee: str = "",
) -> str:
    """Create a task in the authenticated project."""
    auth = get_auth()
    try:
        result = await create_task(
            db_infra,
            project_id=auth.project_id,
            created_by_agent_id=auth.agent_id,
            title=title,
            description=description,
            notes=notes,
            priority=priority,
            task_type=task_type,
            labels=labels or [],
            parent_task_id=parent_task_id or None,
            assignee_agent_id=assignee or None,
        )
    except ValidationError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps(result)


async def task_list(
    db_infra,
    *,
    status: str = "",
    assignee: str = "",
    task_type: str = "",
    priority: int = -1,
    labels: list[str] | None = None,
) -> str:
    """List tasks in the authenticated project."""
    auth = get_auth()
    try:
        tasks = await list_tasks(
            db_infra,
            project_id=auth.project_id,
            status=status or None,
            assignee_agent_id=assignee or None,
            task_type=task_type or None,
            priority=priority if priority >= 0 else None,
            labels=labels or None,
        )
    except ValidationError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"tasks": tasks})


async def task_ready(db_infra, *, unclaimed_only: bool = True) -> str:
    """List ready tasks in the authenticated project."""
    auth = get_auth()
    tasks = await list_ready_tasks(
        db_infra,
        project_id=auth.project_id,
        unclaimed=bool(unclaimed_only),
    )
    return json.dumps({"tasks": tasks})


async def task_get(db_infra, *, ref: str) -> str:
    """Get a task by ref or UUID."""
    auth = get_auth()
    try:
        task = await get_task(db_infra, project_id=auth.project_id, ref=ref)
    except NotFoundError:
        return json.dumps({"error": "Task not found"})
    return json.dumps(task)


async def task_close(db_infra, *, ref: str) -> str:
    """Close a task by ref or UUID."""
    auth = get_auth()
    try:
        task = await update_task(
            db_infra,
            project_id=auth.project_id,
            ref=ref,
            actor_agent_id=auth.agent_id,
            status="closed",
        )
    except (NotFoundError, ValidationError) as exc:
        return json.dumps({"error": exc.detail})
    task.pop("old_status", None)
    task.pop("claim_preacquired", None)
    return json.dumps(task)


async def task_update(
    db_infra,
    *,
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
    """Update a task in the authenticated project."""
    auth = get_auth()

    kwargs = {}
    if status:
        kwargs["status"] = status
    if title:
        kwargs["title"] = title
    if description:
        kwargs["description"] = description
    if notes:
        kwargs["notes"] = notes
    if task_type:
        kwargs["task_type"] = task_type
    if priority >= 0:
        kwargs["priority"] = priority
    if labels is not None:
        kwargs["labels"] = labels
    if assignee:
        kwargs["assignee_agent_id"] = assignee

    if not kwargs:
        return json.dumps(
            {
                "error": "No fields to update. Provide status, title, description, notes, task_type, priority, labels, or assignee."
            }
        )

    try:
        task = await update_task(
            db_infra,
            project_id=auth.project_id,
            ref=ref,
            actor_agent_id=auth.agent_id,
            **kwargs,
        )
    except (ConflictError, NotFoundError, ValidationError) as exc:
        return json.dumps({"error": exc.detail})

    task.pop("old_status", None)
    return json.dumps(task)


async def task_reopen(db_infra, *, ref: str) -> str:
    """Reopen a task by ref or UUID."""
    return await task_update(db_infra, ref=ref, status="open")


async def task_claim(db_infra, *, ref: str) -> str:
    """Claim a task by marking it in progress for the authenticated agent."""
    return await task_update(db_infra, ref=ref, status="in_progress")


async def task_comment_add(db_infra, *, ref: str, body: str) -> str:
    """Add a comment to a task."""
    auth = get_auth()
    try:
        comment = await add_comment(
            db_infra,
            project_id=auth.project_id,
            ref=ref,
            agent_id=auth.agent_id,
            body=body,
        )
    except (NotFoundError, ValidationError) as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps(comment)


async def task_comment_list(db_infra, *, ref: str) -> str:
    """List comments on a task."""
    auth = get_auth()
    try:
        comments = await list_comments(db_infra, project_id=auth.project_id, ref=ref)
    except NotFoundError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"comments": comments})
