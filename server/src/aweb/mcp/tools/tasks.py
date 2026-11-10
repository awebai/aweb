"""MCP tools for team task coordination."""

from __future__ import annotations

import json

from pydantic import ValidationError as InvalidRequest

from aweb.coordination.tasks_service import (
    AddCommentRequest,
    CreateTaskRequest,
    UpdateTaskRequest,
    add_comment,
    create_task,
    get_task,
    list_comments,
    list_ready_tasks,
    list_tasks,
    update_task,
)
from aweb.mcp.mutations import current_mutation_callback
from aweb.mcp.tools._common import require_team_context, team_identity
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError

# What the REST routes answer with 403, 404, 409 and 422.
_REFUSALS = (ConflictError, ForbiddenError, NotFoundError, ValidationError)


def _invalid(exc: InvalidRequest) -> str:
    """The tool's answer to input the request model refuses, as the routes' 422."""
    return json.dumps({
        "error": "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in exc.errors()
        )
    })


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
    """Create a task in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    try:
        payload = CreateTaskRequest(
            title=title,
            description=description,
            notes=notes,
            priority=priority,
            task_type=task_type,
            labels=labels or [],
            parent_task_id=parent_task_id or None,
            assignee_alias=assignee or None,
        )
        result = await create_task(
            db_infra,
            actor=team_identity(auth),
            on_mutation=current_mutation_callback(),
            **payload.model_dump(),
        )
    except InvalidRequest as exc:
        return _invalid(exc)
    except _REFUSALS as exc:
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
    """List tasks in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    try:
        tasks = await list_tasks(
            db_infra,
            team_id=auth.team_id,
            status=status or None,
            assignee_alias=assignee or None,
            task_type=task_type or None,
            priority=priority if priority >= 0 else None,
            labels=labels or None,
        )
    except ValidationError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"tasks": tasks})


async def task_ready(db_infra, *, unclaimed_only: bool = True) -> str:
    """List ready tasks in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    tasks = await list_ready_tasks(
        db_infra,
        team_id=auth.team_id,
        unclaimed=bool(unclaimed_only),
    )
    return json.dumps({"tasks": tasks})


async def task_get(db_infra, *, ref: str) -> str:
    """Get a task by ref or UUID."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    try:
        task = await get_task(db_infra, team_id=auth.team_id, ref=ref)
    except NotFoundError:
        return json.dumps({"error": "Task not found"})
    return json.dumps(task)


async def task_close(db_infra, *, ref: str) -> str:
    """Close a task by ref or UUID."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    try:
        task = await update_task(
            db_infra,
            actor=team_identity(auth),
            on_mutation=current_mutation_callback(),
            ref=ref,
            status="closed",
        )
    except _REFUSALS as exc:
        return json.dumps({"error": exc.detail})
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
    """Update a task in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})

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
        kwargs["assignee_alias"] = assignee

    if not kwargs:
        return json.dumps(
            {
                "error": "No fields to update. Provide status, title, description, notes, task_type, priority, labels, or assignee."
            }
        )

    try:
        task = await update_task(
            db_infra,
            actor=team_identity(auth),
            on_mutation=current_mutation_callback(),
            ref=ref,
            **UpdateTaskRequest(**kwargs).changes(),
        )
    except InvalidRequest as exc:
        return _invalid(exc)
    except _REFUSALS as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps(task)


async def task_reopen(db_infra, *, ref: str) -> str:
    """Reopen a task by ref or UUID."""
    return await task_update(db_infra, ref=ref, status="open")


async def task_claim(db_infra, *, ref: str) -> str:
    """Claim a task by marking it in progress for the authenticated agent."""
    return await task_update(db_infra, ref=ref, status="in_progress")


async def task_comment_add(db_infra, *, ref: str, body: str) -> str:
    """Add a comment to a task."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    try:
        comment = await add_comment(
            db_infra,
            actor=team_identity(auth),
            on_mutation=current_mutation_callback(),
            ref=ref,
            body=AddCommentRequest(body=body).body,
        )
    except InvalidRequest as exc:
        return _invalid(exc)
    except _REFUSALS as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps(comment)


async def task_comment_list(db_infra, *, ref: str) -> str:
    """List comments on a task."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    try:
        comments = await list_comments(db_infra, team_id=auth.team_id, ref=ref)
    except NotFoundError as exc:
        return json.dumps({"error": exc.detail})
    return json.dumps({"comments": comments})
