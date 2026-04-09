"""Native task endpoints."""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.team_auth_deps import get_team_identity
from aweb.hooks import fire_mutation_hook
from aweb.service_errors import NotFoundError
from aweb.coordination.tasks_service import (
    add_comment,
    add_dependency,
    create_task,
    get_task,
    list_active_work,
    list_blocked_tasks,
    list_comments,
    list_ready_tasks,
    list_tasks,
    remove_dependency,
    soft_delete_task,
    update_task,
)

from ...db import DatabaseInfra, get_db_infra

router = APIRouter(prefix="/v1/tasks", tags=["tasks"])


class CreateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=4096)
    description: str = Field("", max_length=65536)
    notes: str = Field("", max_length=65536)
    priority: int = Field(2, ge=0, le=4)
    task_type: Literal["task", "bug", "feature", "epic", "chore"] = "task"
    labels: list[str] = Field(default_factory=list)
    parent_task_id: Optional[str] = None
    assignee_alias: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(None, min_length=1, max_length=4096)
    description: Optional[str] = Field(None, max_length=65536)
    notes: Optional[str] = Field(None, max_length=65536)
    status: Optional[Literal["open", "in_progress", "closed"]] = None
    priority: Optional[int] = Field(None, ge=0, le=4)
    task_type: Optional[Literal["task", "bug", "feature", "epic", "chore"]] = None
    labels: Optional[list[str]] = None
    assignee_alias: Optional[str] = None


class AddDependencyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    depends_on: str = Field(..., min_length=1)


class AddCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., min_length=1, max_length=65536)


class ActiveWorkTaskSummary(BaseModel):
    task_id: str
    task_ref: str
    task_number: int
    title: str
    status: str
    priority: int
    task_type: str
    assignee_alias: Optional[str] = None
    created_by_alias: Optional[str] = None
    parent_task_id: Optional[str] = None
    labels: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    workspace_id: Optional[str] = None
    owner_alias: Optional[str] = None
    claimed_at: Optional[str] = None
    canonical_origin: Optional[str] = None
    branch: Optional[str] = None


class ActiveWorkResponse(BaseModel):
    tasks: list[ActiveWorkTaskSummary]


@router.post("")
async def create_task_route(
    request: Request, payload: CreateTaskRequest, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)

    result = await create_task(
        db_infra,
        team_id=identity.team_id,
        created_by_alias=identity.alias,
        title=payload.title,
        description=payload.description,
        notes=payload.notes,
        priority=payload.priority,
        task_type=payload.task_type,
        labels=payload.labels,
        parent_task_id=payload.parent_task_id,
        assignee_alias=payload.assignee_alias,
    )
    await fire_mutation_hook(
        request,
        "task.created",
        {
            "task_id": result["task_id"],
            "team_id": identity.team_id,
            "task_ref": result["task_ref"],
            "title": result["title"],
            "parent_task_id": result["parent_task_id"],
            "assignee_alias": result["assignee_alias"],
            "actor_alias": identity.alias,
        },
    )
    return result


@router.get("")
async def list_tasks_unified(
    request: Request,
    status: Optional[str] = Query(None),
    assignee_alias: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    priority: Optional[int] = Query(None, ge=0, le=4),
    labels: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    label_list = [s.strip() for s in labels.split(",") if s.strip()] if labels else None

    tasks = await list_tasks(
        db_infra,
        team_id=identity.team_id,
        status=status,
        assignee_alias=assignee_alias,
        task_type=task_type,
        priority=priority,
        labels=label_list,
        q=q,
    )

    return {"tasks": tasks}


@router.get("/ready")
async def list_ready_tasks_route(
    request: Request, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    tasks = await list_ready_tasks(db_infra, team_id=identity.team_id)
    unclaimed = [t for t in tasks if t.get("assignee_alias") is None]
    return {"tasks": unclaimed}


@router.get("/blocked")
async def list_blocked_tasks_route(
    request: Request, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    tasks = await list_blocked_tasks(db_infra, team_id=identity.team_id)
    return {"tasks": tasks}


@router.get("/active")
async def list_active_work_route(
    request: Request, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> ActiveWorkResponse:
    identity = await get_team_identity(request, db_infra)
    tasks = await list_active_work(db_infra, team_id=identity.team_id)
    return ActiveWorkResponse(tasks=tasks)


@router.get("/{ref}")
async def get_task_unified(
    request: Request, ref: str, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)

    try:
        return await get_task(db_infra, team_id=identity.team_id, ref=ref)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Task not found") from None


@router.patch("/{ref}")
async def update_task_route(
    request: Request,
    ref: str,
    payload: UpdateTaskRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)

    kwargs: dict[str, Any] = {}
    if payload.title is not None:
        kwargs["title"] = payload.title
    if payload.description is not None:
        kwargs["description"] = payload.description
    if payload.notes is not None:
        kwargs["notes"] = payload.notes
    if payload.status is not None:
        kwargs["status"] = payload.status
    if payload.priority is not None:
        kwargs["priority"] = payload.priority
    if payload.task_type is not None:
        kwargs["task_type"] = payload.task_type
    if payload.labels is not None:
        kwargs["labels"] = payload.labels
    if "assignee_alias" in payload.model_fields_set:
        kwargs["assignee_alias"] = payload.assignee_alias

    result = await update_task(
        db_infra,
        team_id=identity.team_id,
        ref=ref,
        actor_alias=identity.alias,
        **kwargs,
    )

    old_status = result.pop("old_status", None)
    if old_status is not None:
        await fire_mutation_hook(
            request,
            "task.status_changed",
            {
                "task_id": result["task_id"],
                "task_ref": result["task_ref"],
                "title": result["title"],
                "old_status": old_status,
                "new_status": result["status"],
                "assignee_alias": result["assignee_alias"],
                "parent_task_id": result["parent_task_id"],
                "actor_alias": identity.alias,
                "claim_preacquired": result.pop("claim_preacquired", False),
            },
        )
    else:
        await fire_mutation_hook(
            request,
            "task.updated",
            {"task_id": result["task_id"], "task_ref": result["task_ref"]},
        )
    return result


@router.delete("/{ref}")
async def delete_task_route(
    request: Request, ref: str, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    result = await soft_delete_task(db_infra, team_id=identity.team_id, ref=ref)
    await fire_mutation_hook(
        request,
        "task.deleted",
        {"task_id": result["task_id"], "task_ref": result["task_ref"]},
    )
    return result


@router.post("/{ref}/deps")
async def add_dependency_route(
    request: Request,
    ref: str,
    payload: AddDependencyRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    result = await add_dependency(
        db_infra, team_id=identity.team_id, task_ref=ref, depends_on_ref=payload.depends_on
    )
    await fire_mutation_hook(
        request,
        "task.dependency_added",
        {"task_id": result["task_id"], "depends_on_task_id": result["depends_on_task_id"]},
    )
    return result


@router.delete("/{ref}/deps/{dep_ref}")
async def remove_dependency_route(
    request: Request,
    ref: str,
    dep_ref: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    result = await remove_dependency(db_infra, team_id=identity.team_id, task_ref=ref, dep_ref=dep_ref)
    await fire_mutation_hook(
        request,
        "task.dependency_removed",
        {
            "task_id": result["task_id"],
            "removed_depends_on_task_id": result["removed_depends_on_task_id"],
        },
    )
    return result


@router.post("/{ref}/comments")
async def add_comment_route(
    request: Request,
    ref: str,
    payload: AddCommentRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)

    result = await add_comment(db_infra, team_id=identity.team_id, ref=ref, author_alias=identity.alias, body=payload.body)
    await fire_mutation_hook(
        request,
        "task.comment_added",
        {"task_id": result["task_id"], "comment_id": result["comment_id"]},
    )
    return result


@router.get("/{ref}/comments")
async def list_comments_route(
    request: Request, ref: str, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    identity = await get_team_identity(request, db_infra)
    comments = await list_comments(db_infra, team_id=identity.team_id, ref=ref)
    return {"comments": comments}
