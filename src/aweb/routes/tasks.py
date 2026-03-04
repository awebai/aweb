from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.tasks_service import (
    add_dependency,
    create_task,
    get_task,
    list_ready_tasks,
    list_tasks,
    remove_dependency,
    soft_delete_task,
    update_task,
)

router = APIRouter(prefix="/v1/tasks", tags=["aweb-tasks"])


class CreateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=4096)
    description: str = Field("", max_length=65536)
    notes: str = Field("", max_length=65536)
    priority: int = Field(2, ge=0, le=4)
    task_type: Literal["task", "bug", "feature"] = "task"
    labels: list[str] = Field(default_factory=list)
    parent_task_id: Optional[str] = None
    assignee_agent_id: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(None, min_length=1, max_length=4096)
    description: Optional[str] = Field(None, max_length=65536)
    notes: Optional[str] = Field(None, max_length=65536)
    status: Optional[Literal["open", "in_progress", "closed"]] = None
    priority: Optional[int] = Field(None, ge=0, le=4)
    task_type: Optional[Literal["task", "bug", "feature"]] = None
    labels: Optional[list[str]] = None
    assignee_agent_id: Optional[str] = None


class AddDependencyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    depends_on: str = Field(..., min_length=1)


@router.post("")
async def create_task_route(
    request: Request, payload: CreateTaskRequest, db=Depends(get_db)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    result = await create_task(
        db,
        project_id=project_id,
        created_by_agent_id=actor_id,
        title=payload.title,
        description=payload.description,
        notes=payload.notes,
        priority=payload.priority,
        task_type=payload.task_type,
        labels=payload.labels,
        parent_task_id=payload.parent_task_id,
        assignee_agent_id=payload.assignee_agent_id,
    )

    await fire_mutation_hook(
        request,
        "task.created",
        {"task_id": result["task_id"], "task_ref": result["task_ref"], "title": result["title"]},
    )

    return result


@router.get("")
async def list_tasks_route(
    request: Request,
    status: Optional[str] = Query(None),
    assignee_agent_id: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    priority: Optional[int] = Query(None, ge=0, le=4),
    labels: Optional[str] = Query(None),
    db=Depends(get_db),
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")

    label_list = [s.strip() for s in labels.split(",") if s.strip()] if labels else None

    tasks = await list_tasks(
        db,
        project_id=project_id,
        status=status,
        assignee_agent_id=assignee_agent_id,
        task_type=task_type,
        priority=priority,
        labels=label_list,
    )
    return {"tasks": tasks}


@router.get("/ready")
async def list_ready_tasks_route(request: Request, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    tasks = await list_ready_tasks(db, project_id=project_id)
    return {"tasks": tasks}


@router.get("/{ref}")
async def get_task_route(request: Request, ref: str, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    return await get_task(db, project_id=project_id, ref=ref)


@router.patch("/{ref}")
async def update_task_route(
    request: Request, ref: str, payload: UpdateTaskRequest, db=Depends(get_db)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

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
    if "assignee_agent_id" in payload.model_fields_set:
        kwargs["assignee_agent_id"] = payload.assignee_agent_id

    result = await update_task(
        db,
        project_id=project_id,
        ref=ref,
        actor_agent_id=actor_id,
        **kwargs,
    )

    event = "task.closed" if payload.status == "closed" else "task.updated"
    await fire_mutation_hook(
        request,
        event,
        {"task_id": result["task_id"], "task_ref": result["task_ref"]},
    )

    return result


@router.delete("/{ref}")
async def delete_task_route(request: Request, ref: str, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")

    result = await soft_delete_task(db, project_id=project_id, ref=ref)

    await fire_mutation_hook(
        request,
        "task.deleted",
        {"task_id": result["task_id"]},
    )

    return result


@router.post("/{ref}/deps")
async def add_dependency_route(
    request: Request, ref: str, payload: AddDependencyRequest, db=Depends(get_db)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")

    result = await add_dependency(
        db, project_id=project_id, task_ref=ref, depends_on_ref=payload.depends_on
    )

    await fire_mutation_hook(
        request,
        "task.dependency_added",
        {"task_id": result["task_id"], "depends_on_task_id": result["depends_on_task_id"]},
    )

    return result


@router.delete("/{ref}/deps/{dep_ref}")
async def remove_dependency_route(
    request: Request, ref: str, dep_ref: str, db=Depends(get_db)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")

    result = await remove_dependency(db, project_id=project_id, task_ref=ref, dep_ref=dep_ref)

    await fire_mutation_hook(
        request,
        "task.dependency_removed",
        {
            "task_id": result["task_id"],
            "removed_depends_on_task_id": result["removed_depends_on_task_id"],
        },
    )

    return result
