"""Native task endpoints."""

from __future__ import annotations

from aweb.event_types import MutationEventType
from aweb.hook_contexts import TaskCommentAddedContext, TaskStatusChangedContext

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from aweb.application_state import application_registry_client
from aweb.redis_client import get_redis
from pydantic import BaseModel, ConfigDict, Field
from fastapi.responses import JSONResponse

from aweb.team_auth_deps import (
    TeamIdentity,
    get_team_identity,
    team_identity_with_grant_scope,
)
from aweb.hooks import fire_mutation_hook, mutation_callback
from aweb.service_errors import NotFoundError, ServiceError
from aweb.task_contracts import AnswerRequest, parse_contract, strict_json_bytes
from aweb.coordination.tasks_service import (
    AddCommentRequest,
    CreateTaskRequest,
    TaskDeletionIncompleteError,
    UpdateTaskRequest,
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
    answer_task_on,
    answer_comment_projection,
    get_task_answer_on,
    resolve_task_ref,
)

from ...db import DatabaseInfra, get_db_infra
from .app_tasks import router as app_tasks_router
from aweb.coordination.app_tasks import verify_answer_actor

router = APIRouter(prefix="/v1/tasks", tags=["tasks"])
router.include_router(app_tasks_router)


class AddDependencyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    depends_on: str = Field(..., min_length=1)


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
    owner_last_seen_at: Optional[str] = None
    canonical_origin: Optional[str] = None
    branch: Optional[str] = None


class ActiveWorkResponse(BaseModel):
    tasks: list[ActiveWorkTaskSummary]


@router.post("")
async def create_task_route(
    request: Request,
    payload: CreateTaskRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.write")),
) -> dict[str, Any]:
    """Create a member-authorized task through the shared task service."""
    return await create_task(
        db_infra,
        actor=identity,
        on_mutation=mutation_callback(request),
        **payload.model_dump(),
    )


@router.get("")
async def list_tasks_unified(
    request: Request,
    status: Optional[str] = Query(None),
    assignee_alias: Optional[str] = Query(None),
    eligible_did: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    priority: Optional[int] = Query(None, ge=0, le=4),
    labels: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> dict[str, Any]:
    """List tasks visible in the current native team with the requested filters."""
    label_list = [s.strip() for s in labels.split(",") if s.strip()] if labels else None

    tasks = await list_tasks(
        db_infra,
        team_id=identity.team_id,
        status=status,
        assignee_alias=assignee_alias,
        eligible_did=eligible_did,
        task_type=task_type,
        priority=priority,
        labels=label_list,
        q=q,
        parent_task_id=parent_task_id,
    )

    return {"tasks": tasks}


@router.get("/ready")
async def list_ready_tasks_route(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> dict[str, Any]:
    """List unblocked work in the authenticated team scope."""
    tasks = await list_ready_tasks(db_infra, team_id=identity.team_id)
    unclaimed = [t for t in tasks if t.get("assignee_alias") is None]
    return {"tasks": unclaimed}


@router.get("/blocked")
async def list_blocked_tasks_route(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> dict[str, Any]:
    """List blocked work in the authenticated team scope."""
    tasks = await list_blocked_tasks(db_infra, team_id=identity.team_id)
    return {"tasks": tasks}


@router.get("/active")
async def list_active_work_route(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> ActiveWorkResponse:
    """List active task claims in the authenticated team scope."""
    tasks = await list_active_work(
        db_infra,
        team_id=identity.team_id,
        redis=redis,
        registry_client=application_registry_client(request.app.state),
        request=request,
    )
    return ActiveWorkResponse(tasks=tasks)


@router.get("/{ref}")
async def get_task_unified(
    request: Request,
    ref: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> dict[str, Any]:
    """Resolve one task reference within the authenticated team."""
    try:
        return await get_task(db_infra, team_id=identity.team_id, ref=ref)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Task not found") from None


@router.post("/{ref}/answer")
async def answer_task_route(
    request: Request,
    ref: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(get_team_identity),
):
    """Commit a signed task answer with its revision preconditions and mutation events."""
    if not request.headers.get("X-AWEB-Signed-Payload"):
        raise HTTPException(status_code=401, detail="signature_invalid")
    try:
        body = strict_json_bytes(await request.body())
        if isinstance(body, dict) and "expected_task_rev" not in body:
            raise HTTPException(status_code=428, detail="precondition_required")
        payload = parse_contract(AnswerRequest, body)
        answer_comment_projection(
            body_md=payload.body_md, answer_sha256=payload.answer_sha256
        )
        await verify_answer_actor(request, identity)
        task_id = await resolve_task_ref(db_infra, team_id=identity.team_id, ref=ref)
        outcome: dict[str, Any] = {}
        async with db_infra.get_manager("aweb").transaction() as tx:
            receipt = await answer_task_on(
                tx,
                team_id=identity.team_id,
                task_id=task_id,
                actor=identity,
                outcome=outcome,
                **payload.model_dump(),
            )
        if outcome["created"]:
            await fire_mutation_hook(
                request,
                MutationEventType.TASK_STATUS_CHANGED.value,
                TaskStatusChangedContext(
                    task_id=str(task_id),
                    team_id=identity.team_id,
                    task_ref=outcome["task_ref"],
                    title=outcome["title"],
                    old_status="open",
                    new_status="closed",
                    actor_agent_id=identity.agent_id,
                    actor_alias=identity.alias,
                    actor_did_aw=identity.did_aw,
                    assignee_alias=outcome["assignee_alias"],
                    released_claim_workspace_ids=outcome[
                        "released_claim_workspace_ids"
                    ],
                ).to_context(),
            )
            await fire_mutation_hook(
                request,
                MutationEventType.TASK_COMMENT_ADDED.value,
                TaskCommentAddedContext(
                    task_id=str(task_id),
                    comment_id=outcome["comment_id"],
                    actor_agent_id=identity.agent_id,
                    actor_did_aw=identity.did_aw,
                ).to_context(),
            )
        return JSONResponse(receipt, status_code=201 if outcome["created"] else 200)
    except ServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail="resource_not_found"
            if isinstance(exc, NotFoundError)
            else exc.detail,
        ) from exc


@router.get("/{ref}/answer")
async def task_answer_receipt_route(
    request: Request,
    ref: str,
    answer_key: str = Query(...),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
):
    """Read an answer receipt within the authenticated task scope."""
    try:
        task_id = await resolve_task_ref(db_infra, team_id=identity.team_id, ref=ref)
        async with db_infra.get_manager("aweb").transaction() as tx:
            return await get_task_answer_on(
                tx, team_id=identity.team_id, task_id=task_id, answer_key=answer_key
            )
    except ServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail="resource_not_found"
            if isinstance(exc, NotFoundError)
            else exc.detail,
        ) from exc


@router.patch("/{ref}")
async def update_task_route(
    request: Request,
    ref: str,
    payload: UpdateTaskRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.write")),
) -> dict[str, Any]:
    """Update a task through the shared service and its authorization checks."""
    return await update_task(
        db_infra,
        actor=identity,
        on_mutation=mutation_callback(request),
        ref=ref,
        **payload.changes(),
    )


@router.delete("/{ref}")
async def delete_task_route(
    request: Request,
    ref: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(get_team_identity),
) -> dict[str, Any]:
    """Soft-delete a task through the shared service and its mutation callback."""
    try:
        return await soft_delete_task(
            db_infra, actor=identity, on_mutation=mutation_callback(request), ref=ref
        )
    except TaskDeletionIncompleteError as exc:
        # This expected partial commit is actionable; generic internal service
        # failures remain private at the application's shared error boundary.
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.post("/{ref}/deps")
async def add_dependency_route(
    request: Request,
    ref: str,
    payload: AddDependencyRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.write")),
) -> dict[str, Any]:
    """Add a dependency within the authenticated native team."""
    return await add_dependency(
        db_infra,
        actor=identity,
        on_mutation=mutation_callback(request),
        task_ref=ref,
        depends_on_ref=payload.depends_on,
    )


@router.delete("/{ref}/deps/{dep_ref}")
async def remove_dependency_route(
    request: Request,
    ref: str,
    dep_ref: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.write")),
) -> dict[str, Any]:
    """Remove a dependency within the authenticated native team."""
    return await remove_dependency(
        db_infra,
        actor=identity,
        on_mutation=mutation_callback(request),
        task_ref=ref,
        dep_ref=dep_ref,
    )


@router.post("/{ref}/comments")
async def add_comment_route(
    request: Request,
    ref: str,
    payload: AddCommentRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.write")),
) -> dict[str, Any]:
    """Append an attributed comment through the shared task service."""
    return await add_comment(
        db_infra,
        actor=identity,
        on_mutation=mutation_callback(request),
        ref=ref,
        body=payload.body,
    )


@router.get("/{ref}/comments")
async def list_comments_route(
    request: Request,
    ref: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("coord.read")),
) -> dict[str, Any]:
    """Read comments for a task in the authenticated team."""
    comments = await list_comments(db_infra, team_id=identity.team_id, ref=ref)
    return {"comments": comments}
