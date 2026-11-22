"""C2 purpose-bound app task routes; no member-header shortcuts."""


from aweb.event_types import MutationEventType
from aweb.hook_contexts import TaskCommentAddedContext, TaskCreatedContext, TaskStatusChangedContext
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from aweb.db import DatabaseInfra, get_db_infra
from aweb.hooks import fire_mutation_hook
from aweb.service_errors import ForbiddenError, NotFoundError, ServiceError
from aweb.task_contracts import strict_json_bytes
from aweb.coordination.app_tasks import (
    _scopes, app_request_transport_on,
    cancel_app_task_on, create_app_task_on, prepare_app_task, read_app_request_on,
)
from aweb.coordination.tasks_service import _answer_receipt

router = APIRouter()


@router.post("/app-requests")
async def create_app_request(request: Request, db: DatabaseInfra = Depends(get_db_infra)):
    """Create or exactly replay a purpose-bound app request after its authority checks."""
    try:
        raw = await request.body()
        prepared = await prepare_app_task(request, body=strict_json_bytes(raw))
        outcome: dict[str, Any] = {}
        async with db.get_manager("aweb").transaction() as tx:
            credential, installation = await app_request_transport_on(request, tx)
            receipt, created = await create_app_task_on(tx, credential=credential,
                installation=installation, prepared=prepared, outcome=outcome)
        if created:
            await fire_mutation_hook(request, MutationEventType.TASK_CREATED.value, TaskCreatedContext(task_id=receipt['task_id'], task_ref=receipt['task_ref'], team_id=credential.team_id, **outcome, parent_task_id=None).to_context())
        return JSONResponse(receipt, status_code=201 if created else 200)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/app-requests/{external_request_id}")
async def app_request_receipt(request: Request, external_request_id: str, originator: str = Query(...),
                              db: DatabaseInfra = Depends(get_db_infra)):
    """Read the receipt authorized for the current app installation and originator."""
    try:
        async with db.get_manager("aweb").transaction() as tx:
            credential, installation = await app_request_transport_on(request, tx)
            return await read_app_request_on(tx, credential=credential, installation=installation,
                external_request_id=external_request_id, originator=originator)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.post("/app-requests/{external_request_id}/cancel")
async def cancel_app_request(request: Request, external_request_id: str, originator: str = Query(...),
                             db: DatabaseInfra = Depends(get_db_infra)):
    """Cancel an authorized app request and publish only newly committed changes."""
    try:
        async with db.get_manager("aweb").transaction() as tx:
            credential, installation = await app_request_transport_on(request, tx)
            if "requests.create" not in _scopes(installation):
                raise ForbiddenError("scope_denied")
            row = await tx.fetch_one(
                """SELECT task_id FROM {{tables.task_app_requests}}
                   WHERE team_id=$1 AND app_id=$2 AND installation_id=$3
                     AND originator_did=$4 AND external_request_id=$5""",
                credential.team_id, credential.app_id, credential.installation_id, originator, external_request_id,
            )
            if not row:
                raise NotFoundError("resource_not_found")
            outcome: dict[str, Any] = {}
            await cancel_app_task_on(tx, team_id=credential.team_id, task_id=row["task_id"],
                external_request_id=external_request_id, reason="requested", outcome=outcome)
            result = await read_app_request_on(tx, credential=credential, installation=installation,
                external_request_id=external_request_id, originator=originator, required_scope="requests.create")
        if outcome["changed"]:
            await fire_mutation_hook(request, MutationEventType.TASK_STATUS_CHANGED.value, TaskStatusChangedContext(task_id=str(row['task_id']), team_id=credential.team_id, task_ref=outcome['task_ref'], actor_alias=credential.app_id, old_status=outcome['old_status'], new_status='closed').to_context())
            await fire_mutation_hook(request, MutationEventType.TASK_COMMENT_ADDED.value, TaskCommentAddedContext(task_id=str(row['task_id']), comment_id=outcome['comment_id']).to_context())
        return result
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/answers/{task_answer_ref}")
async def app_answer_receipt(request: Request, task_answer_ref: str, db: DatabaseInfra = Depends(get_db_infra)):
    """Read an answer receipt within the authenticated app installation scope."""
    try:
        async with db.get_manager("aweb").transaction() as tx:
            credential, installation = await app_request_transport_on(request, tx)
            if "requests.read" not in _scopes(installation):
                raise ForbiddenError("scope_denied")
            try:
                receipt_id = UUID(task_answer_ref)
            except ValueError as exc:
                raise NotFoundError("resource_not_found") from exc
            row = await tx.fetch_one(
                """SELECT a.*, t.question_rev AS current_question_rev, t.cancellation
                   FROM {{tables.task_answers}} a
                   JOIN {{tables.tasks}} t ON t.task_id=a.task_id
                   JOIN {{tables.task_app_requests}} r ON r.task_id=t.task_id
                   WHERE a.receipt_id=$1 AND r.team_id=$2 AND r.app_id=$3
                     AND r.installation_id=$4 AND t.deleted_at IS NULL FOR SHARE OF t""",
                receipt_id, credential.team_id, credential.app_id, credential.installation_id,
            )
            if not row:
                raise NotFoundError("resource_not_found")
            return _answer_receipt(row, current_question_rev=row["current_question_rev"], cancelled=row["cancellation"] is not None)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
