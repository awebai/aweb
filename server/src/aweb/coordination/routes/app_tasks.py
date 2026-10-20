"""C2 purpose-bound app task routes; no member-header shortcuts."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from aweb.db import DatabaseInfra, get_db_infra
from aweb.hooks import fire_mutation_hook
from aweb.service_errors import ForbiddenError, NotFoundError, ServiceError
from aweb.task_contracts import strict_json_bytes
from aweb.coordination.app_tasks import (
    _scopes, app_request_transport_on,
    cancel_app_task_on, create_app_task_on, read_app_request_on,
)
from aweb.coordination.tasks_service import _answer_receipt, get_task

router = APIRouter()


@router.post("/app-requests")
async def create_app_request(request: Request, db: DatabaseInfra = Depends(get_db_infra)):
    try:
        raw = await request.body()
        async with db.get_manager("aweb").transaction() as tx:
            credential, installation = await app_request_transport_on(request, tx)
            receipt, created = await create_app_task_on(request, tx, credential=credential,
                installation=installation, body=strict_json_bytes(raw))
        if created:
            task = await get_task(db, team_id=credential.team_id, ref=receipt["task_id"])
            await fire_mutation_hook(request, "task.created", {
                "task_id": receipt["task_id"], "task_ref": receipt["task_ref"],
                "team_id": credential.team_id, "actor_alias": task["created_by_alias"],
                "title": task["title"], "assignee_alias": task["assignee_alias"],
                "parent_task_id": None,
            })
        return JSONResponse(receipt, status_code=201 if created else 200)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/app-requests/{external_request_id}")
async def app_request_receipt(request: Request, external_request_id: str, originator: str = Query(...),
                              db: DatabaseInfra = Depends(get_db_infra)):
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
            await cancel_app_task_on(tx, team_id=credential.team_id, task_id=row["task_id"],
                external_request_id=external_request_id, reason="requested")
            return await read_app_request_on(tx, credential=credential, installation=installation,
                external_request_id=external_request_id, originator=originator, required_scope="requests.create")
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/answers/{task_answer_ref}")
async def app_answer_receipt(request: Request, task_answer_ref: str, db: DatabaseInfra = Depends(get_db_infra)):
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
