"""Unified tasks endpoints with beads fallback.

Overrides the aweb tasks router's GET endpoints to merge in beads issues
for projects that still use beads as their issue tracker. Native aweb tasks
always take priority. Mutation endpoints (POST, PATCH, DELETE) are handled
by the aweb tasks router directly.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

from aweb.auth import get_project_from_auth
from aweb.service_errors import NotFoundError
from aweb.tasks_service import (
    get_task,
    list_blocked_tasks,
    list_ready_tasks,
    list_tasks,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..db import DatabaseInfra, get_db_infra

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/tasks", tags=["tasks"])


def _beads_issue_to_task(row: dict[str, Any]) -> dict[str, Any]:
    """Map a beads_issues row to the aweb task response shape."""
    return {
        "task_id": None,
        "task_ref": row["bead_id"],
        "task_number": None,
        "title": row["title"],
        "status": row["status"],
        "priority": row["priority"] if row["priority"] is not None else 2,
        "task_type": row.get("issue_type") or "task",
        "assignee_agent_id": None,
        "created_by_agent_id": None,
        "parent_task_id": None,
        "labels": list(row["labels"]) if row.get("labels") else [],
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
    }


def _beads_issue_detail_to_task(row: dict[str, Any]) -> dict[str, Any]:
    """Map a beads_issues row to the aweb task detail response shape."""
    task = _beads_issue_to_task(row)
    task["description"] = row.get("description") or ""
    task["notes"] = ""
    task["project_id"] = str(row["project_id"]) if row.get("project_id") else None
    task["parent_task_id"] = None
    task["closed_by_agent_id"] = None
    task["closed_at"] = None
    task["blocked_by"] = []
    task["blocks"] = []
    return task


async def _fetch_beads_issues(
    db_infra: DatabaseInfra,
    project_id: str,
    *,
    status: str | None = None,
    task_type: str | None = None,
    priority: int | None = None,
) -> list[dict[str, Any]]:
    """Fetch beads issues for a project, applying optional filters."""
    try:
        beads_db = db_infra.get_manager("beads")
    except Exception:
        return []

    conditions = ["project_id = $1"]
    params: list[Any] = [UUID(project_id)]
    idx = 2

    if status is not None:
        conditions.append(f"status = ${idx}")
        params.append(status)
        idx += 1

    if task_type is not None:
        conditions.append(f"issue_type = ${idx}")
        params.append(task_type)
        idx += 1

    if priority is not None:
        conditions.append(f"priority = ${idx}")
        params.append(priority)
        idx += 1

    where = " AND ".join(conditions)
    query = (
        "SELECT DISTINCT ON (bead_id)"
        " bead_id, title, status, priority, issue_type,"
        " labels, created_at, updated_at"
        " FROM {{tables.beads_issues}}"
        f" WHERE {where}"
        " ORDER BY bead_id, updated_at DESC NULLS LAST"
    )
    try:
        rows = await beads_db.fetch_all(query, *params)
    except Exception:
        logger.debug("beads_issues query failed (table may not exist)", exc_info=True)
        return []

    return [_beads_issue_to_task(dict(r)) for r in rows]


async def _fetch_beads_issue_detail(
    db_infra: DatabaseInfra, project_id: str, ref: str
) -> dict[str, Any] | None:
    """Fetch a single beads issue by bead_id, mapped to task shape."""
    try:
        beads_db = db_infra.get_manager("beads")
    except Exception:
        return None

    try:
        row = await beads_db.fetch_one(
            """
            SELECT bead_id, project_id, title, description, status, priority,
                   issue_type, labels, created_at, updated_at
            FROM {{tables.beads_issues}}
            WHERE project_id = $1 AND bead_id = $2
            ORDER BY updated_at DESC NULLS LAST
            LIMIT 1
            """,
            UUID(project_id),
            ref,
        )
    except Exception:
        logger.debug("beads_issues detail query failed", exc_info=True)
        return None

    if row is None:
        return None
    return _beads_issue_detail_to_task(dict(row))


@router.get("")
async def list_tasks_unified(
    request: Request,
    status: Optional[str] = Query(None),
    assignee_agent_id: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    priority: Optional[int] = Query(None, ge=0, le=4),
    labels: Optional[str] = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db_infra, manager_name="aweb")
    label_list = [s.strip() for s in labels.split(",") if s.strip()] if labels else None

    native_tasks = await list_tasks(
        db_infra,
        project_id=project_id,
        status=status,
        assignee_agent_id=assignee_agent_id,
        task_type=task_type,
        priority=priority,
        labels=label_list,
    )

    # Beads fallback: merge in beads issues (labels/assignee filters don't apply to beads)
    beads_tasks = await _fetch_beads_issues(
        db_infra, project_id, status=status, task_type=task_type, priority=priority
    )

    # Deduplicate: native task_ref takes priority over beads
    native_refs = {t["task_ref"] for t in native_tasks}
    merged = list(native_tasks)
    for bt in beads_tasks:
        if bt["task_ref"] not in native_refs:
            merged.append(bt)

    return {"tasks": merged}


@router.get("/ready")
async def list_ready_tasks_route(
    request: Request, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db_infra, manager_name="aweb")
    tasks = await list_ready_tasks(db_infra, project_id=project_id)
    return {"tasks": tasks}


@router.get("/blocked")
async def list_blocked_tasks_route(
    request: Request, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db_infra, manager_name="aweb")
    tasks = await list_blocked_tasks(db_infra, project_id=project_id)
    return {"tasks": tasks}


@router.get("/{ref}")
async def get_task_unified(
    request: Request, ref: str, db_infra: DatabaseInfra = Depends(get_db_infra)
) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db_infra, manager_name="aweb")

    # Try native aweb task first
    try:
        return await get_task(db_infra, project_id=project_id, ref=ref)
    except NotFoundError:
        pass

    # Fall back to beads
    result = await _fetch_beads_issue_detail(db_infra, project_id, ref)
    if result is not None:
        return result

    raise HTTPException(status_code=404, detail="Task not found")
