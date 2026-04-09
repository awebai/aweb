"""MCP tools for coordination-aware work discovery."""

from __future__ import annotations

import json

from aweb.coordination.tasks_service import list_blocked_tasks, list_ready_tasks, list_tasks
from aweb.mcp.auth import get_auth


async def _claim_rows(aweb_db, *, team_address: str) -> list[dict]:
    return await aweb_db.fetch_all(
        """
        SELECT task_ref, workspace_id, alias, claimed_at
        FROM {{tables.task_claims}}
        WHERE team_address = $1
        ORDER BY claimed_at DESC
        """,
        team_address,
    )


async def work_ready(db_infra) -> str:
    """List ready tasks not already claimed by another workspace."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    claim_rows = await _claim_rows(aweb_db, team_address=auth.team_address)
    claimed_by_others = {
        row["task_ref"]
        for row in claim_rows
        if str(row["workspace_id"]) != auth.agent_id
    }

    tasks = await list_ready_tasks(db_infra, team_address=auth.team_address)
    items = [task for task in tasks if task["task_ref"] not in claimed_by_others]
    return json.dumps({"kind": "ready", "tasks": items})


async def work_active(db_infra) -> str:
    """List active in-progress work across the project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    tasks = await list_tasks(db_infra, team_address=auth.team_address, status="in_progress")
    claim_rows = await _claim_rows(aweb_db, team_address=auth.team_address)

    claims_by_ref = {}
    for row in claim_rows:
        task_ref = row["task_ref"]
        if task_ref not in claims_by_ref:
            claims_by_ref[task_ref] = {
                "owner_alias": row["alias"],
                "claimed_at": row["claimed_at"].isoformat(),
            }

    items = []
    for task in tasks:
        item = dict(task)
        claim = claims_by_ref.get(task["task_ref"])
        if claim is not None:
            item["owner_alias"] = claim["owner_alias"]
            item["claimed_at"] = claim["claimed_at"]
        elif task.get("assignee_alias"):
            item["owner_alias"] = task["assignee_alias"]
        items.append(item)

    items.sort(key=lambda item: (item["priority"], item["task_ref"]))
    return json.dumps({"kind": "active", "tasks": items})


async def work_blocked(db_infra) -> str:
    """List blocked tasks in the authenticated team."""
    auth = get_auth()
    tasks = await list_blocked_tasks(db_infra, team_address=auth.team_address)
    return json.dumps({"kind": "blocked", "tasks": tasks})
