"""MCP tools for coordination-aware work discovery."""

from __future__ import annotations

import json
import logging

from aweb.coordination.tasks_service import (
    list_active_work,
    list_blocked_tasks,
    list_ready_tasks,
)
from aweb.mcp.tools._common import require_team_context
from aweb.application_state import RegistryClientUnavailable

logger = logging.getLogger(__name__)


async def _claim_rows(aweb_db, *, team_id: str) -> list[dict]:
    return await aweb_db.fetch_all(
        """
        SELECT task_ref, workspace_id, alias, claimed_at
        FROM {{tables.task_claims}}
        WHERE team_id = $1
        ORDER BY claimed_at DESC
        """,
        team_id,
    )


async def work_ready(db_infra) -> str:
    """List ready tasks not already claimed by another workspace."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps(
            {"error": "This tool requires team context. Use a team certificate."}
        )
    aweb_db = db_infra.get_manager("aweb")

    claim_rows = await _claim_rows(aweb_db, team_id=auth.team_id)
    current_workspace_id = (auth.workspace_id or "").strip()
    if not current_workspace_id:
        logger.warning(
            "work_ready: missing workspace_id for team-authenticated MCP caller agent_id=%s",
            auth.agent_id,
        )
    claimed_by_others = {
        row["task_ref"]
        for row in claim_rows
        if str(row["workspace_id"]) != current_workspace_id
    }

    tasks = await list_ready_tasks(db_infra, team_id=auth.team_id)
    items = [task for task in tasks if task["task_ref"] not in claimed_by_others]
    return json.dumps({"kind": "ready", "tasks": items})


async def work_active(db_infra, redis=None, *, registry_client=None) -> str:
    """List active in-progress work across the team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps(
            {"error": "This tool requires team context. Use a team certificate."}
        )
    if registry_client is None:
        raise RegistryClientUnavailable()
    items = await list_active_work(
        db_infra,
        team_id=auth.team_id,
        redis=redis,
        registry_client=registry_client,
        request=auth.request,
    )
    items.sort(key=lambda item: (item["priority"], item["task_ref"]))
    return json.dumps({"kind": "active", "tasks": items})


async def work_blocked(db_infra) -> str:
    """List blocked tasks in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps(
            {"error": "This tool requires team context. Use a team certificate."}
        )
    tasks = await list_blocked_tasks(db_infra, team_id=auth.team_id)
    return json.dumps({"kind": "blocked", "tasks": tasks})
