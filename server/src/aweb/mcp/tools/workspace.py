"""MCP tools for workspace-style coordination status."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from aweb.mcp.tools._common import require_team_context
from aweb.presence import list_agent_presences_by_workspace_ids


async def workspace_status(db_infra, redis, *, limit: int = 15) -> str:
    """Show self/team coordination status for the authenticated agent."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    aweb_db = db_infra.get_manager("aweb")

    workspaces = await aweb_db.fetch_all(
        """
        SELECT
            w.workspace_id,
            w.agent_id,
            w.alias,
            w.human_name,
            COALESCE(w.role, a.role) AS role
        FROM {{tables.workspaces}} w
        JOIN {{tables.agents}} a ON a.agent_id = w.agent_id
        WHERE w.team_id = $1
          AND w.deleted_at IS NULL
          AND a.deleted_at IS NULL
          AND COALESCE(a.agent_type, 'agent') != 'human'
        ORDER BY w.alias
        """,
        auth.team_id,
    )
    workspace_ids = [str(row["workspace_id"]) for row in workspaces]
    presences = await list_agent_presences_by_workspace_ids(redis, workspace_ids)
    presence_map = {}
    for presence in presences:
        presence_id = (presence.get("workspace_id") or presence.get("agent_id") or "").strip()
        if presence_id:
            presence_map[presence_id] = presence

    claim_rows = await aweb_db.fetch_all(
        """
        SELECT c.task_ref, c.workspace_id, c.alias, c.human_name, c.claimed_at, c.team_id,
               counts.claimant_count, t.title
        FROM {{tables.task_claims}} c
        JOIN (
            SELECT team_id, task_ref, COUNT(*) AS claimant_count
            FROM {{tables.task_claims}}
            GROUP BY team_id, task_ref
        ) counts ON c.team_id = counts.team_id AND c.task_ref = counts.task_ref
        LEFT JOIN {{tables.tasks}} t
            ON t.team_id = c.team_id
            AND t.task_ref_suffix = SUBSTRING(c.task_ref FROM POSITION('-' IN c.task_ref) + 1)
            AND t.deleted_at IS NULL
        WHERE c.team_id = $1
        ORDER BY c.claimed_at DESC
        """,
        auth.team_id,
    )

    claims_by_workspace = {}
    conflict_map = {}
    for row in claim_rows:
        workspace_id = str(row["workspace_id"])
        claims_by_workspace.setdefault(workspace_id, []).append(
            {
                "task_ref": row["task_ref"],
                "title": row["title"],
                "claimed_at": row["claimed_at"].isoformat(),
                "claimant_count": int(row["claimant_count"]),
            }
        )
        if int(row["claimant_count"]) > 1:
            task_ref = row["task_ref"]
            conflict_map.setdefault(task_ref, []).append(
                {
                    "alias": row["alias"],
                    "human_name": row["human_name"] or None,
                    "workspace_id": workspace_id,
                }
            )

    def _workspace_entry(row) -> dict:
        workspace_id = str(row["workspace_id"])
        presence = presence_map.get(workspace_id) or {}
        return {
            "workspace_id": workspace_id,
            "alias": row["alias"],
            "human_name": row.get("human_name") or None,
            "role": (presence.get("role") or row.get("role") or None),
            "role_name": (presence.get("role") or row.get("role") or None),
            "status": presence.get("status") or ("active" if workspace_id in presence_map else "offline"),
            "last_seen": presence.get("last_seen") or None,
            "current_branch": presence.get("current_branch") or None,
            "claims": claims_by_workspace.get(workspace_id, []),
        }

    entries = [_workspace_entry(row) for row in workspaces]
    self_entry = next((entry for entry in entries if entry["workspace_id"] == auth.workspace_id), None)
    if self_entry is None:
        self_entry = {
            "workspace_id": auth.workspace_id,
            "alias": auth.alias or "",
            "human_name": None,
            "role": None,
            "role_name": None,
            "status": "offline",
            "last_seen": None,
            "current_branch": None,
            "claims": claims_by_workspace.get(auth.workspace_id or "", []),
        }

    team = [entry for entry in entries if entry["workspace_id"] != auth.workspace_id]
    team.sort(
        key=lambda entry: (
            -len(entry["claims"]),
            0 if entry["status"] == "active" else 1,
            entry["alias"],
        )
    )
    team = team[: max(0, int(limit))]

    conflicts = [
        {"task_ref": task_ref, "claimants": claimants}
        for task_ref, claimants in sorted(conflict_map.items())
    ]

    return json.dumps(
        {
            "team_id": auth.team_id,
            "workspace_id": auth.workspace_id,
            "self": self_entry,
            "team_agents": team,
            "conflicts": conflicts,
            "conflict_count": len(conflicts),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
