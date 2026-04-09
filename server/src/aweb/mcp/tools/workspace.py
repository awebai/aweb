"""MCP tools for workspace-style coordination status."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from aweb.mcp.auth import get_auth
from aweb.presence import list_agent_presences_by_ids


async def workspace_status(db_infra, redis, *, limit: int = 15) -> str:
    """Show self/team coordination status for the authenticated agent."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    agents = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, human_name, role
        FROM {{tables.agents}}
        WHERE team_id = $1 AND deleted_at IS NULL AND agent_type != 'human'
        ORDER BY alias
        """,
        auth.team_id,
    )
    agent_ids = [str(row["agent_id"]) for row in agents]
    presences = await list_agent_presences_by_ids(redis, agent_ids)
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

    def _agent_entry(row) -> dict:
        agent_id = str(row["agent_id"])
        presence = presence_map.get(agent_id) or {}
        return {
            "workspace_id": agent_id,
            "alias": row["alias"],
            "human_name": row.get("human_name") or None,
            "role": (presence.get("role") or row.get("role") or None),
            "role_name": (presence.get("role") or row.get("role") or None),
            "status": presence.get("status") or ("active" if agent_id in presence_map else "offline"),
            "last_seen": presence.get("last_seen") or None,
            "current_branch": presence.get("current_branch") or None,
            "claims": claims_by_workspace.get(agent_id, []),
        }

    entries = [_agent_entry(row) for row in agents]
    self_entry = next((entry for entry in entries if entry["workspace_id"] == auth.agent_id), None)
    if self_entry is None:
        self_entry = {
            "workspace_id": auth.agent_id,
            "alias": "",
            "human_name": None,
            "role": None,
            "role_name": None,
            "status": "offline",
            "last_seen": None,
            "current_branch": None,
            "claims": claims_by_workspace.get(auth.agent_id, []),
        }

    team = [entry for entry in entries if entry["workspace_id"] != auth.agent_id]
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
            "workspace_id": auth.agent_id,
            "self": self_entry,
            "team_agents": team,
            "conflicts": conflicts,
            "conflict_count": len(conflicts),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
