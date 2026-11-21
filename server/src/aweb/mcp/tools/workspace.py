"""MCP tools for workspace-style coordination status."""

from __future__ import annotations

from aweb.human_kind import agent_listing_predicate_sql
from aweb.member_team_key import current_member_sql
from aweb.task_refs import task_title_join

import json
from datetime import UTC, datetime
from aweb.application_state import RegistryClientUnavailable
from aweb.grant_liveness_policy import GrantLivenessFailurePolicy
from aweb.workspace_activity import workspace_activity_by_id
from datetime import timezone

from aweb.mcp.tools._common import require_team_context


async def workspace_status(
    db_infra, redis, *, registry_client=None, limit: int = 15
) -> str:
    """Show self/team coordination status for the authenticated agent."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps(
            {"error": "This tool requires team context. Use a team certificate."}
        )
    if registry_client is None:
        raise RegistryClientUnavailable()
    aweb_db = db_infra.get_manager("aweb")

    workspaces = await aweb_db.fetch_all(
        f"""
        SELECT
            w.workspace_id,
            w.agent_id,
            w.alias,
            w.human_name,
            COALESCE(w.role, a.role) AS role
        FROM {{{{tables.workspaces}}}} w
        JOIN {{{{tables.agents}}}} a ON a.agent_id = w.agent_id AND a.team_id = w.team_id
        WHERE w.team_id = $1
          AND w.deleted_at IS NULL
          AND {current_member_sql("a")}
          AND {agent_listing_predicate_sql("a")}
        ORDER BY w.alias
        """,
        auth.team_id,
    )
    workspace_ids = [str(row["workspace_id"]) for row in workspaces]
    activity_by_id = await workspace_activity_by_id(
        aweb_db,
        redis,
        workspace_ids=workspace_ids,
        registry_client=registry_client,
        request=auth.request,
        failure_policy=GrantLivenessFailurePolicy.OMIT_UNPROVEN,
    )
    now = datetime.now(UTC)

    claim_rows = await aweb_db.fetch_all(
        f"""
        WITH current_claims AS (
            SELECT c.* FROM {{{{tables.task_claims}}}} c
            WHERE c.team_id = $1 AND c.workspace_id = ANY($2::UUID[])
        )
        SELECT c.task_ref, c.workspace_id, c.alias, c.human_name, c.claimed_at, c.team_id,
               counts.claimant_count, task_info.title
        FROM current_claims c
        JOIN (
            SELECT team_id, task_ref, COUNT(*) AS claimant_count
            FROM current_claims
            GROUP BY team_id, task_ref
        ) counts ON c.team_id = counts.team_id AND c.task_ref = counts.task_ref
        {task_title_join(alias="task_info", team_id_col="c.team_id", task_ref_col="c.task_ref")}
        ORDER BY c.claimed_at DESC
        """,
        auth.team_id,
        [row["workspace_id"] for row in workspaces],
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
        activity = activity_by_id.get(workspace_id)
        presence = (activity.presence or {}) if activity else {}
        return {
            "workspace_id": workspace_id,
            "alias": row["alias"],
            "human_name": row.get("human_name") or None,
            "role": (presence.get("role") or row.get("role") or None),
            "role_name": (presence.get("role") or row.get("role") or None),
            "status": activity.display_status(now=now) if activity else "offline",
            "last_seen": activity.last_seen_at.isoformat()
            if activity and activity.last_seen_at
            else None,
            "current_branch": presence.get("current_branch") or None,
            "claims": claims_by_workspace.get(workspace_id, []),
        }

    entries = [_workspace_entry(row) for row in workspaces]
    self_entry = next(
        (entry for entry in entries if entry["workspace_id"] == auth.workspace_id), None
    )
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
