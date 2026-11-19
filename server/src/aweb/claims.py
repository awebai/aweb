"""Task claim lifecycle operations."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from awid.team_ids import team_slug
from .service_errors import ConflictError
from .task_refs import format_task_ref, task_ref_suffix

if TYPE_CHECKING:
    from .db import DatabaseInfra

logger = logging.getLogger(__name__)


async def fetch_workspace_aliases(
    db_infra: "DatabaseInfra", team_id: str, workspace_ids: list[str]
) -> dict[str, str]:
    """Return {workspace_id: alias} for a list of workspace IDs.

    Skips deleted workspaces (they return alias="" via caller fallback).
    """
    if not workspace_ids:
        return {}
    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        "SELECT workspace_id, alias FROM {{tables.workspaces}} "
        "WHERE team_id = $1 AND workspace_id = ANY($2) AND deleted_at IS NULL",
        team_id,
        [UUID(ws_id) for ws_id in workspace_ids],
    )
    return {str(row["workspace_id"]): row["alias"] for row in rows}


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def list_active_claims(
    db_infra: "DatabaseInfra",
    *,
    team_id: str,
    workspace_id: str | None = None,
    claimed_before: datetime | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """List active task claims ordered by most recent first."""
    aweb_db = db_infra.get_manager("aweb")

    conditions: list[str] = ["team_id = $1"]
    params: list[object] = [team_id]
    param_idx = 2

    if workspace_id:
        conditions.append(f"workspace_id = ${param_idx}")
        params.append(UUID(workspace_id))
        param_idx += 1

    if claimed_before is not None:
        conditions.append(f"claimed_at < ${param_idx}")
        params.append(claimed_before)
        param_idx += 1

    where_clause = f"WHERE {' AND '.join(conditions)}"
    limit_clause = ""
    if limit is not None:
        limit_clause = f"LIMIT ${param_idx}"
        params.append(limit)

    rows = await aweb_db.fetch_all(
        f"""
        SELECT task_ref, workspace_id, alias, human_name, claimed_at, team_id
        FROM {{{{tables.task_claims}}}}
        {where_clause}
        ORDER BY claimed_at DESC
        {limit_clause}
        """,
        *params,
    )
    return [dict(row) for row in rows]


def claim_focus_task_ref(task_ref: str, apex_task_ref: Optional[str]) -> str:
    """Prefer apex_task_ref for workspace focus, falling back to the claimed task."""
    return apex_task_ref or task_ref


async def resolve_task_claim_apex(
    db_infra: DatabaseInfra,
    team_id: str,
    task_ref: str,
    max_depth: int = 20,
) -> Optional[str]:
    """Walk native tasks parent_task_id chain to find the sticky focus apex."""
    return await resolve_task_claim_apex_on(
        db_infra.get_manager("aweb"), team_id, task_ref, max_depth=max_depth
    )


async def resolve_task_claim_apex_on(
    aweb_db,
    team_id: str,
    task_ref: str,
    max_depth: int = 20,
) -> Optional[str]:
    """Resolve the apex using one manager or transaction-visible connection.

    Prefer the highest epic ancestor when one exists. Otherwise fall back to
    the root task ref so non-epic task trees still have a stable apex.
    """
    slug = team_slug(team_id)

    ref_suffix = task_ref_suffix(team_id=team_id, ref=task_ref)
    if not ref_suffix:
        return None

    current = await aweb_db.fetch_one(
        """
        SELECT task_id, task_ref_suffix, parent_task_id, task_type
        FROM {{tables.tasks}}
        WHERE team_id = $1 AND task_ref_suffix = $2 AND deleted_at IS NULL
        """,
        team_id,
        ref_suffix,
    )
    if not current:
        return None

    epic_ref: Optional[str] = None
    if (current.get("task_type") or "").strip().lower() == "epic":
        epic_ref = format_task_ref(
            team_slug=slug, task_ref_suffix=current["task_ref_suffix"]
        )

    # Walk parent chain to root
    depth = 0
    while current.get("parent_task_id") and depth < max_depth:
        parent = await aweb_db.fetch_one(
            """
            SELECT task_id, task_ref_suffix, parent_task_id, task_type
            FROM {{tables.tasks}}
            WHERE task_id = $1 AND deleted_at IS NULL
            """,
            current["parent_task_id"],
        )
        if not parent:
            break
        current = parent
        if (current.get("task_type") or "").strip().lower() == "epic":
            epic_ref = format_task_ref(
                team_slug=slug, task_ref_suffix=current["task_ref_suffix"]
            )
        depth += 1

    return epic_ref or format_task_ref(
        team_slug=slug, task_ref_suffix=current["task_ref_suffix"]
    )


async def _is_open_task_ref(
    tx,
    *,
    team_id: str,
    task_ref: str,
) -> bool:
    ref_suffix = task_ref_suffix(team_id=team_id, ref=task_ref)

    row = await tx.fetch_one(
        """
        SELECT status
        FROM {{tables.tasks}}
        WHERE team_id = $1
          AND task_ref_suffix = $2
          AND deleted_at IS NULL
        LIMIT 1
        """,
        team_id,
        ref_suffix,
    )
    if not row:
        return False
    return (row["status"] or "").strip().lower() != "closed"


async def acquire_task_claim_on(
    tx, *, team_id: str, actor_alias: str, task_ref: str, now: datetime
) -> bool:
    """Acquire a claim while the caller holds its task row lock."""
    apex_task_ref = await resolve_task_claim_apex_on(tx, team_id, task_ref)
    workspace = await tx.fetch_one(
        """
        SELECT workspace_id, alias, human_name
        FROM {{tables.workspaces}}
        WHERE alias = $1 AND team_id = $2 AND deleted_at IS NULL
        """,
        actor_alias,
        team_id,
    )
    if workspace is not None:
        conflicting_claim = await tx.fetch_one(
            """
            SELECT workspace_id, alias
            FROM {{tables.task_claims}}
            WHERE team_id = $1 AND task_ref = $2 AND workspace_id != $3
            LIMIT 1
            """,
            team_id,
            task_ref,
            workspace["workspace_id"],
        )
        if conflicting_claim:
            raise ConflictError("Task is already in progress by another agent")

        await tx.execute(
            """
            INSERT INTO {{tables.task_claims}} (
                team_id, workspace_id, alias, human_name, task_ref,
                apex_task_ref, claimed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (team_id, task_ref, workspace_id)
            DO UPDATE SET
                alias = EXCLUDED.alias,
                human_name = EXCLUDED.human_name,
                apex_task_ref = EXCLUDED.apex_task_ref,
                claimed_at = EXCLUDED.claimed_at
            """,
            team_id,
            workspace["workspace_id"],
            workspace["alias"],
            workspace["human_name"] or "",
            task_ref,
            apex_task_ref,
            now,
        )

        await tx.execute(
            """
            UPDATE {{tables.workspaces}}
            SET focus_task_ref = $1,
                focus_updated_at = $2,
                updated_at = $2
            WHERE team_id = $3 AND workspace_id = $4
            """,
            claim_focus_task_ref(task_ref, apex_task_ref),
            now,
            team_id,
            workspace["workspace_id"],
        )
        return True
    return False


async def upsert_claim(
    db_infra: DatabaseInfra,
    *,
    team_id: str,
    workspace_id: str,
    alias: str,
    human_name: str,
    task_ref: str,
) -> Optional[dict[str, Any]]:
    """Attempt to claim a task.

    Returns ``None`` on success, or the conflicting
    claim dict (with alias, human_name, workspace_id) if already held by
    another workspace."""
    aweb_db = db_infra.get_manager("aweb")

    apex_task_ref = await resolve_task_claim_apex(db_infra, team_id, task_ref)

    async with aweb_db.transaction() as tx:
        # Check if another workspace already holds this claim.
        existing = await tx.fetch_one(
            """
            SELECT workspace_id, alias, human_name
            FROM {{tables.task_claims}}
            WHERE team_id = $1 AND task_ref = $2 AND workspace_id != $3
            """,
            team_id,
            task_ref,
            UUID(workspace_id),
        )
        if existing:
            return {
                "workspace_id": str(existing["workspace_id"]),
                "alias": existing["alias"],
                "human_name": existing["human_name"],
            }

        await tx.execute(
            """
            INSERT INTO {{tables.task_claims}} (
                team_id, workspace_id, alias, human_name, task_ref,
                apex_task_ref, claimed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (team_id, task_ref, workspace_id)
            DO UPDATE SET
                alias = EXCLUDED.alias,
                human_name = EXCLUDED.human_name,
                apex_task_ref = EXCLUDED.apex_task_ref,
                claimed_at = EXCLUDED.claimed_at
            """,
            team_id,
            UUID(workspace_id),
            alias,
            human_name,
            task_ref,
            apex_task_ref,
            _now(),
        )
        await tx.execute(
            """
            UPDATE {{tables.workspaces}}
            SET focus_task_ref = $1,
                focus_updated_at = NOW(),
                updated_at = NOW()
            WHERE team_id = $2 AND workspace_id = $3
            """,
            claim_focus_task_ref(task_ref, apex_task_ref),
            team_id,
            UUID(workspace_id),
        )

    return None


async def release_task_claims(
    db_infra: DatabaseInfra,
    *,
    team_id: str,
    task_ref: str,
    workspace_id: str | None = None,
) -> list[str]:
    """Release claims on a task and update affected workspaces' focus.

    If workspace_id is provided, only that workspace's claim is removed.
    If workspace_id is None, all claims on the task are removed.

    This is used when
    a task is closed/deleted, since any workspace's claim becomes stale.

    Returns the workspace_id strings of affected claimants.
    """
    aweb_db = db_infra.get_manager("aweb")
    async with aweb_db.transaction() as tx:
        return await release_task_claims_on(
            tx, team_id=team_id, task_ref=task_ref, workspace_id=workspace_id
        )


async def release_task_claims_on(
    tx, *, team_id: str, task_ref: str, workspace_id: str | None = None
) -> list[str]:
    """Release task claims/focus in an existing lifecycle transaction."""
    released_focus_by_workspace: dict[str, str] = {}
    if workspace_id:
        released_rows = await tx.fetch_all(
            """
            DELETE FROM {{tables.task_claims}}
            WHERE team_id = $1 AND workspace_id = $2 AND task_ref = $3
            RETURNING workspace_id, task_ref, apex_task_ref
            """,
            team_id,
            UUID(workspace_id),
            task_ref,
        )
        affected_ws_ids = [row["workspace_id"] for row in released_rows]
    else:
        released_rows = await tx.fetch_all(
            """
            DELETE FROM {{tables.task_claims}}
            WHERE team_id = $1 AND task_ref = $2
            RETURNING workspace_id, task_ref, apex_task_ref
            """,
            team_id,
            task_ref,
        )
        affected_ws_ids = [row["workspace_id"] for row in released_rows]

    for row in released_rows:
        released_focus_by_workspace[str(row["workspace_id"])] = claim_focus_task_ref(
            row["task_ref"],
            row["apex_task_ref"],
        )

    # Update each affected workspace's focus to its next active claim.
    # If no claims remain, preserve the released apex/task as sticky focus
    # while that focus task is still open.
    for ws_id in affected_ws_ids:
        next_claim = await tx.fetch_one(
            """
            SELECT task_ref, apex_task_ref
            FROM {{tables.task_claims}}
            WHERE team_id = $1 AND workspace_id = $2
            ORDER BY claimed_at DESC
            LIMIT 1
            """,
            team_id,
            ws_id,
        )
        next_focus = None
        if next_claim:
            next_focus = claim_focus_task_ref(
                next_claim["task_ref"], next_claim["apex_task_ref"]
            )
        else:
            released_focus = released_focus_by_workspace.get(str(ws_id))
            if released_focus and await _is_open_task_ref(
                tx,
                team_id=team_id,
                task_ref=released_focus,
            ):
                next_focus = released_focus
        await tx.execute(
            """
            UPDATE {{tables.workspaces}}
            SET focus_task_ref = $1,
                focus_updated_at = NOW(),
                updated_at = NOW()
            WHERE team_id = $2 AND workspace_id = $3
            """,
            next_focus,
            team_id,
            ws_id,
        )

    return [str(ws_id) for ws_id in affected_ws_ids]
