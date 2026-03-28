"""Task claim lifecycle operations."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

if TYPE_CHECKING:
    from .db import DatabaseInfra

logger = logging.getLogger(__name__)


async def fetch_workspace_aliases(
    db_infra: "DatabaseInfra", project_id: str, workspace_ids: list[str]
) -> dict[str, str]:
    """Return {workspace_id: alias} for a list of workspace IDs.

    Skips deleted workspaces (they return alias="" via caller fallback).
    """
    if not workspace_ids:
        return {}
    server_db = db_infra.get_manager("server")
    rows = await server_db.fetch_all(
        "SELECT workspace_id, alias FROM {{tables.workspaces}} "
        "WHERE project_id = $1 AND workspace_id = ANY($2) AND deleted_at IS NULL",
        UUID(project_id),
        [UUID(ws_id) for ws_id in workspace_ids],
    )
    return {str(row["workspace_id"]): row["alias"] for row in rows}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def claim_focus_task_ref(task_ref: str, apex_task_ref: Optional[str]) -> str:
    """Prefer apex_task_ref for workspace focus, falling back to the claimed task."""
    return apex_task_ref or task_ref


def _claim_focus_task_ref(task_ref: str, apex_task_ref: Optional[str]) -> str:
    """Backward-compatible alias for claim_focus_task_ref."""
    return claim_focus_task_ref(task_ref, apex_task_ref)


async def resolve_task_claim_apex(
    db_infra: DatabaseInfra,
    project_id: str,
    task_ref: str,
    max_depth: int = 20,
) -> Optional[str]:
    """Walk native tasks parent_task_id chain to find the root task ref.

    Returns the root task ref, or ``None`` if the task cannot be resolved.
    """
    server_db = db_infra.get_manager("server")

    # Look up the project slug for task_ref reconstruction
    project = await server_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        UUID(project_id),
    )
    if not project:
        return None
    slug = project["slug"]

    prefix = slug + "-"
    ref_suffix = task_ref[len(prefix) :] if task_ref.startswith(prefix) else task_ref
    ref_suffix = ref_suffix.strip()
    if not ref_suffix:
        return None

    current = await server_db.fetch_one(
        """
        SELECT task_id, task_ref_suffix, parent_task_id
        FROM {{tables.tasks}}
        WHERE project_id = $1 AND task_ref_suffix = $2 AND deleted_at IS NULL
        """,
        UUID(project_id),
        ref_suffix,
    )
    if not current:
        return None

    # Walk parent chain to root
    depth = 0
    while current.get("parent_task_id") and depth < max_depth:
        parent = await server_db.fetch_one(
            """
            SELECT task_id, task_ref_suffix, parent_task_id
            FROM {{tables.tasks}}
            WHERE task_id = $1 AND deleted_at IS NULL
            """,
            current["parent_task_id"],
        )
        if not parent:
            break
        current = parent
        depth += 1

    return f"{slug}-{current['task_ref_suffix']}"


async def upsert_claim(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    workspace_id: str,
    alias: str,
    human_name: str,
    task_ref: str,
) -> Optional[dict[str, Any]]:
    """Attempt to claim a task.

    Returns ``None`` on success, or the conflicting
    claim dict (with alias, human_name, workspace_id) if already held by
    another workspace."""
    server_db = db_infra.get_manager("server")

    apex_task_ref = await resolve_task_claim_apex(db_infra, project_id, task_ref)

    async with server_db.transaction() as tx:
        # Check if another workspace already holds this claim.
        existing = await tx.fetch_one(
            """
            SELECT workspace_id, alias, human_name
            FROM {{tables.task_claims}}
            WHERE project_id = $1 AND task_ref = $2 AND workspace_id != $3
            """,
            UUID(project_id),
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
                project_id, workspace_id, alias, human_name, task_ref,
                apex_task_ref, claimed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (project_id, task_ref, workspace_id)
            DO UPDATE SET
                alias = EXCLUDED.alias,
                human_name = EXCLUDED.human_name,
                apex_task_ref = EXCLUDED.apex_task_ref,
                claimed_at = EXCLUDED.claimed_at
            """,
            UUID(project_id),
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
            WHERE project_id = $2 AND workspace_id = $3
            """,
            claim_focus_task_ref(task_ref, apex_task_ref),
            UUID(project_id),
            UUID(workspace_id),
        )

    return None


async def release_task_claims(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
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
    server_db = db_infra.get_manager("server")
    async with server_db.transaction() as tx:
        # Find affected workspaces before deleting.
        if workspace_id:
            affected_ws_ids = [UUID(workspace_id)]
            await tx.execute(
                """
                DELETE FROM {{tables.task_claims}}
                WHERE project_id = $1 AND workspace_id = $2 AND task_ref = $3
                """,
                UUID(project_id),
                UUID(workspace_id),
                task_ref,
            )
        else:
            rows = await tx.fetch_all(
                """
                DELETE FROM {{tables.task_claims}}
                WHERE project_id = $1 AND task_ref = $2
                RETURNING workspace_id
                """,
                UUID(project_id),
                task_ref,
            )
            affected_ws_ids = [row["workspace_id"] for row in rows]

        # Update each affected workspace's focus to its next active claim.
        for ws_id in affected_ws_ids:
            next_claim = await tx.fetch_one(
                """
                SELECT task_ref, apex_task_ref
                FROM {{tables.task_claims}}
                WHERE project_id = $1 AND workspace_id = $2
                ORDER BY claimed_at DESC
                LIMIT 1
                """,
                UUID(project_id),
                ws_id,
            )
            await tx.execute(
                """
                UPDATE {{tables.workspaces}}
                SET focus_task_ref = $1,
                    focus_updated_at = NOW(),
                    updated_at = NOW()
                WHERE project_id = $2 AND workspace_id = $3
                """,
                (
                    claim_focus_task_ref(next_claim["task_ref"], next_claim["apex_task_ref"])
                    if next_claim
                    else None
                ),
                UUID(project_id),
                ws_id,
            )

    return [str(ws_id) for ws_id in affected_ws_ids]
