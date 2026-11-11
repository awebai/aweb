"""Operator release of task claims that remain on closed tasks."""

from __future__ import annotations

from awid.team_ids import team_slug

from .claims import release_task_claims_on
from .coordination.tasks_service import format_task_ref


async def _claims_on_closed_tasks(db) -> dict[tuple[str, str], int]:
    """Return {(team_id, task_ref): claim count} for claims on closed tasks.

    A claim names its task by the reference the task service forms,
    ``format_task_ref(team_slug(team_id), task_ref_suffix)``, within the
    claim's own team; the reference is formed here with those functions.
    """
    claim_rows = await db.fetch_all(
        """
        SELECT team_id, task_ref, COUNT(*) AS claims
        FROM {{tables.task_claims}}
        GROUP BY team_id, task_ref
        """
    )
    if not claim_rows:
        return {}
    task_rows = await db.fetch_all(
        """
        SELECT team_id, task_ref_suffix
        FROM {{tables.tasks}}
        WHERE team_id = ANY($1) AND status = 'closed' AND deleted_at IS NULL
        """,
        sorted({row["team_id"] for row in claim_rows}),
    )
    closed_refs = {
        (row["team_id"], format_task_ref(team_slug(row["team_id"]), row["task_ref_suffix"]))
        for row in task_rows
    }
    return {
        (row["team_id"], row["task_ref"]): row["claims"]
        for row in claim_rows
        if (row["team_id"], row["task_ref"]) in closed_refs
    }


async def _release_if_closed(db, *, team_id: str, task_ref: str) -> int:
    """Release a task's claims in one transaction while its row shows it closed.

    The task row is locked first, so a status change that reopens the task
    either commits before this check or waits for this release.
    """
    suffix = task_ref[len(team_slug(team_id)) + 1 :]
    async with db.transaction() as tx:
        status = await tx.fetch_value(
            """
            SELECT status
            FROM {{tables.tasks}}
            WHERE team_id = $1 AND task_ref_suffix = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            team_id,
            suffix,
        )
        if status != "closed":
            return 0
        return len(await release_task_claims_on(tx, team_id=team_id, task_ref=task_ref))


async def release_closed_task_claims(db, *, apply: bool = False) -> dict:
    """Report, and with ``apply`` release, every claim on a closed task.

    The report carries counts and team ids only. Each task's claims are
    released through ``release_task_claims_on`` in a transaction of its own,
    which also sets each released workspace's focus.
    """
    stale = await _claims_on_closed_tasks(db)
    teams: dict[str, dict[str, int]] = {}
    for (team_id, task_ref), claims in sorted(stale.items()):
        team = teams.setdefault(team_id, {"tasks": 0, "claims": 0, "released_claims": 0})
        team["tasks"] += 1
        team["claims"] += claims
        if apply:
            team["released_claims"] += await _release_if_closed(
                db, team_id=team_id, task_ref=task_ref
            )
    return {
        "apply": apply,
        "claims": sum(team["claims"] for team in teams.values()),
        "released_claims": sum(team["released_claims"] for team in teams.values()),
        "teams": teams,
    }
