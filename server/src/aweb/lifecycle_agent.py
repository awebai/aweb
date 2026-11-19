"""Native agent disposition and ephemeral coordination cleanup."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID


class AgentDisposition(StrEnum):
    """Native identity disposition; hosts retain external lifecycle authority."""

    PRESERVED = "preserved"
    DELETED = "deleted"
    RETIRED = "retired"
    PREPARED_REMOVAL = "prepared_removal"


async def apply_agent_disposition_on(
    tx,
    *,
    agent_ids: list[UUID],
    team_id: str | None,
    disposition: AgentDisposition,
    deleted_at: datetime,
) -> int:
    """Apply native state only (docs/aweb-sot.md:1227–1245).

    Prepared removal fences native activity via deleted_at while keeping status
    active. The host owns completion credentials, external revocation and its
    removal ledger; this owner never destroys or revokes credentials.
    """
    if not agent_ids or disposition == AgentDisposition.PRESERVED:
        return 0
    status = "active" if disposition == AgentDisposition.PREPARED_REMOVAL else disposition.value
    rows = await tx.fetch_all(
        """UPDATE {{tables.agents}}
        SET status=$3, deleted_at=COALESCE(deleted_at,$4)
        WHERE agent_id=ANY($1::uuid[]) AND ($2::text IS NULL OR team_id=$2)
        RETURNING agent_id""",
        agent_ids,
        team_id,
        status,
        deleted_at,
    )
    return len(rows)


async def clear_agent_coordination_on(tx, *, agent_ids: list[UUID], team_id: str | None) -> None:
    """Retire ephemeral state, retaining control history and credentials.

    Implements docs/aweb-sot.md:1227–1245. These writes use
    the outer lifecycle transaction even when the target has no workspaces.
    """
    if not agent_ids:
        return
    await tx.execute(
        "DELETE FROM {{tables.session_admission_leases}} WHERE principal_agent_id=ANY($1::uuid[]) "
        "AND ($2::text IS NULL OR team_id=$2)",
        agent_ids,
        team_id,
    )
    await tx.execute(
        "DELETE FROM {{tables.identity_grant_liveness}} WHERE subject_agent_id=ANY($1::uuid[]) "
        "AND ($2::text IS NULL OR team_id=$2)",
        agent_ids,
        team_id,
    )
    await tx.execute(
        "UPDATE {{tables.control_signals}} SET consumed_at=NOW() "
        "WHERE target_agent_id=ANY($1::uuid[]) AND consumed_at IS NULL "
        "AND ($2::text IS NULL OR team_id=$2)",
        agent_ids,
        team_id,
    )
    await tx.execute(
        "DELETE FROM {{tables.agent_status_hosts}} WHERE agent_id=ANY($1::uuid[]) "
        "AND ($2::text IS NULL OR team_id=$2)",
        agent_ids,
        team_id,
    )
    await tx.execute(
        "DELETE FROM {{tables.agent_status}} WHERE agent_id=ANY($1::uuid[]) "
        "AND ($2::text IS NULL OR team_id=$2)",
        agent_ids,
        team_id,
    )
