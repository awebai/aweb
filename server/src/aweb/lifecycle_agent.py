"""Native agent disposition and ephemeral coordination cleanup."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from .member_status import MemberStatus


class AgentDisposition(StrEnum):
    """Native identity disposition; hosts retain external lifecycle authority."""

    PRESERVED = "preserved"
    DELETED = "deleted"
    RETIRED = "retired"
    PREPARED_REMOVAL = "prepared_removal"


class AgentDispositionConflict(RuntimeError):
    """The native state changed before a prepared-removal write could apply."""

    def __init__(self, *, agent_ids: tuple[UUID, ...]) -> None:
        self.agent_ids = agent_ids
        super().__init__("Prepared removal requires the target agent to remain active")


def _require_team_id(team_id: str) -> None:
    """A missing team must never widen a native lifecycle write."""
    if not isinstance(team_id, str) or not team_id.strip():
        raise ValueError("Native lifecycle writes require a nonempty team_id")


async def apply_agent_disposition_on(
    tx,
    *,
    agent_ids: list[UUID],
    team_id: str,
    disposition: AgentDisposition,
    deleted_at: datetime,
) -> int:
    """Apply native state only (docs/aweb-sot.md:1227–1252).

    Prepared removal fences native activity via deleted_at while keeping status
    active. The host owns completion credentials, external revocation and its
    removal ledger; this owner never destroys or revokes credentials.
    """
    _require_team_id(team_id)
    if not agent_ids or disposition == AgentDisposition.PRESERVED:
        return 0
    status = {
        AgentDisposition.DELETED: MemberStatus.DELETED,
        AgentDisposition.RETIRED: MemberStatus.RETIRED,
        AgentDisposition.PREPARED_REMOVAL: MemberStatus.ACTIVE,
    }[disposition]
    rows = await tx.fetch_all(
        """UPDATE {{tables.agents}}
        SET status=$3, deleted_at=COALESCE(deleted_at,$4)
        WHERE agent_id=ANY($1::uuid[]) AND team_id=$2
          AND ($3::text <> $5::text OR status=$5)
        RETURNING agent_id""",
        agent_ids,
        team_id,
        status,
        deleted_at,
        MemberStatus.ACTIVE,
    )
    if disposition == AgentDisposition.PREPARED_REMOVAL and len(rows) != len(
        set(agent_ids)
    ):
        # The caller transaction rolls back any preceding coordination writes.
        raise AgentDispositionConflict(agent_ids=tuple(agent_ids))
    return len(rows)


async def clear_agent_coordination_on(
    tx, *, agent_ids: list[UUID], team_id: str
) -> None:
    """Retire ephemeral state, retaining control history and credentials.

    Implements docs/aweb-sot.md:1227–1252. These writes use
    the outer lifecycle transaction even when the target has no workspaces.
    """
    _require_team_id(team_id)
    if not agent_ids:
        return
    await tx.execute(
        "DELETE FROM {{tables.session_admission_leases}} WHERE principal_agent_id=ANY($1::uuid[]) "
        "AND team_id=$2",
        agent_ids,
        team_id,
    )
    await tx.execute(
        "DELETE FROM {{tables.identity_grant_liveness}} WHERE subject_agent_id=ANY($1::uuid[]) "
        "AND team_id=$2",
        agent_ids,
        team_id,
    )
    await tx.execute(
        "UPDATE {{tables.control_signals}} SET consumed_at=NOW() "
        "WHERE target_agent_id=ANY($1::uuid[]) AND consumed_at IS NULL "
        "AND team_id=$2",
        agent_ids,
        team_id,
    )
