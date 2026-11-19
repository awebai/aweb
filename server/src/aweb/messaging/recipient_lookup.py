"""Shared native messaging identity lookups; reads grant no membership."""

from __future__ import annotations

from uuid import UUID

from aweb.identity_binding import verified_key_sql
from aweb.member_team_key import MemberProjection, member_projection_columns_sql
from aweb.messaging.recipient import Recipient
from aweb.service_errors import ValidationError


def _agent_uuid(agent_id: str) -> UUID:
    try:
        return UUID(str(agent_id).strip())
    except ValueError as exc:
        raise ValidationError(
            "Invalid agent_id format. Choose an agent_id from the team roster and retry."
        ) from exc


async def get_agent_by_id(
    db, *, agent_id: str, team_id: str | None = None
) -> Recipient | None:
    """Read an exact nondeleted row; optional team scope never chooses a team.

    docs/identity-messaging-contract.md:96-116 keeps this projection distinct
    from the current-member and delivery-policy decisions made by its caller.
    """
    row = await db.get_manager("aweb").fetch_one(
        "SELECT "
        + member_projection_columns_sql("a")
        + """
        FROM {{tables.agents}} a
        WHERE a.agent_id=$1 AND ($2::text IS NULL OR a.team_id=$2)
          AND a.deleted_at IS NULL
        """,
        _agent_uuid(agent_id),
        team_id,
    )
    return (
        Recipient.from_member_projection(MemberProjection.from_row(row))
        if row
        else None
    )


async def resolve_agent_by_did(db, did: str) -> Recipient | None:
    """Read a visible identity using R2's canonical verified-key projection.

    This retains the existing native lookup ordering. It grants no current
    membership; R2 owns the subsequent member-selector consumer migration.
    """
    row = await db.get_manager("aweb").fetch_one(
        "SELECT "
        + member_projection_columns_sql("a")
        + f"""
        FROM {{{{tables.agents}}}} a
        WHERE a.deleted_at IS NULL
          AND ((a.did_aw=$1 AND {verified_key_sql("a")}) OR a.did_key=$1)
        ORDER BY CASE WHEN a.did_aw=$1 THEN 0 ELSE 1 END, a.created_at DESC
        LIMIT 1
        """,
        did,
    )
    return (
        Recipient.from_member_projection(MemberProjection.from_row(row))
        if row
        else None
    )
