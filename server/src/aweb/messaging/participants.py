"""Messaging-only selected-team human selectors; discovery grants no authority.

The agent roster remains agent-only. A human alias names the existing per-team
actor, never a newly invented global address or membership in another team.
"""

from __future__ import annotations

from aweb.human_kind import is_verified_human
from aweb.member_team_key import current_membership
from aweb.member_team_key import (
    current_member_projections,
    messaging_identity_projection,
)


async def messaging_participants_by_aliases(
    db,
    *,
    team_id: str,
    aliases: list[str],
    selected_team_id: str | None,
    registry_client,
) -> list[dict]:
    if not aliases:
        return []
    rows = await current_member_projections(db, team_id=team_id, aliases=aliases)
    result = []
    for projection in rows:
        row = messaging_identity_projection(projection)
        if is_verified_human(row):
            if team_id != selected_team_id:
                continue
            if not row.get("did_key"):
                continue
            # Follow the existing admitting-certificate policy. An unavailable
            # revocation authority must not silently make a human routable.
            if row.get("certificate_id"):
                current = await current_membership(registry_client, row)
                if not current or current.get("team_id") != team_id:
                    continue
        result.append(row)
    return result


async def messaging_participant_by_alias(
    db,
    *,
    team_id: str,
    alias: str,
    selected_team_id: str | None,
    registry_client,
) -> dict | None:
    rows = await messaging_participants_by_aliases(
        db,
        team_id=team_id,
        aliases=[alias],
        selected_team_id=selected_team_id,
        registry_client=registry_client,
    )
    # Database uniqueness normally enforces this; ambiguous data never picks a
    # "most recent" actor or crosses into another team.
    return rows[0] if len(rows) == 1 else None
