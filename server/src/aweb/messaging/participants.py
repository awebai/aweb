"""Messaging-only selected-team human selectors; discovery grants no authority.

The agent roster remains agent-only. A human alias names the existing per-team
actor, never a newly invented global address or membership in another team.
"""

from __future__ import annotations

from aweb.identity_auth_deps import _enforce_current_membership


async def messaging_participants_by_aliases(
    db,
    *,
    team_id: str,
    aliases: list[str],
    selected_team_id: str | None,
    request=None,
) -> list[dict]:
    if not aliases:
        return []
    rows = await db.get_manager("aweb").fetch_all(
        """SELECT agent_id, team_id, alias, did_key, did_aw, address,
                  inbound_mode, status, deleted_at, agent_type, certificate_id,
                  identity_scope
           FROM {{tables.agents}}
           WHERE team_id=$1 AND alias=ANY($2::text[]) AND deleted_at IS NULL""",
        team_id,
        aliases,
    )
    result = []
    for row in rows:
        row = dict(row)
        if row.get("agent_type") == "human":
            if team_id != selected_team_id or row.get("status") != "active":
                continue
            if not row.get("did_key"):
                continue
            # Follow the existing admitting-certificate policy. An unavailable
            # revocation authority must not silently make a human routable.
            if row.get("certificate_id"):
                if request is None:
                    continue
                current = await _enforce_current_membership(request, row)
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
    request=None,
) -> dict | None:
    rows = await messaging_participants_by_aliases(
        db,
        team_id=team_id,
        aliases=[alias],
        selected_team_id=selected_team_id,
        request=request,
    )
    # Database uniqueness normally enforces this; ambiguous data never picks a
    # "most recent" actor or crosses into another team.
    return rows[0] if len(rows) == 1 else None
