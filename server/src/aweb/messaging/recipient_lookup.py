"""Current-member selection for native messaging; residence is independent."""

from __future__ import annotations

from dataclasses import replace
from uuid import UUID

from aweb.member_team_key import current_member_projections
from aweb.messaging.recipient import Recipient
from aweb.service_errors import ConflictError, ValidationError


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
    """Select an exact current member, using the shared member rule.

    This roster selector is distinct from an independently admitted identity's
    residence or existing participation. Those reads do not require membership.
    """
    rows = await current_member_projections(
        db, agent_id=_agent_uuid(agent_id), team_id=team_id
    )
    return Recipient.from_member_projection(rows[0]) if rows else None


async def resolve_agent_by_did(
    db, did: str, *, team_id: str | None = None
) -> Recipient | None:
    """Resolve current verified member identity without a newest-row winner."""
    rows = await current_member_projections(db, dids=[did], team_id=team_id)
    if not rows:
        return None
    recipient = Recipient.from_member_projection(rows[0])
    if len(rows) == 1:
        return recipient
    identities = {(row.verified_identity().get("did_aw"), row["did_key"]) for row in rows}
    if len(identities) != 1 or not recipient.did_aw:
        raise ConflictError(
            "Identity matches several current memberships. Select a team member name or address."
        )
    # Several memberships of one verified identity choose no team or address.
    return replace(
        recipient.as_identity(), address=None, alias=recipient.did_aw
    )
