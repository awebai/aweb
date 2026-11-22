"""Canonical native team authority scope, independent of member projection."""

from awid.team_ids import parse_team_id

from aweb.service_errors import AuthenticationError


def member_team_scope(team_id: str) -> tuple[str, str]:
    """Require the team:domain scope in docs/identity.md:93-95.

    A malformed authority scope never means an empty revocation list.
    """
    try:
        return parse_team_id(team_id)
    except ValueError as exc:
        raise AuthenticationError(
            "Team identity is invalid. Reconnect using a certificate for a canonical team ID."
        ) from exc
