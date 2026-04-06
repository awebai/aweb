"""FastAPI dependencies for team certificate authentication.

Provides TeamIdentity — the authenticated context for all routes
in the team-based architecture. Every authenticated endpoint resolves
a TeamIdentity from the request's certificate headers.
"""

from __future__ import annotations

from dataclasses import dataclass

from pgdbm import AsyncDatabaseManager


@dataclass(frozen=True)
class TeamIdentity:
    """Authenticated agent identity within a team.

    Resolved from the verified team certificate and the agents table.
    """

    team_address: str
    alias: str
    did_key: str
    agent_id: str
    lifetime: str
    certificate_id: str


async def resolve_team_identity(
    db: AsyncDatabaseManager,
    cert_info: dict[str, str],
) -> TeamIdentity:
    """Resolve a TeamIdentity from verified certificate info.

    Looks up the agent row by (team_address, did_key). The agent must
    already exist (created via POST /v1/connect).

    Args:
        db: The aweb database manager.
        cert_info: Verified certificate fields from parse_and_verify_certificate().

    Returns:
        TeamIdentity with resolved agent_id.

    Raises:
        ValueError: If the agent is not found (not connected).
    """
    team_address = cert_info["team_address"]
    did_key = cert_info["did_key"]

    row = await db.fetch_one(
        """
        SELECT agent_id FROM {{tables.agents}}
        WHERE team_address = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        team_address,
        did_key,
    )

    if not row:
        raise ValueError(
            f"Agent not connected: no agent with did_key {did_key[:20]}... "
            f"in team {team_address}"
        )

    return TeamIdentity(
        team_address=team_address,
        alias=cert_info["alias"],
        did_key=did_key,
        agent_id=str(row["agent_id"]),
        lifetime=cert_info.get("lifetime", "ephemeral"),
        certificate_id=cert_info.get("certificate_id", ""),
    )
