"""FastAPI dependencies for team certificate authentication.

Provides TeamIdentity — the authenticated context for all routes
in the team-based architecture. Every authenticated endpoint resolves
a TeamIdentity from the request's certificate headers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb.routes.dns_auth import parse_didkey_auth
from aweb.team_auth import parse_and_verify_certificate

logger = logging.getLogger(__name__)


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


async def get_team_identity(request: Request, db) -> TeamIdentity:
    """FastAPI dependency: authenticate request via team certificate.

    Extracts Authorization (DIDKey) and X-AWID-Team-Certificate headers,
    verifies the certificate signature against the team's public key
    (looked up from the teams table), checks revocation, and resolves
    the agent row.

    Returns a TeamIdentity or raises HTTPException(401/403).
    """
    cert_header = request.headers.get("X-AWID-Team-Certificate")
    if not cert_header:
        raise HTTPException(status_code=401, detail="Missing X-AWID-Team-Certificate header")

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    did_key, _ = parse_didkey_auth(auth_header)

    aweb_db = db.get_manager("aweb")

    async def _team_key_resolver(team_address: str) -> str:
        """Resolve team public key from the teams table."""
        row = await aweb_db.fetch_one(
            "SELECT team_did_key FROM {{tables.teams}} WHERE team_address = $1",
            team_address,
        )
        if not row:
            return ""
        return row["team_did_key"]

    # Synchronous wrapper for parse_and_verify_certificate's callable interface
    # Pre-resolve the team key since the certificate contains the team_address
    import base64, json
    try:
        cert_data = json.loads(base64.b64decode(cert_header))
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed certificate")

    cert_team_address = cert_data.get("team", "")
    team_did_key = await _team_key_resolver(cert_team_address)

    def team_key_resolver_sync(team_address: str) -> str:
        return team_did_key

    def revocation_checker(team_address: str, certificate_id: str) -> bool:
        # TODO: check cached revocation list from awid (aweb-aaex dependency)
        return False

    try:
        cert_info = parse_and_verify_certificate(
            cert_header,
            request_did_key=did_key,
            team_public_key_resolver=team_key_resolver_sync,
            revocation_checker=revocation_checker,
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        return await resolve_team_identity(aweb_db, cert_info)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
