"""FastAPI dependencies for team certificate authentication.

Provides TeamIdentity — the authenticated context for all routes
in the team-based architecture. Every authenticated endpoint resolves
a TeamIdentity from the request's certificate headers.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb.awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.routes.dns_auth import parse_didkey_auth, require_timestamp, enforce_timestamp_skew
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

    1. Parse Authorization: DIDKey <did:key> <signature>
    2. Verify Ed25519 signature over canonical JSON payload + timestamp
    3. Parse and verify team certificate (X-AWID-Team-Certificate)
    4. Resolve team public key from awid registry (with local DB fallback)
    5. Check revocation list from awid registry
    6. Look up agent row

    Returns a TeamIdentity or raises HTTPException(401/403).
    """
    # -- Step 1: Extract DIDKey auth header --
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    did_key, signature_b64 = parse_didkey_auth(auth_header)

    # -- Step 2: Verify DIDKey signature over request payload + timestamp --
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    # Build canonical payload from request body
    try:
        body_bytes = await request.body()
        if body_bytes:
            body_dict = json.loads(body_bytes)
        else:
            body_dict = {}
    except Exception:
        body_dict = {}

    payload_with_ts = body_dict | {"timestamp": timestamp}
    payload_bytes = canonical_json_bytes(payload_with_ts)
    try:
        verify_did_key_signature(did_key=did_key, payload=payload_bytes, signature_b64=signature_b64)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature")

    # -- Step 3: Extract and decode certificate header --
    cert_header = request.headers.get("X-AWID-Team-Certificate")
    if not cert_header:
        raise HTTPException(status_code=401, detail="Missing X-AWID-Team-Certificate header")

    try:
        cert_data = json.loads(base64.b64decode(cert_header))
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed certificate")

    cert_team_address = cert_data.get("team", "")

    # -- Step 4: Resolve team public key from awid (with local DB fallback) --
    team_did_key = await _resolve_team_key(request, db, cert_team_address)
    if not team_did_key:
        raise HTTPException(status_code=401, detail=f"Unknown team: {cert_team_address}")

    # -- Step 5: Check revocation --
    revoked_certs = await _get_revoked_certificates(request, db, cert_team_address)

    def team_key_resolver(team_address: str) -> str:
        return team_did_key

    def revocation_checker(team_address: str, certificate_id: str) -> bool:
        return certificate_id in revoked_certs

    try:
        cert_info = parse_and_verify_certificate(
            cert_header,
            request_did_key=did_key,
            team_public_key_resolver=team_key_resolver,
            revocation_checker=revocation_checker,
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    # -- Step 6: Resolve agent from DB --
    aweb_db = db.get_manager("aweb")
    try:
        return await resolve_team_identity(aweb_db, cert_info)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


async def _resolve_team_key(request: Request, db, team_address: str) -> str:
    """Resolve team public key. Tries awid registry first, falls back to local DB."""
    # Parse team_address to get domain and team name
    parts = team_address.split("/", 1)
    if len(parts) != 2:
        return ""
    domain, team_name = parts

    # Try awid registry client (if available on app state)
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is not None:
        try:
            key = await registry_client.get_team_public_key(domain, team_name)
            if key:
                return key
        except Exception:
            logger.debug("Failed to resolve team key from awid for %s", team_address, exc_info=True)

    # Fallback: local teams table
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_address = $1",
        team_address,
    )
    if row:
        return row["team_did_key"]

    return ""


async def _get_revoked_certificates(request: Request, db, team_address: str) -> set[str]:
    """Get the set of revoked certificate IDs for a team."""
    parts = team_address.split("/", 1)
    if len(parts) != 2:
        return set()
    domain, team_name = parts

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is not None:
        try:
            return await registry_client.get_team_revocations(domain, team_name)
        except Exception:
            logger.debug(
                "Failed to fetch revocations from awid for %s", team_address, exc_info=True
            )

    return set()
