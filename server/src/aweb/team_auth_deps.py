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

from fastapi import Depends, HTTPException, Request

from aweb.deps import get_db
from pgdbm import AsyncDatabaseManager

from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.dns_auth import parse_didkey_auth, require_timestamp, enforce_timestamp_skew
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


# ---------------------------------------------------------------------------
# Shared certificate verification (steps 1-5, no agent lookup)
# ---------------------------------------------------------------------------


async def verify_request_certificate(request: Request, db) -> dict[str, str]:
    """Verify a request's DIDKey signature and team certificate.

    Steps 1-5 of the auth pipeline:
    1. Parse Authorization: DIDKey <did:key> <signature>
    2. Verify Ed25519 signature over canonical JSON payload + timestamp
    3. Parse and verify team certificate (X-AWID-Team-Certificate)
    4. Resolve team public key from awid registry
    5. Check revocation list from awid registry

    Returns cert_info dict (team_address, alias, did_key, lifetime, certificate_id).
    Does NOT look up the agent in the local DB — suitable for /v1/connect
    where the agent may not exist yet.

    Raises HTTPException on any failure.
    """
    # -- Step 1: Extract DIDKey auth header --
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    did_key, signature_b64 = parse_didkey_auth(auth_header)

    # -- Step 2: Verify DIDKey signature over {team_address, timestamp} --
    # The signature proves the caller holds the private key for the did:key.
    # We sign headers only (not the body) to avoid ASGI body-stream conflicts.
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    cert_header = request.headers.get("X-AWID-Team-Certificate")
    if not cert_header:
        raise HTTPException(status_code=401, detail="Missing X-AWID-Team-Certificate header")

    try:
        cert_data = json.loads(base64.b64decode(cert_header))
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed certificate")

    cert_team_address = cert_data.get("team", "")

    # Verify Ed25519 signature over {team, timestamp, body_sha256}
    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is None:
        import hashlib as _hashlib
        body_sha256 = _hashlib.sha256(b"").hexdigest()
    sig_payload = canonical_json_bytes({
        "body_sha256": body_sha256,
        "team": cert_team_address,
        "timestamp": timestamp,
    })
    try:
        verify_did_key_signature(did_key=did_key, payload=sig_payload, signature_b64=signature_b64)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature")

    # -- Step 4: Resolve team public key from awid --
    team_did_key = await _resolve_team_key(request, cert_team_address)
    if not team_did_key:
        raise HTTPException(status_code=401, detail=f"Unknown team: {cert_team_address}")

    # -- Step 5: Check revocation --
    revoked_certs = await _get_revoked_certificates(request, cert_team_address)

    def team_key_resolver(_team_address: str) -> str:
        return team_did_key

    def revocation_checker(_team_address: str, certificate_id: str) -> bool:
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

    # Include the registry-resolved team key (not the certificate's claim)
    cert_info["verified_team_did_key"] = team_did_key
    return cert_info


async def get_team_identity(request: Request, db=Depends(get_db)) -> TeamIdentity:
    """FastAPI dependency: authenticate request via team certificate.

    Full auth pipeline (steps 1-6): verifies the certificate and
    resolves the agent from the local DB. For routes where the agent
    must already exist.

    IMPORTANT: this must be used as Depends(get_team_identity) so FastAPI
    evaluates it before body parameter injection. Calling it directly
    inside a route handler deadlocks on POST requests because
    request.body() blocks after FastAPI has already consumed the stream.

    Returns a TeamIdentity or raises HTTPException(401/403).
    """
    cert_info = await verify_request_certificate(request, db)

    aweb_db = db.get_manager("aweb")
    try:
        return await resolve_team_identity(aweb_db, cert_info)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _resolve_team_key(request: Request, team_address: str) -> str:
    """Resolve team public key from awid registry.

    Returns the team's did:key, or empty string if the team is unknown.
    Raises HTTPException(503) if awid is unreachable.
    """
    parts = team_address.split("/", 1)
    if len(parts) != 2:
        return ""
    domain, team_name = parts

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry client not configured")

    try:
        key = await registry_client.get_team_public_key(domain, team_name)
        return key or ""
    except Exception:
        logger.warning("AWID registry unreachable for team key resolution: %s", team_address, exc_info=True)
        raise HTTPException(status_code=503, detail="AWID registry unavailable")


async def _get_revoked_certificates(request: Request, team_address: str) -> set[str]:
    """Get the set of revoked certificate IDs from awid.

    Raises HTTPException(503) if awid is unreachable.
    """
    parts = team_address.split("/", 1)
    if len(parts) != 2:
        return set()
    domain, team_name = parts

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry client not configured")

    try:
        return await registry_client.get_team_revocations(domain, team_name)
    except Exception:
        logger.warning("AWID registry unreachable for revocation check: %s", team_address, exc_info=True)
        raise HTTPException(status_code=503, detail="AWID registry unavailable")
