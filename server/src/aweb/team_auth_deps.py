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

from awid.signing import verify_did_key_signature
from awid.team_ids import parse_team_id
from awid.dns_auth import parse_didkey_auth, require_timestamp, enforce_timestamp_skew
from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
)
from aweb.config import get_settings, require_registered_certificates
from aweb.identity_scope import legacy_lifetime_for_scope, normalize_identity_scope
from aweb.team_auth import parse_and_verify_certificate
from aweb.team_auth_envelope import team_auth_signature_payload

logger = logging.getLogger(__name__)


def _aweb_db(db_or_manager):
    return db_or_manager.get_manager("aweb") if hasattr(db_or_manager, "get_manager") else db_or_manager


def _team_auth_allowed_audiences(request: Request) -> list[str]:
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    if configured:
        return [configured]
    return [get_settings().public_origin]


@dataclass(frozen=True)
class TeamIdentity:
    """Authenticated agent identity within a team.

    Resolved from the verified team certificate and the agents table.
    """

    team_id: str
    alias: str
    did_key: str
    did_aw: str
    address: str
    agent_id: str
    identity_scope: str
    certificate_id: str

    @property
    def lifetime(self) -> str:
        """Deprecated certificate compatibility alias."""
        return legacy_lifetime_for_scope(self.identity_scope)


async def resolve_team_identity(
    db: AsyncDatabaseManager,
    cert_info: dict[str, str],
) -> TeamIdentity:
    """Resolve a TeamIdentity from verified certificate info.

    Looks up the agent row by (team_id, did_key). The agent must
    already exist (created via POST /v1/connect).

    Args:
        db: The aweb database manager.
        cert_info: Verified certificate fields from parse_and_verify_certificate().

    Returns:
        TeamIdentity with resolved agent_id.

    Raises:
        ValueError: If the agent is not found (not connected).
    """
    team_id = cert_info["team_id"]
    did_key = cert_info["did_key"]

    row = await db.fetch_one(
        """
        SELECT agent_id, certificate_id FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        team_id,
        did_key,
    )

    if not row:
        raise ValueError(
            f"Agent not connected: no agent with did_key {did_key[:20]}... "
            f"in team {team_id}"
        )

    # Keep the admitting certificate recorded on the projection current
    # (aweb-abfn): identity-only auth checks THIS value against the registry's
    # revocations, so a row still naming a replaced certificate would either
    # miss a revocation or strip a live member. The certificate presented here
    # was verified against the registry (signature and revocation) above.
    presented_certificate_id = (cert_info.get("certificate_id") or "").strip()
    if presented_certificate_id and presented_certificate_id != (row.get("certificate_id") or "").strip():
        await db.execute(
            "UPDATE {{tables.agents}} SET certificate_id = $2 WHERE agent_id = $1",
            row["agent_id"],
            presented_certificate_id,
        )

    return TeamIdentity(
        team_id=team_id,
        alias=cert_info["alias"],
        did_key=did_key,
        did_aw=(cert_info.get("member_did_aw") or "").strip(),
        address=(cert_info.get("member_address") or "").strip(),
        agent_id=str(row["agent_id"]),
        identity_scope=normalize_identity_scope(cert_info.get("identity_scope") or cert_info.get("lifetime")),
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

    Returns cert_info dict (team_id, alias, did_key, identity_scope,
    certificate_id, member_did_aw, member_address). The last two are
    empty strings for local certificates. Does NOT look up the agent
    in the local DB — suitable for /v1/connect where the agent may not
    exist yet.

    Raises HTTPException on any failure.
    """
    # -- Step 1: Extract DIDKey auth header --
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    did_key, signature_b64 = parse_didkey_auth(auth_header)

    # -- Step 2: Verify DIDKey signature over {team_id, timestamp} --
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

    cert_team_id = cert_data.get("team_id", "")

    # Verify Ed25519 signature over the team-auth request envelope.
    # Legacy clients sign compact v1: {team_id, timestamp, body_sha256}.
    # `aw id request --team-auth` signs request-bound v2 bytes in
    # X-AWEB-Signed-Payload and the verifier binds those claims below.
    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is None:
        import hashlib as _hashlib
        body_sha256 = _hashlib.sha256(b"").hexdigest()
    allowed_audiences = (
        _team_auth_allowed_audiences(request)
        if str(request.headers.get("X-AWEB-Signed-Payload") or "").strip()
        else []
    )
    try:
        envelope = team_auth_signature_payload(
            request,
            team_id=cert_team_id,
            timestamp=timestamp,
            body_sha256=body_sha256,
            allowed_audiences=allowed_audiences,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=envelope.canonical_payload,
            signature_b64=signature_b64,
        )
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature")

    # -- Step 4: Resolve team public key from awid --
    team_did_key = await _resolve_team_key(request, cert_team_id)
    if not team_did_key:
        raise HTTPException(status_code=401, detail=f"Unknown team: {cert_team_id}")

    # -- Step 5: Check revocation --
    revoked_certs = await _get_revoked_certificates(request, cert_team_id)

    def team_key_resolver(_team_id: str) -> str:
        return team_did_key

    def revocation_checker(_team_id: str, certificate_id: str) -> bool:
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

    # -- Step 5b (staged, default OFF): require registry existence --
    # An unregistered certificate is unrevocable — the revocation set can
    # never name it — so once hosted anchoring backfill completes,
    # "not registered" becomes a verification failure. Ordering matters:
    # this runs only after signature and revocation checks pass, so a
    # revoked certificate keeps its revocation verdict. See
    # aweb.config.require_registered_certificates for the activation
    # contract; when OFF this adds zero registry reads.
    if require_registered_certificates():
        registered_certs = await _get_registered_certificates(request, cert_team_id)
        presented_certificate_id = (cert_info.get("certificate_id") or "").strip()
        if presented_certificate_id not in registered_certs:
            logger.warning(
                "certificate existence check failed: certificate %s presented for team %s "
                "is not registered at the AWID registry",
                presented_certificate_id,
                cert_team_id,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Certificate not registered: {presented_certificate_id}",
            )

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

    aweb_db = _aweb_db(db)
    try:
        return await resolve_team_identity(aweb_db, cert_info)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _resolve_team_key(request: Request, team_id: str) -> str:
    """Resolve team public key from awid registry.

    Returns the team's did:key, or empty string if the team is unknown.
    Raises HTTPException(503) if awid is unreachable.
    """
    try:
        domain, team_name = parse_team_id(team_id)
    except ValueError:
        return ""

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID team key resolution")

    try:
        key = await registry_client.get_team_public_key(domain, team_name)
        return key or ""
    except AWID_DEPENDENCY_ERRORS as exc:
        logger.warning("AWID registry dependency failed for team key resolution: %s", team_id, exc_info=True)
        raise awid_dependency_http_exception(exc, operation="AWID team key resolution") from exc
    except Exception as exc:
        logger.exception("Unexpected AWID registry dependency error for team key resolution: %s", team_id)
        raise awid_dependency_http_exception(exc, operation="AWID team key resolution") from exc


async def _get_revoked_certificates(request: Request, team_id: str) -> set[str]:
    """Get the set of revoked certificate IDs from awid.

    Raises HTTPException(503) if awid is unreachable.
    """
    try:
        domain, team_name = parse_team_id(team_id)
    except ValueError:
        return set()

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID team revocation check")

    try:
        return await registry_client.get_team_revocations(domain, team_name)
    except AWID_DEPENDENCY_ERRORS as exc:
        logger.warning("AWID registry dependency failed for revocation check: %s", team_id, exc_info=True)
        raise awid_dependency_http_exception(exc, operation="AWID team revocation check") from exc
    except Exception as exc:
        logger.exception("Unexpected AWID registry dependency error for revocation check: %s", team_id)
        raise awid_dependency_http_exception(exc, operation="AWID team revocation check") from exc


async def _get_registered_certificates(request: Request, team_id: str) -> set[str]:
    """Get the set of certificate IDs the AWID registry knows for a team.

    Used only when AWEB_REQUIRE_REGISTERED_CERTIFICATES is on. Reads through
    the cached registry client's team-certificates tier (same pull-and-cache
    shape as the revocation set — no per-request registry round-trip), with
    active_only=False so existence means "the registry has seen this
    certificate", independent of revocation state (revocation is checked
    separately, first). Same availability posture as the revocation check:
    if the registry cannot be consulted past the cached client's internal
    staleness allowance, fail closed with 503 — an existence check must not
    silently fail open.
    """
    try:
        domain, team_name = parse_team_id(team_id)
    except ValueError:
        return set()

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID certificate existence check")

    try:
        certificates = await registry_client.list_team_certificates(
            domain, team_name, active_only=False
        )
    except AWID_DEPENDENCY_ERRORS as exc:
        status_code = getattr(exc, "status_code", None)
        if status_code == 404:
            # Team unknown to the registry: nothing is registered. Mirrors
            # the revocation read's 404-means-empty behavior rather than
            # treating a definitive answer as an outage.
            return set()
        logger.warning(
            "AWID registry dependency failed for certificate existence check: %s", team_id, exc_info=True
        )
        raise awid_dependency_http_exception(exc, operation="AWID certificate existence check") from exc
    except Exception as exc:
        logger.exception(
            "Unexpected AWID registry dependency error for certificate existence check: %s", team_id
        )
        raise awid_dependency_http_exception(exc, operation="AWID certificate existence check") from exc

    return {
        cert_id
        for cert_id in ((cert.certificate_id or "").strip() for cert in certificates)
        if cert_id
    }
