"""Team certificate authentication and dashboard JWT verification.

Team certificates are Ed25519-signed JSON documents that prove an agent
is a member of a specific team. They replace API key auth.

Dashboard tokens are short-lived JWTs containing allowed team_ids,
issued by the hosted dashboard for human dashboard access.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import jwt as pyjwt

from collections.abc import Collection

from fastapi import HTTPException

from awid.team_certificate import TeamCertificateError, check_team_certificate, refusal_answer
from aweb.identity_scope import legacy_lifetime_for_scope, normalize_identity_scope

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Certificate verification
# ---------------------------------------------------------------------------


def certificate_refusal(error: TeamCertificateError) -> HTTPException:
    """What the server answers for a certificate the shared check refuses
    (awid.team_certificate.refusal_answer)."""
    status_code, detail = refusal_answer(error)
    return HTTPException(status_code=status_code, detail=detail)


def parse_and_verify_certificate(
    encoded_certificate: str,
    *,
    request_did_key: str,
    team_did_key: str,
    revoked_certificate_ids: Collection[str],
    registered_certificate_ids: Collection[str] | None,
) -> dict[str, str]:
    """Check a team certificate and return the fields the server reads.

    Args:
        encoded_certificate: Base64-encoded certificate JSON.
        request_did_key: The did:key from the Authorization header.
        team_did_key: The registry's current key for the team the certificate
            names. The caller resolves it from the certificate's team_id, or
            compares the returned team_id with the team it resolved the key
            for before using it.
        revoked_certificate_ids: The team's revoked certificates, from the registry.
        registered_certificate_ids: The team's registered certificates, from
            the registry; None only while require_registered_certificates()
            is off.

    Returns:
        Dict with team_id, alias, did_key, identity_scope, certificate_id,
        member_did_aw, member_address, plus compatibility lifetime. The last
        two identity fields are empty strings for local certificates.

    Raises:
        TeamCertificateError: with the reason the certificate is refused for
            (awid.team_certificate.check_team_certificate); certificate_refusal
            turns it into the server's answer.
    """
    cert = check_team_certificate(
        encoded_certificate,
        subject_did_key=request_did_key,
        team_did_key=team_did_key,
        revoked_certificate_ids=revoked_certificate_ids,
        registered_certificate_ids=registered_certificate_ids,
    )
    team_id = cert["team_id"]
    member_did_key = cert["member_did_key"]
    certificate_id = cert["certificate_id"]

    identity_scope = normalize_identity_scope(cert.get("identity_scope") or cert.get("lifetime"))
    return {
        "team_id": team_id,
        "alias": cert["alias"],
        "did_key": member_did_key,
        "identity_scope": identity_scope,
        "lifetime": legacy_lifetime_for_scope(identity_scope),
        "certificate_id": certificate_id,
        "member_did_aw": cert.get("member_did_aw", ""),
        "member_address": cert.get("member_address", ""),
    }


# ---------------------------------------------------------------------------
# Dashboard JWT verification
# ---------------------------------------------------------------------------


def verify_dashboard_token(
    token: str,
    secret: str,
    *,
    required_team: Optional[str] = None,
) -> dict[str, Any]:
    """Verify a dashboard JWT and optionally check team authorization.

    Args:
        token: The JWT string from X-Dashboard-Token header.
        secret: The shared secret (AWEB_DASHBOARD_JWT_SECRET).
        required_team: If provided, verify the token grants access to this team.

    Returns:
        Dict with user_id, team_ids.

    Raises:
        ValueError: If the token is invalid, expired, or unauthorized.
    """
    if not secret:
        raise ValueError("Dashboard JWT secret not configured")

    try:
        payload = pyjwt.decode(token, secret, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise ValueError("Dashboard token expired")
    except pyjwt.InvalidTokenError:
        raise ValueError("Dashboard token invalid")

    user_id = payload.get("user_id")
    team_ids = payload.get("team_ids", [])

    if not user_id:
        raise ValueError("Dashboard token missing user_id")

    if required_team and required_team not in team_ids:
        raise ValueError(f"User not authorized for team {required_team}")

    return {
        "user_id": user_id,
        "team_ids": team_ids,
    }
