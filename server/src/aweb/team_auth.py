"""Team certificate authentication and dashboard JWT verification.

Team certificates are Ed25519-signed JSON documents that prove an agent
is a member of a specific team. They replace API key auth.

Dashboard tokens are short-lived JWTs containing allowed team_addresses,
issued by aweb-cloud for human dashboard access.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Callable, Optional

import jwt as pyjwt

from aweb.awid.did import public_key_from_did
from aweb.awid.signing import canonical_json_bytes, verify_signature_with_public_key, VerifyResult

logger = logging.getLogger(__name__)

_CERTIFICATE_VERSION = 1


# ---------------------------------------------------------------------------
# Certificate verification
# ---------------------------------------------------------------------------


def _verify_certificate_signature(cert: dict, team_did_key: str) -> bool:
    """Verify that a certificate was signed by the given team key.

    The team_did_key MUST come from a trusted source (the awid registry),
    never from the certificate itself.
    """
    signature = cert.get("signature")
    if not signature:
        return False

    # The signed payload is the entire certificate minus the signature field.
    payload_fields = {k: v for k, v in cert.items() if k != "signature"}
    payload_bytes = canonical_json_bytes(payload_fields)

    try:
        public_key = public_key_from_did(team_did_key)
    except Exception:
        return False

    result = verify_signature_with_public_key(public_key, payload_bytes, signature)
    return result == VerifyResult.VERIFIED


def parse_and_verify_certificate(
    encoded_certificate: str,
    *,
    request_did_key: str,
    team_public_key_resolver: Callable[[str], str],
    revocation_checker: Callable[[str, str], bool],
) -> dict[str, str]:
    """Parse, verify, and validate a team certificate.

    Args:
        encoded_certificate: Base64-encoded certificate JSON.
        request_did_key: The did:key from the Authorization header.
        team_public_key_resolver: Given a team_address, returns team_did_key
            from the awid registry (cached). Must raise on failure.
        revocation_checker: Given (team_address, certificate_id), returns
            True if the certificate has been revoked.

    Returns:
        Dict with team_address, alias, did_key, lifetime, certificate_id.

    Raises:
        ValueError: If the certificate is invalid, tampered, revoked, or mismatched.
    """
    try:
        cert_json = base64.b64decode(encoded_certificate)
        cert = json.loads(cert_json)
    except Exception:
        raise ValueError("Malformed certificate: invalid base64 or JSON")

    version = cert.get("version")
    if version != _CERTIFICATE_VERSION:
        raise ValueError(f"Unsupported certificate version: {version}")

    team_address = cert.get("team")
    member_did_key = cert.get("member_did_key")
    certificate_id = cert.get("certificate_id")

    if not team_address or not member_did_key or not certificate_id:
        raise ValueError("Certificate missing required fields")

    # Verify the requesting agent's did:key matches the certificate
    if member_did_key != request_did_key:
        raise ValueError("Certificate did_key mismatch: agent's did:key does not match certificate")

    # Get the team's public key from a trusted source (awid registry)
    team_did_key = team_public_key_resolver(team_address)
    if not team_did_key:
        raise ValueError(f"Unknown team: {team_address}")

    # Verify certificate signature against the registry-resolved team key
    if not _verify_certificate_signature(cert, team_did_key):
        raise ValueError("Certificate signature verification failed")

    # Check revocation
    if revocation_checker(team_address, certificate_id):
        raise ValueError(f"Certificate {certificate_id} has been revoked")

    return {
        "team_address": team_address,
        "alias": cert.get("alias", ""),
        "did_key": member_did_key,
        "lifetime": cert.get("lifetime", "ephemeral"),
        "certificate_id": certificate_id,
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
        Dict with user_id, team_addresses.

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
    team_addresses = payload.get("team_addresses", [])

    if not user_id:
        raise ValueError("Dashboard token missing user_id")

    if required_team and required_team not in team_addresses:
        raise ValueError(f"User not authorized for team {required_team}")

    return {
        "user_id": user_id,
        "team_addresses": team_addresses,
    }
