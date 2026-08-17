"""Identity session-grant request auth.

A grant lets a worker holding a fresh session Ed25519 keypair authenticate
and act AS the grant's subject identity for mail/chat, without holding the
subject's root keys. Scope enforcement lives here: a grant can only reach
the messaging surfaces its scopes allow, and can never reach mint/revoke,
session-leases, reservations, federation, workspaces, or admin surfaces.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, require_timestamp
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature

from aweb.config import get_settings
from aweb.identity_auth_deps import MessagingAuth
from aweb.team_auth_deps import _aweb_db, _get_revoked_certificates
from aweb.team_auth_envelope import decode_signed_payload_header, raw_request_target

GRANT_AUTH_SCHEME = "AWEB-Grant "
GRANT_AUTH_PREFIX = "AWEB-Grant DIDKey "
GRANT_AUTH_VERSION = 1
GRANT_AUTH_KIND = "identity-grant"

GRANT_SCOPES = ("mail.read", "mail.send", "chat.read", "chat.send")

_GENERIC_DETAIL = "identity grant rejected"
_OUT_OF_SCOPE_DETAIL = "outside grant scope"
_READ_METHODS = {"GET", "HEAD"}


def _grant_allowed_audiences(request: Request) -> set[str]:
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    return {canonical_server_origin(configured or get_settings().public_origin)}


def _app_relative_path(request: Request) -> str:
    path = str(request.scope.get("path") or request.url.path or "/")
    root_path = str(request.scope.get("root_path") or "")
    if root_path and path.startswith(root_path):
        path = path[len(root_path):] or "/"
    return path


def required_grant_scope(method: str, path: str) -> str | None:
    """Map a request to the scope it needs, or None for any-grant paths.

    Raises HTTPException(403) for every path outside the grant surface.
    """
    method = method.upper()
    if path == "/v1/agents" and method in _READ_METHODS:
        return None
    if path == "/v1/messages" or path.startswith("/v1/messages/"):
        return "mail.read" if method in _READ_METHODS else "mail.send"
    if path == "/v1/chat" or path.startswith("/v1/chat/"):
        if method in _READ_METHODS:
            return "chat.read"
        if method == "POST" and path.endswith("/read"):
            return "chat.read"
        return "chat.send"
    raise HTTPException(status_code=403, detail=_OUT_OF_SCOPE_DETAIL)


async def verify_identity_grant_auth(request: Request, db) -> MessagingAuth:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.startswith(GRANT_AUTH_PREFIX):
        raise HTTPException(status_code=401, detail="Missing identity grant Authorization header")
    rest = auth[len(GRANT_AUTH_PREFIX):].strip()
    parts = rest.split()
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Malformed identity grant Authorization header")
    did_key, signature_b64 = parts

    grant_id = (request.headers.get("X-AWEB-Grant-ID") or "").strip()
    try:
        grant_id = str(UUID(grant_id))
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL) from exc

    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is None:
        import hashlib as _hashlib
        body_sha256 = _hashlib.sha256(getattr(request.state, "cached_body", b"") or b"").hexdigest()

    try:
        canonical = decode_signed_payload_header(str(request.headers.get("X-AWEB-Signed-Payload") or "").strip())
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL) from exc
    try:
        payload = json.loads(canonical)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL) from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != canonical:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)

    expected = {
        "v": GRANT_AUTH_VERSION,
        "auth": GRANT_AUTH_KIND,
        "method": request.method.upper(),
        "path": raw_request_target(request),
        "grant_id": grant_id,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)

    aud = str(payload.get("aud") or "").strip()
    try:
        canonical_aud = canonical_server_origin(aud)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL) from exc
    if canonical_aud not in _grant_allowed_audiences(request):
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)

    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=canonical,
            signature_b64=signature_b64,
        )
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL) from exc

    aweb_db = _aweb_db(db)
    row = await aweb_db.fetch_one(
        """
        SELECT g.team_id, g.grant_did_key, g.scopes, g.expires_at, g.revoked_at,
               g.issued_by_certificate_id,
               a.did_key AS subject_did_key, a.did_aw, a.address, a.alias,
               a.agent_id, a.identity_scope, a.status, a.deleted_at
        FROM {{tables.identity_session_grants}} AS g
        JOIN {{tables.agents}} AS a ON a.agent_id = g.subject_agent_id
        WHERE g.grant_id = $1::UUID
        """,
        grant_id,
    )
    if row is None or row["grant_did_key"] != did_key:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)
    if row["revoked_at"] is not None:
        raise HTTPException(status_code=403, detail="grant revoked")
    if row["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="grant expired")
    if row["status"] != "active" or row["deleted_at"] is not None:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)
    # A grant is a delegation from a membership; revoking the issuing
    # certificate must end the delegation with it (aweb-abfn). Grants minted
    # before issued_by_certificate_id was recorded cannot be checked and are
    # bounded by their own expiry. Registry unavailability fails closed with
    # the same 503 the certificate-presenting path raises.
    issuing_certificate_id = (row.get("issued_by_certificate_id") or "").strip()
    if issuing_certificate_id:
        revoked_certs = await _get_revoked_certificates(request, row["team_id"])
        if issuing_certificate_id in revoked_certs:
            raise HTTPException(status_code=403, detail="grant issuing certificate revoked")

    required = required_grant_scope(request.method, _app_relative_path(request))
    if required is not None and required not in list(row["scopes"] or []):
        raise HTTPException(status_code=403, detail=_OUT_OF_SCOPE_DETAIL)

    return MessagingAuth(
        did_key=row["subject_did_key"],
        did_aw=row.get("did_aw") or None,
        address=row.get("address") or None,
        team_id=row["team_id"],
        alias=row["alias"],
        agent_id=str(row["agent_id"]),
        identity_scope=row["identity_scope"],
        certificate_id=f"grant:{grant_id}",
        verified_team_id=row["team_id"],
    )
