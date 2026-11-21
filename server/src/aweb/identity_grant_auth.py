"""Identity session-grant request auth.

A grant lets a worker holding a fresh session Ed25519 keypair authenticate
and act AS the grant's subject identity for mail/chat, without holding the
subject's root keys. Scope enforcement lives here: a grant can only reach
the messaging surfaces its scopes allow, and can never reach mint/revoke,
session-leases, reservations, federation, workspaces, or admin surfaces.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

from awid.dns_auth import enforce_timestamp_skew, require_timestamp
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature
from fastapi import HTTPException, Request

from aweb.application_state import application_registry_client
from aweb.auth_context import GRANT_SCOPE_ANY, GrantContext, MessagingAuth, TeamIdentity
from aweb.auth_context import GRANT_SCOPES as GRANT_SCOPES
from aweb.certificate_registration import configured_registration_mode
from aweb.config import get_settings
from aweb.grant_expiry import never_expires
from aweb.id_chain_auth import authenticate_id_chain
from aweb.identity_binding import refresh_projection_binding, verify_identity_binding
from aweb.identity_grant_status import GrantValidityState, grant_validity
from aweb.member_team_key import (
    GRANT_ISSUER_RECOVERY_DETAIL,
    member_key_columns_sql,
)
from aweb.request_body import request_body_sha256
from aweb.team_auth_envelope import decode_signed_payload_header, raw_request_target
from aweb.team_registry import native_database_manager

GRANT_AUTH_SCHEME = "AWEB-Grant "
GRANT_AUTH_PREFIX = "AWEB-Grant DIDKey "
GRANT_AUTH_VERSION = 1
GRANT_AUTH_KIND = "identity-grant"

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
        path = path[len(root_path) :] or "/"
    return path


def required_grant_scope(method: str, path: str) -> str | None:
    """Map a request to the scope it needs, or None for any-grant paths.

    Raises HTTPException(403) for every path outside the grant surface.
    """
    method = method.upper()
    if (
        path
        in (
            "/v1/messaging/capabilities",
            "/v1/messaging/resolve",
            "/v1/messaging/prepare",
        )
    ) or (
        method in _READ_METHODS
        and (
            path.startswith("/v1/messaging/participants/")
            or path.startswith("/v1/messaging/ingress-results/")
        )
    ):
        # Discovery has no send effects. Prepare/accept and result recovery
        # enforce the native kind's send scope after decoding the typed DTO.
        return None
    if path == "/v1/agents" and method in _READ_METHODS:
        return None
    if path == "/v1/conversations/unread-counts" and method in _READ_METHODS:
        return "mail.read"
    if path == "/v1/conversations" and method in _READ_METHODS:
        # The conversations index can return mail, chat, or both depending on
        # query parameters. Authenticate the grant here; the route enforces the
        # type-specific read scopes after it validates the requested type.
        return None
    if path == "/v1/messages" or path.startswith("/v1/messages/"):
        return "mail.read" if method in _READ_METHODS else "mail.send"
    if path == "/v1/chat" or path.startswith("/v1/chat/"):
        if method in _READ_METHODS:
            return "chat.read"
        if method == "POST" and path.endswith("/read"):
            return "chat.read"
        return "chat.send"
    if path == "/v1/contacts" or path.startswith("/v1/contacts/"):
        if method in _READ_METHODS:
            return "contacts.read"
        return "contacts.write"
    raise HTTPException(status_code=403, detail=_OUT_OF_SCOPE_DETAIL)


_USE_PATH_SCOPE = object()


async def _verify_identity_grant_row(
    request: Request, db, *, required_scope=_USE_PATH_SCOPE
) -> tuple[dict, GrantContext]:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.startswith(GRANT_AUTH_PREFIX):
        raise HTTPException(status_code=401, detail="Missing identity grant Authorization header")
    rest = auth[len(GRANT_AUTH_PREFIX) :].strip()
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

    body_sha256 = request_body_sha256(request)

    try:
        canonical = decode_signed_payload_header(
            str(request.headers.get("X-AWEB-Signed-Payload") or "").strip()
        )
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

    aweb_db = native_database_manager(db)
    row = await aweb_db.fetch_one(
        """
        SELECT g.team_id, g.grant_did_key, g.scopes, g.issued_at, g.expires_at, g.revoked_at,
               g.issued_by_certificate_id,
               a.did_key AS subject_did_key, a.did_aw, a.address, a.alias,
               a.agent_id, a.identity_scope, a.status AS subject_status, a.deleted_at AS subject_deleted_at,
               a.certificate_id, """
        + member_key_columns_sql("a")
        + """
        FROM {{tables.identity_session_grants}} AS g
        JOIN {{tables.agents}} AS a ON a.agent_id = g.subject_agent_id
        WHERE g.grant_id = $1::UUID
        """,
        grant_id,
    )
    if row is None or row["grant_did_key"] != did_key:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)
    issuing_certificate_id = await _require_request_grant_validity(request, row)

    required = (
        required_grant_scope(request.method, _app_relative_path(request))
        if required_scope is _USE_PATH_SCOPE
        else required_scope
    )
    scopes = tuple(str(scope).strip() for scope in (row["scopes"] or []) if str(scope).strip())
    if required != GRANT_SCOPE_ANY and required is not None and required not in scopes:
        raise HTTPException(status_code=403, detail=_OUT_OF_SCOPE_DETAIL)

    binding = await verify_identity_binding(
        request,
        did_key=row["subject_did_key"],
        did_aw=row.get("did_aw") or "",
        address=row.get("address") or "",
    )
    await authenticate_id_chain(request, binding)
    await refresh_projection_binding(
        aweb_db,
        agent_id=row["agent_id"],
        did_key=row["subject_did_key"],
        binding=binding,
    )
    row = {**dict(row), "did_aw": binding.did_aw, "address": binding.address}
    grant = GrantContext(
        grant_id=grant_id,
        session_did_key=did_key,
        issuing_certificate_id=issuing_certificate_id or None,
        scopes=scopes,
        expires_at=row["expires_at"],
        never_expires=never_expires(row.get("issued_at"), row["expires_at"]),
    )
    return dict(row), grant


async def _require_request_grant_validity(request: Request, row) -> str:
    """Map the common grant observation to the released request refusals."""
    observation = await grant_validity(
        row=row,
        now=datetime.now(UTC),
        registry_client=application_registry_client(request.app.state),
        registration_mode=configured_registration_mode(),
        request=request,
    )
    observation.raise_if_unavailable()
    state = observation.state
    if state is GrantValidityState.REVOKED:
        raise HTTPException(status_code=403, detail="grant revoked")
    if state is GrantValidityState.EXPIRED:
        raise HTTPException(status_code=403, detail="grant expired")
    if state is GrantValidityState.SUBJECT_INACTIVE:
        raise HTTPException(status_code=403, detail=_GENERIC_DETAIL)
    if state in (
        GrantValidityState.ISSUER_SUPERSEDED,
        GrantValidityState.ISSUER_REVOKED,
    ):
        raise HTTPException(
            status_code=403,
            detail="grant issuing certificate revoked. " + GRANT_ISSUER_RECOVERY_DETAIL,
        )
    if state is GrantValidityState.ISSUER_UNREGISTERED:
        raise HTTPException(
            status_code=403,
            detail="grant issuing certificate not registered. " + GRANT_ISSUER_RECOVERY_DETAIL,
        )
    return str(row.get("issued_by_certificate_id") or "").strip()


async def verify_identity_grant_auth(request: Request, db) -> MessagingAuth:
    row, grant = await _verify_identity_grant_row(request, db)
    return MessagingAuth(
        did_key=row["subject_did_key"],
        did_aw=row.get("did_aw") or None,
        address=row.get("address") or None,
        team_id=row["team_id"],
        alias=row["alias"],
        agent_id=str(row["agent_id"]),
        identity_scope=row["identity_scope"],
        certificate_id=None,
        verified_team_id=row["team_id"],
        grant=grant,
        id_chain=getattr(request.state, "id_chain", None),
    )


async def verify_identity_grant_team_identity(
    request: Request, db, *, required_scope: str
) -> TeamIdentity:
    row, grant = await _verify_identity_grant_row(request, db, required_scope=required_scope)
    return TeamIdentity(
        team_id=row["team_id"],
        alias=row["alias"],
        did_key=row["subject_did_key"],
        did_aw=row.get("did_aw") or "",
        address=row.get("address") or "",
        agent_id=str(row["agent_id"]),
        identity_scope=row["identity_scope"],
        certificate_id="",
        grant=grant,
    )
