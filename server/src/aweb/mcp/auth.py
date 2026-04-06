"""MCP authentication middleware.

Resolves the calling agent's identity and makes it available to MCP tool
handlers via a contextvar. Authenticates using team certificates.
"""

from __future__ import annotations

import base64
import contextvars
import json
import logging
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from aweb.routes.dns_auth import parse_didkey_auth
from aweb.awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.team_auth import parse_and_verify_certificate

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """Resolved identity for the current MCP request."""

    team_address: str
    agent_id: str
    alias: str
    did_key: str


_auth_context: contextvars.ContextVar[AuthContext | None] = contextvars.ContextVar(
    "aweb_mcp_auth", default=None
)


def get_auth() -> AuthContext:
    """Return the auth context for the current request.

    Raises RuntimeError if called outside an authenticated request.
    """
    ctx = _auth_context.get()
    if ctx is None:
        raise RuntimeError("No MCP auth context — request was not authenticated")
    return ctx


class MCPAuthMiddleware:
    """ASGI middleware that resolves agent identity for MCP requests.

    Authenticates via team certificate (DIDKey signature + X-AWID-Team-Certificate).
    """

    def __init__(self, app: ASGIApp, db_infra: Any) -> None:
        self.app = app
        self.db_infra = db_infra

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        try:
            ctx = await self._resolve_certificate_auth(request)
        except HTTPException as exc:
            response = JSONResponse(
                {"error": exc.detail},
                status_code=exc.status_code,
                headers=exc.headers,
            )
            await response(scope, receive, send)
            return

        if ctx is None:
            response = JSONResponse(
                {"error": "Authentication required"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        cv_token = _auth_context.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _auth_context.reset(cv_token)

    async def _resolve_certificate_auth(self, request: Request) -> AuthContext | None:
        """Resolve auth from team certificate headers."""
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("DIDKey "):
            return None

        cert_header = request.headers.get("x-awid-team-certificate", "")
        if not cert_header:
            return None

        did_key, signature_b64 = parse_didkey_auth(auth_header)

        # Verify DIDKey signature over {team_address, timestamp}
        timestamp = request.headers.get("x-aweb-timestamp", "")
        if not timestamp:
            raise HTTPException(status_code=401, detail="Missing X-AWEB-Timestamp header")

        try:
            cert_data = json.loads(base64.b64decode(cert_header))
        except Exception:
            raise HTTPException(status_code=401, detail="Malformed certificate")

        cert_team_address = cert_data.get("team", "")

        import hashlib as _hashlib
        body_sha256 = getattr(request.state, "body_sha256", None)
        if body_sha256 is None:
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

        # Resolve team key from awid registry
        registry_client = getattr(request.app.state, "awid_registry_client", None)
        team_did_key = ""
        if registry_client is not None:
            parts = cert_team_address.split("/", 1)
            if len(parts) == 2:
                try:
                    team_did_key = await registry_client.get_team_public_key(parts[0], parts[1]) or ""
                except Exception:
                    raise HTTPException(status_code=503, detail="AWID registry unavailable")

        if not team_did_key:
            raise HTTPException(status_code=401, detail=f"Unknown team: {cert_team_address}")

        # Check revocations
        revoked_certs: set[str] = set()
        if registry_client is not None:
            parts = cert_team_address.split("/", 1)
            if len(parts) == 2:
                try:
                    revoked_certs = await registry_client.get_team_revocations(parts[0], parts[1])
                except Exception:
                    raise HTTPException(status_code=503, detail="AWID registry unavailable")

        try:
            cert_info = parse_and_verify_certificate(
                cert_header,
                request_did_key=did_key,
                team_public_key_resolver=lambda _ta: team_did_key,
                revocation_checker=lambda _ta, cid: cid in revoked_certs,
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

        # Look up agent
        aweb_db = self.db_infra.get_manager("aweb")
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias FROM {{tables.agents}}
            WHERE team_address = $1 AND did_key = $2 AND deleted_at IS NULL
            """,
            cert_info["team_address"],
            cert_info["did_key"],
        )
        if not row:
            raise HTTPException(status_code=403, detail="Agent not connected")

        return AuthContext(
            team_address=cert_info["team_address"],
            agent_id=str(row["agent_id"]),
            alias=row["alias"],
            did_key=cert_info["did_key"],
        )
