from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.team_certificate import (
    TeamCertificateError,
    check_team_certificate,
    decode_team_certificate,
    refusal_answer,
)
from fastapi import HTTPException, Request
from pgdbm import AsyncDatabaseManager

from library.config import Settings

logger = logging.getLogger(__name__)

TEAM_AUTH_ENVELOPE_V2 = 2
_B64URL_NO_PADDING = re.compile(r"^[A-Za-z0-9_-]+$")
_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    team_id: str
    did_key: str
    did_aw: str | None
    address: str | None
    alias: str
    certificate_id: str
    team_did_key: str


def _parse_didkey_auth(header: str) -> tuple[str, str]:
    parts = header.strip().split()
    if len(parts) != 3 or parts[0] != "DIDKey":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    did_key, signature = parts[1].strip(), parts[2].strip()
    if not did_key.startswith("did:key:") or not signature:
        raise HTTPException(status_code=401, detail="Invalid DIDKey Authorization header")
    return did_key, signature


def _parse_rfc3339_utc(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Timestamp") from exc
    if parsed.tzinfo is None:
        raise HTTPException(status_code=401, detail="X-AWEB-Timestamp must include timezone")
    return parsed.astimezone(UTC)


def _certificate_refusal(error: TeamCertificateError) -> HTTPException:
    """The answer for a certificate the shared check refuses (awid's one table)."""
    status_code, detail = refusal_answer(error)
    return HTTPException(status_code=status_code, detail=detail)


def _certificate_locator(header: str) -> tuple[str, str]:
    """The team and certificate ids a certificate names, to read that team's
    facts at the registry before the certificate is checked against them."""
    try:
        certificate = decode_team_certificate(header)
        for name in ("team_id", "certificate_id"):
            value = certificate.get(name)
            if not isinstance(value, str) or not value.strip():
                raise TeamCertificateError("invalid_field", name)
    except TeamCertificateError as exc:
        raise _certificate_refusal(exc) from exc
    return certificate["team_id"], certificate["certificate_id"]


def _decode_signed_payload_header(value: str) -> bytes:
    text = value.strip()
    if not text:
        raise HTTPException(status_code=401, detail="Missing X-AWEB-Signed-Payload")
    if "=" in text or _B64URL_NO_PADDING.fullmatch(text) is None:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload") from exc


def raw_request_target(request: Request) -> str:
    raw_path_value = request.scope.get("raw_path")
    if isinstance(raw_path_value, bytes):
        path = raw_path_value.decode("ascii")
    elif raw_path_value:
        path = str(raw_path_value)
    else:
        path = quote(str(request.scope.get("path") or request.url.path or "/"), safe="/%")

    root_path = str(request.scope.get("root_path") or "")
    if root_path and not path.startswith(root_path):
        encoded_root = quote(root_path.rstrip("/"), safe="/%")
        path = encoded_root + (path if path.startswith("/") else f"/{path}")

    if not path.startswith("/"):
        path = f"/{path}"

    query_string = request.scope.get("query_string") or b""
    if isinstance(query_string, bytes):
        query = query_string.decode("ascii")
    else:
        query = str(query_string)
    if query:
        return f"{path}?{query}"
    return path


def _verified_signed_payload(
    request: Request,
    *,
    settings: Settings,
    did_key: str,
    signature: str,
    header_timestamp: str,
    team_id: str,
    body: bytes,
) -> dict[str, Any]:
    signed_payload_header = request.headers.get("X-AWEB-Signed-Payload") or request.headers.get("x-aweb-signed-payload") or ""
    canonical = _decode_signed_payload_header(signed_payload_header)
    try:
        payload = json.loads(canonical)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != canonical:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload")

    if payload.get("v") != TEAM_AUTH_ENVELOPE_V2:
        raise HTTPException(status_code=401, detail="Unsupported team-auth envelope version")

    expected = {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "method": request.method.upper(),
        "path": raw_request_target(request),
        "team_id": team_id,
        "timestamp": header_timestamp.strip(),
    }
    for field, expected_value in expected.items():
        if str(payload.get(field) or "").strip() != expected_value:
            raise HTTPException(status_code=401, detail="Signed request payload does not match request")

    try:
        configured_audience = canonical_server_origin(settings.public_origin)
        signed_audience = canonical_server_origin(str(payload.get("aud") or "").strip())
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Signed request payload audience is invalid") from exc
    if signed_audience != configured_audience:
        raise HTTPException(status_code=401, detail="Signed request payload audience is not allowed")

    try:
        verify_did_key_signature(did_key=did_key, payload=canonical, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature") from exc

    return payload


async def authenticate_request(
    request: Request,
    *,
    settings: Settings,
    team_cache: AWIDTeamCache,
    db: AsyncDatabaseManager,
) -> Principal:
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization") or ""
    did_key, signature = _parse_didkey_auth(auth_header)

    timestamp = request.headers.get("X-AWEB-Timestamp") or request.headers.get("x-aweb-timestamp") or ""
    if not timestamp:
        raise HTTPException(status_code=401, detail="Missing X-AWEB-Timestamp")
    parsed_timestamp = _parse_rfc3339_utc(timestamp)
    skew = abs((datetime.now(UTC) - parsed_timestamp).total_seconds())
    if skew > settings.timestamp_skew_seconds:
        raise HTTPException(status_code=401, detail="X-AWEB-Timestamp outside allowed clock skew")

    cert_header = request.headers.get("X-AWID-Team-Certificate") or request.headers.get("x-awid-team-certificate") or ""
    if not cert_header:
        raise HTTPException(status_code=401, detail="Missing X-AWID-Team-Certificate")
    team_id, certificate_id = _certificate_locator(cert_header)

    body = await request.body()
    request.state.cached_body = body
    request.state.body_sha256 = hashlib.sha256(body).hexdigest()
    _verified_signed_payload(
        request,
        settings=settings,
        did_key=did_key,
        signature=signature,
        header_timestamp=timestamp,
        team_id=team_id,
        body=body,
    )

    try:
        facts = await team_cache.get(team_id, certificate_id)
    except ValueError as exc:
        raise _certificate_refusal(TeamCertificateError("invalid_field", "team_id")) from exc
    try:
        # The team's key and certificates were read for the certificate's own team_id.
        cert = check_team_certificate(
            cert_header,
            subject_did_key=did_key,
            team_did_key=facts.team_did_key,
            revoked_certificate_ids=facts.revoked_certificate_ids,
            registered_certificate_ids=facts.published_certificate_ids,
        )
    except TeamCertificateError as exc:
        raise _certificate_refusal(exc) from exc
    alias = cert["alias"]

    principal = Principal(
        team_id=team_id,
        did_key=did_key,
        did_aw=(str(cert.get("member_did_aw") or "").strip() or None),
        address=(str(cert.get("member_address") or "").strip() or None),
        alias=alias,
        certificate_id=certificate_id,
        team_did_key=facts.team_did_key,
    )
    await record_observed_principal(db, principal)
    return principal


async def record_observed_principal(db: AsyncDatabaseManager, principal: Principal) -> None:
    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, team_did_key)
        VALUES ($1, $2)
        ON CONFLICT (team_id) DO UPDATE
        SET team_did_key = EXCLUDED.team_did_key,
            last_seen_at = NOW()
        """,
        principal.team_id,
        principal.team_did_key,
    )
    await db.execute(
        """
        INSERT INTO {{tables.agents}}
          (team_id, did_key, did_aw, address, alias, latest_certificate_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (team_id, did_key, alias) DO UPDATE
        SET did_aw = EXCLUDED.did_aw,
            address = EXCLUDED.address,
            latest_certificate_id = EXCLUDED.latest_certificate_id,
            last_seen_at = NOW()
        """,
        principal.team_id,
        principal.did_key,
        principal.did_aw,
        principal.address,
        principal.alias,
        principal.certificate_id,
    )
