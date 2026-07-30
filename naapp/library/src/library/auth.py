from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from awid.did import public_key_from_did
from awid.log import canonical_server_origin
from awid.signing import (
    VerifyResult,
    canonical_json_bytes,
    verify_did_key_signature,
    verify_signature_with_public_key,
)
from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request
from pgdbm import AsyncDatabaseManager

from library.config import Settings

TEAM_AUTH_ENVELOPE_V2 = 2
_B64URL_NO_PADDING = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class Principal:
    team_id: str
    did_key: str
    did_aw: str | None
    address: str | None
    alias: str
    certificate_id: str
    team_did_key: str


@dataclass(frozen=True)
class CachedTeamFacts:
    team_did_key: str
    revoked_certificate_ids: frozenset[str]
    expires_at: float


class AWIDTeamCache:
    """Small in-memory cache of public AWID team auth facts."""

    def __init__(self, *, registry_url: str, ttl_seconds: int) -> None:
        self.registry_url = registry_url.rstrip("/")
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, CachedTeamFacts] = {}

    async def get(self, team_id: str) -> CachedTeamFacts:
        now = time.monotonic()
        cached = self._cache.get(team_id)
        if cached and cached.expires_at > now:
            return cached

        domain, team_name = parse_team_id(team_id)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                team_resp = await client.get(f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}")
                if team_resp.status_code == 404:
                    raise HTTPException(status_code=401, detail="Unknown AWID team")
                if team_resp.status_code >= 400:
                    raise HTTPException(status_code=503, detail="AWID registry unavailable")
                team_payload = team_resp.json()

                team_did_key = str(team_payload.get("team_did_key") or "").strip()
                if not team_did_key:
                    raise HTTPException(status_code=503, detail="AWID team response missing team_did_key")

                cert_resp = await client.get(
                    f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}/certificates"
                )
                if cert_resp.status_code >= 400:
                    raise HTTPException(status_code=503, detail="AWID certificate revocation lookup unavailable")
                cert_payload = cert_resp.json()
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc

        revoked: set[str] = set()
        for item in cert_payload.get("certificates", []):
            if item.get("revoked_at") is not None and item.get("certificate_id"):
                revoked.add(str(item["certificate_id"]))

        facts = CachedTeamFacts(
            team_did_key=team_did_key,
            revoked_certificate_ids=frozenset(revoked),
            expires_at=now + self.ttl_seconds,
        )
        self._cache[team_id] = facts
        return facts


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


def _decode_certificate(header: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(header, validate=True)
        cert = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Malformed team certificate") from exc
    if not isinstance(cert, dict):
        raise HTTPException(status_code=401, detail="Malformed team certificate")
    return cert


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


def _verify_certificate_signature(cert: dict[str, Any], team_did_key: str) -> None:
    signature = str(cert.get("signature") or "")
    if not signature:
        raise HTTPException(status_code=401, detail="Team certificate missing signature")
    payload = {k: v for k, v in cert.items() if k != "signature"}
    try:
        public_key = public_key_from_did(team_did_key)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Invalid AWID team public key") from exc
    if verify_signature_with_public_key(public_key, canonical_json_bytes(payload), signature) != VerifyResult.VERIFIED:
        raise HTTPException(status_code=401, detail="Team certificate signature verification failed")


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
    cert = _decode_certificate(cert_header)

    team_id = str(cert.get("team_id") or "").strip()
    certificate_id = str(cert.get("certificate_id") or "").strip()
    member_did_key = str(cert.get("member_did_key") or "").strip()
    alias = str(cert.get("alias") or "").strip()
    if not team_id or not certificate_id or not member_did_key or not alias:
        raise HTTPException(status_code=401, detail="Team certificate missing required fields")
    if member_did_key != did_key:
        raise HTTPException(status_code=401, detail="Team certificate member_did_key mismatch")

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
        facts = await team_cache.get(team_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid AWID team id") from exc
    if certificate_id in facts.revoked_certificate_ids:
        raise HTTPException(status_code=401, detail="Team certificate has been revoked")
    _verify_certificate_signature(cert, facts.team_did_key)

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
