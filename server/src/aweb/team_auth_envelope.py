"""Shared team certificate request-envelope verification."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

from fastapi import Request

from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes

TEAM_AUTH_ENVELOPE_V2 = 2


@dataclass(frozen=True)
class TeamAuthEnvelope:
    version: int
    canonical_payload: bytes
    payload: dict[str, Any]


def compact_team_auth_payload(*, team_id: str, timestamp: str, body_sha256: str) -> bytes:
    return canonical_json_bytes(
        {
            "body_sha256": body_sha256,
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )


def decode_signed_payload_header(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError("invalid X-AWEB-Signed-Payload header") from exc


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


def canonical_audiences(values: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        out.add(canonical_server_origin(raw))
    return out


def team_auth_signature_payload(
    request: Request,
    *,
    team_id: str,
    timestamp: str,
    body_sha256: str,
    allowed_audiences: Iterable[str],
) -> TeamAuthEnvelope:
    signed_payload_header = str(request.headers.get("X-AWEB-Signed-Payload") or "").strip()
    if not signed_payload_header:
        canonical = compact_team_auth_payload(
            team_id=team_id,
            timestamp=timestamp,
            body_sha256=body_sha256,
        )
        return TeamAuthEnvelope(version=1, canonical_payload=canonical, payload={})

    canonical = decode_signed_payload_header(signed_payload_header)
    try:
        payload = json.loads(canonical)
    except Exception as exc:
        raise ValueError("invalid X-AWEB-Signed-Payload header") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid X-AWEB-Signed-Payload header")
    if canonical_json_bytes(payload) != canonical:
        raise ValueError("invalid X-AWEB-Signed-Payload header")

    if payload.get("v") != TEAM_AUTH_ENVELOPE_V2:
        raise ValueError("unsupported team-auth envelope version")

    audiences = canonical_audiences(allowed_audiences)
    if not audiences:
        raise ValueError("team-auth public audience is not configured")

    expected = {
        "method": request.method.upper(),
        "path": raw_request_target(request),
        "team_id": team_id,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
    }
    for field, expected_value in expected.items():
        if str(payload.get(field) or "").strip() != expected_value:
            raise ValueError("signed request payload does not match request")

    aud = str(payload.get("aud") or "").strip()
    try:
        canonical_aud = canonical_server_origin(aud)
    except Exception as exc:
        raise ValueError("signed request payload audience is invalid") from exc
    if canonical_aud not in audiences:
        raise ValueError("signed request payload audience is not allowed")

    return TeamAuthEnvelope(version=TEAM_AUTH_ENVELOPE_V2, canonical_payload=canonical, payload=payload)


def body_sha256_for_bytes(body: bytes | None) -> str:
    return hashlib.sha256(body or b"").hexdigest()
