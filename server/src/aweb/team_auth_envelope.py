"""Shared team certificate request-envelope verification."""

from __future__ import annotations

import hashlib
from typing import Iterable

from fastapi import Request
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes
from awid.request_auth import (
    RequestAuthEnvelope as TeamAuthEnvelope,
    decode_signed_payload_header,
    raw_request_target,
    parse_request_auth_v2,
    sign_request_credential,
)

TEAM_AUTH_ENVELOPE_V2 = 2


def compact_team_auth_payload(*, team_id: str, timestamp: str, body_sha256: str) -> bytes:
    return canonical_json_bytes(
        {
            "body_sha256": body_sha256,
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )


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
    return _request_auth_signature_payload(
        request, claims={"team_id": team_id}, timestamp=timestamp,
        body_sha256=body_sha256, allowed_audiences=allowed_audiences,
    )


def identity_auth_signature_payload(
    request: Request, *, did_aw: str, timestamp: str, body_sha256: str,
    allowed_audiences: Iterable[str],
) -> TeamAuthEnvelope:
    """Identity possession only; this envelope confers no team membership."""
    return _request_auth_signature_payload(
        request, claims={"did_aw": did_aw}, timestamp=timestamp,
        body_sha256=body_sha256, allowed_audiences=allowed_audiences,
    )


def _request_auth_signature_payload(
    request: Request, *, claims: dict[str, str], timestamp: str,
    body_sha256: str, allowed_audiences: Iterable[str],
) -> TeamAuthEnvelope:
    if request.headers.get("X-AWEB-Signed-Payload") is None:
        canonical = canonical_json_bytes({
            **claims, "timestamp": timestamp, "body_sha256": body_sha256,
        })
        return TeamAuthEnvelope(version=1, canonical_payload=canonical, payload={})
    return parse_request_auth_v2(
        request, claims=claims, timestamp=timestamp, body_sha256=body_sha256,
        allowed_audiences=allowed_audiences,
    )


def body_sha256_for_bytes(body: bytes | None) -> str:
    return hashlib.sha256(body or b"").hexdigest()
