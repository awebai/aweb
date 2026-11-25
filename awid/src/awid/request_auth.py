"""Shared identity and team request-envelope parsing; signature and authority are separate."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Iterable
from urllib.parse import quote

from fastapi import Request

from awid.did import did_key_from_signing_key
from awid.log import canonical_server_origin
from awid.signature_wire import Base64Profile, decode_base64
from awid.signing import canonical_json_bytes, sign_message

TEAM_AUTH_ENVELOPE_V2 = 2


class RequestAuthProfile(Enum):
    SERVER_COMPATIBILITY = auto()
    NAAPP_V2 = auto()


@dataclass(frozen=True)
class TeamAuthEnvelope:
    version: int
    canonical_payload: bytes
    payload: dict[str, Any]


def compact_team_auth_payload(
    *, team_id: str, timestamp: str, body_sha256: str
) -> bytes:
    return canonical_json_bytes(
        {
            "body_sha256": body_sha256,
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )


def decode_signed_payload_header(
    value: str, *, profile: RequestAuthProfile = RequestAuthProfile.SERVER_COMPATIBILITY
) -> bytes:
    """Decode the consumer's released wire profile without inventing a cutoff."""
    encoding = (
        Base64Profile.UNPADDED_URL
        if profile is RequestAuthProfile.NAAPP_V2
        else Base64Profile.LEGACY_PYTHON_SIGNATURE
    )
    try:
        return decode_base64(value, profile=encoding)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid X-AWEB-Signed-Payload header") from exc


def raw_request_target(request: Request) -> str:
    raw_path_value = request.scope.get("raw_path")
    if isinstance(raw_path_value, bytes):
        path = raw_path_value.decode("ascii")
    elif raw_path_value:
        path = str(raw_path_value)
    else:
        path = quote(
            str(request.scope.get("path") or request.url.path or "/"), safe="/%"
        )

    root_path = str(request.scope.get("root_path") or "")
    encoded_root = quote(root_path.rstrip("/"), safe="/%")
    if (
        encoded_root
        and path != encoded_root
        and not path.startswith(encoded_root + "/")
    ):
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
    profile: RequestAuthProfile = RequestAuthProfile.SERVER_COMPATIBILITY,
) -> TeamAuthEnvelope:
    return _request_auth_signature_payload(
        request,
        claims={"team_id": team_id},
        timestamp=timestamp,
        body_sha256=body_sha256,
        allowed_audiences=allowed_audiences,
        profile=profile,
    )


def identity_auth_signature_payload(
    request: Request,
    *,
    did_aw: str,
    timestamp: str,
    body_sha256: str,
    allowed_audiences: Iterable[str],
) -> TeamAuthEnvelope:
    """Identity possession only; this envelope confers no team membership."""
    return _request_auth_signature_payload(
        request,
        claims={"did_aw": did_aw},
        timestamp=timestamp,
        body_sha256=body_sha256,
        allowed_audiences=allowed_audiences,
    )


def _request_auth_signature_payload(
    request: Request,
    *,
    claims: dict[str, str],
    timestamp: str,
    body_sha256: str,
    allowed_audiences: Iterable[str],
    profile: RequestAuthProfile = RequestAuthProfile.SERVER_COMPATIBILITY,
) -> TeamAuthEnvelope:
    signed_payload_header = str(
        request.headers.get("X-AWEB-Signed-Payload") or ""
    ).strip()
    if not signed_payload_header:
        if profile is RequestAuthProfile.NAAPP_V2:
            raise ValueError("missing X-AWEB-Signed-Payload header")
        canonical = canonical_json_bytes(
            {
                **claims,
                "timestamp": timestamp,
                "body_sha256": body_sha256,
            }
        )
        return TeamAuthEnvelope(version=1, canonical_payload=canonical, payload={})

    canonical = decode_signed_payload_header(signed_payload_header, profile=profile)
    # docs/team-auth-envelope-v2.md:47-49 requires decodable canonical JSON.
    # Its re-encoding can refuse Unicode escapes that JSON itself accepts.
    try:
        payload = json.loads(canonical)
        if not isinstance(payload, dict) or canonical_json_bytes(payload) != canonical:
            raise ValueError("invalid X-AWEB-Signed-Payload header")
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("invalid X-AWEB-Signed-Payload header") from exc

    if payload.get("type") == "aweb.awid-controller-request":
        raise ValueError(
            "wrong request envelope type: sign a team-auth v2 request for this service instead of an AWID controller request."
        )

    if payload.get("v") != TEAM_AUTH_ENVELOPE_V2:
        raise ValueError("unsupported team-auth envelope version")

    audiences = canonical_audiences(allowed_audiences)
    if not audiences:
        raise ValueError("team-auth public audience is not configured")

    expected = {
        "method": request.method.upper(),
        "path": raw_request_target(request),
        **claims,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
    }
    for field, expected_value in expected.items():
        if field not in payload or str(payload[field]).strip() != expected_value:
            raise ValueError("signed request payload does not match request")

    aud = str(payload.get("aud") or "").strip()
    try:
        canonical_aud = canonical_server_origin(aud)
    except Exception as exc:
        raise ValueError("signed request payload audience is invalid") from exc
    if canonical_aud not in audiences:
        raise ValueError("signed request payload audience is not allowed")

    return TeamAuthEnvelope(
        version=TEAM_AUTH_ENVELOPE_V2, canonical_payload=canonical, payload=payload
    )


def team_auth_request_headers(
    *,
    signing_key: bytes,
    team_id: str,
    audience: str,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: str,
) -> dict[str, str]:
    """Sign one explicit external request with the relying-party v2 purpose.

    Audience is configured by the caller, never inferred from request headers.
    No legacy retry is performed. Certificate presentation is the caller's job.
    """
    if not path.startswith("/") or "#" in path:
        raise ValueError(
            "Provide the external raw path and query, starting with / and without a fragment."
        )
    payload = canonical_json_bytes(
        {
            "v": TEAM_AUTH_ENVELOPE_V2,
            "aud": canonical_server_origin(audience),
            "method": method.upper(),
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "team_id": team_id,
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"DIDKey {did_key_from_signing_key(signing_key)} {sign_message(signing_key, payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload)
        .rstrip(b"=")
        .decode("ascii"),
    }
