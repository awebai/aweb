"""Shared auth and validation helpers for DNS-backed awid routes."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, auto

from fastapi import HTTPException, Request

from awid.did import validate_did
from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.utc_timestamps import parse_zoned_timestamp


class DIDKeyHeaderProfile(Enum):
    SINGLE_SPACE = auto()
    WHITESPACE_SEPARATED = auto()


def parse_didkey_auth(
    authorization: str | None,
    *,
    profile: DIDKeyHeaderProfile = DIDKeyHeaderProfile.SINGLE_SPACE,
) -> tuple[str, str]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = (
        authorization.strip().split()
        if profile is DIDKeyHeaderProfile.WHITESPACE_SEPARATED
        else authorization.split(" ")
    )
    if len(parts) != 3 or parts[0] != "DIDKey":
        raise HTTPException(
            status_code=401,
            detail="Authorization must be: DIDKey <did:key> <signature>",
        )
    return parts[1], parts[2]


def require_timestamp(
    request: Request, *, header_name: str = "X-AWEB-Timestamp"
) -> str:
    value = request.headers.get(header_name)
    if not value:
        raise HTTPException(status_code=401, detail=f"Missing {header_name} header")
    return value


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def enforce_timestamp_skew(ts: str, *, max_delta_seconds: int = 300) -> None:
    try:
        dt = parse_zoned_timestamp(ts)
    except ValueError as exc:
        detail = (
            "Timestamp must include timezone"
            if "timezone" in str(exc)
            else "Malformed timestamp"
        )
        raise HTTPException(status_code=401, detail=detail) from exc
    delta = abs((_utc_now() - dt).total_seconds())
    if delta > max_delta_seconds:
        raise HTTPException(
            status_code=401, detail="Timestamp outside allowed skew window"
        )


def verify_signed_json_request(
    request: Request,
    *,
    payload_dict: dict[str, str],
    authorization_header: str = "Authorization",
    timestamp_header: str = "X-AWEB-Timestamp",
) -> str:
    did_key, sig = parse_didkey_auth(request.headers.get(authorization_header))
    timestamp = require_timestamp(request, header_name=timestamp_header)
    enforce_timestamp_skew(timestamp)

    payload = canonical_json_bytes(payload_dict | {"timestamp": timestamp})
    try:
        verify_did_key_signature(did_key=did_key, payload=payload, signature_b64=sig)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid signature")
    return did_key


def validate_did_key(value: str) -> str:
    normalized = (value or "").strip()
    if not validate_did(normalized):
        raise ValueError("must be a valid did:key Ed25519 identifier")
    return normalized
