"""Shared E2E encryption-key assertion helpers.

These helpers implement the identity-authorized key assertion shape from
docs/e2e-messaging-contract.md. They intentionally do not perform any
registry or team-controller lookup; callers supply the current identity
did:key and optional did:aw stable id that the assertion must bind to.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any

from awid.did import public_key_from_did
from awid.signing import canonical_json_bytes, verify_did_key_signature

ENCRYPTION_KEY_ASSERTION_OPERATION = "publish_encryption_key"
ENCRYPTION_KEY_ASSERTION_VERSION = "aweb-e2ee-key-v1"
ENCRYPTION_KEY_ALGORITHM_X25519 = "x25519"


def decode_raw_standard_b64(value: str, *, field_name: str) -> bytes:
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be RFC4648 standard base64 without padding") from exc


def raw_standard_b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def encryption_key_id(encryption_public_key_b64: str) -> str:
    raw = decode_raw_standard_b64(
        encryption_public_key_b64,
        field_name="encryption_public_key",
    )
    if len(raw) != 32:
        raise ValueError(f"encryption_public_key must decode to 32 bytes, got {len(raw)}")
    digest = hashlib.sha256(b"aweb-e2ee-v2 encryption-key\n" + raw).digest()
    return "sha256:" + raw_standard_b64(digest)


def parse_contract_time(value: str, *, field_name: str) -> datetime:
    raw = (value or "").strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except Exception as exc:
        raise ValueError(f"{field_name} must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc)


def encryption_assertion_payload(assertion: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in assertion.items():
        if key == "signature" or value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        payload[key] = value
    return payload


def canonical_encryption_assertion(assertion: dict[str, Any]) -> bytes:
    return canonical_json_bytes(encryption_assertion_payload(assertion))


def validate_encryption_key_assertion(
    assertion: dict[str, Any],
    *,
    current_did_key: str,
    stable_id: str | None,
    now: datetime,
) -> tuple[bytes, datetime, datetime, datetime]:
    """Validate an identity-signed encryption-key assertion.

    ``stable_id`` is required for global did:aw identities and should be None
    for local/team identities. Local assertions must omit identity_stable_id
    entirely rather than sending an empty string.
    """
    operation = str(assertion.get("operation") or "").strip()
    if operation != ENCRYPTION_KEY_ASSERTION_OPERATION:
        raise ValueError("operation must be publish_encryption_key")
    version = str(assertion.get("version") or "").strip()
    if version != ENCRYPTION_KEY_ASSERTION_VERSION:
        raise ValueError("version must be aweb-e2ee-key-v1")
    algorithm = str(assertion.get("algorithm") or "").strip()
    if algorithm != ENCRYPTION_KEY_ALGORITHM_X25519:
        raise ValueError("algorithm must be x25519")

    identity_did = str(assertion.get("identity_did") or "").strip()
    if identity_did != current_did_key:
        raise ValueError("identity_did must match current did:key")
    public_key_from_did(identity_did)

    assertion_stable_id = str(assertion.get("identity_stable_id") or "").strip()
    expected_stable_id = (stable_id or "").strip()
    if expected_stable_id:
        if assertion_stable_id != expected_stable_id:
            raise ValueError("identity_stable_id must match did:aw")
    elif "identity_stable_id" in assertion and assertion_stable_id:
        raise ValueError("local encryption key assertions must omit identity_stable_id")

    expected_key_id = encryption_key_id(str(assertion.get("encryption_public_key") or ""))
    if str(assertion.get("encryption_key_id") or "").strip() != expected_key_id:
        raise ValueError("encryption_key_id does not match encryption_public_key")

    not_before = parse_contract_time(str(assertion.get("not_before") or ""), field_name="not_before")
    expires_at = parse_contract_time(str(assertion.get("expires_at") or ""), field_name="expires_at")
    created_at = parse_contract_time(str(assertion.get("created_at") or ""), field_name="created_at")
    now = now.astimezone(timezone.utc)
    if expires_at <= not_before:
        raise ValueError("expires_at must be after not_before")
    if created_at > now:
        raise ValueError("created_at must not be in the future")
    if expires_at <= now:
        raise ValueError("encryption key assertion is expired")
    if not_before > now:
        raise ValueError("encryption key assertion is not active yet")

    payload = canonical_encryption_assertion(assertion)
    verify_did_key_signature(
        did_key=identity_did,
        payload=payload,
        signature_b64=str(assertion.get("signature") or ""),
    )
    return payload, created_at, not_before, expires_at
