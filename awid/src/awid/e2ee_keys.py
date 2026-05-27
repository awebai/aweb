"""Shared E2E encryption-key assertion helpers.

These helpers implement the identity-authorized key assertion shape from
docs/e2e-messaging-contract.md. They intentionally do not perform any
registry or team-controller lookup; callers supply the current identity
did:key and optional did:aw stable id that the assertion must bind to.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.did import public_key_from_did
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature

ENCRYPTION_KEY_ASSERTION_OPERATION = "publish_encryption_key"
ENCRYPTION_KEY_ASSERTION_VERSION = "aweb-e2ee-key-v1"
ENCRYPTION_KEY_ALGORITHM_X25519 = "x25519"
ENCRYPTION_KEY_CUSTODY_SELF = "self"
ENCRYPTION_KEY_CUSTODY_HOSTED = "hosted_custodial"


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


def build_encryption_key_assertion(
    *,
    signing_key: bytes,
    identity_did: str,
    identity_stable_id: str | None,
    encryption_public_key: bytes,
    previous_encryption_key_id: str | None = None,
    custody: str = ENCRYPTION_KEY_CUSTODY_SELF,
    now: datetime | None = None,
) -> dict[str, Any]:
    if len(encryption_public_key) != 32:
        raise ValueError("encryption_public_key must be 32 bytes")
    if not signing_key:
        raise ValueError("signing_key is required")
    verify_key = bytes(SigningKey(signing_key).verify_key)
    if did_from_public_key(verify_key) != identity_did:
        raise ValueError("identity_did does not match signing key")
    custody = (custody or "").strip()
    if custody not in {ENCRYPTION_KEY_CUSTODY_SELF, ENCRYPTION_KEY_CUSTODY_HOSTED}:
        raise ValueError("custody must be one of self, hosted_custodial")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    public_key_b64 = raw_standard_b64(encryption_public_key)
    assertion: dict[str, Any] = {
        "operation": ENCRYPTION_KEY_ASSERTION_OPERATION,
        "version": ENCRYPTION_KEY_ASSERTION_VERSION,
        "identity_did": identity_did,
        "custody": custody,
        "encryption_key_id": encryption_key_id(public_key_b64),
        "encryption_public_key": public_key_b64,
        "algorithm": ENCRYPTION_KEY_ALGORITHM_X25519,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "not_before": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
    }
    stable_id = (identity_stable_id or "").strip()
    if stable_id:
        assertion["identity_stable_id"] = stable_id
    previous = (previous_encryption_key_id or "").strip()
    if previous:
        assertion["previous_encryption_key_id"] = previous
    assertion["signature"] = sign_message(signing_key, canonical_encryption_assertion(assertion))
    return assertion


def validate_encryption_key_assertion(
    assertion: dict[str, Any],
    *,
    current_did_key: str,
    stable_id: str | None,
    now: datetime,
    expected_custody: str | None = None,
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
    custody = str(assertion.get("custody") or "").strip()
    if custody and custody not in {ENCRYPTION_KEY_CUSTODY_SELF, ENCRYPTION_KEY_CUSTODY_HOSTED}:
        raise ValueError("custody must be one of self, hosted_custodial")
    if expected_custody:
        expected_custody = expected_custody.strip()
        if expected_custody == ENCRYPTION_KEY_CUSTODY_HOSTED and custody != expected_custody:
            raise ValueError("hosted custodial encryption key assertions must include custody")
        if custody and custody != expected_custody:
            raise ValueError("custody does not match expected identity custody")

    identity_did = str(assertion.get("identity_did") or "").strip()
    if identity_did != current_did_key:
        raise ValueError("identity_did must match current did:key")
    public_key_from_did(identity_did)

    assertion_stable_id = str(assertion.get("identity_stable_id") or "").strip()
    expected_stable_id = (stable_id or "").strip()
    if expected_stable_id:
        if assertion_stable_id != expected_stable_id:
            raise ValueError("identity_stable_id must match did:aw")
    elif "identity_stable_id" in assertion:
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
