"""Canonical JSON payload construction plus Ed25519 signing and verification."""

from __future__ import annotations

import base64
import enum
import json

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from awid.did import public_key_from_did

SIGNED_FIELDS = frozenset(
    {
        "body",
        "from",
        "from_did",
        "from_stable_id",
        "message_id",
        "subject",
        "timestamp",
        "to",
        "to_did",
        "to_stable_id",
        "type",
    }
)


class VerifyResult(enum.Enum):
    VERIFIED = "verified"
    VERIFIED_CUSTODIAL = "verified_custodial"
    UNVERIFIED = "unverified"
    FAILED = "failed"


def canonical_json_bytes(fields: dict) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def canonical_payload(fields: dict) -> bytes:
    filtered = {k: v for k, v in fields.items() if k in SIGNED_FIELDS}
    return canonical_json_bytes(filtered)


def sign_message(private_key: bytes, payload: bytes) -> str:
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(payload)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


def _decode_signature(signature_b64: str) -> bytes:
    padded = signature_b64 + "=" * (-len(signature_b64) % 4)
    return base64.urlsafe_b64decode(padded)


def verify_signature_with_public_key(
    public_key: bytes, payload: bytes, signature_b64: str | None
) -> VerifyResult:
    if not signature_b64:
        return VerifyResult.UNVERIFIED

    try:
        sig_bytes = _decode_signature(signature_b64)
    except Exception:
        return VerifyResult.FAILED

    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(payload, sig_bytes)
        return VerifyResult.VERIFIED
    except BadSignatureError:
        return VerifyResult.FAILED
    except Exception:
        return VerifyResult.FAILED


def verify_signature(did: str | None, payload: bytes, signature_b64: str | None) -> VerifyResult:
    if not did or not signature_b64:
        return VerifyResult.UNVERIFIED

    if not did.startswith("did:key:z"):
        return VerifyResult.UNVERIFIED

    try:
        public_key = public_key_from_did(did)
    except Exception:
        return VerifyResult.FAILED

    return verify_signature_with_public_key(public_key, payload, signature_b64)


def verify_did_key_signature(*, did_key: str, payload: bytes, signature_b64: str) -> None:
    result = verify_signature(did_key, payload, signature_b64)
    if result != VerifyResult.VERIFIED:
        raise ValueError("invalid signature")


