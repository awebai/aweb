"""Canonical JSON payload construction, Ed25519 signing and verification.

Implements message signing per clawdid/sot.md §4.2: lexicographic key sort,
no whitespace, literal UTF-8 (no \\uXXXX escapes), base64 no-padding signatures.
"""

from __future__ import annotations

import base64
import enum
import json

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from aweb.did import public_key_from_did

# The 8 fields included in the signed payload. Transport fields are excluded.
SIGNED_FIELDS = frozenset(
    {"body", "from", "from_did", "subject", "timestamp", "to", "to_did", "type"}
)


class VerifyResult(enum.Enum):
    VERIFIED = "verified"
    VERIFIED_CUSTODIAL = "verified_custodial"
    UNVERIFIED = "unverified"
    FAILED = "failed"


def canonical_payload(fields: dict) -> bytes:
    """Build a canonical JSON payload for signing.

    Filters to SIGNED_FIELDS only, sorts keys lexicographically,
    uses compact separators (no whitespace), and ensures literal UTF-8.
    """
    filtered = {k: v for k, v in fields.items() if k in SIGNED_FIELDS}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sign_message(private_key: bytes, payload: bytes) -> str:
    """Sign a payload with an Ed25519 private key (seed). Returns base64 no-padding signature."""
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(payload)
    # signed.signature is the 64-byte Ed25519 signature
    return base64.urlsafe_b64encode(signed.signature).rstrip(b"=").decode("ascii")


def verify_signature(did: str | None, payload: bytes, signature_b64: str | None) -> VerifyResult:
    """Verify an Ed25519 signature against a did:key.

    Returns UNVERIFIED if DID or signature is missing/invalid format.
    Returns FAILED if the signature doesn't match.
    Returns VERIFIED if the signature is valid.
    """
    if not did or not signature_b64:
        return VerifyResult.UNVERIFIED

    try:
        public_key = public_key_from_did(did)
    except Exception:
        return VerifyResult.UNVERIFIED

    try:
        # Restore base64 padding
        padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        sig_bytes = base64.urlsafe_b64decode(padded)
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
