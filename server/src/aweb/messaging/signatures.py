"""Wire-shape validation for Ed25519 message signatures."""

from __future__ import annotations

import base64
import binascii
import logging

from awid.signing import verify_did_key_signature
from fastapi import HTTPException

logger = logging.getLogger(__name__)

INVALID_MESSAGE_SIGNATURE = (
    "The message signature does not verify. "
    "Sign the message again with the authenticated sender's key and resend it."
)


def require_verified_message_signature(*, signed_payload: str, signature: str, did_key: str) -> None:
    """Authenticate the original message bytes under the transport's sender key."""
    try:
        verify_did_key_signature(did_key=did_key, payload=signed_payload.encode("utf-8"), signature_b64=signature)
    except ValueError as exc:
        logger.warning("message_signature_invalid")
        raise HTTPException(status_code=422, detail=INVALID_MESSAGE_SIGNATURE) from exc


ED25519_SIGNATURE_BYTES = 64


class MessageSignatureShapeError(ValueError):
    """Raised when a mail or chat signature cannot be an Ed25519 signature."""


def validate_ed25519_message_signature(signature: str) -> None:
    """Require valid RFC 4648 standard-base64 that decodes to 64 bytes."""
    try:
        decoded = base64.b64decode(
            signature + "=" * (-len(signature) % 4),
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise MessageSignatureShapeError("signature must be valid base64") from exc

    if len(decoded) != ED25519_SIGNATURE_BYTES:
        raise MessageSignatureShapeError(
            f"signature must decode to {ED25519_SIGNATURE_BYTES} bytes"
        )
