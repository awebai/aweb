"""Wire-shape validation for Ed25519 message signatures."""

from __future__ import annotations

import base64
import binascii


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
