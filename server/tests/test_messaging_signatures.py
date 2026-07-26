from __future__ import annotations

import base64

import pytest

from aweb.messaging.signatures import (
    MessageSignatureShapeError,
    validate_ed25519_message_signature,
)


@pytest.mark.parametrize("padded", [False, True])
def test_ed25519_message_signature_shape_accepts_standard_base64_padding_variants(padded):
    signature = base64.b64encode(bytes(64)).decode("ascii")
    if not padded:
        signature = signature.rstrip("=")

    validate_ed25519_message_signature(signature)


def test_ed25519_message_signature_shape_rejects_non_base64():
    signature = base64.b64encode(bytes(64)).rstrip(b"=").decode("ascii") + "!!!!"

    with pytest.raises(MessageSignatureShapeError, match="signature must be valid base64"):
        validate_ed25519_message_signature(signature)


def test_ed25519_message_signature_shape_rejects_wrong_decoded_length():
    signature = base64.b64encode(bytes(63)).rstrip(b"=").decode("ascii")

    with pytest.raises(MessageSignatureShapeError, match="signature must decode to 64 bytes"):
        validate_ed25519_message_signature(signature)
