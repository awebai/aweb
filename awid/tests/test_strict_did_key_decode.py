"""Degenerate Ed25519 keys are refused at the did:key decode and verify chokepoints.

Small-order, non-canonical and mixed-order public keys pass did:key syntax.
PyNaCl refuses a purely small-order key at verification but accepts a
mixed-order one, so every Python path that decodes or verifies through
awid.did and awid.signing refuses them before any signature is checked.
"""

from __future__ import annotations

import base64

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, public_key_from_did, validate_did
from awid.dns_auth import validate_did_key
from awid.signing import (
    VerifyResult,
    canonical_json_bytes,
    verify_did_key_signature,
    verify_signature,
    verify_signature_with_public_key,
)

from id_tree_support import VECTORS, MixedOrderController, ed25519_vector_key

DEGENERATE = [
    case["name"] for case in VECTORS["ed25519_verification"]["cases"]
    if case["name"].startswith(("small-order-A-", "noncanonical-A-", "mixed-order-A-"))
]


def test_the_frozen_degenerate_keys_are_all_here():
    assert len(DEGENERATE) == 12


@pytest.mark.parametrize("name", DEGENERATE)
def test_a_degenerate_key_does_not_decode(name):
    did_key = ed25519_vector_key(name)
    with pytest.raises(ValueError):
        public_key_from_did(did_key)
    assert validate_did(did_key) is False
    with pytest.raises(ValueError):
        validate_did_key(did_key)


def test_a_mixed_order_controller_key_does_not_decode():
    controller = MixedOrderController()
    with pytest.raises(ValueError):
        public_key_from_did(controller.did_key)


@pytest.mark.parametrize("name", DEGENERATE)
def test_a_degenerate_public_key_never_verifies(name):
    [case] = [c for c in VECTORS["ed25519_verification"]["cases"] if c["name"] == name]
    public = bytes.fromhex(case["public_key_hex"])
    message = bytes.fromhex(case["message_hex"])
    signature = bytes.fromhex(case["signature_hex"])
    encoded = base64.b64encode(signature).rstrip(b"=").decode()
    assert verify_signature_with_public_key(public, message, encoded) == VerifyResult.FAILED
    assert verify_signature(did_from_public_key(public), message, encoded) == VerifyResult.FAILED
    with pytest.raises(ValueError):
        verify_did_key_signature(did_key=did_from_public_key(public), payload=message, signature_b64=encoded)


def test_a_mixed_order_signature_that_libsodium_accepts_is_refused():
    """MixedOrderController's signature verifies under plain cofactorless checking."""
    controller = MixedOrderController()
    headers = controller.signed_headers(domain="example.com", operation="register")
    _, did_key, signature = headers["Authorization"].split(" ")
    payload = canonical_json_bytes({
        "domain": "example.com", "operation": "register", "timestamp": headers["X-AWEB-Timestamp"],
    })
    assert verify_signature(did_key, payload, signature) == VerifyResult.FAILED


def test_an_honest_key_still_decodes_and_verifies():
    key = SigningKey.generate()
    did_key = did_from_public_key(bytes(key.verify_key))
    assert public_key_from_did(did_key) == bytes(key.verify_key)
    assert validate_did(did_key) is True
    assert validate_did_key(did_key) == did_key
    signature = base64.b64encode(key.sign(b"payload").signature).rstrip(b"=").decode()
    assert verify_signature(did_key, b"payload", signature) == VerifyResult.VERIFIED
