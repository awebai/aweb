"""Server request fields that carry a did:key decode it with the shared strict decoder.

A small-order, non-canonical or mixed-order key passes a did:key prefix check;
these fields refuse it as awid.dns_auth.validate_did_key does.
"""

from __future__ import annotations

import pytest
from nacl.bindings import crypto_core_ed25519_add, crypto_scalarmult_ed25519_base_noclamp, crypto_core_ed25519_scalar_reduce
from pydantic import ValidationError

from awid.did import did_from_public_key, generate_keypair
from aweb.federation.envelope import verify_federation_envelope
from aweb.routes.identity_grants import GrantMintRequest

from test_federation_envelope import _envelope, _sign

# The identity point (order 1), its non-canonical encoding, and an honest
# point plus the order-2 torsion point: one small-order, one non-canonical and
# one mixed-order key.
_IDENTITY = bytes([1]) + bytes(31)
_IDENTITY_NONCANONICAL = bytes([0xEE]) + bytes([0xFF] * 30) + bytes([0x7F])
_ORDER_TWO = bytes([0xEC]) + bytes([0xFF] * 30) + bytes([0x7F])


def _mixed_order() -> bytes:
    honest = crypto_scalarmult_ed25519_base_noclamp(crypto_core_ed25519_scalar_reduce(bytes(range(64))))
    return crypto_core_ed25519_add(honest, _ORDER_TWO)


DEGENERATE = {
    "small-order": did_from_public_key(_IDENTITY),
    "noncanonical": did_from_public_key(_IDENTITY_NONCANONICAL),
    "mixed-order": did_from_public_key(_mixed_order()),
}


@pytest.mark.parametrize("name", DEGENERATE)
def test_a_grant_cannot_be_minted_for_a_degenerate_key(name):
    with pytest.raises(ValidationError):
        GrantMintRequest(grant_did_key=DEGENERATE[name], scopes=["mail.read"])


def test_a_grant_can_be_minted_for_an_honest_key():
    _, public = generate_keypair()
    did_key = did_from_public_key(public)
    assert GrantMintRequest(grant_did_key=did_key, scopes=["mail.read"]).grant_did_key == did_key


@pytest.mark.parametrize("name", DEGENERATE)
def test_a_federation_envelope_cannot_name_a_degenerate_target_key(name):
    signing_key, public = generate_keypair()
    envelope = _envelope(did_from_public_key(public)) | {"target_current_did_key": DEGENERATE[name]}
    with pytest.raises(ValidationError):
        verify_federation_envelope(envelope, _sign(envelope, signing_key))
