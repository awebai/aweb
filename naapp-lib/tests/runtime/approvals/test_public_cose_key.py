"""One check that a credential's COSE key carries public parameters only: B3's
retained-proof check and the human-role holder binding both use it."""

from __future__ import annotations

import os

import cbor2
import pytest
from aweb_naapp_testing.webauthn import SoftCredential
from cryptography.hazmat.primitives.asymmetric import ec

from aweb_naapp.runtime.passkeys.proof import is_public_cose_key


def public_key() -> dict:
    credential = SoftCredential(
        os.urandom(32), ec.generate_private_key(ec.SECP256R1()), "app.example.com", os.urandom(32)
    )
    return cbor2.loads(credential.cose_public_key())


def test_a_public_ec2_key_is_public() -> None:
    assert is_public_cose_key(cbor2.dumps(public_key()))


def test_an_ec2_key_with_its_private_component_is_refused() -> None:
    key = public_key()
    key[-4] = os.urandom(32)
    assert not is_public_cose_key(cbor2.dumps(key))


@pytest.mark.parametrize("label", [-3, -4, -5, -6, -7, -8, -9])
def test_an_rsa_key_with_any_private_parameter_is_refused(label: int) -> None:
    key = {1: 3, 3: -257, -1: os.urandom(256), -2: b"\x01\x00\x01", label: os.urandom(32)}
    assert not is_public_cose_key(cbor2.dumps(key))


@pytest.mark.parametrize(
    "encoded",
    [cbor2.dumps(public_key()) + b"\x00", b"\xff", cbor2.dumps([1, 2]), cbor2.dumps({3: -7})],
    ids=["trailing-bytes", "not-cbor", "not-a-map", "no-key-type"],
)
def test_anything_but_one_complete_cose_key_is_refused(encoded: bytes) -> None:
    assert not is_public_cose_key(encoded)
