"""The did:key of a held Ed25519 seed, derived in one shared place."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from awid.did import did_from_public_key, did_key_from_signing_key, generate_keypair

_IDENTITY_VECTOR = Path(__file__).resolve().parents[2] / "docs" / "vectors" / "identity-log-v1.json"


def test_a_seeds_did_key_is_its_public_keys_did_key():
    seed, public_key = generate_keypair()
    assert did_key_from_signing_key(seed) == did_from_public_key(public_key)


def test_the_identity_vector_seeds_derive_their_recorded_did_keys():
    vector = json.loads(_IDENTITY_VECTOR.read_text(encoding="utf-8"))
    seeds, mapping = vector["key_seeds"], vector["mapping"]
    for seed, did_key in (
        ("initial_seed_hex", "initial_did_key"),
        ("rotated_seed_hex", "rotated_did_key"),
    ):
        assert did_key_from_signing_key(bytes.fromhex(seeds[seed])) == mapping[did_key]


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_a_seed_that_is_not_32_bytes_is_refused(length):
    with pytest.raises(ValueError):
        did_key_from_signing_key(bytes(length))
