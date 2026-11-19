"""Standalone runner shares public codec/canonical vectors without awid imports."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aweb_secrets_runner.protocol import canonical, decode64, public_did, public_key

VECTORS = Path(__file__).resolve().parents[4] / "docs" / "vectors"


def test_runner_url_codec_obeys_public_vectors():
    vector = json.loads((VECTORS / "signature-primitives-v1.json").read_text())
    for case in vector["base64url_cases"]:
        if case["hex"] is None:
            with pytest.raises(ValueError):
                decode64(case["text"])
        else:
            assert decode64(case["text"]).hex() == case["hex"], case["name"]


def test_runner_canonical_bytes_obey_public_unicode_vectors():
    vector = json.loads((VECTORS / "canonical-json-v1.json").read_text())
    for case in vector["cases"] + vector["code_point_key_order_cases"]:
        assert canonical(case["value"]).hex() == case["canonical_hex"], case["name"]


def test_runner_did_key_codec_obeys_public_signing_vectors():
    for case in json.loads((VECTORS / "message-signing-v1.json").read_text()):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(case["signing_seed_hex"]))
        encoded = case["signing_did_key"]
        assert public_did(key.public_key()) == encoded, case["name"]
        assert public_key(encoded).public_bytes_raw() == key.public_key().public_bytes_raw()
        for invalid in (encoded + "1", encoded.replace("did:key:z", "did:other:z", 1)):
            with pytest.raises(ValueError):
                public_key(invalid)
