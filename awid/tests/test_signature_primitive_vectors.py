"""Public exact-byte signing/verification vectors, including released spellings."""

import json
from pathlib import Path

from awid.signing import canonical_payload, sign_message, verify_signature

VECTORS = Path(__file__).resolve().parents[2] / "docs" / "vectors"


def test_all_public_message_verification_cases():
    vector = json.loads((VECTORS / "signature-primitives-v1.json").read_text())
    for case in vector["cases"]:
        assert (
            verify_signature(
                case["did_key"], case["payload"].encode(), case["signature"]
            ).value
            == case["expected"]["python"]
        ), case["name"]


def test_public_message_signing_bytes_and_signatures():
    for case in json.loads((VECTORS / "message-signing-v1.json").read_text()):
        canonical = canonical_payload(case["message"])
        assert canonical.decode() == case["canonical_payload"]
        assert (
            sign_message(bytes.fromhex(case["signing_seed_hex"]), canonical)
            == case["signature_b64"]
        )


def test_public_url_codec_cases():
    import pytest
    from awid.signature_wire import Base64Profile, decode_base64

    vector = json.loads((VECTORS / "signature-primitives-v1.json").read_text())
    for case in vector["base64url_cases"]:
        if case["hex"] is None:
            with pytest.raises(ValueError):
                decode_base64(case["text"], profile=Base64Profile.CANONICAL_URL)
        else:
            assert (
                decode_base64(case["text"], profile=Base64Profile.CANONICAL_URL).hex()
                == case["hex"]
            ), case["name"]


def test_python_canonical_bytes_obey_public_unicode_vectors():
    from awid.signing import canonical_json_bytes

    vector = json.loads((VECTORS / "canonical-json-v1.json").read_text())
    for case in vector["cases"] + vector["code_point_key_order_cases"]:
        assert canonical_json_bytes(case["value"]).hex() == case["canonical_hex"], case[
            "name"
        ]
