"""Pure ID-certificate codecs consume the single frozen root vector file."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from awid.id_certificates import (
    IDCertificateError,
    decode_id_chain_header,
    encode_id_chain_header,
    id_certificate_id,
    id_certificate_signing_bytes,
    strict_did_key,
    verify_ed25519,
    verify_id_certificate,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs" / "vectors" / "id-certificates-v1.json").read_text()
)


@pytest.mark.parametrize("name,case", VECTORS["certificates"].items())
def test_certificate_signing_bytes_and_digest_are_frozen(name, case):
    certificate = case["signed"]["certificate"]
    assert id_certificate_signing_bytes(certificate).hex() == case["signing_bytes_hex"]
    assert id_certificate_id(certificate) == case["certificate_id"]


def test_chain_header_round_trip_is_the_frozen_canonical_header():
    case = VECTORS["presentation"]
    assert encode_id_chain_header(case["bundle"]) == case["header"]
    assert decode_id_chain_header(case["header"]) == case["bundle"]


@pytest.mark.parametrize("case", VECTORS["raw_wire_refusals"], ids=lambda case: case["name"])
def test_raw_header_refusals(case):
    if "header" in case:
        header = case["header"]
    elif "header_repeat" in case:
        repeat = case["header_repeat"]
        header = repeat["character"] * repeat["count"]
    else:
        if "raw_utf8" in case:
            raw = case["raw_utf8"].encode()
        else:
            repeat = case["decoded_repeat"]
            raw = (repeat["character"] * repeat["count"]).encode()
        header = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    with pytest.raises(IDCertificateError) as caught:
        decode_id_chain_header(header)
    assert caught.value.code in case.get("allowed_reasons", [case["expected_reason"]])


def test_human_cannot_be_a_local_did_key_even_with_a_valid_signature():
    signed = VECTORS["certificates"]["did-key-human"]["signed"]
    with pytest.raises(IDCertificateError) as caught:
        verify_id_certificate(signed, issuer_key=signed["certificate"]["issuer_key"])
    assert caught.value.code == "invalid_shape"


def test_certificate_signature_checks_the_independent_issuer_key():
    signed = VECTORS["certificates"]["alice"]["signed"]
    verify_id_certificate(signed, issuer_key=VECTORS["keys"]["root"]["did_key"])
    with pytest.raises(IDCertificateError) as caught:
        verify_id_certificate(signed, issuer_key=VECTORS["keys"]["bob"]["did_key"])
    assert caught.value.code == "invalid_signature"


def test_a_signature_for_one_certificate_does_not_cover_a_changed_parent():
    signed = copy.deepcopy(VECTORS["certificates"]["coordinator"]["signed"])
    signed["certificate"]["parent"]["id"] = VECTORS["keys"]["bob"]["did_aw"]
    with pytest.raises(IDCertificateError) as caught:
        verify_id_certificate(signed, issuer_key=VECTORS["keys"]["alice"]["did_key"])
    assert caught.value.code == "invalid_signature"


def test_canonical_utf8_preserves_literal_escape_text():
    assert id_certificate_signing_bytes({"text": "\u2028", "literal": r"\u2028"}) == (
        b'aweb.id-certificate/1\n{"literal":"\\\\u2028","text":"'
        + "\u2028".encode()
        + b'"}'
    )


@pytest.mark.parametrize("case", VECTORS["ed25519_verification"]["cases"], ids=lambda case: case["name"])
def test_ed25519_profile_probes_through_certificate_verification(case):
    from awid.did import did_from_public_key

    signed = copy.deepcopy(VECTORS["certificates"]["alice"]["signed"])
    assert id_certificate_signing_bytes(signed["certificate"]).hex() == case["message_hex"]
    signed["certificate"]["issuer_key"] = did_from_public_key(bytes.fromhex(case["public_key_hex"]))
    signed["signature"] = base64.urlsafe_b64encode(bytes.fromhex(case["signature_hex"])).rstrip(b"=").decode()
    if case["expected"]["accepted"]:
        verify_id_certificate(signed, issuer_key=signed["certificate"]["issuer_key"])
    else:
        with pytest.raises(IDCertificateError) as caught:
            verify_id_certificate(signed, issuer_key=signed["certificate"]["issuer_key"])
        assert caught.value.code == case["expected"]["reason"]


@pytest.mark.parametrize("case", VECTORS["ed25519_verification"]["cases"], ids=lambda case: case["name"])
def test_public_raw_verifier_uses_the_frozen_strict_profile(case):
    from awid.did import did_from_public_key

    did_key = did_from_public_key(bytes.fromhex(case["public_key_hex"]))
    assert strict_did_key(did_key) is (case["expected"]["reason"] != "invalid_shape")
    message, signature = bytes.fromhex(case["message_hex"]), bytes.fromhex(case["signature_hex"])
    if case["expected"]["accepted"]:
        assert verify_ed25519(did_key, message, signature) is None
    else:
        with pytest.raises(IDCertificateError) as caught:
            verify_ed25519(did_key, message, signature)
        assert caught.value.code == case["expected"]["reason"]


@pytest.mark.parametrize("signature", [b"", b"x" * 63, b"x" * 65, "x" * 64, None])
def test_public_raw_verifier_refuses_non_signature_bytes(signature):
    with pytest.raises(IDCertificateError) as caught:
        verify_ed25519(VECTORS["keys"]["alice"]["did_key"], b"payload", signature)
    assert caught.value.code == "invalid_signature"


@pytest.mark.parametrize("value", [None, "", VECTORS["keys"]["alice"]["did_aw"], "did:key:zbad"])
def test_public_key_predicate_does_not_accept_non_keys(value):
    assert strict_did_key(value) is False


def test_public_raw_verifier_requires_exact_message_bytes():
    with pytest.raises(IDCertificateError) as caught:
        verify_ed25519(VECTORS["keys"]["alice"]["did_key"], "payload", b"x" * 64)
    assert caught.value.code == "invalid_shape"


@pytest.mark.parametrize("name", ["maximum-depth-eight", "depth-nine-refuses"])
def test_codec_depth_limit_on_genuinely_signed_chains(name):
    case = next(case for case in VECTORS["verification_cases"] if case["name"] == name)
    bundle = {"v": 1, "type": "aweb.id-chain", "certificates": [VECTORS["certificates"][n]["signed"] for n in case["chain"]]}
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    assert len(raw) < 6144  # Exercises the depth limit, not the byte limit.
    header = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    if name == "maximum-depth-eight":
        assert decode_id_chain_header(header) == bundle
        assert encode_id_chain_header(bundle) == header
    else:
        for operation in [lambda: decode_id_chain_header(header), lambda: encode_id_chain_header(bundle)]:
            with pytest.raises(IDCertificateError) as caught:
                operation()
            assert caught.value.code == "depth_exceeded"


def test_claimed_issuer_cannot_differ_from_the_independently_selected_signer():
    from nacl.signing import SigningKey

    signed = copy.deepcopy(VECTORS["certificates"]["alice"]["signed"])
    # The signature is valid under the supplied Bob key, but the certificate
    # still selects root. Crypto alone must not silently ignore that selector.
    signer = SigningKey(bytes.fromhex(VECTORS["keys"]["bob"]["seed_hex"]))
    signed["signature"] = base64.urlsafe_b64encode(signer.sign(id_certificate_signing_bytes(signed["certificate"])).signature).rstrip(b"=").decode()
    with pytest.raises(IDCertificateError) as caught:
        verify_id_certificate(signed, issuer_key=VECTORS["keys"]["bob"]["did_key"])
    assert caught.value.code == "invalid_signature"


def test_year_zero_is_not_a_calendar_instant():
    signed = copy.deepcopy(VECTORS["certificates"]["alice"]["signed"])
    signed["certificate"]["issued_at"] = "0000-01-01T00:00:00Z"
    with pytest.raises(IDCertificateError) as caught:
        verify_id_certificate(signed, issuer_key=signed["certificate"]["issuer_key"])
    assert caught.value.code == "invalid_shape"
