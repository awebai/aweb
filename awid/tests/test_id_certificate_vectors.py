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
