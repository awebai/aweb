"""The AWID codec reproduces docs/vectors/principal-attestation-v1.json byte for byte."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from awid.attestation_records import (
    RecordError,
    decode_attestation_header,
    encode_attestation_header,
    sign_record,
    signing_bytes,
    verify_record,
)

VECTORS = json.loads(
    (Path(__file__).parents[2] / "docs" / "vectors" / "principal-attestation-v1.json").read_text()
)
TEAM = VECTORS["keys"]["team"]


def _seed(name: str) -> bytes:
    return bytes.fromhex(VECTORS["keys"][name]["seed_hex"])


@pytest.mark.parametrize("case", VECTORS["records"], ids=lambda case: case["name"])
def test_records_have_the_frozen_signed_bytes_and_signature(case):
    record = case["record"]
    assert base64.urlsafe_b64encode(signing_bytes(record)).rstrip(b"=").decode() == case["signing_bytes_b64url"]
    assert sign_record(_seed("team"), record) == case["signature"]
    verify_record(record, case["signature"], team_did_key=TEAM["did_key"])


@pytest.mark.parametrize("case", VECTORS["record_negative_cases"], ids=lambda case: case["name"])
def test_record_refusals(case):
    with pytest.raises(RecordError):
        verify_record(case["record"], case["signature"], team_did_key=case["team_did_key"])


def test_the_attestation_header_is_reproduced_and_parsed():
    attestation = VECTORS["attestation"]
    assert encode_attestation_header(_seed("issuer"), attestation["payload"]) == attestation["header"]
    payload, signature = decode_attestation_header(attestation["header"])
    assert payload == attestation["payload"]
    assert len(signature) == 64
