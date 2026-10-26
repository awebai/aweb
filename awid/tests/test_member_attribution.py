"""The public Python reader consumes the reviewed attribution bytes."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from awid.member_attribution import (
    AttributionError,
    attribution_fingerprint,
    decode_attribution_presentation,
    decode_member_attribution,
    encode_attribution_presentation,
    member_attribution_signing_bytes,
    normalize_attribution_email,
    sign_member_attribution,
    verify_member_attribution,
)

VECTORS = json.loads((Path(__file__).parents[2] / "docs/vectors/member-attribution-v1.json").read_text())
CERT = VECTORS["presentation"]["certificate"]


def context(**overrides):
    return dict(
        team_id=CERT["team_id"], team_did_key=CERT["team_did_key"],
        certificate_id=CERT["certificate_id"], member_did_key=CERT["member_did_key"],
        membership_active=True, **overrides,
    )


@pytest.mark.parametrize("case", VECTORS["normalization"])
def test_frozen_normalization_and_scoped_matching(case):
    assert normalize_attribution_email(case["input"]) == case["normalized"]
    assert attribution_fingerprint(case["team_id"], case["input"]) == case["fingerprint"]


@pytest.mark.parametrize("email", VECTORS["normalization_refusals"])
def test_unsupported_email_is_not_rewritten_to_another_human(email):
    with pytest.raises(AttributionError):
        normalize_attribution_email(email)


@pytest.mark.parametrize("case", VECTORS["records"], ids=lambda case: case["name"])
def test_controller_signed_record_matches_frozen_bytes(case):
    record = case["record"]
    assert decode_member_attribution(case["canonical_record_utf8"].encode()) == record
    assert base64.urlsafe_b64encode(member_attribution_signing_bytes(record)).rstrip(b"=").decode() == case["signing_bytes_b64url"]
    assert sign_member_attribution(bytes.fromhex(VECTORS["keys"]["team"]["seed_hex"]), record) == case["signature"]
    verify_member_attribution(record, case["signature"], **context())
    if record["human"]:
        assert set(record["human"]) == {"domain", "fingerprint"}
        verify_member_attribution(record, case["signature"], **context(known_email=" Alice@EXAMPLE.com "))


@pytest.mark.parametrize("case", VECTORS["negative_records"], ids=lambda case: case["name"])
def test_refusals_check_shape_signature_and_independent_binding(case):
    expected = context()
    for name, value in case.get("verified_context_override", {}).items():
        if name == "revoked":
            expected["membership_active"] = not value
        else:
            expected[name] = value
    with pytest.raises(AttributionError) as error:
        verify_member_attribution(case["record"], case["signature"], **expected)
    assert error.value.code == case["expected"]


@pytest.mark.parametrize("case", [case for case in VECTORS["raw_wire_refusals"] if "raw_utf8" in case])
def test_raw_record_requires_canonical_json_without_duplicate_keys(case):
    with pytest.raises(AttributionError):
        decode_member_attribution(case["raw_utf8"].encode())


def test_presentation_is_the_frozen_optional_transport_bundle():
    case = VECTORS["presentation"]
    assert encode_attribution_presentation(case["certificate"], case["bundle"]["attribution"]) == case["header"]
    assert decode_attribution_presentation(case["header"]) == case["bundle"]
    for invalid in (case["header"] + "=", "x" * 16385):
        with pytest.raises(AttributionError):
            decode_attribution_presentation(invalid)


def test_signing_refuses_a_readable_email_and_foreign_controller_key():
    case = next(case for case in VECTORS["negative_records"] if case["name"] == "readable-email-field")
    with pytest.raises(AttributionError):
        sign_member_attribution(bytes.fromhex(VECTORS["keys"]["team"]["seed_hex"]), case["record"])
    case = VECTORS["records"][1]
    with pytest.raises(AttributionError):
        sign_member_attribution(bytes.fromhex(VECTORS["keys"]["other"]["seed_hex"]), case["record"])
