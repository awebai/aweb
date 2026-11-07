"""The owner-act delivery vector against its generator and the Python
owner-act verifier (docs/owner-act-delivery.md)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from aweb_naapp.hooks.owner_act import Refused
from aweb_naapp.hooks.owner_act import _verify_owner_act as verify_owner_act
from tests.hooks.owner_act_delivery_vector import build_vector, render

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = AWEB_ROOT / "docs" / "vectors" / "owner-act-delivery-v1.json"
VECTOR = json.loads(VECTOR_PATH.read_bytes())
SIGNED = [c for c in VECTOR["delivery_cases"] if c["result"]["status"] != 400]


@pytest.mark.skipif(
    os.environ.get("OWNER_ACT_DELIVERY_WRITE_VECTOR") != "1",
    reason="set OWNER_ACT_DELIVERY_WRITE_VECTOR=1",
)
def test_write_vector() -> None:
    VECTOR_PATH.write_bytes(render(build_vector()))


def test_the_vector_regenerates_byte_for_byte() -> None:
    assert VECTOR_PATH.read_bytes() == render(build_vector())


def _verify(case: dict[str, Any], expected_subject: dict[str, Any]):
    options = case["verifier"]
    return verify_owner_act(
        base64.b64decode(case["body"]["signing"], validate=True),
        case["body"]["signature"],
        team_id=options["team_id"],
        current_team_key_did=options["current_team_key_did"],
        audience=options["audience"],
        acts=options["acts"],
        now=datetime.strptime(options["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        expected_subject=expected_subject,
        nonce_used=lambda nonce: options["nonce_used"],
    )


@pytest.mark.parametrize(
    "case", [c for c in SIGNED if c["verifier_code"] is None and c["row"]], ids=lambda c: c["name"]
)
def test_an_act_the_contract_does_not_refuse_verifies_against_its_row(case) -> None:
    act = _verify(case, case["row"])
    assert act.subject == case["row"]


@pytest.mark.parametrize(
    "case", [c for c in SIGNED if c["verifier_code"] is not None], ids=lambda c: c["name"]
)
def test_a_verifier_refusal_behind_owner_required_is_the_one_named(case) -> None:
    assert case["result"] == {"status": 403, "detail": "owner_required", "response": None}
    with pytest.raises(Refused) as refused:
        _verify(case, case["row"])
    assert refused.value.code == case["verifier_code"]


def test_a_contact_that_does_not_match_the_row_is_refused_though_the_act_verifies() -> None:
    case = next(
        c for c in VECTOR["delivery_cases"] if c["name"] == "contact_that_does_not_match_the_row"
    )
    _verify(case, case["row"])
    digest = hashlib.sha256(case["body"]["contact"].encode("utf-8")).hexdigest()
    assert digest != case["row"]["contact_sha256"]


@pytest.mark.parametrize(
    "case",
    [c for c in VECTOR["delivery_cases"] if c["result"]["status"] == 200],
    ids=lambda c: c["name"],
)
def test_an_accepted_delivery_names_the_rows_token_and_contact(case) -> None:
    assert case["result"]["response"]["role"] == case["row"]["role"]
    if "contact_sha256" in case["row"]:
        digest = hashlib.sha256(case["body"]["contact"].encode("utf-8")).hexdigest()
        assert digest == case["row"]["contact_sha256"]
    else:
        assert "contact" not in case["body"]


def test_url_safe_unpadded_signing_is_not_standard_base64() -> None:
    case = next(
        c
        for c in VECTOR["delivery_cases"]
        if c["name"] == "signing_in_url_safe_base64_without_padding"
    )
    with pytest.raises(binascii.Error):
        base64.b64decode(case["body"]["signing"], validate=True)
