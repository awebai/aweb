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

import cbor2
import pytest

from aweb_naapp.hooks.owner_act import (
    HUMAN_ROLE_ACTS,
    Refused,
    human_credential_sha256,
    owner_act_signing_bytes,
)
from aweb_naapp.hooks.owner_act import _verify_owner_act as verify_owner_act
from tests.hooks.owner_act_delivery_vector import build_vector, render

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = AWEB_ROOT / "docs" / "vectors" / "owner-act-delivery-v1.json"
VECTOR = json.loads(VECTOR_PATH.read_bytes())
SIGNED = [
    c
    for c in VECTOR["delivery_cases"]
    if c["result"]["status"] != 400 and c["verifier"]["registry"] == "available"
]
ACCEPTED = [c for c in VECTOR["delivery_cases"] if c["result"]["status"] == 200]


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


def _credential_sha256(credential: dict[str, str]) -> str:
    text = json.dumps(credential, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(b"aweb.human-credential/1\n" + text.encode("ascii")).hexdigest()


def _unpadded_b64url(text: str) -> bytes:
    assert "=" not in text
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_the_route_vocabulary_is_the_human_role_acts() -> None:
    for case in VECTOR["delivery_cases"]:
        assert case["verifier"]["acts"] == sorted(HUMAN_ROLE_ACTS)


@pytest.mark.parametrize(
    "case",
    [c for c in SIGNED if c["verifier_code"] is None and c["expected_subject"]],
    ids=lambda c: c["name"],
)
def test_an_act_the_verifier_does_not_refuse_verifies_against_the_expected_subject(case) -> None:
    act = _verify(case, case["expected_subject"])
    assert act.subject == case["expected_subject"]


@pytest.mark.parametrize(
    "case", [c for c in SIGNED if c["verifier_code"] is not None], ids=lambda c: c["name"]
)
def test_a_verifier_refusal_behind_owner_required_is_the_one_named(case) -> None:
    assert case["result"] == {"status": 403, "detail": "owner_required", "response": None}
    with pytest.raises(Refused) as refused:
        _verify(case, case["expected_subject"] or {})
    assert refused.value.code == case["verifier_code"]


@pytest.mark.parametrize("registry", ["available", "unavailable"])
def test_a_forged_act_gets_one_answer_whether_or_not_a_holding_exists(registry) -> None:
    pair = [
        c
        for c in VECTOR["delivery_cases"]
        if c["name"].startswith("forged_signature_") and c["verifier"]["registry"] == registry
    ]
    assert sorted(c["state"]["holding"] for c in pair) == [False, True]
    assert pair[0]["result"] == pair[1]["result"]
    assert pair[0]["result"]["status"] != 200


@pytest.mark.parametrize("case", VECTOR["credential_cases"], ids=lambda c: c["name"])
def test_the_credential_hash_and_fingerprint(case) -> None:
    digest = _credential_sha256(case["credential"])
    assert case["credential_sha256"] == digest
    groups = case["fingerprint"].split(" ")
    assert groups == [digest[0:4], digest[4:8], digest[8:12], digest[12:16]]


@pytest.mark.parametrize("case", VECTOR["credential_cases"], ids=lambda c: c["name"])
def test_the_runtime_names_a_credential_by_the_vector_hash(case) -> None:
    assert human_credential_sha256(case["credential"]) == case["credential_sha256"]


@pytest.mark.parametrize("case", ACCEPTED, ids=lambda c: c["name"])
def test_an_accepted_delivery_binds_what_the_body_carries(case) -> None:
    subject = case["act"]["subject"]
    response = case["result"]["response"]
    assert (response["act"], response["role"], response["principal"]) == (
        case["act"]["act"],
        subject["role"],
        subject["principal"],
    )
    assert subject["role"] == case["app"]["role"]["name"]
    assert case["act"]["act"] in case["app"]["role"]["acts"]
    assert case["act"]["aud"] == case["app"]["owner_acts_origin"]
    body = case["body"]
    if case["act"]["act"] == "human-role.revoke":
        assert set(body) == {"signing", "signature"}
        return
    assert case["state"]["principal_status"] == "member_human"
    assert subject["credential_sha256"] == _credential_sha256(body["credential"])
    if case["app"]["role"]["notice_contact"]:
        notice = hashlib.sha256(body["notice_contact"].encode("utf-8")).hexdigest()
        assert subject["notice_contact_sha256"] == notice
    else:
        assert "notice_contact" not in body
        assert "notice_contact_sha256" not in subject
    rp_id = body["credential"]["rp_id"]
    host = case["app"]["owner_acts_origin"].removeprefix("https://")
    assert rp_id == host or (rp_id == "aweb:" and case["app"]["security_key"])
    key = cbor2.loads(_unpadded_b64url(body["credential"]["public_key"]))
    assert -4 not in key


def test_a_revoke_needs_no_principal_status() -> None:
    revokes = {c["state"]["principal_status"] for c in ACCEPTED if "revoke" in c["act"]["act"]}
    assert revokes == {"member_human", "not_member", "unavailable"}


def test_the_refused_credential_carries_a_private_key_parameter() -> None:
    case = next(
        c
        for c in VECTOR["delivery_cases"]
        if c["name"] == "credential_with_a_private_key_parameter"
    )
    key = cbor2.loads(_unpadded_b64url(case["body"]["credential"]["public_key"]))
    assert -4 in key
    assert case["result"]["detail"] == "owner_required"


@pytest.mark.parametrize("case", VECTOR["role_cases"], ids=lambda c: c["name"])
def test_the_role_bound_matches_the_owner_act_signer(case) -> None:
    act = json.loads(
        base64.b64decode(VECTOR["delivery_cases"][0]["body"]["signing"])[
            len(b"aweb.owner-act/1\n") :
        ]
    )
    act["subject"]["role"] = case["role"]
    if case["valid"]:
        owner_act_signing_bytes(act)
    else:
        with pytest.raises(Refused) as refused:
            owner_act_signing_bytes(act)
        assert refused.value.code == "invalid_value"


def test_url_safe_unpadded_signing_is_not_standard_base64() -> None:
    case = next(
        c
        for c in VECTOR["delivery_cases"]
        if c["name"] == "signing_in_url_safe_base64_without_padding"
    )
    with pytest.raises(binascii.Error):
        base64.b64decode(case["body"]["signing"], validate=True)
