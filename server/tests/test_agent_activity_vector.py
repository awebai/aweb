"""The server's activity-event verifier against the frozen agent-activity-v1 vector."""

from __future__ import annotations

import base64
import copy
from datetime import datetime
import json
from pathlib import Path

import pytest

from awid.signing import VerifyResult, canonical_json_bytes, sign_message, verify_signature
from aweb.agent_activity import ActivityEventError, verify_activity_event

VECTOR = json.loads(
    (Path(__file__).parents[2] / "docs" / "vectors" / "agent-activity-v1.json").read_text()
)
SEEDS = {
    VECTOR["agent_did_key"]: VECTOR["agent_seed_hex"],
    VECTOR["other_did_key"]: VECTOR["other_seed_hex"],
    VECTOR["grant_session_did_key"]: VECTOR["grant_session_seed_hex"],
}


def _now(case) -> datetime:
    return datetime.fromisoformat(case["now"].replace("Z", "+00:00"))


def _verify(case, signed_payload=None, signature=None):
    caller = case.get("caller", VECTOR["default_caller"])
    return verify_activity_event(
        case["signed_payload"] if signed_payload is None else signed_payload,
        case["signature"] if signature is None else signature,
        signer_did=caller["signer_did"],
        team_id=caller["team_id"],
        stable_id=caller["stable_id"],
        now=_now(case),
    )


@pytest.mark.parametrize("case", VECTOR["valid"], ids=lambda case: case["name"])
def test_valid_events_verify(case):
    assert _verify(case) == case["document"]


@pytest.mark.parametrize("case", VECTOR["invalid"], ids=lambda case: case["name"])
def test_invalid_events_are_refused_with_their_code(case):
    with pytest.raises(ActivityEventError) as refused:
        _verify(case)
    assert refused.value.code == case["error"]


def test_activity_signature_does_not_verify_over_message_canonical_bytes():
    case = VECTOR["cross_type"]
    result = verify_signature(
        VECTOR["agent_did_key"],
        case["message_canonical_payload"].encode("utf-8"),
        case["signature"],
    )
    assert result is VerifyResult.FAILED


BASE_CASE = VECTOR["valid"][0]


def _signed_raw(raw: bytes, signer_did: str = VECTOR["agent_did_key"]):
    return (
        base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        sign_message(bytes.fromhex(SEEDS[signer_did]), raw),
    )


def _signed_variant(**changes):
    document = copy.deepcopy(BASE_CASE["document"])
    document.update(changes)
    return _signed_raw(canonical_json_bytes(document))


@pytest.mark.parametrize(
    "changes",
    [
        {"v": None},
        {"v": "1"},
        {"v": True},
        {"from_did": None},
        {"from_did": ["did:key:x"]},
        {"from_stable_id": None},
        {"team_id": None},
        {"team_id": {}},
        {"session_id": 7},
        {"session_id": []},
        {"turn_id": None},
        {"turn_id": 12},
        {"seq": None},
        {"seq": "17"},
        {"phase": None},
        {"phase": ["tool"]},
        {"tool": None},
        {"tool": 3},
        {"summary": None},
        {"summary": ["Running pytest"]},
        {"timestamp": None},
        {"expires_at": 1792080000},
    ],
    ids=repr,
)
def test_malformed_field_shapes_are_refused_as_invalid_values(changes):
    signed_payload, signature = _signed_variant(**changes)
    with pytest.raises(ActivityEventError) as refused:
        _verify(BASE_CASE, signed_payload, signature)
    assert refused.value.code == "invalid_value"


FULLWIDTH_DIGITS = str.maketrans("0123456789", "０１２３４５６７８９")


@pytest.mark.parametrize("field", ["timestamp", "expires_at"])
def test_times_with_non_ascii_digits_are_refused_as_invalid_values(field):
    year, rest = BASE_CASE["document"][field].split("-", 1)
    signed_payload, signature = _signed_variant(**{field: year.translate(FULLWIDTH_DIGITS) + "-" + rest})
    with pytest.raises(ActivityEventError) as refused:
        _verify(BASE_CASE, signed_payload, signature)
    assert refused.value.code == "invalid_value"


def test_well_formed_neighbour_of_the_malformed_shapes_verifies():
    signed_payload, signature = _signed_variant(session_id=None, phase="writing", tool="Edit")
    document = _verify(BASE_CASE, signed_payload, signature)
    assert document["session_id"] is None


@pytest.mark.parametrize("text", ["\ud800", "\udfff", "a\udc00b"], ids=repr)
def test_text_without_a_utf8_form_is_refused_as_non_canonical(text):
    document = copy.deepcopy(BASE_CASE["document"])
    document["summary"] = text
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    signed_payload, signature = _signed_raw(raw)
    with pytest.raises(ActivityEventError) as refused:
        _verify(BASE_CASE, signed_payload, signature)
    assert refused.value.code == "non_canonical"


@pytest.mark.parametrize(
    "signed_payload",
    ["not base64url!", "eyJ2Ijox", base64.urlsafe_b64encode(b"[1,2]").rstrip(b"=").decode("ascii")],
    ids=["bad_alphabet", "truncated_json", "json_array"],
)
def test_undecodable_payloads_are_malformed(signed_payload):
    with pytest.raises(ActivityEventError) as refused:
        _verify(BASE_CASE, signed_payload, BASE_CASE["signature"])
    assert refused.value.code == "malformed_payload"


@pytest.mark.parametrize(
    "changes",
    [
        {"turn_id": BASE_CASE["document"]["turn_id"] + "\n"},
        {"tool": "Bash\n"},
        {"session_id": BASE_CASE["document"]["session_id"] + "\n"},
    ],
    ids=["turn_id", "tool", "session_id"],
)
def test_a_trailing_newline_is_not_part_of_an_identifier(changes):
    signed_payload, signature = _signed_variant(**changes)
    with pytest.raises(ActivityEventError) as refused:
        _verify(BASE_CASE, signed_payload, signature)
    assert refused.value.code == "invalid_value"


def test_identifiers_without_the_newline_verify():
    document = BASE_CASE["document"]
    signed_payload, signature = _signed_variant(
        turn_id=document["turn_id"], tool="Bash", session_id=document["session_id"],
    )
    assert _verify(BASE_CASE, signed_payload, signature)["tool"] == "Bash"
