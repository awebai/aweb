"""The server's status-document verifier against the frozen agent-status-v1 vector."""

from __future__ import annotations

import base64
import copy
from datetime import datetime
import json
from pathlib import Path

import pytest

from awid.signing import VerifyResult, canonical_json_bytes, sign_message, verify_signature
from aweb.agent_status import StatusDocumentError, verify_status_document

VECTOR = json.loads(
    (Path(__file__).parents[2] / "docs" / "vectors" / "agent-status-v1.json").read_text()
)
# stale_seq depends on the stored row; the publish route tests cover it.
DOCUMENT_ONLY_INVALID = [case for case in VECTOR["invalid"] if "stored_seq" not in case]


def _now(case) -> datetime:
    return datetime.fromisoformat(case["now"].replace("Z", "+00:00"))


@pytest.mark.parametrize("case", VECTOR["valid"], ids=lambda case: case["name"])
def test_valid_documents_verify(case):
    document = verify_status_document(
        case["signed_payload"],
        case["signature"],
        signer_did=VECTOR["publisher_did_key"],
        now=_now(case),
    )
    assert document == case["document"]


@pytest.mark.parametrize("case", DOCUMENT_ONLY_INVALID, ids=lambda case: case["name"])
def test_invalid_documents_are_refused_with_their_code(case):
    with pytest.raises(StatusDocumentError) as refused:
        verify_status_document(
            case["signed_payload"],
            case["signature"],
            signer_did=VECTOR["publisher_did_key"],
            now=_now(case),
        )
    assert refused.value.code == case["error"]


def test_every_invalid_document_case_is_exercised():
    assert {case["error"] for case in VECTOR["invalid"]} - {
        case["error"] for case in DOCUMENT_ONLY_INVALID
    } == {"stale_seq"}


def test_status_signature_does_not_verify_as_a_message():
    case = VECTOR["cross_type"]
    result = verify_signature(
        VECTOR["publisher_did_key"],
        case["message_canonical_payload"].encode("utf-8"),
        case["signature"],
    )
    assert result is VerifyResult.FAILED


def _signed_variant(**changes):
    base = copy.deepcopy(VECTOR["valid"][0]["document"])
    base.update(changes)
    canonical = canonical_json_bytes(base)
    return (
        base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
        sign_message(bytes.fromhex(VECTOR["signing_seed_hex"]), canonical),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"reachable": []},
        {"reachable": {}},
        {"reachable": None},
        {"fixing": {"by": []}},
        {"fixing": {"by": {}}},
        {"fixing": {"by": "automatic", "text": None}},
        {"reason": None},
        {"fixing": None},
        {"reason": "oats.grant_expired"},
        {"reason": {"code": None, "text": "x"}},
        {"reason": {"code": "oats.grant_expired", "text": None}},
        {"reachable": "yes", "reason": None},
        {"team_id": None},
        {"observed_at": None},
    ],
    ids=repr,
)
def test_malformed_field_shapes_are_refused_as_invalid_values(changes):
    signed_payload, signature = _signed_variant(**changes)
    with pytest.raises(StatusDocumentError) as refused:
        verify_status_document(
            signed_payload,
            signature,
            signer_did=VECTOR["publisher_did_key"],
            now=_now(VECTOR["valid"][0]),
        )
    assert refused.value.code == "invalid_value"


def test_well_formed_neighbour_of_the_malformed_shapes_verifies():
    signed_payload, signature = _signed_variant(
        reachable="no",
        reason={"code": "oats.grant_expired", "text": "Its connection expired."},
        fixing={"by": "unknown"},
    )
    document = verify_status_document(
        signed_payload,
        signature,
        signer_did=VECTOR["publisher_did_key"],
        now=_now(VECTOR["valid"][0]),
    )
    assert document["fixing"] == {"by": "unknown"}
