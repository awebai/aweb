"""The frozen intent preparation vectors (docs/page-actions.md §3, §3.1)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from aweb_naapp.runtime.task_requests import (
    SIGNER_FIELDS,
    TASK_AUTHORIZATION_BINDINGS,
    TaskRequestRefused,
    check_prepared_intent,
    complete_task_authorization,
    parse_json,
    sign_task_authorization,
    task_body_sha256,
    verify_task_authorization,
)

AWEB_ROOT = Path(__file__).resolve().parents[3]
PREPARE = json.loads((AWEB_ROOT / "docs" / "vectors" / "page-action-prepare-v1.json").read_text())

CALLS = {"prepare", "submit", "deliver", "reconcile"}
OUTCOMES = {
    "prepared",
    "accepted",
    "replayed",
    "preparation_required",
    "preparation_stale",
    "idempotency_conflict",
    "target_mismatch",
    "authorization_expired",
    "revision_conflict",
    "unauthenticated",
    "evidence_limit",
    "delivered",
    "resource_not_found",
}


def at(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def key(name: str) -> SigningKey:
    return SigningKey(bytes.fromhex(PREPARE["keys"][name]["seed_hex"]))


@pytest.mark.parametrize("case", PREPARE["preparations"], ids=lambda case: case["name"])
def test_preparation_digest_and_bindings(case):
    prepared = case["response"]
    assert set(prepared["bindings"]) == TASK_AUTHORIZATION_BINDINGS
    assert task_body_sha256(prepared["task"]) == prepared["task_body_sha256"]
    check_prepared_intent(prepared, expected=case["signer_expects"])


@pytest.mark.parametrize("case", PREPARE["preparations"], ids=lambda case: case["name"])
def test_signer_completion_signs_and_verifies(case):
    signer = case["signer"]
    assert set(signer["fields"]) == SIGNER_FIELDS
    payload = complete_task_authorization(case["response"]["bindings"], **signer["fields"])
    assert payload == signer["payload"]
    signature = sign_task_authorization(payload, key(signer["key"]))
    assert signature == signer["signature"]
    verify_task_authorization(
        payload, signature, expected=case["response"]["bindings"], now=at(PREPARE["now"])
    )


def test_completion_refuses_missing_or_extra_bindings():
    bindings = PREPARE["preparations"][0]["response"]["bindings"]
    fields = PREPARE["preparations"][0]["signer"]["fields"]
    with pytest.raises(ValueError):
        complete_task_authorization({k: v for k, v in bindings.items() if k != "aud"}, **fields)
    with pytest.raises(ValueError):
        complete_task_authorization(
            {**bindings, "actor_did_key": fields["actor_did_key"]}, **fields
        )


@pytest.mark.parametrize("case", PREPARE["check_cases"], ids=lambda case: case["name"])
def test_pre_signing_checks(case):
    def check():
        check_prepared_intent(case["response"], expected=case["signer_expects"])

    if case["expect"] is None:
        check()
        return
    with pytest.raises(TaskRequestRefused) as refused:
        check()
    assert refused.value.code == case["expect"]


@pytest.mark.parametrize("case", PREPARE["raw_cases"], ids=lambda case: case["name"])
def test_raw_pre_signing_checks(case):
    with pytest.raises(TaskRequestRefused) as refused:
        check_prepared_intent(
            parse_json(case["raw"].encode("utf-8")), expected=case["signer_expects"]
        )
    assert refused.value.code == case["expect"]


def test_pre_signing_check_refuses_incomplete_expectations():
    case = PREPARE["preparations"][0]
    expects = dict(case["signer_expects"])
    for field in ("aud", "page_id", "action_id"):
        with pytest.raises(ValueError):
            check_prepared_intent(
                case["response"], expected={k: v for k, v in expects.items() if k != field}
            )


def test_sequence_is_well_formed():
    """Each step names a known call, actor and outcome, and every reference
    points at an earlier step, so a naapp runner can replay it in order."""
    steps = PREPARE["sequence"]["steps"]
    seen: set[str] = set()
    for step in steps:
        assert step["call"] in CALLS, step["name"]
        assert step["actor"] in PREPARE["keys"], step["name"]
        assert step["request"] in PREPARE["sequence"]["requests"], step["name"]
        prepared_by = step.get("authorization", {}).get("prepared_by")
        assert prepared_by is None or prepared_by in seen, (step["name"], "prepared_by")
        assert step["expect"]["outcome"] in OUTCOMES, step["name"]
        for field in (
            "same_as",
            "request_id_of",
            "distinct_from",
            "receipt_same_as",
            "task_same_as",
        ):
            ref = step["expect"].get(field)
            assert ref is None or ref in seen, (step["name"], field)
        seen.add(step["name"])
    outcomes = {step["expect"]["outcome"] for step in steps}
    assert outcomes == OUTCOMES
