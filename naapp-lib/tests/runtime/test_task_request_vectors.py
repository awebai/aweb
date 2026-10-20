"""The frozen app task request vectors: task authorizations, the app-request
credential and task answer digests (docs/app-task-requests.md)."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from aweb_naapp.runtime.task_requests import (
    TaskRequestRefused,
    answer_sha256,
    app_request_credential,
    parse_json,
    sign_stage_receipt,
    sign_task_authorization,
    stage_receipt_signing_bytes,
    task_authorization_signing_bytes,
    task_body_sha256,
    validate_task,
    verify_stage_receipt,
    verify_task_authorization,
)

AWEB_ROOT = Path(__file__).resolve().parents[3]
AUTH = json.loads((AWEB_ROOT / "docs" / "vectors" / "app-task-authorization-v1.json").read_text())
CREDENTIAL = json.loads(
    (AWEB_ROOT / "docs" / "vectors" / "app-request-credential-v1.json").read_text()
)
ANSWERS = json.loads((AWEB_ROOT / "docs" / "vectors" / "task-answer-v1.json").read_text())


def at(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def member_key() -> SigningKey:
    return SigningKey(bytes.fromhex(AUTH["keys"]["member"]["seed_hex"]))


def expected_bindings(payload: dict) -> dict:
    keys = (
        "aud",
        "app_origin",
        "team_id",
        "app_id",
        "installation_id",
        "installation_generation",
        "external_request_id",
        "task_body_sha256",
        "target_dids",
        "action_id",
        "proposal_rev",
        "proposal_sha256",
    )
    return {key: payload[key] for key in keys}


@pytest.mark.parametrize("case", AUTH["valid"], ids=lambda case: case["name"])
def test_task_body_digest(case):
    validate_task(case["task"])
    assert task_body_sha256(case["task"]) == case["task_body_sha256"]


@pytest.mark.parametrize("case", AUTH["valid"], ids=lambda case: case["name"])
def test_signing_bytes_and_signature(case):
    payload = case["payload"]
    assert task_authorization_signing_bytes(payload) == case["signing_bytes"].encode("utf-8")
    assert sign_task_authorization(payload, member_key()) == case["signature"]


@pytest.mark.parametrize("case", AUTH["valid"], ids=lambda case: case["name"])
def test_valid_authorization_verifies(case):
    payload = case["payload"]
    verify_task_authorization(
        payload, case["signature"], expected=expected_bindings(payload), now=at(AUTH["now"])
    )


@pytest.mark.parametrize("case", AUTH["verification_cases"], ids=lambda case: case["name"])
def test_verification_cases(case):
    def verify():
        verify_task_authorization(
            case["payload"], case["signature"], expected=case["expected"], now=at(case["now"])
        )

    if case["expect"] is None:
        verify()
        return
    with pytest.raises(TaskRequestRefused) as refused:
        verify()
    assert refused.value.code == case["expect"]


@pytest.mark.parametrize("case", AUTH["raw_json_cases"], ids=lambda case: case["name"])
def test_strict_json(case):
    with pytest.raises(TaskRequestRefused) as refused:
        parse_json(case["json"].encode("utf-8"))
    assert refused.value.code == case["expect"]


def test_strict_json_accepts_the_valid_bodies():
    for case in AUTH["valid"]:
        raw = json.dumps({"task": case["task"]}, ensure_ascii=False).encode("utf-8")
        assert parse_json(raw) == {"task": case["task"]}


@pytest.mark.parametrize("case", AUTH["task_body_valid"], ids=lambda case: case["name"])
def test_task_body_bounds_accepted(case):
    validate_task(case["task"])
    assert task_body_sha256(case["task"]) == case["task_body_sha256"]


@pytest.mark.parametrize("case", AUTH["task_body_refusals"], ids=lambda case: case["name"])
def test_task_body_refusals(case):
    with pytest.raises(TaskRequestRefused) as refused:
        validate_task(case["task"])
    assert refused.value.code == case["expect"]


def test_app_request_credential():
    request = CREDENTIAL["request"]
    payload = CREDENTIAL["payload"]
    headers = app_request_credential(
        signing_key=SigningKey(bytes.fromhex(CREDENTIAL["keys"]["app"]["seed_hex"])),
        aud=payload["aud"],
        method=request["method"],
        path=request["path"],
        team_id=payload["team_id"],
        app_id=payload["app_id"],
        kid=payload["kid"],
        installation_id=payload["installation_id"],
        installation_generation=payload["installation_generation"],
        body=request["body"].encode("utf-8"),
        timestamp=payload["timestamp"],
    )
    assert headers == CREDENTIAL["headers"]
    signed = base64.urlsafe_b64decode(headers["X-AWEB-Signed-Payload"] + "==")
    assert signed == CREDENTIAL["canonical_payload"].encode("utf-8")


@pytest.mark.parametrize("case", ANSWERS["bodies"], ids=lambda case: case["name"])
def test_answer_digest(case):
    assert answer_sha256(case["body_md"]) == case["answer_sha256"]


STAGE = ANSWERS["stage_receipt"]


def test_stage_receipt_signing_bytes_and_signature():
    valid = STAGE["valid"]
    key = SigningKey(bytes.fromhex(ANSWERS["keys"]["app"]["seed_hex"]))
    assert stage_receipt_signing_bytes(valid["payload"]) == valid["signing_bytes"].encode("utf-8")
    assert sign_stage_receipt(valid["payload"], key) == valid["signature"]


@pytest.mark.parametrize("case", STAGE["verification_cases"], ids=lambda case: case["name"])
def test_stage_receipt_verification_cases(case):
    def verify():
        verify_stage_receipt(
            case["payload"], case["signature"], expected=case["expected"], now=at(case["now"])
        )

    if case["expect"] is None:
        verify()
        return
    with pytest.raises(TaskRequestRefused) as refused:
        verify()
    assert refused.value.code == case["expect"]
