"""Building the frozen aweb.secrets.use-approval/1 request (secrets §10.4).

Each positive vector case is rebuilt from the records and the call it stands
for, and must come out as exactly the vector's frozen request.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aweb_naapp.runtime.team_auth import Principal

from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_approval import (
    MAX_REASON_LENGTH,
    MAX_RENDERED_BODY_BYTES,
    ApprovalUnrenderable,
    BrokerOpen,
    BrokerOperation,
    RunJob,
    UseApprovalRefused,
    use_approval_request,
)

VECTOR = json.loads((Path(__file__).parents[1] / "vectors" / "use-approval-v1.json").read_text())


def _when(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _inputs(case: dict) -> dict:
    """The records and call a positive case was frozen from."""
    request = case["request"]
    requester, secret = request["requester"], request["secret"]
    if request["action"] == "run_job":
        job = request["run_job"]
        action = RunJob(
            runner_id=job["runner_id"],
            job_id=job["job_id"],
            job_digest=job["job_digest"],
            params=job["params"],
            credential_delivery=job["credential_delivery"],
        )
    elif "operation_id" in request["broker"]:
        op = request["broker"]
        action = BrokerOperation(
            operation_id=op["operation_id"],
            operation_digest=op["operation_digest"],
            params=op["params"],
        )
    else:
        open_ = request["broker"]
        action = BrokerOpen(
            method=open_["method"],
            canonical_url=open_["canonical_url"],
            header_names=tuple(reversed([h.upper() for h in open_["header_names"]])),
            body=open_["body_preview"].encode(),
        )
    issued_at = _when(request["issued_at"])
    return dict(
        installation_id=request["installation_id"],
        install_generation=request["install_generation"],
        team_id=request["team_id"],
        requester=Principal(
            team_id=request["team_id"],
            did_key=requester["member_did_key"],
            did_aw=requester.get("did_aw"),
            address=None,
            alias=requester["alias"],
            certificate_id=requester["certificate_id"],
            team_did_key="did:key:z6MkteamKey",
        ),
        secret=SecretRecord(
            secret_id=secret["secret_id"],
            ref=secret["secret_ref"],
            description="",
            kind=secret["kind"],
            kind_params={},
            sensitivity="sensitive",
            approve_only=True,
            backend=secret["backend"],
        ),
        secret_version=secret["version"],
        policy_digest=request["policy_digest"],
        grant_id=request["grant_id"],
        request_id=request["request_id"],
        reason=request["reason"],
        issued_at=issued_at,
        ttl=_when(request["expires_at"]) - issued_at,
        action=action,
    )


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda c: c["name"])
def test_the_frozen_request_is_rebuilt_exactly_from_its_records(case):
    assert use_approval_request(**_inputs(case)) == case["request"]


def _open_case() -> dict:
    return next(c for c in VECTOR["positive_cases"] if c["name"] == "broker-open-request")


def _open_with(body: bytes) -> dict:
    inputs = _inputs(_open_case())
    open_ = inputs["action"]
    inputs["action"] = BrokerOpen(
        method=open_.method,
        canonical_url=open_.canonical_url,
        header_names=open_.header_names,
        body=body,
    )
    return inputs


def test_an_open_request_freezes_its_whole_body_and_its_digest():
    body = b'{"note":"caf\xc3\xa9"}'
    frozen = use_approval_request(**_open_with(body))["broker"]
    assert frozen["body_preview"] == body.decode()
    assert frozen["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_an_open_request_the_console_cannot_show_in_full_is_unrenderable():
    for body in (
        b"\xff\xfe binary",
        b"x" * (MAX_RENDERED_BODY_BYTES + 1),
    ):
        with pytest.raises(ApprovalUnrenderable):
            use_approval_request(**_open_with(body))
    at_limit = b"x" * MAX_RENDERED_BODY_BYTES
    assert use_approval_request(**_open_with(at_limit))["broker"]["body_preview"] == (
        at_limit.decode()
    )


def test_issued_and_expiry_times_are_whole_seconds_in_utc():
    inputs = _inputs(VECTOR["positive_cases"][0])
    inputs["issued_at"] = inputs["issued_at"].replace(microsecond=731000)
    frozen = use_approval_request(**inputs)
    assert frozen["issued_at"] == "2026-10-20T12:00:00Z"
    assert frozen["expires_at"] == "2026-10-20T12:15:00Z"
    inputs["issued_at"] = datetime(2026, 10, 20, 12, 0)
    with pytest.raises(ValueError):
        use_approval_request(**inputs)


def test_a_requester_without_a_did_aw_is_named_by_its_did_key_only():
    case = next(c for c in VECTOR["positive_cases"] if c["name"] == "run-job-local-identity")
    frozen = use_approval_request(**_inputs(case))
    assert "did_aw" not in frozen["requester"]
    assert frozen["requester"]["principal"] == frozen["requester"]["member_did_key"]


def test_the_ttl_must_be_positive():
    inputs = _inputs(VECTOR["positive_cases"][0])
    inputs["ttl"] = timedelta(0)
    with pytest.raises(ValueError):
        use_approval_request(**inputs)


def test_a_reason_is_bounded_and_never_truncated():
    inputs = _inputs(VECTOR["positive_cases"][0])
    inputs["reason"] = "é" * MAX_REASON_LENGTH
    assert use_approval_request(**inputs)["reason"] == "é" * MAX_REASON_LENGTH
    inputs["reason"] = "é" * (MAX_REASON_LENGTH + 1)
    with pytest.raises(UseApprovalRefused) as refused:
        use_approval_request(**inputs)
    assert refused.value.code == "params_invalid"
    assert MAX_REASON_LENGTH == 1024


def test_an_unrenderable_request_is_refused_with_its_code():
    with pytest.raises(UseApprovalRefused) as refused:
        use_approval_request(**_open_with(b"\xff"))
    assert refused.value.code == "approval_unrenderable"
