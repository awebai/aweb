"""What the console shows an approver, rendered from the frozen request alone (§10.4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aweb_secrets.use_approval import ApprovalUnrenderable, use_approval_view

VECTOR = json.loads((Path(__file__).parents[1] / "vectors" / "use-approval-v1.json").read_text())


def _request(name: str) -> dict:
    return next(c["request"] for c in VECTOR["positive_cases"] if c["name"] == name)


def test_a_named_operation_shows_the_operation_and_its_typed_params():
    view = use_approval_view(_request("broker-operation"))
    assert (view.secret_ref, view.secret_kind, view.secret_version) == (
        "payments-live",
        "bearer",
        4,
    )
    assert view.operation is not None and view.open_request is None and view.job is None
    assert view.operation.operation_id == "refund"
    assert view.operation.params == {
        "amount_minor_units": 1250,
        "charge": "ch_3Pq",
        "currency": "EUR",
    }
    assert view.requester_alias == "alice"
    assert view.requester_did == "did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk"
    assert view.untrusted_reason == "Refund the duplicate charge on order 1042"
    assert (view.issued_at, view.expires_at) == ("2026-10-20T12:00:00Z", "2026-10-20T12:15:00Z")


def test_an_open_request_shows_the_full_url_with_its_host_apart_and_the_whole_body():
    view = use_approval_view(_request("broker-open-request"))
    shown = view.open_request
    assert shown is not None
    assert shown.method == "POST"
    assert (shown.url_before_host, shown.host, shown.url_after_host) == (
        "https://",
        "api.payments.example",
        "/v1/refunds",
    )
    assert shown.url_before_host + shown.host + shown.url_after_host == (
        "https://api.payments.example/v1/refunds"
    )
    assert shown.header_names == ("content-type", "idempotency-key")
    assert shown.body_text == '{"amount_minor_units":1250,"charge":"ch_3Pq"}'


def test_a_job_shows_the_runner_job_and_params():
    view = use_approval_view(_request("run-job-local-identity"))
    assert view.job is not None
    assert (view.job.runner_id, view.job.job_id) == ("rnr_Unqp9DFTnajhUdVDTR1eYQ", "nightly-backup")
    assert view.job.credential_delivery == "short_lived"
    assert view.requester_did.startswith("did:key:")


def test_a_request_of_another_type_is_not_rendered():
    request = {**_request("broker-operation"), "type": "aweb.secrets.change"}
    with pytest.raises(ApprovalUnrenderable):
        use_approval_view(request)
