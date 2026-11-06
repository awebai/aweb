"""MCP clients can distinguish outcomes without inferring them from HTTP status."""

import json

import pytest

from aweb_secrets import tool_results as results

REQUEST_ID = "caller-kept-id"
INTENT = "int_stable-locator"


@pytest.mark.parametrize(
    "envelope",
    [
        results.completed({"status": "ok"}, request_id=REQUEST_ID, request_ref=INTENT),
        results.awaiting_approval(
            request_id=REQUEST_ID, request_ref=INTENT, approval_ref="approval-1"
        ),
        results.refused("grant_revoked", request_id=REQUEST_ID),
        results.outcome_unknown(request_id=REQUEST_ID, request_ref=INTENT),
        results.result_withheld("credential_shaped", request_id=REQUEST_ID, request_ref=INTENT),
    ],
)
def test_mutation_outcomes_keep_the_callers_resubmission_identity(envelope):
    decoded = json.loads(json.dumps(envelope))
    assert decoded["request_id"] == REQUEST_ID
    assert decoded["state"] in {
        "completed",
        "awaiting_approval",
        "refused",
        "outcome_unknown",
        "result_withheld",
    }
    assert not {"retry", "send", "may_send", "dispatch_id", "link_token"} & decoded.keys()
    if decoded["state"] == "awaiting_approval":
        assert decoded["approval_ref"] == "approval-1"
        assert decoded["request_ref"] == INTENT
    if decoded["state"] in {"refused", "result_withheld"}:
        assert decoded["code"]


def test_read_outcomes_keep_explicit_null_without_a_resubmission_id():
    for response in (
        results.completed({"secrets": []}, request_id=None),
        results.refused("secret_not_found", request_id=None),
    ):
        assert "request_id" in response and response["request_id"] is None
        assert "request_ref" not in response


@pytest.mark.parametrize("request_id", ["", 1, False, []])
def test_invalid_request_identity_is_never_replaced_with_a_generated_one(request_id):
    with pytest.raises(ValueError):
        results.completed({}, request_id=request_id)


def test_a_send_related_outcome_cannot_become_a_read_receipt():
    with pytest.raises(ValueError):
        results.outcome_unknown(request_id=None, request_ref=INTENT)
    with pytest.raises(ValueError):
        results.completed({}, request_id=None, request_ref=INTENT)


def test_uncertain_outcome_names_its_original_association_for_reconciliation_reads():
    reply = results.outcome_unknown(request_id=REQUEST_ID, request_ref=INTENT)
    assert reply["reconcile_ref"] == INTENT
    assert not {"next", "send", "may_send", "dispatch_id", "link_token"} & reply.keys()
