"""Other payload versions cannot gain fresh run authority (§10.4).

Historical setup changes only the encoder/parser version while the real
composition mints and signs its B2 records. Every endpoint under test runs
after restoring the current version; immutable records are never rewritten.
"""

import json
from enum import IntEnum

import pytest
from aweb_naapp.dispatch import State
from aweb_naapp.runtime.approvals import ApprovalState, Decision
from aweb_naapp_testing.owner_acts import AUDIENCE

from aweb_secrets import use_approval
from aweb_secrets.use_approval import UseApprovalRefusalCode
from tests.test_production_bootstrap import ApprovalAction, ProductionRequest, approval_request
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import member_replay


class PayloadVersion(IntEnum):
    RETAINED_V1 = 1
    CURRENT_V2 = 2


async def _signed_in_run(root, *, version: PayloadVersion, onepassword_values):
    pending = await approval_request(
        root, kind=ApprovalAction.RUN, onepassword_values=onepassword_values
    )
    service, client, configured, *_ = root
    frozen = await service.runtime.db().fetch_value("SELECT request FROM run_slot_approvals")
    assert json.loads(frozen)["v"] == version.value
    human = configured.console_origin
    hint = await client.post(human + "/run-approvals/sign-in", json={"token": pending.token})
    assert hint.status_code == 200
    scope = hint.json()["scope"]
    options = await client.post(human + "/login/options", json={"scope": scope})
    assert options.status_code == 200
    login = await client.post(
        human + "/login",
        json={"scope": scope, "assertion": pending.device.get(options.json())},
    )
    assert login.status_code == 200
    return pending, {"X-CSRF-Token": login.json()["csrf_token"]}


async def _decision_options(root, *, pending: ProductionRequest, csrf: dict[str, str]):
    _, client, configured, *_ = root
    return await client.post(
        configured.console_origin + "/run-approvals/decision-options",
        json={"token": pending.token, "decision": Decision.APPROVE},
        headers=csrf,
    )


async def _decide(root, *, pending: ProductionRequest, csrf: dict[str, str], assertion: dict):
    _, client, configured, *_ = root
    return await client.post(
        configured.console_origin + "/run-approvals/decide",
        json={"token": pending.token, "decision": Decision.APPROVE, "assertion": assertion},
        headers=csrf,
    )


async def _approve_run(root, *, pending: ProductionRequest, csrf: dict[str, str]) -> None:
    options = await _decision_options(root, pending=pending, csrf=csrf)
    assert options.status_code == 200
    response = await _decide(
        root, pending=pending, csrf=csrf, assertion=pending.device.get(options.json())
    )
    assert response.status_code == 200
    assert response.json()["state"] == ApprovalState.APPROVED


async def _authority_snapshot(root):
    db = root[0].runtime.db()
    return (
        await db.fetch_all(
            "SELECT state,consumed_operation_id FROM approvals ORDER BY approval_id"
        ),
        await db.fetch_value("SELECT count(*) FROM passkey_assertions"),
        await db.fetch_value("SELECT count(*) FROM outbox_events"),
        await db.fetch_value("SELECT count(*) FROM run_approval_admissions"),
        await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL"),
    )


@pytest.mark.parametrize("version", list(PayloadVersion))
async def test_only_current_run_payload_can_get_decision_options(
    root, monkeypatch, version, *, onepassword_values
):
    with monkeypatch.context() as historical:
        historical.setattr(use_approval, "REQUEST_VERSION", version.value)
        pending, csrf = await _signed_in_run(
            root, version=version, onepassword_values=onepassword_values
        )
    assert use_approval.REQUEST_VERSION == PayloadVersion.CURRENT_V2.value
    before = await _authority_snapshot(root)
    response = await _decision_options(root, pending=pending, csrf=csrf)
    if version is PayloadVersion.RETAINED_V1:
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "This approval uses an unsupported format. "
            "Ask the requester to submit a new request ID."
        )
    else:
        assert response.status_code == 200
    assert await _authority_snapshot(root) == before


@pytest.mark.parametrize("version", list(PayloadVersion))
async def test_only_current_run_payload_can_be_decided_with_a_bound_proof(
    root, monkeypatch, version, *, onepassword_values
):
    with monkeypatch.context() as historical:
        historical.setattr(use_approval, "REQUEST_VERSION", version.value)
        pending, csrf = await _signed_in_run(
            root, version=version, onepassword_values=onepassword_values
        )
        options = await _decision_options(root, pending=pending, csrf=csrf)
        assert options.status_code == 200
        assertion = pending.device.get(options.json())
    assert use_approval.REQUEST_VERSION == PayloadVersion.CURRENT_V2.value
    before = await _authority_snapshot(root)
    response = await _decide(root, pending=pending, csrf=csrf, assertion=assertion)
    db = root[0].runtime.db()
    if version is PayloadVersion.RETAINED_V1:
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "This approval uses an unsupported format. "
            "Ask the requester to submit a new request ID."
        )
        assert await _authority_snapshot(root) == before
    else:
        assert response.status_code == 200
        assert await db.fetch_value("SELECT state FROM approvals") == ApprovalState.APPROVED
        assert await db.fetch_value("SELECT consumed_operation_id FROM approvals") is None
        assert await db.fetch_value("SELECT count(*) FROM run_approval_admissions") == 0


@pytest.mark.parametrize("version", list(PayloadVersion))
async def test_only_current_approved_run_payload_can_gain_fresh_admission(
    root, monkeypatch, version, *, onepassword_values
):
    with monkeypatch.context() as historical:
        historical.setattr(use_approval, "REQUEST_VERSION", version.value)
        pending, csrf = await _signed_in_run(
            root, version=version, onepassword_values=onepassword_values
        )
        await _approve_run(root, pending=pending, csrf=csrf)
    assert use_approval.REQUEST_VERSION == PayloadVersion.CURRENT_V2.value
    db = root[0].runtime.db()
    response = await member_replay(root, pending)
    if version is PayloadVersion.RETAINED_V1:
        assert response.status_code == 403
        assert response.json()["code"] == UseApprovalRefusalCode.UNRENDERABLE
        assert await db.fetch_value("SELECT consumed_operation_id FROM approvals") is None
        assert await db.fetch_value("SELECT count(*) FROM run_approval_admissions") == 0
        assert await db.fetch_value("SELECT state FROM dispatches") == State.AWAITING_APPROVAL
    else:
        assert response.status_code == 202
        assert response.json()["state"] == State.ADMITTED
        assert await db.fetch_value("SELECT count(*) FROM run_approval_admissions") == 1
        assert await db.fetch_value("SELECT consumed_operation_id FROM approvals") is not None
    assert (
        await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL")
        == 0
    )


@pytest.mark.parametrize("version", list(PayloadVersion))
async def test_an_original_run_admission_remains_readable_without_rearming(
    root, monkeypatch, version, *, onepassword_values
):
    with monkeypatch.context() as historical:
        historical.setattr(use_approval, "REQUEST_VERSION", version.value)
        pending, csrf = await _signed_in_run(
            root, version=version, onepassword_values=onepassword_values
        )
        await _approve_run(root, pending=pending, csrf=csrf)
        admitted = await member_replay(root, pending)
        assert admitted.status_code == 202
        assert admitted.json()["state"] == State.ADMITTED
    assert use_approval.REQUEST_VERSION == PayloadVersion.CURRENT_V2.value
    before = await _authority_snapshot(root)
    _, client, _, member, *_ = root
    path = "/v1/status/" + pending.reply["request_ref"]
    status = await client.get(
        AUDIENCE + path, headers=member.headers(aud=AUDIENCE, method="GET", path=path)
    )
    assert status.status_code == 200
    assert status.json() == admitted.json()
    replay = await member_replay(root, pending)
    assert replay.status_code == 202
    assert replay.json() == admitted.json()
    assert await _authority_snapshot(root) == before
