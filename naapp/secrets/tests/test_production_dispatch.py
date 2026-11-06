"""Run decisions through the production root's original B2/B3/audit services.

Confirmed configuration is fixture state. These are HTTP/passkey composition
checks; the hosted MCP, external vault and separate-user job remain S19/M9.
"""

import json

from aweb_naapp_testing.owner_acts import AUDIENCE

from tests.test_production_bootstrap import ProductionRequest, approval_request, envelopes
from tests.test_production_bootstrap import root as root


async def member_replay(root, pending):
    _, client, _, member, *_ = root
    return await client.post(
        AUDIENCE + pending.path,
        content=pending.raw,
        headers=member.headers(aud=AUDIENCE, method="POST", path=pending.path, body=pending.raw)
        | {"Content-Type": "application/json"},
    )


async def decide_run(root, *, decision):
    service, client, configured, member, *_ = root
    pending = await approval_request(root, "run")
    human = configured.console_origin
    db = service.runtime.db()
    before = await db.fetch_all("SELECT payload,signature FROM outbox_events ORDER BY position")
    entry = await client.post(human + "/approvals/dispatch", json={"token": pending.token})
    assert entry.status_code == 200 and entry.json() == {"kind": "run", "path": "/run-approvals"}
    hint = await client.post(human + "/run-approvals/sign-in", json={"token": pending.token})
    assert hint.status_code == 200
    scope = hint.json()["scope"]
    login = await client.post(human + "/login/options", json={"scope": scope})
    assert login.status_code == 200
    login_proof = pending.device.get(login.json())
    signed_in = await client.post(human + "/login", json={"scope": scope, "assertion": login_proof})
    assert signed_in.status_code == 200
    csrf = {"X-CSRF-Token": signed_in.json()["csrf_token"]}
    # Neither the delivered locator nor LOGIN can approve or publish a run.
    assert await db.fetch_value("SELECT state FROM approvals") == "pending"
    assert await db.fetch_value("SELECT state FROM dispatches") == "awaiting_approval"
    assert (
        await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL")
        == 0
    )
    assert (
        await db.fetch_all("SELECT payload,signature FROM outbox_events ORDER BY position")
        == before
    )
    refused = await client.post(
        human + "/run-approvals/decide",
        json={"token": pending.token, "decision": decision, "assertion": login_proof},
        headers=csrf,
    )
    assert refused.status_code == 409
    assert await db.fetch_value("SELECT state FROM approvals") == "pending"
    options = await client.post(
        human + "/run-approvals/decision-options",
        json={"token": pending.token, "decision": decision},
        headers=csrf,
    )
    assert options.status_code == 200
    decided = await client.post(
        human + "/run-approvals/decide",
        json={
            "token": pending.token,
            "decision": decision,
            "assertion": pending.device.get(options.json()),
        },
        headers=csrf,
    )
    assert decided.status_code == 200, (decided.status_code, decided.json().get("detail"))
    expected = "approved" if decision == "approve" else "rejected"
    assert decided.json()["state"] == expected
    assert await db.fetch_value("SELECT state FROM approvals") == expected
    assert await db.fetch_value("SELECT consumed_operation_id FROM approvals") is None
    assert await db.fetch_value("SELECT state FROM dispatches") == "awaiting_approval"
    assert (
        await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL")
        == 0
    )
    proof = await db.fetch_one("SELECT purpose,approval_id FROM run_approval_audit_proofs")
    assert proof["purpose"] == decision and proof["approval_id"] == decided.json()["approval_id"]
    events = [e for e in await envelopes(db, member.team_id) if e["hook"] == "post-secret-use-hook"]
    assert [e["payload"]["action"] for e in events] == ["approval_requested", "approval_decided"]
    assert all(e["payload"]["op_kind"] == "run_job" for e in events)
    assert all(e["payload"]["use_ref"] == pending.reply["request_ref"] for e in events)
    assert events[-1]["payload"]["approval_decision"] == (
        "approved" if decision == "approve" else "denied"
    )
    if pending.credential in json.dumps(events) or pending.token in json.dumps(events):
        raise AssertionError("private material reached signed run audit")
    return pending


async def admitted_run(root) -> ProductionRequest:
    pending = await decide_run(root, decision="approve")
    service, *_ = root
    admitted = await member_replay(root, pending)
    assert admitted.status_code == 202 and admitted.json()["state"] == "admitted", (
        admitted.status_code,
        admitted.json().get("code"),
    )
    assert admitted.json()["request_ref"] == pending.reply["request_ref"]
    assert await service.runtime.db().fetch_value("SELECT state FROM dispatches") == "admitted"
    return pending


async def test_production_run_approval_uses_original_audit_and_requires_member_resubmission(root):
    pending = await admitted_run(root)
    service, client, _, member, *_ = root
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM dispatches") == 1
    assert (
        await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL")
        == 0
    )
    status_path = "/v1/status/" + pending.reply["request_ref"]
    status = await client.get(
        AUDIENCE + status_path,
        headers=member.headers(aud=AUDIENCE, method="GET", path=status_path),
    )
    assert status.status_code == 200 and status.json()["state"] == "admitted"
    replay = await member_replay(root, pending)
    assert replay.status_code == 202 and replay.json() == status.json()
    assert await db.fetch_value("SELECT count(*) FROM dispatches") == 1


async def test_production_rejected_run_cannot_be_admitted_or_release_a_credential(root):
    pending = await decide_run(root, decision="reject")
    response = await member_replay(root, pending)
    assert response.json()["state"] == "refused" and response.json()["code"] == "approval_denied"
    db = root[0].runtime.db()
    assert (
        await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL")
        == 0
    )
    assert await db.fetch_value("SELECT count(*) FROM dispatches") == 1
