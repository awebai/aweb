"""An uncertain real broker effect is settled through the production owner console."""

import asyncio
import json
from uuid import uuid4

import pytest
from aweb_naapp.egress import InternalDestinations
from aweb_naapp_testing.network import TlsServer, local_address, make_certificates

from tests.test_production_bootstrap import enrolled_owner, envelopes
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_production_egress_denials import scoped_request
from tests.test_production_runner_dispatch import runner_headers


@pytest.fixture
async def upstream(tmp_path):
    host = local_address()
    certificates = make_certificates(tmp_path, [], [host])
    state = {"drop": True}

    async def respond(seen):
        if state["drop"]:
            # TlsServer closes the real connection after reading the request.
            raise ConnectionError("the upstream accepted the request but lost its answer")
        return 200, b'{"ok":true}', [("Content-Type", "application/json")]

    server = TlsServer(certificates, host, respond=respond)
    await server.start()
    try:
        yield server, state
    finally:
        await server.close()


@pytest.fixture
def production_settings(upstream):
    server, _ = upstream
    return {
        "internal_destinations": InternalDestinations.ALLOWED,
        "egress_ca_file": server.certificates.ca_file,
        "sweep_interval_seconds": 1,
    }


async def member_request(root, path, body):
    _, client, configured, member, *_ = root
    raw = json.dumps(body).encode()
    return await client.post(
        configured.public_origin + path,
        content=raw,
        headers=member.headers(aud=configured.public_origin, method="POST", path=path, body=raw)
        | {"Content-Type": "application/json"},
    )


async def settle(root, reconcile_ref):
    service, client, configured, *_ = root
    holder = await enrolled_owner(root)
    human = configured.console_origin
    path = "/reconciliations/" + reconcile_ref
    page = await client.get(human + path)
    assert page.status_code == 200, "the production activity settlement link must exist"
    activity = await client.get(human + "/activity")
    assert path in activity.text
    headers = {"X-CSRF-Token": holder.csrf_token}
    minted = await client.post(
        human + path + "/controls", json={"outcome": "unknown-closed"}, headers=headers
    )
    assert minted.status_code == 201, "the owner must be able to request settlement"
    presentation = minted.json()
    token = presentation["personal_token"]
    approval_id = presentation["status"]["control"]["approval_id"]
    control = human + "/reconciliation-controls/" + approval_id
    premature = await client.post(control + "/settle", json={}, headers=headers)
    assert premature.status_code == 409, "LOGIN alone must not authorize settlement"
    for options, finish, decision in (
        ("view-options", "view", None),
        ("decision-options", "decide", "approve"),
    ):
        body = {"token": token}
        if decision is not None:
            body["decision"] = decision
        challenge = await client.post(
            human + "/reconciliation-approvals/" + options, json=body, headers=headers
        )
        assert challenge.status_code == 200
        answer = await client.post(
            human + "/reconciliation-approvals/" + finish,
            json={**body, "assertion": holder.device.get(challenge.json())},
            headers=headers,
        )
        assert answer.status_code == 200
    settled = await client.post(control + "/settle", json={}, headers=headers)
    assert settled.status_code == 200
    assert settled.json()["state"] == "reconciled_unknown"
    assert (
        await service.runtime.db().fetch_value(
            "SELECT state FROM approvals WHERE approval_id=$1", approval_id
        )
        == "consumed"
    )


async def test_owner_can_settle_an_uncertain_production_broker_effect_and_unblock_the_pair(
    root, upstream
):
    service, _, _, member, *_ = root
    server, state = upstream
    first = await scoped_request(
        root, f"https://{server.host}:{server.port}/effect", server.host, server.port
    )
    assert first.status_code == 200 and first.json()["state"] == "outcome_unknown"
    assert first.json()["reconcile_ref"] == first.json()["request_ref"]
    assert len(server.seen) == 1, "the upstream must actually have received the original request"
    path, original = first.request.url.path, json.loads(first.request.content)
    blocked = await member_request(root, path, {**original, "request_id": uuid4().hex})
    assert blocked.status_code == 409 and blocked.json()["code"] == "reconciliation_pending"
    assert len(server.seen) == 1
    await settle(root, first.json()["request_ref"])
    assert blocked.json()["next_step"] == {"action": "owner_reconcile", "path": "/activity"}
    assert len(server.seen) == 1, "settlement must not send the uncertain operation again"
    events = await envelopes(service.runtime.db(), member.team_id)
    assert any(event["payload"].get("action") == "reconciled" for event in events)
    state["drop"] = False
    fresh = await member_request(root, path, {**original, "request_id": uuid4().hex})
    assert fresh.status_code == 200 and fresh.json()["state"] == "completed"
    assert len(server.seen) == 2


async def test_owner_can_settle_a_swept_production_run_and_request_a_fresh_approval(root):
    service, client, configured, *_ = root
    pending = await admitted_run(root)
    claimed = await client.post(
        configured.public_origin + "/runner/v1/claim",
        content=b"{}",
        headers=runner_headers(pending, configured.public_origin, "/runner/v1/claim"),
    )
    assert claimed.status_code == 200, "the production runner must receive a real assignment"
    ref = pending.reply["request_ref"]
    db = service.runtime.db()
    # Advance only the persisted recovery deadline. The production recovery
    # task, not this test, must decide and record the uncertain outcome.
    await db.execute(
        "UPDATE dispatches SET sweep_after=clock_timestamp()-interval '1 second'"
        " WHERE dispatch_id=(SELECT dispatch_id FROM run_contexts WHERE intent_id=$1)",
        ref,
    )
    async with asyncio.timeout(10):
        while (
            await db.fetch_value(
                "SELECT d.state FROM dispatches d JOIN run_contexts c USING(dispatch_id)"
                " WHERE c.intent_id=$1",
                ref,
            )
            != "outcome_unknown"
        ):
            await asyncio.sleep(0.02)
    original = json.loads(pending.raw)
    blocked = await member_request(root, pending.path, {**original, "request_id": uuid4().hex})
    assert blocked.status_code == 409 and blocked.json()["code"] == "reconciliation_pending"
    await settle(root, ref)
    assert blocked.json()["next_step"] == {"action": "owner_reconcile", "path": "/activity"}
    assert await db.fetch_value("SELECT count(*) FROM run_deliveries") == 1
    fresh = await member_request(root, pending.path, {**original, "request_id": uuid4().hex})
    assert fresh.status_code == 202 and fresh.json()["state"] == "awaiting_approval"
    assert fresh.json()["request_ref"] != ref
    assert await db.fetch_value("SELECT count(*) FROM run_deliveries") == 1
