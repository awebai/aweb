"""Runner containment through the mounted production owner and runner routes."""

import json
from uuid import uuid4

import pytest

from tests.test_production_bootstrap import approval_request, envelopes
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_production_runner_dispatch import runner_headers


async def deregister(root, request, *, request_id=None):
    _, client, configured, member, *_ = root
    path = "/v1/containment"
    raw = json.dumps(
        {
            "request_id": request_id or uuid4().hex,
            "action": "deregister-runner",
            "target": request.runner_id,
        }
    ).encode()
    return await client.post(
        configured.public_origin + path,
        content=raw,
        headers=member.headers(aud=configured.public_origin, method="POST", path=path, body=raw)
        | {"Content-Type": "application/json"},
    )


async def claim(root, request):
    _, client, configured, *_ = root
    path = "/runner/v1/claim"
    return await client.post(
        configured.public_origin + path,
        content=b"{}",
        headers=runner_headers(request, configured.public_origin, path),
    )


@pytest.mark.parametrize("state", ["awaiting_approval", "admitted", "dispatching"])
async def test_deregistration_settles_original_runs_before_returning(root, state):
    service, _, _, member, *_ = root
    request = (
        await approval_request(root, "run")
        if state == "awaiting_approval"
        else await admitted_run(root)
    )
    db = service.runtime.db()
    if state == "dispatching":
        assert (await claim(root, request)).status_code == 200
    assert await db.fetch_value("SELECT state FROM dispatches") == state
    before = await envelopes(db, member.team_id)

    response = await deregister(root, request)
    assert response.status_code == 200
    expected = "outcome_unknown" if state == "dispatching" else "cancelled"
    assert await db.fetch_value("SELECT state FROM dispatches") == expected
    runner = await db.fetch_one(
        "SELECT signing_key,encryption_key,code_hash,deregistered_at FROM runners WHERE runner_id=$1",
        request.runner_id,
    )
    assert runner["deregistered_at"] is not None
    assert all(runner[key] is None for key in ("signing_key", "encryption_key", "code_hash"))
    if state != "dispatching":
        assert await db.fetch_value("SELECT assignment FROM run_deliveries") is None
        assert await db.fetch_value("SELECT state FROM approvals") == "revoked"
    # Even an originally admitted, approved request cannot obtain a sealed
    # assignment after the committed deregistration fence.
    refused = await claim(root, request)
    assert refused.status_code != 200
    assert "credentials" not in refused.json()
    after = await envelopes(db, member.team_id)
    emitted = after[len(before) :]
    governance = [event for event in emitted if event["hook"] == "post-governance-hook"]
    assert len(governance) == 1
    assert governance[0]["payload"]["act"] == "runner.deregistered"
    assert governance[0]["payload"]["resource_ref"] == request.runner_id
    if request.credential in json.dumps(after) or request.token in json.dumps(after):
        raise AssertionError("private material reached containment audit")


@pytest.mark.parametrize("claimed", [False, True])
async def test_local_containment_commit_failure_rolls_back_keys_runs_and_audit(root, claimed):
    import asyncpg

    service, _, _, member, *_ = root
    request = await admitted_run(root)
    db = service.runtime.db()
    if claimed:
        assert (await claim(root, request)).status_code == 200
    runner = await db.fetch_one("SELECT * FROM runners WHERE runner_id=$1", request.runner_id)
    state = await db.fetch_one("SELECT * FROM dispatches")
    approval = await db.fetch_one("SELECT * FROM approvals")
    before = await envelopes(db, member.team_id)
    await db.execute(
        "CREATE FUNCTION reject_deregister_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.action='deregister-runner' THEN RAISE EXCEPTION 'test local commit failure'; "
        "END IF; RETURN NEW; END $$"
    )
    await db.execute(
        "CREATE TRIGGER reject_deregister_receipt BEFORE INSERT ON containment_receipts "
        "FOR EACH ROW EXECUTE FUNCTION reject_deregister_receipt()"
    )
    with pytest.raises(asyncpg.RaiseError):
        await deregister(root, request)
    assert (
        await db.fetch_one("SELECT * FROM runners WHERE runner_id=$1", request.runner_id) == runner
    )
    assert await db.fetch_one("SELECT * FROM dispatches") == state
    assert await db.fetch_one("SELECT * FROM approvals") == approval
    assert await envelopes(db, member.team_id) == before
    assert await db.fetch_value("SELECT count(*) FROM containment_receipts") == 0
