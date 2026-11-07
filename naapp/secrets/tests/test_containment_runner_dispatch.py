"""Runner containment through the mounted production owner and runner routes."""

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aweb_naapp.hooks.strictjson import encode_base64url
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import jobs, records, runners
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from tests.test_containment_service import act
from tests.test_containment_service import service as containment_service
from tests.test_jobs import after as job_after
from tests.test_production_bootstrap import approval_request, envelopes
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_production_runner_dispatch import runner_headers
from tests.test_use_approvals import POLICY_BODY, SECRET
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


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


async def independent_run(root, original):
    """Confirmed fixture metadata; a second real member submission needs no approval."""
    service, client, configured, member, installed, *_ = root
    db = service.runtime.db()
    body = job_after()
    body["job_id"] = "other-runner-job"
    body["credentials"][0]["secret_ref"] = SECRET["ref"]
    body["env"] = {"DB_ADMIN": {"$credential": SECRET["ref"], "field": "value"}}
    job = jobs.JobDefinition.from_after(body)
    record = runners.RunnerRecord.from_after(
        {
            "v": 1,
            "runner_id": body["runner_ids"][0],
            "label": "Independent runner",
            "allowed_jobs": [job.job_id],
        }
    )
    signing, encryption = SigningKey.generate(), X25519PrivateKey.generate()
    policy = Policy.from_body({**POLICY_BODY, "approval": "none", "approvers": []})
    async with db.transaction() as tx:
        await jobs.create_job(tx, installed["installation_id"], member.team_id, job)
        await records.create_policy(tx, installed["installation_id"], policy)
        await records.create_grant(
            tx,
            installed["installation_id"],
            member.team_id,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": "grt_other_runner",
                    "secret_id": SECRET["secret_id"],
                    "subject": {"principal": member.did_key},
                    "capability": "run",
                    "operations": [],
                    "open_request": False,
                    "jobs": [{"job_id": job.job_id, "digest": job.digest}],
                    "policy_digest": policy.digest,
                }
            ),
        )
        code = await runners.create_runner(
            tx, installed["installation_id"], member.team_id, record, now=datetime.now(UTC)
        )
        await runners.register_runner(
            tx,
            code=code,
            signing_key=did_from_public_key(bytes(signing.verify_key)),
            encryption_key=encode_base64url(encryption.public_key().public_bytes_raw()),
        )
    path = "/v1/jobs/" + job.job_id + "/runs"
    raw = json.dumps(
        {"request_id": uuid4().hex, "runner": record.runner_id, "params": {"database": "orders"}}
    ).encode()
    response = await client.post(
        configured.public_origin + path,
        content=raw,
        headers=member.headers(aud=configured.public_origin, method="POST", path=path, body=raw)
        | {"Content-Type": "application/json"},
    )
    assert response.status_code == 202 and response.json()["state"] == "admitted"
    return replace(
        original,
        path=path,
        raw=raw,
        reply=response.json(),
        job_id=job.job_id,
        runner_id=record.runner_id,
        runner_signing_key=signing,
        runner_encryption_key=encryption,
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
    original_approval = await db.fetch_one(
        "SELECT state,consumed_operation_id,dispatch_outcome FROM approvals"
    )
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
    if state == "awaiting_approval":
        assert await db.fetch_value("SELECT state FROM approvals") == "revoked"
    else:
        approval = await db.fetch_one(
            "SELECT state,consumed_operation_id,dispatch_outcome FROM approvals"
        )
        assert approval["state"] == original_approval["state"] == "consumed"
        assert approval["consumed_operation_id"] == original_approval["consumed_operation_id"]
        assert approval["dispatch_outcome"] == (
            "outcome_unknown" if state == "dispatching" else original_approval["dispatch_outcome"]
        )
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
    # Owner-confirmed replacement is fixture configuration here. A new valid
    # key must not revive a run approved for the deregistered registration.
    signing, encryption = SigningKey.generate(), X25519PrivateKey.generate()
    record = runners.RunnerRecord.from_after(
        json.loads(
            await db.fetch_value("SELECT record FROM runners WHERE runner_id=$1", request.runner_id)
        )
    )
    async with db.transaction() as tx:
        code = await runners.replace_runner(
            tx,
            root[4]["installation_id"],
            member.team_id,
            record,
            now=datetime.now(UTC),
        )
        await runners.register_runner(
            tx,
            code=code,
            signing_key=did_from_public_key(bytes(signing.verify_key)),
            encryption_key=encode_base64url(encryption.public_key().public_bytes_raw()),
        )
    replacement = replace(request, runner_signing_key=signing, runner_encryption_key=encryption)
    assert (await claim(root, replacement)).status_code == (409 if state == "dispatching" else 204)
    assert await db.fetch_value("SELECT state FROM dispatches") == expected


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


async def test_deregistration_does_not_touch_another_runner_or_its_dispatch(root):
    service, *_ = root
    request = await admitted_run(root)
    other = await independent_run(root, request)
    db = service.runtime.db()
    preserved = await db.fetch_one("SELECT * FROM runners WHERE runner_id=$1", other.runner_id)
    assert (await deregister(root, request)).status_code == 200
    rows = await db.fetch_all(
        "SELECT c.runner_id,d.state FROM run_contexts c JOIN dispatches d USING(dispatch_id)"
    )
    assert {row["runner_id"]: row["state"] for row in rows} == {
        request.runner_id: "cancelled",
        other.runner_id: "admitted",
    }
    assert (
        await db.fetch_one("SELECT * FROM runners WHERE runner_id=$1", other.runner_id) == preserved
    )
    assert (await claim(root, other)).status_code == 200


async def test_no_approval_job_cancels_without_inventing_an_approval_decision(root):
    service, _, _, member, *_ = root
    first = await approval_request(root, "run")
    target = await independent_run(root, first)
    db = service.runtime.db()
    before = await envelopes(db, member.team_id)
    assert (await deregister(root, target)).status_code == 200
    assert (
        await db.fetch_value(
            "SELECT d.state FROM dispatches d JOIN run_contexts c USING(dispatch_id) WHERE c.runner_id=$1",
            target.runner_id,
        )
        == "cancelled"
    )
    emitted = (await envelopes(db, member.team_id))[len(before) :]
    use = [event for event in emitted if event["hook"] == "post-secret-use-hook"]
    assert len(use) == 1
    assert use[0]["payload"]["action"] == "refused"
    assert use[0]["payload"]["dispatch_state"] == "cancelled"
    assert use[0]["payload"]["refusal_code"] == "runner_unavailable"
    assert use[0]["payload"]["use_ref"] == target.reply["request_ref"]
    assert "approval_id" not in use[0]["payload"]
    assert await db.fetch_value("SELECT state FROM approvals") == "pending"


async def wait_for_blocker(db, blocker, task):
    async with asyncio.timeout(5):
        while not await db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() "
            "AND $1=ANY(pg_blocking_pids(pid)))",
            blocker,
        ):
            assert not task.done()
            await asyncio.sleep(0.01)


async def test_complete_approval_union_is_held_before_any_dispatch_row(root):
    service, client, configured, member, *_ = root
    request = await admitted_run(root)
    body = {**json.loads(request.raw), "request_id": uuid4().hex}
    raw = json.dumps(body).encode()
    second = await client.post(
        configured.public_origin + request.path,
        content=raw,
        headers=member.headers(
            aud=configured.public_origin, method="POST", path=request.path, body=raw
        )
        | {"Content-Type": "application/json"},
    )
    assert second.status_code == 202 and second.json()["state"] == "awaiting_approval"
    db = service.runtime.db()
    ordered = await db.fetch_all(
        "SELECT c.dispatch_id,a.approval_id FROM run_contexts c "
        "JOIN run_approval_audits a USING(dispatch_id) ORDER BY c.dispatch_id"
    )
    assert len(ordered) == 2
    pending = None
    try:
        async with db.transaction() as barrier:
            await barrier.fetch_one(
                "SELECT approval_id FROM approvals WHERE approval_id=$1 FOR UPDATE",
                ordered[1]["approval_id"],
            )
            blocker = await barrier.fetch_value("SELECT pg_backend_pid()")
            pending = asyncio.create_task(deregister(root, request))
            await wait_for_blocker(db, blocker, pending)
            # This is a different actual PG connection. A per-run B2/S3 loop
            # would already hold the first S3 row while waiting on the second B2.
            async with db.transaction() as probe:
                assert await probe.fetch_value("SELECT pg_backend_pid()") != blocker
                assert (
                    await probe.fetch_value(
                        "SELECT dispatch_id FROM dispatches WHERE dispatch_id=$1 FOR UPDATE NOWAIT",
                        ordered[0]["dispatch_id"],
                    )
                    == ordered[0]["dispatch_id"]
                )
        assert (await asyncio.wait_for(pending, 5)).status_code == 200
        assert await db.fetch_value("SELECT count(*) FROM dispatches WHERE state='cancelled'") == 2
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("first", ["claim", "deregister"])
async def test_competing_claim_and_deregistration_do_not_leave_live_runs(root, first):
    service, *_ = root
    request = await admitted_run(root)
    db = service.runtime.db()
    tasks = []
    try:
        async with db.transaction() as barrier:
            await barrier.fetch_one(
                "SELECT runner_id FROM runners WHERE runner_id=$1 FOR UPDATE", request.runner_id
            )
            blocker = await barrier.fetch_value("SELECT pg_backend_pid()")
            tasks.append(
                asyncio.create_task(
                    claim(root, request) if first == "claim" else deregister(root, request)
                )
            )
            await wait_for_blocker(db, blocker, tasks[0])
            tasks.append(
                asyncio.create_task(
                    deregister(root, request) if first == "claim" else claim(root, request)
                )
            )
        responses = await asyncio.wait_for(asyncio.gather(*tasks), 5)
        claim_response, deregister_response = (
            responses if first == "claim" else list(reversed(responses))
        )
        assert deregister_response.status_code == 200
        expected = "outcome_unknown" if claim_response.status_code == 200 else "cancelled"
        assert await db.fetch_value("SELECT state FROM dispatches") == expected
        assert (await claim(root, request)).status_code != 200
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("claimed", [False, True])
@pytest.mark.parametrize("stalled", [False, True])
async def test_dispatch_cleanup_never_requires_audit_targets_or_delivery(uses, claimed, stalled):
    from tests.test_run_dispatch_service import setup

    context = await setup(uses)
    containment = await containment_service(uses)
    containment.deregister_runner = context.service.deregister_runner
    admitted = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert admitted.status == 202
    if claimed:
        assert (await context.service.claim(context.signed("/runner/v1/claim"))).status == 200
    context.available[0] = False
    db = uses.world.db
    if stalled:
        event_id = await db.fetch_value("SELECT event_id FROM {{tables.outbox_events}} LIMIT 1")
        await db.execute(
            "INSERT INTO {{tables.outbox_deliveries}}(event_id,target_id,state,attempts) "
            "VALUES ($1,'stalled-target','stalled',40)",
            event_id,
        )
    receipt = await act(
        containment, uses, action="deregister-runner", target=context.runner.runner_id
    )
    assert receipt.action == "deregister-runner"
    assert await db.fetch_value("SELECT state FROM {{tables.dispatches}}") == (
        "outcome_unknown" if claimed else "cancelled"
    )
