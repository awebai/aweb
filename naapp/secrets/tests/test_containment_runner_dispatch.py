"""Runner containment through the mounted production owner and runner routes."""

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
from tests.test_jobs import after as job_after
from tests.test_production_bootstrap import approval_request, envelopes
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_production_runner_dispatch import runner_headers
from tests.test_use_approvals import POLICY_BODY, SECRET


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
