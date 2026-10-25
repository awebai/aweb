"""Required reviewer cases on the unchanged, unlanded durable service.

The deadline adapter performs every real F6 SQL check and only delays its
return/advances the injected clock. It manufactures no authorization result.
"""

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks.strictjson import encode_base64url
from aweb_naapp.runtime.installation import InstallationFence

from aweb_secrets import jobs, records
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from aweb_secrets.runner_protocol import RunnerRefused, canonical, parse_request
from aweb_secrets.runner_types import RunnerSubmission
from tests.test_run_dispatch_service import report, setup
from tests.test_use_approvals import TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def replace_run_grant(context, *, job=None, policy=None):
    db, scope = context.uses.world.db, context.uses.world.admitted
    async with db.transaction() as tx:
        old = await tx.fetch_value(
            "SELECT record FROM {{tables.grants}} WHERE grant_id='grt_durable001'"
        )
        import json

        old = json.loads(old)
        if policy is not None:
            await records.create_policy(tx, scope.installation_id, policy)
            old["policy_digest"] = policy.digest
        if job is not None:
            await jobs.create_job(tx, scope.installation_id, TEAM, job)
            old["jobs"] = [{"job_id": job.job_id, "digest": job.digest}]
            context.job = job
        await records.revoke_grant(tx, scope.installation_id, old["grant_id"])
        old["grant_id"] = "grt_review_repro"
        await records.create_grant(tx, scope.installation_id, TEAM, GrantRecord.from_after(old))


@pytest.mark.parametrize("unknown", [False, True])
async def test_another_request_on_a_busy_runner_returns_a_bounded_conflict(uses, unknown):
    context = await setup(uses)
    await context.assigned()
    if unknown:
        async with uses.world.db.transaction() as tx:
            await tx.execute(
                "UPDATE {{tables.dispatches}} SET sweep_after=clock_timestamp()-interval '1 second'"
            )
        assert await context.service.sweep() == 1
    import json

    body = json.loads(context.submission.inbound.body)
    body["request_id"] = "another-run"
    another = replace(
        context.submission, inbound=replace(context.submission.inbound, body=canonical(body))
    )
    tables = (
        "run_contexts",
        "run_approval_plans",
        "run_slot_approvals",
        "idempotency_keys",
        "rate_buckets",
        "dispatches",
    )
    before = {
        table: [
            dict(row)
            for row in await uses.world.db.fetch_all("SELECT * FROM {{tables." + table + "}}")
        ]
        for table in tables
    }
    reply = await context.service.submit(job=context.job.job_id, submission=another)
    assert reply.status == 409
    assert reply.body["code"] == ("reconciliation_pending" if unknown else "dispatch_in_flight")
    after = {
        table: [
            dict(row)
            for row in await uses.world.db.fetch_all("SELECT * FROM {{tables." + table + "}}")
        ]
        for table in tables
    }
    assert after == before


async def test_delayed_start_cannot_be_swept_before_its_full_execution_window(uses):
    context = await setup(uses)
    body = context.job.after
    body["timeout_s"] = 1
    context.arguments["assignment_ttl"] = timedelta(seconds=5)
    context.arguments["sweep_margin"] = timedelta(seconds=1)
    await replace_run_grant(context, job=jobs.JobDefinition.from_after(body))
    _, _, wire = await context.assigned()
    # The original implementation swept at publication + timeout + margin,
    # although the runner can still legitimately start before assignment expiry.
    old_threshold = await uses.world.db.fetch_value(
        "SELECT updated_at + interval '2 seconds' FROM {{tables.dispatches}}"
    )
    await asyncio.sleep(max(0, (old_threshold - datetime.now(UTC)).total_seconds()) + 0.05)
    uses.clock.now = await uses.world.db.fetch_value("SELECT clock_timestamp()")
    expires = await uses.world.db.fetch_value("SELECT expires_at FROM {{tables.run_deliveries}}")
    assert uses.clock() < expires
    dispatch_ref = wire["assignment"]["dispatch_id"]
    assert (
        await context.service.started(
            dispatch_ref, context.signed(f"/runner/v1/dispatches/{dispatch_ref}/started")
        )
    ).status == 204
    assert await context.service.sweep() == 0
    assert (
        await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "dispatching"
    )
    # Replaying an assignment must not move the immutable recovery deadline.
    before = await uses.world.db.fetch_value("SELECT sweep_after FROM {{tables.dispatches}}")
    assert (await context.service.claim(context.signed("/runner/v1/claim"))).status == 200
    assert (
        await uses.world.db.fetch_value("SELECT sweep_after FROM {{tables.dispatches}}") == before
    )


async def test_reused_nonce_precedes_a_conflicting_result_without_writes(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    target = f"/runner/v1/dispatches/{wire['assignment']['dispatch_id']}/result"
    first = context.signed(target, report())
    assert (await context.service.result(wire["assignment"]["dispatch_id"], first)).status == 204
    payload = dict(parse_request(first.header).payload)
    changed = report("changed")
    payload["body_sha256"] = hashlib.sha256(changed).hexdigest()
    encoded = canonical(payload)
    signature = context.signing_key.sign(b"aweb.secrets.runner-request/1\n" + encoded).signature
    replay = RunnerSubmission(
        encode_base64url(encoded) + "." + encode_base64url(signature), "POST", target, changed
    )
    before = await uses.world.db.fetch_one(
        "SELECT state,result,late_results FROM {{tables.dispatches}}"
    )
    nonces = await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}")
    with pytest.raises(RunnerRefused) as refused:
        await context.service.result(wire["assignment"]["dispatch_id"], replay)
    assert refused.value.code == "runner_request_replayed"
    assert (
        await uses.world.db.fetch_one("SELECT state,result,late_results FROM {{tables.dispatches}}")
        == before
    )
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == nonces
    )


class DelayedFence(InstallationFence):
    """Real F6 plus a scheduling boundary in the final publication tail."""

    tail_checks = 0

    def __init__(self, original, clock, expired):
        super().__init__(original.db, app_id=original.app_id, grants=original.grants)
        self.clock, self.expired = clock, expired

    async def _check_locked(self, tx, admitted):
        await super()._check_locked(tx, admitted)
        released = await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.dispatches}} WHERE state='dispatching')"
        )
        if released:
            self.tail_checks += 1
            if self.tail_checks == 2:
                self.clock.now = self.expired
                await asyncio.sleep(0)


async def test_policy_window_crossed_during_final_f6_tail_cannot_publish(uses):
    context = await setup(uses)
    context.arguments["assignment_ttl"] = timedelta(seconds=120)
    async with uses.world.db.transaction() as tx:
        digest = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id='grt_durable001'"
        )
        original = await records.policy(tx, uses.world.admitted.installation_id, digest)
    expiry = uses.clock().replace(second=0, microsecond=0) + timedelta(minutes=1)
    zone = "UTC" if expiry.date() == uses.clock().date() else "Etc/GMT+1"
    offset = timedelta(0) if zone == "UTC" else timedelta(hours=1)
    policy = Policy.from_body(
        {
            **dict(original.body),
            "windows": {
                "time_zone": zone,
                "ranges": [
                    {
                        "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                        "from": (uses.clock() - offset).strftime("%H:%M"),
                        "to": (expiry - offset).strftime("%H:%M"),
                    }
                ],
            },
        }
    )
    await replace_run_grant(context, policy=policy)
    fence = DelayedFence(context.arguments["fence"], uses.clock, expiry)
    context.arguments["fence"] = fence
    admitted = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert admitted.body["state"] == "admitted"
    with pytest.raises(RunnerRefused) as refused:
        await context.service.claim(context.signed("/runner/v1/claim"))
    assert refused.value.code == "runner_unavailable"
    assert fence.tail_checks == 2
    assert (
        await uses.world.db.fetch_value("SELECT assignment FROM {{tables.run_deliveries}}") is None
    )
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
    assert await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "refused"
    # The failed publication inserts no nonce. The required REFUSED closure
    # records exactly this one claim nonce atomically, per protocol §4.4.
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 1
