"""Shared status reads original run receipts without admission or release."""

from dataclasses import replace

import pytest
from aweb_naapp.roles import assign, principal_key
from aweb_naapp.runtime.approvals import Decision
from aweb_naapp.runtime.authorization import Authorization

from aweb_secrets import records
from aweb_secrets.run_service import RunDispatch
from aweb_secrets.status_service import UseStatus
from tests.test_admission import BOB
from tests.test_run_dispatch_service import decide, report, setup
from tests.test_status_service import STATUS
from tests.test_use_approvals import REQUESTER
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


def authorization(context, *, principal=REQUESTER):
    return Authorization(
        principal,
        STATUS,
        replace(context.submission.authorization.grant, scopes=frozenset({"secrets:read"})),
    )


async def snapshot(db):
    return {
        table: [
            dict(row)
            for row in await db.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        ]
        for table in (
            "dispatches",
            "run_contexts",
            "run_deliveries",
            "run_approval_admissions",
            "approvals",
            "scoped_nonces",
            "rate_buckets",
            "outbox_events",
            "broker_use_events",
        )
    }


async def test_aggregate_run_approval_status_requires_a_fresh_submission(uses):
    context = await setup(uses, approval_required=True)
    pending = await context.service.submit(job=context.job.job_id, submission=context.submission)
    await decide(context, pending, Decision.APPROVE)
    service = UseStatus(
        uses.world.db,
        fence=context.arguments["fence"],
        approvals=context.arguments["approvals"],
        runs=context.service.status,
    )
    before = await snapshot(uses.world.db)
    for locator in (
        pending.body["request_id"],
        pending.body["request_ref"],
        pending.body["approval_ref"],
    ):
        reply = await service.get(ref=locator, authorization=authorization(context))
        assert reply.status == 200
        assert reply.body == {
            "state": "approved",
            "request_id": pending.body["request_id"],
            "request_ref": pending.body["request_ref"],
            "next": "resubmit",
        }
    assert await snapshot(uses.world.db) == before
    assert (await context.service.claim(context.signed("/runner/v1/claim"))).status == 204


@pytest.mark.parametrize("withheld", [False, True])
async def test_only_original_requester_receives_stored_run_output(uses, withheld):
    context = await setup(uses)
    admitted, _, wire = await context.assigned()
    dispatch_ref = wire["assignment"]["dispatch_id"]
    reporter = RunDispatch(uses.world.db, **context.arguments) if withheld else context.service
    await reporter.result(
        dispatch_ref, context.signed(f"/runner/v1/dispatches/{dispatch_ref}/result", report())
    )
    service = UseStatus(
        uses.world.db,
        fence=context.arguments["fence"],
        approvals=context.arguments["approvals"],
        runs=context.service.status,
    )
    owner = BOB
    async with uses.world.db.transaction() as tx:
        await assign(tx, principal_key(owner), "secrets.owner")
    before = await snapshot(uses.world.db)
    own = await service.get(ref=admitted.body["request_ref"], authorization=authorization(context))
    inspected = await service.get(
        ref=admitted.body["request_ref"], authorization=authorization(context, principal=owner)
    )
    assert own.status == inspected.status == 200
    assert "result" in own.body and "result" not in inspected.body
    assert inspected.body == {key: value for key, value in own.body.items() if key != "result"}
    missing = await service.get(
        ref=admitted.body["request_id"], authorization=authorization(context, principal=owner)
    )
    assert missing.status == 404
    assert await snapshot(uses.world.db) == before


async def test_run_status_is_hidden_after_original_grant_revocation(uses):
    context = await setup(uses)
    admitted = await context.service.submit(job=context.job.job_id, submission=context.submission)
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, uses.world.admitted.installation_id, "grt_durable001")
    service = UseStatus(
        uses.world.db,
        fence=context.arguments["fence"],
        approvals=context.arguments["approvals"],
        runs=context.service.status,
    )
    before = await snapshot(uses.world.db)
    reply = await service.get(
        ref=admitted.body["request_ref"], authorization=authorization(context)
    )
    assert reply.status == 404
    assert reply.body == {"state": "refused", "request_id": None, "code": "not_found"}
    assert await snapshot(uses.world.db) == before
