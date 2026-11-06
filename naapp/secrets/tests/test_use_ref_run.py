"""A run's public ref survives approval/reports; separate executions stay distinct."""

import json
import re
import secrets
from dataclasses import replace

import asyncpg
import pytest
from aweb_naapp.runtime.approvals import Decision

from aweb_secrets import records
from aweb_secrets.runner_protocol import canonical
from tests.test_broker_audit import envelopes
from tests.test_run_dispatch_service import decide, report, setup
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_ref_broker import assert_scope, use_events


def changed(context, **changes):
    body = {**json.loads(context.submission.inbound.body), **changes}
    return replace(
        context.submission, inbound=replace(context.submission.inbound, body=canonical(body))
    )


async def test_run_approval_assignment_result_replay_and_distinct_execution_refs(uses):
    context = await setup(uses, approval_required=True)
    marker = secrets.token_urlsafe(32)
    request = changed(context, request_id=marker)
    first = await context.service.submit(job=context.job.job_id, submission=request)
    assert first.body["state"] == "awaiting_approval"
    assert (await context.service.submit(job=context.job.job_id, submission=request)).body[
        "request_ref"
    ] == first.body["request_ref"]
    await decide(context, first, Decision.APPROVE)
    admitted = await context.service.submit(job=context.job.job_id, submission=request)
    assert (
        admitted.body["state"] == "admitted"
        and admitted.body["request_ref"] == first.body["request_ref"]
    )
    assignment = await context.service.claim(context.signed("/runner/v1/claim"))
    wire = json.loads(assignment.body)
    ref = wire["assignment"]["dispatch_id"]
    target = f"/runner/v1/dispatches/{ref}"
    await context.service.started(ref, context.signed(target + "/started"))
    for _ in range(2):
        assert (
            await context.service.result(ref, context.signed(target + "/result", report()))
        ).status == 204
    complete = await context.service.submit(job=context.job.job_id, submission=request)
    assert (
        complete.body["state"] == "completed"
        and complete.body["request_ref"] == first.body["request_ref"]
    )
    events = use_events(await envelopes(uses.world.db))
    assert_scope(events, request.authorization)
    assert all(e["payload"]["use_ref"] == first.body["request_ref"] for e in events)
    assert any(e["payload"]["action"] == "completed" for e in events)
    if marker in json.dumps(events) or context.credential in json.dumps(events):
        raise AssertionError("request ID or credential reached a signed run event")
    second = await context.service.submit(
        job=context.job.job_id, submission=changed(context, request_id="second-execution")
    )
    assert second.body["request_ref"] != first.body["request_ref"]
    second_event = use_events(await envelopes(uses.world.db))[-1]
    assert second_event["payload"]["use_ref"] == second.body["request_ref"]
    assert second_event["payload"]["job_id"] == events[0]["payload"]["job_id"]
    await decide(context, second, Decision.APPROVE)
    second_request = changed(context, request_id="second-execution")
    await context.service.submit(job=context.job.job_id, submission=second_request)
    second_claim = await context.service.claim(context.signed("/runner/v1/claim"))
    second_ref = json.loads(second_claim.body)["assignment"]["dispatch_id"]
    assert second_ref != ref
    second_target = f"/runner/v1/dispatches/{second_ref}"
    await context.service.started(second_ref, context.signed(second_target + "/started"))
    await context.service.result(second_ref, context.signed(second_target + "/result", report()))
    second_receipt = await context.service.submit(job=context.job.job_id, submission=second_request)
    assert second_receipt.body["state"] == "completed"
    assert second_receipt.body["request_ref"] == second.body["request_ref"]
    finished = use_events(await envelopes(uses.world.db))
    assert len([e for e in finished if e["payload"]["action"] == "completed"]) == 2
    assert finished[-1]["payload"]["use_ref"] == second.body["request_ref"]


@pytest.mark.parametrize("injected", [False, True])
async def test_run_pre_admission_refusal_refs_are_fresh_and_caller_input_is_rejected(
    uses, injected
):
    context = await setup(uses)
    if not injected:
        async with uses.world.db.transaction() as tx:
            await records.revoke_grant(tx, uses.world.admitted.installation_id, "grt_durable001")
    marker = secrets.token_urlsafe(32)
    request = changed(
        context, request_id=marker, **({"use_ref": "caller-injected"} if injected else {})
    )
    replies = [
        await context.service.submit(job=context.job.job_id, submission=request) for _ in range(2)
    ]
    assert all(r.body["state"] == "refused" for r in replies)
    assert all(
        r.body["code"] == ("params_invalid" if injected else "job_not_allowed") for r in replies
    )
    refs = [r.body["use_ref"] for r in replies]
    assert all(re.fullmatch(r"use_[A-Za-z0-9_-]{22}", ref) for ref in refs) and refs[0] != refs[1]
    events = use_events(await envelopes(uses.world.db))
    assert_scope(events, request.authorization)
    assert [e["payload"]["use_ref"] for e in events] == refs
    assert all("dispatch_id" not in e["payload"] for e in events)
    if marker in json.dumps(events) or "caller-injected" in json.dumps(events):
        raise AssertionError("caller input reached signed run refusal correlation")
    for table in ("dispatches", "run_contexts", "idempotency_keys", "rate_buckets"):
        assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0


async def test_run_refusal_record_failure_presents_no_ref_and_rolls_back_audit(uses):
    from tests.test_run_status import snapshot

    context = await setup(uses)
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, uses.world.admitted.installation_id, "grt_durable001")
    await uses.world.db.execute(
        "ALTER TABLE {{tables.broker_use_events}} ADD CONSTRAINT fail_refusal CHECK(false) NOT VALID"
    )
    before, replies = await snapshot(uses.world.db), []
    with pytest.raises(asyncpg.CheckViolationError):
        replies.append(
            await context.service.submit(job=context.job.job_id, submission=context.submission)
        )
    assert replies == [] and await snapshot(uses.world.db) == before


async def test_unknown_run_and_owner_settlement_keep_the_original_public_ref(uses):
    from tests.reconciliation_world import OwnerFence, service_world
    from tests.test_reconciliation_service import approve, mint

    context, original, controls, console, session = await service_world(uses)
    ref = original.original.reconcile_ref
    pending = await mint(uses, controls, console, session, ref)
    await approve(uses, pending)
    async with uses.world.db.transaction() as tx:
        receipt = await controls.settle(
            tx,
            approval_id=pending.approval.approval_id,
            fence=OwnerFence(console, session, uses.world.admitted),
        )
    assert receipt.reconcile_ref == ref
    events = use_events(await envelopes(uses.world.db))
    assert [e["payload"]["action"] for e in events] == [
        "admitted",
        "dispatching",
        "outcome_unknown",
        "reconciled",
    ]
    assert all(e["payload"]["use_ref"] == ref for e in events)
    reply = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert reply.body["request_ref"] == ref
