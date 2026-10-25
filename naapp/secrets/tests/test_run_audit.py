"""Original run-slot audit through real planner, PostgreSQL, B2 and passkeys."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from aweb_naapp.dispatch import Dispatches
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.hooks.strictjson import Refused

from aweb_secrets.run_approvals import request_run_approvals
from aweb_secrets.run_audit import RunAudit, associate_run_approval
from aweb_secrets.run_context import original_run, store_run_context
from aweb_secrets.run_input import RunInput
from aweb_secrets.run_planner import RunPlanner
from aweb_secrets.runner_protocol import canonical
from aweb_secrets.use_audit import UseAuditUnavailable
from tests.run_world import setup
from tests.test_broker_audit import envelopes
from tests.test_use_approvals import REQUESTER, SECRET, TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def stage(context, *, request_id="run-audit", params=None):
    db, args = context.uses.world.db, context.arguments
    params = {"database": "orders"} if params is None else params
    logical_body = {"request_id": request_id, "runner": context.runner.runner_id, "params": params}
    inputs = RunInput.from_body(context.job.job_id, logical_body, job_digest=context.job.digest)
    inbound = replace(context.submission.inbound, body=canonical(logical_body))
    planner = RunPlanner(
        args["fence"],
        clock=context.uses.clock,
        derived_max_ttl_s=3600,
        internal_destinations=args["internal_destinations"],
    )
    dispatch_id, run_id, intent_id = uuid4(), "run_" + uuid4().hex, "int_" + uuid4().hex
    view = await args["registration_view"](TEAM)
    audit = args["use_audit"]
    async with db.transaction() as tx:
        prepared = await planner.prepare(
            tx,
            grant=context.submission.authorization.grant,
            principal=REQUESTER,
            run_id=run_id,
            intent_id=intent_id,
            dispatch_id=dispatch_id,
            candidate_job=context.job,
            runner_id=context.runner.runner_id,
            params=params,
        )
        scope = prepared.installation
        commitments = args["committer"].commit(
            CommitmentContext(
                scope.app_id, scope.team_id, scope.installation_id, scope.generation, "run"
            ),
            inbound,
            parameters=params,
        )
        dispatch_ref = await store_run_context(
            tx,
            prepared=prepared,
            inputs=inputs,
            principal=REQUESTER,
            commitments=commitments,
            signed_trace_id=None,
        )
        with audit.minting(dispatch_id), audit.prepared_view(view):
            pending = await request_run_approvals(
                tx, args["approvals"], prepared=prepared, principal=REQUESTER, reason="scheduled"
            )
        machine = Dispatches(
            on_transition=RunAudit(producer=args["producer"], view=view),
            max_dispatch=timedelta(seconds=context.job.after["timeout_s"]),
            sweep_margin=args["sweep_margin"],
        )
        await machine.create(
            tx, dispatch_id=dispatch_id, subject="original-run", action=context.job.job_id
        )
        await machine.await_approval(tx, dispatch_id)
        await prepared.recheck(tx)
    for item in pending:
        await args["approvals"].deliver(item.pending)
    return dispatch_id, dispatch_ref, pending


async def test_run_request_decision_proof_and_activity_keep_the_original_slot(uses):
    from aweb_naapp.runtime.approvals import Assurance, Decision

    context = await setup(uses, approval_required=True)
    dispatch_id, dispatch_ref, pending = await stage(context)
    approval_id = pending[0].approval_id
    approvals = context.arguments["approvals"]
    [token] = [
        token
        for candidate, token in uses.world.inbox.links["finance@acme.com"]
        if candidate == approval_id
    ]
    options = await approvals.challenge(
        approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    with context.arguments["use_audit"].prepared_view(
        await context.arguments["registration_view"](TEAM)
    ):
        await approvals.decide(
            approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            uses.world.devices["finance@acme.com"].get(dict(options)),
            link_token=token,
        )
    events = await envelopes(uses.world.db)
    assert [event["payload"]["action"] for event in events] == [
        "approval_requested",
        "approval_decided",
    ]
    assert all(event["payload"]["op_kind"] == "run_job" for event in events)
    assert events[-1]["payload"]["approval_assurance"] == "passkey"
    assert len(events[-1]["payload"]["approval_evidence_sha256"]) == 64
    async with uses.world.db.transaction() as tx:
        original = await original_run(tx, dispatch_id)
    assert original.dispatch_ref == dispatch_ref
    assert original.plan.slots[0].source_id == SECRET["secret_id"]
    assert (
        original.plan.slots[0].body["source"]["ref"]
        == context.job.after["credentials"][0]["secret_ref"]
    )
    proof = await uses.world.db.fetch_one("SELECT * FROM {{tables.run_approval_audit_proofs}}")
    assert proof["approval_id"] == approval_id and proof["purpose"] == "approve"
    rows = await uses.world.db.fetch_all(
        "SELECT correlation FROM {{tables.broker_use_events}} ORDER BY occurred_at,event_id"
    )
    assert len(rows) == 2
    if context.credential in repr(events) + repr(rows):
        raise AssertionError("run audit contains a credential")


async def test_b2_run_request_cannot_be_associated_with_another_original_plan(uses):
    context = await setup(uses, approval_required=True)
    first, _, pending = await stage(context, request_id="first")
    second, _, _ = await stage(context, request_id="second", params={"database": "customers"})
    approval = await context.arguments["approvals"].get(pending[0].approval_id)
    before = await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.run_approval_audits}}")
    with pytest.raises(UseAuditUnavailable):
        async with uses.world.db.transaction() as tx:
            await associate_run_approval(tx, approval, second)
    assert first != second
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.run_approval_audits}}")
        == before
    )
    assert (
        await uses.world.db.fetch_value(
            "SELECT dispatch_id FROM {{tables.run_approval_audits}} WHERE approval_id=$1",
            approval.approval_id,
        )
        == first
    )


async def test_required_run_audit_failure_rolls_back_plan_approval_and_dispatch(uses):
    context = await setup(uses, approval_required=True)
    context.available[0] = False
    with pytest.raises(Refused) as refused:
        await stage(context)
    assert refused.value.code == "audit_target_unavailable"
    for table in (
        "run_contexts",
        "run_approval_plans",
        "run_slot_approvals",
        "run_approval_audits",
        "dispatches",
    ):
        assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0
    assert await envelopes(uses.world.db) == []


async def test_joint_run_admission_and_b2_final_check_use_the_whole_prepared_authority(uses):
    import json

    from aweb_naapp.runtime.approvals import Assurance, Decision
    from aweb_naapp.runtime.approvals.dispatch_fence import DispatchBinding

    from aweb_secrets.run_approvals import admit_run_approvals
    from aweb_secrets.run_dispatch_authority import RunDispatchAuthority

    context = await setup(uses, approval_required=True)
    dispatch_id, _, pending = await stage(context)
    args, db = context.arguments, uses.world.db
    approval_id, approvals = pending[0].approval_id, args["approvals"]
    [token] = [
        t for candidate, t in uses.world.inbox.links["finance@acme.com"] if candidate == approval_id
    ]
    options = await approvals.challenge(
        approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    with args["use_audit"].prepared_view(await args["registration_view"](TEAM)):
        await approvals.decide(
            approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            uses.world.devices["finance@acme.com"].get(dict(options)),
            link_token=token,
        )

    class RollbackProof(Exception):
        pass

    planner = RunPlanner(
        args["fence"],
        clock=uses.clock,
        derived_max_ttl_s=3600,
        internal_destinations=args["internal_destinations"],
    )
    with pytest.raises(RollbackProof):
        async with db.transaction() as tx:
            original = await original_run(tx, dispatch_id)
            adapter = RunDispatchAuthority(
                original=original,
                planner=planner,
                grant=context.submission.authorization.grant,
                passkeys=uses.world.passkeys,
            )
            originals = await args["use_audit"].dispatch_approvals(tx, dispatch_id)
            await adapter.prepare(tx, originals)
            admitted = await admit_run_approvals(tx, approvals, prepared=adapter.prepared)
            assert admitted.may_send and admitted.refusal is None
            rows = await tx.fetch_all(
                "SELECT approval_id,request FROM {{tables.run_slot_approvals}} WHERE approval_id IS NOT NULL"
            )
            prepared = await approvals.prepare_dispatches(
                tx,
                [
                    DispatchBinding(
                        row["approval_id"], json.loads(row["request"]), str(dispatch_id)
                    )
                    for row in rows
                ],
                authority=adapter,
            )
            before = await tx.fetch_all(
                "SELECT relation,mode FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation' ORDER BY relation,mode"
            )
            for handle in prepared:
                await approvals.check_dispatch(tx, handle)
            await adapter.prepared.recheck(tx)
            after = await tx.fetch_all(
                "SELECT relation,mode FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation' ORDER BY relation,mode"
            )
            assert before == after
            raise RollbackProof()
    assert (await approvals.get(approval_id)).consumed_operation_id is None
    assert await db.fetch_value("SELECT count(*) FROM {{tables.run_approval_admissions}}") == 0
