"""Original owner-page projections on real broker/run records, without effects."""

from dataclasses import replace

import pytest
from aweb_naapp.dispatch import State
from aweb_naapp.runtime.installation import InstallationRefused
from aweb_secrets.reconciliation_reads import ReconciliationReads

from aweb_secrets import records, tool_results
from tests.test_admission import SECRET
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence
from tests.test_broker_audit import prepared
from tests.test_broker_fence import authority
from tests.test_run_dispatch_service import setup as run_setup
from tests.test_run_status import snapshot as run_snapshot
from tests.test_status_service import snapshot as broker_snapshot
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def test_broker_projection_uses_only_original_opaque_scoped_records_without_effects(
    db, fence
):
    request, admission, dispatch_id, machine = await prepared(db, fence)
    async with db.transaction() as tx:
        await machine.admit(
            tx, dispatch_id, fence=authority(fence, admission, request, dispatch_id)
        )
        final = authority(fence, admission, request, dispatch_id)
        dispatch = await machine.begin_dispatch(tx, dispatch_id, fence=final)
        await final.check(tx, dispatch)
        assert await machine.outcome_unknown(
            tx,
            dispatch_id,
            tool_results.outcome_unknown(
                request_id=request.request_id, request_ref=admission.intent_id
            ),
        )
    reads = ReconciliationReads()
    scope = admission.installation
    async with db.transaction() as tx:
        await records.set_active_version(
            tx, scope.installation_id, scope.team_id, SECRET["secret_id"], 5
        )
    before = await broker_snapshot(db)
    async with db.transaction() as tx:
        view = await reads.get(tx, scope=scope, reconcile_ref=admission.intent_id)
        assert view is not None and view.state is State.OUTCOME_UNKNOWN
        original = view.original
        assert (original.reconcile_ref, original.request_id, original.dispatch_id) == (
            admission.intent_id,
            request.request_id,
            dispatch_id,
        )
        assert original.installation == scope and original.op_kind == "broker"
        assert original.operation_id == request.operation_id
        assert original.operation_digest is not None
        assert len(original.resources) == 1
        assert original.resources[0].secret_ref == request.secret_ref
        assert original.resources[0].version == 4
        for foreign in (
            replace(scope, app_id="other"),
            replace(scope, installation_id="other"),
            replace(scope, team_id="backend:other.example"),
        ):
            assert await reads.get(tx, scope=foreign, reconcile_ref=admission.intent_id) is None
        assert await reads.get(tx, scope=scope, reconcile_ref=request.request_id) is None
        assert await reads.get(tx, scope=scope, reconcile_ref="missing") is None
        with pytest.raises(InstallationRefused) as refused:
            await reads.get(
                tx,
                scope=replace(scope, generation=scope.generation + 1),
                reconcile_ref=admission.intent_id,
            )
        assert refused.value.code == "generation_superseded"
    assert await broker_snapshot(db) == before


async def test_run_projection_keeps_frozen_job_and_resources_and_never_returns_output_or_tokens(
    uses,
):
    context = await run_setup(uses)
    admitted, _, _ = await context.assigned()
    db, scope = uses.world.db, uses.world.admitted
    await db.execute(
        "UPDATE {{tables.dispatches}} SET sweep_after=clock_timestamp()-interval '1 second'"
    )
    assert await context.service.sweep() == 1
    before = await run_snapshot(db)
    async with db.transaction() as tx:
        reads = ReconciliationReads(enable_runs=True)
        view = await reads.get(tx, scope=scope, reconcile_ref=admitted.body["request_ref"])
        assert view is not None and view.state is State.OUTCOME_UNKNOWN
        original = view.original
        assert original.reconcile_ref == admitted.body["request_ref"]
        assert original.request_id == admitted.body["request_id"]
        assert original.op_kind == "run_job" and original.installation == scope
        assert (original.job_id, original.job_digest, original.runner_id) == (
            context.job.job_id,
            context.job.digest,
            context.runner.runner_id,
        )
        assert tuple(item.secret_ref for item in original.resources) == tuple(
            slot["secret_ref"] for slot in context.job.after["credentials"]
        )
        assert context.credential not in repr(view)
        assert "params" not in repr(view) and "personal_token" not in repr(view)
        assert await reads.get(tx, scope=scope, reconcile_ref=admitted.body["request_id"]) is None
        assert (
            await reads.get(
                tx,
                scope=replace(scope, team_id="backend:other.example"),
                reconcile_ref=original.reconcile_ref,
            )
            is None
        )
        assert (
            await ReconciliationReads().get(tx, scope=scope, reconcile_ref=original.reconcile_ref)
            is None
        )
    assert await run_snapshot(db) == before
