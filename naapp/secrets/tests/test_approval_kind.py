"""The common entry gets a kind only, from actual immutable B2 associations."""

from dataclasses import replace
from uuid import uuid4

import pytest

from aweb_secrets.approval_kind import approval_kind
from aweb_secrets.reconciliation_control_audit import apply_reconciliation_migrations
from aweb_secrets.reconciliation_policy import reconciliation_policy_ref
from aweb_secrets.use_audit import UseAuditUnavailable
from tests.test_change_sets import ALICE
from tests.test_reconciliation_control_audit import control_world
from tests.test_run_dispatch_service import setup
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_audit import composition


async def linked(uses, kind):
    if kind == "use":
        _, _, pending, _, _ = await composition(uses)
        pending = pending.pending
    elif kind == "run":
        context = await setup(uses, approval_required=True)
        reply = await context.service.submit(job=context.job.job_id, submission=context.submission)
        approval_id = await uses.world.db.fetch_value(
            "SELECT approval_id FROM {{tables.run_slot_approvals}} WHERE approval_ref=$1",
            reply.body["approval_ref"],
        )
        approvals = context.arguments["approvals"]
        [token] = [t for a, t in uses.world.inbox.links["finance@acme.com"] if a == approval_id]
        return await approvals.open_link(token)
    else:
        _, _, request, _, _, _ = await control_world(uses)
        async with uses.world.db.transaction() as tx:
            pending = await uses.approvals.mint(
                request=request,
                policy_ref=reconciliation_policy_ref(request),
                requested_by=ALICE.principal_did,
                tx=tx,
            )
        await uses.approvals.deliver(pending)
    return await uses.approvals.open_link(pending.deliveries[0].link_token)


@pytest.mark.parametrize("kind", ["use", "run", "reconciliation_control"])
async def test_link_routes_only_from_its_exact_persisted_association_without_terms_or_effects(
    uses, kind
):
    actual = await linked(uses, kind)
    assert actual.request is None
    db = uses.world.db
    before = await db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    async with db.transaction() as tx:
        flags = dict(
            enable_runs=kind != "use", enable_reconciliation=kind == "reconciliation_control"
        )
        assert await approval_kind(tx, actual.approval, **flags) == kind
        for changed in (
            replace(actual.approval, request_ref=str(uuid4())),
            replace(actual.approval, request_sha256="0" * 64),
            replace(actual.approval, policy_ref="other"),
            replace(actual.approval, policy_version=999),
        ):
            with pytest.raises(UseAuditUnavailable):
                await approval_kind(tx, changed, **flags)
        assert (
            await approval_kind(tx, replace(actual.approval, approval_id=str(uuid4())), **flags)
            is None
        )
        if kind != "use":
            assert await approval_kind(tx, actual.approval) is None
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == before


async def test_default_use_lookup_does_not_require_optional_run_or_control_tables(uses):
    actual = await linked(uses, "use")
    async with uses.world.db.transaction() as tx:
        assert await approval_kind(tx, actual.approval) == "use"


async def test_multiple_persisted_app_kinds_refuse_even_when_all_identity_fields_match(uses):
    actual = await linked(uses, "use")
    db = uses.world.db
    await apply_reconciliation_migrations(db)
    # Deliberately create an inconsistent second association in the real DB.
    # No normal mint can do this; the entry must still refuse corrupt routing.
    async with db.transaction() as tx:
        await tx.execute(
            "INSERT INTO {{tables.reconciliation_controls}}"
            " (control_id,approval_id,app_id,installation_id,team_id,install_generation,"
            "reconcile_ref,dispatch_id,outcome,request_ref,request_sha256,policy_ref,policy_version,"
            "owner_scope,owner_subject,owner_principal,expires_at)"
            " SELECT $1,a.approval_id,c.app_id,c.installation_id,c.team_id,c.install_generation,"
            "c.intent_id,c.dispatch_id,'completed',a.request_ref,a.request_sha256,$2,$3,"
            "'corrupt-routing-scope','corrupt-routing-subject',$4,$5"
            " FROM {{tables.use_approval_audits}} a JOIN {{tables.use_contexts}} c USING(dispatch_id)"
            " WHERE a.approval_id=$6",
            uuid4(),
            actual.approval.policy_ref,
            actual.approval.policy_version,
            ALICE.principal_did,
            actual.approval.expires_at,
            actual.approval.approval_id,
        )
        with pytest.raises(UseAuditUnavailable):
            await approval_kind(tx, actual.approval, enable_reconciliation=True)
