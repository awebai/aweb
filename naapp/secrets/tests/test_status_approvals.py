"""Status reads real B2/passkey decisions without consuming or dispatching them."""

from datetime import timedelta

import pytest
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.runtime.approvals import Decision
from aweb_naapp.runtime.authorization import Authorization

from aweb_secrets.status_service import UseStatus
from aweb_secrets.use_context import UseCommitments, apply_use_context_migrations, store_use_context
from tests.test_status_service import STATUS
from tests.test_use_approvals import REQUESTER, approve, designate, install, request
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def receipt(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, pending = await request(uses)
    db = uses.world.db
    await apply_dispatch_migrations(db)
    await apply_use_context_migrations(db)
    scope = admission.installation
    # Persist the read fixture at S3's pending state. All B2 requests and
    # passkey decisions above/below use their actual services and database.
    async with db.transaction() as tx:
        await store_use_context(
            tx,
            admission=admission,
            dispatch_id=dispatch_id,
            commitments=UseCommitments(
                CommitmentContext(
                    scope.app_id, scope.team_id, scope.installation_id, scope.generation, "request"
                ),
                "a" * 64,
                None,
            ),
        )
        await tx.execute(
            "INSERT INTO {{tables.dispatches}} (dispatch_id,subject,action,retry_exempt,state)"
            " VALUES ($1,'status-fixture','broker',false,'awaiting_approval')",
            dispatch_id,
        )
    return admission, pending


async def unchanged_read(uses, ref):
    db = uses.world.db
    tables = ("intents", "dispatches", "use_approvals", "approvals", "rate_buckets", "audit_outbox")
    before = {
        table: [dict(row) for row in await db.fetch_all("SELECT * FROM {{tables." + table + "}}")]
        for table in tables
    }
    reply = await UseStatus(db, fence=uses.world.fence, approvals=uses.approvals).get(
        ref=ref, authorization=Authorization(principal=REQUESTER, tool=STATUS, grant=uses.grant)
    )
    after = {
        table: [dict(row) for row in await db.fetch_all("SELECT * FROM {{tables." + table + "}}")]
        for table in tables
    }
    assert before == after
    return reply


async def test_approved_status_requires_explicit_resubmission_without_consumption(uses):  # noqa: F811
    admission, pending = await receipt(uses)
    initial = await unchanged_read(uses, admission.intent_id)
    assert initial.status == 200 and initial.body["state"] == "awaiting_approval"
    assert initial.body["approval_ref"] == pending.approval_ref
    await approve(uses, pending, "finance@acme.com")
    for ref in ("req_1", admission.intent_id, pending.approval_ref):
        reply = await unchanged_read(uses, ref)
        assert reply.status == 200
        assert reply.body == {
            "state": "approved",
            "request_id": "req_1",
            "request_ref": admission.intent_id,
            "next": "resubmit",
        }
        for _, token in uses.world.inbox.links["finance@acme.com"]:
            if token in repr(reply):
                raise AssertionError("approval link appeared in status reply")


@pytest.mark.parametrize("decision", ["denied", "expired", "revoked"])
async def test_failed_decisions_have_locator_and_aggregate_states_without_side_effects(
    uses, decision
):  # noqa: F811
    admission, pending = await receipt(uses)
    if decision == "denied":
        await approve(uses, pending, "finance@acme.com", decision=Decision.REJECT)
    elif decision == "expired":
        uses.clock.now += timedelta(seconds=901)
    else:
        await uses.approvals.revoke_many(
            [pending.pending.approval.approval_id],
            revoked_by="status-test",
            reason="approval_revoked",
        )
    reply = await unchanged_read(uses, pending.approval_ref)
    assert reply.status == 200 and reply.body["state"] == decision
    assert "next" not in reply.body
    aggregate = await unchanged_read(uses, admission.intent_id)
    assert aggregate.status == 200 and aggregate.body["state"] == "refused"
    assert aggregate.body["code"] == "approval_" + decision
    assert "next" not in aggregate.body
