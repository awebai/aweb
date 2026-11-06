"""The required composite routes real B3/B2 effects on their original transaction."""

from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.runtime.approvals import ApprovalState, Assurance, Decision, PgApprovalStore
from aweb_naapp.runtime.audit import AuditEvent, AuditKind

from aweb_secrets.audit_sink import SecretsAudit
from aweb_secrets.use_audit import UseApprovalAudit, UseAuditUnavailable
from tests.test_change_sets import ALICE, by_member, change_set, enrol_owner
from tests.test_credential_audit import audit_for, designate
from tests.test_use_approvals import designate_approver
from tests.test_use_approvals import uses as _uses
from tests.test_use_approvals import world as _world
from tests.test_use_audit import composition

world = _world
uses = _uses


async def composite(world):
    credentials = await audit_for(world)
    use = UseApprovalAudit(
        producer=credentials._producer,
        passkeys=lambda: world.passkeys,
        approval=credentials._approval,
        max_backlog_age=timedelta(minutes=5),
    )
    sink = SecretsAudit(credentials=credentials, use=use)
    world.passkeys._audit = sink
    world.approvals._audit = sink
    return sink, credentials, use


@pytest.mark.parametrize("missing", ["credentials", "use"])
async def test_both_production_branches_are_required(world, missing):
    _, credentials, use = await composite(world)
    with pytest.raises(ValueError):
        SecretsAudit(
            credentials=None if missing == "credentials" else credentials,
            use=None if missing == "use" else use,
        )


async def test_designation_reaches_the_credential_branch_and_sole_signed_outbox(world):
    _, credentials, _ = await composite(world)
    await designate(world, credentials)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    assert (
        await world.db.fetch_value("SELECT kind FROM {{tables.credential_audit_events}}")
        == AuditKind.APPROVER_DESIGNATED.value
    )


class AbortEffect(Exception):
    pass


async def test_change_ceremony_records_locally_and_rolls_back_with_its_original_tx(world):
    await enrol_owner(world, ALICE, "owner@example.com")
    await composite(world)
    baseline = {
        table: await world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}")
        for table in ("approvals", "change_sets", "credential_audit_events", "outbox_events")
    }
    request = change_set(
        drafter=by_member(ALICE),
        changes=[designate_approver("finance", "finance@example.com", ["sec_19ab42"])],
    )
    with pytest.raises(AbortEffect):
        async with world.db.transaction() as tx:
            pending = await world.change_sets.draft(tx, request)
            assert (
                await tx.fetch_value(
                    "SELECT approval_id FROM {{tables.credential_audit_events}} WHERE approval_id=$1",
                    pending.approval.approval_id,
                )
                == pending.approval.approval_id
            )
            assert (
                await tx.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
                == baseline["outbox_events"]
            )
            raise AbortEffect
    for table in ("approvals", "change_sets", "credential_audit_events", "outbox_events"):
        assert (
            await world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}")
            == baseline[table]
        )


async def test_use_decision_and_signed_event_roll_back_on_the_original_caller_tx(uses):
    use, view, pending, _, _ = await composition(uses)
    world = uses.world
    credentials = await audit_for(world, shared_producer=use._producer)
    sink = SecretsAudit(credentials=credentials, use=use)
    uses.approvals._audit = sink
    world.passkeys._audit = sink
    event_count = await world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    credential_count = await world.db.fetch_value(
        "SELECT count(*) FROM {{tables.credential_audit_events}}"
    )
    approval_id = pending.pending.approval.approval_id
    [token] = [t for aid, t in world.inbox.links["finance@acme.com"] if aid == approval_id]
    options = await uses.approvals.challenge(
        approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    proof = world.devices["finance@acme.com"].get(dict(options))
    with pytest.raises(AbortEffect), use.prepared_view(view):
        async with world.db.transaction() as tx:
            await uses.approvals.decide(
                approval_id, Decision.APPROVE, Assurance.PASSKEY, proof, link_token=token, tx=tx
            )
            original = await PgApprovalStore(world.db).get_in(approval_id, tx)
            assert original.state is ApprovalState.APPROVED
            assert (
                await tx.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
                == event_count + 1
            )
            assert (
                await tx.fetch_value("SELECT count(*) FROM {{tables.credential_audit_events}}")
                == credential_count
            )
            raise AbortEffect
    assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == event_count
    )
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.use_approval_audit_proofs}}") == 0
    )


async def test_reserved_run_refuses_without_a_governance_fallback_or_run_tables(world):
    sink, _, _ = await composite(world)
    event = AuditEvent(
        AuditKind.APPROVAL_REQUESTED,
        "requester",
        "approval",
        datetime.now(UTC),
        approval_id="approval",
        details={"policy_ref": "secrets.run|installation|team|grant|digest|-|-|-"},
    )
    with pytest.raises(UseAuditUnavailable):
        async with world.db.transaction() as tx:
            await sink.emit(event, tx)
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.credential_audit_events}}") == 0
    )
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
