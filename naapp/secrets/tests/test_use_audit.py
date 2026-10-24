"""Actual B2/S12/B3 decisions and signed lifecycle records in one transaction."""

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aweb_naapp.dispatch import Dispatches, State, apply_dispatch_migrations
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentContext, CommitmentKey, Purpose, RequestBytes
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.approvals import Approvals, ApprovalState, Decision, PgApprovalStore
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.admission import admit_use
from aweb_secrets.broker_audit import BrokerAudit, freeze_broker_audit
from aweb_secrets.broker_fence import BrokerFence
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.use_approvals import UseApprovers, UsePolicies, request_use_approval
from aweb_secrets.use_audit import UseApprovalAudit, UseAuditUnavailable, is_use_approval
from aweb_secrets.use_context import UseCommitter, apply_use_context_migrations, store_use_context
from tests.test_broker_audit import envelopes
from tests.test_use_approvals import (
    BODY,
    REQUESTER,
    SECRET,
    TEAM,
    approve,
    designate,
    install,
    open_action,
    use_request,
)
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


def targets(now):
    return RegistrationView(
        TEAM,
        "post-secret-use-hook",
        datetime.now(UTC),
        timedelta(seconds=60),
        (
            Registration(
                str(uuid4()),
                "https://logs.example.com",
                "POST",
                "/hooks/ingest",
                now - timedelta(days=1),
            ),
        ),
    )


async def composition(uses, *, awaiting=True):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    db = uses.world.db
    await apply_dispatch_migrations(db)
    await apply_use_context_migrations(db)
    seed = os.urandom(32)

    def producer(*, installation_id, generation):
        return HookProducer(
            ServerProducer.app(
                origin="https://secrets.example.com",
                app_id="secrets",
                installation_id=installation_id,
                generation=generation,
                kid="use-audit-test",
                seed=seed,
            ),
            clock=uses.clock,
        )

    store = PgApprovalStore(db)

    async def approval(tx, approval_id):
        # The shared 18.42 getter, on the exact callback transaction.
        return await store.get_in(approval_id, tx)

    audit = UseApprovalAudit(
        producer=producer,
        passkeys=lambda: uses.world.passkeys,
        approval=approval,
        max_backlog_age=timedelta(minutes=5),
        clock=uses.clock,
    )
    uses.approvals = Approvals(
        store=store,
        policies=UsePolicies(db),
        approvers=UseApprovers(db, uses.world.passkeys, uses.world.directory),
        delivery=uses.world.inbox,
        authenticators=[uses.world.passkeys.authenticator()],
        audit=audit,
        clock=uses.clock,
    )
    async with db.transaction() as tx:
        await records.create_destination(
            tx,
            INSTALLATION_ID,
            TEAM,
            DestinationRecord.from_after(
                {
                    "v": 1,
                    "destination_id": "dst_useaudit",
                    "secret_id": SECRET["secret_id"],
                    "scheme": "https",
                    "host": "api.payments.example",
                    "port": 443,
                    "path": "/v1/**",
                    "methods": ["POST"],
                    "query_rules": {},
                    "header_allow": ["content-type"],
                    "network": "public",
                    "cidr": None,
                },
                internal_destinations=InternalDestinations.DISABLED,
            ),
        )
    dispatch_id, request = uuid4(), use_request()
    view = targets(uses.clock())
    machine = Dispatches(
        on_transition=BrokerAudit(producer=producer, view=view),
        max_dispatch=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=5),
    )
    with audit.prepared_view(view), audit.minting(dispatch_id):
        async with db.transaction() as tx:
            admission = await admit_use(
                tx,
                fence=uses.world.fence,
                grant=uses.grant,
                principal=REQUESTER,
                request=request,
                attestation=None,
                now=uses.clock(),
            )
            fence = BrokerFence(
                uses.world.fence,
                admission=admission,
                principal=REQUESTER,
                request=request,
                dispatch_id=dispatch_id,
                headers=[],
                attestation=None,
                clock=uses.clock,
                derived_max_ttl_s=3600,
                internal_destinations=InternalDestinations.DISABLED,
                open_call=open_action(),
            )
            await fence.prepare(tx)
            context = CommitmentContext(
                "secrets", TEAM, INSTALLATION_ID, admission.installation.generation, "request"
            )
            committer = UseCommitter(
                CommitmentKey(Purpose.SECRET_REQUEST, os.urandom(32)),
                CommitmentKey(Purpose.SECRET_PARAMS, os.urandom(32)),
            )
            await store_use_context(
                tx,
                admission=admission,
                dispatch_id=dispatch_id,
                commitments=committer.commit(
                    context,
                    RequestBytes(
                        "POST", b"/v1/secrets/staging-api/requests", (b"application/json",), BODY
                    ),
                    parameters=None,
                ),
            )
            await freeze_broker_audit(
                tx,
                admission=admission,
                principal=REQUESTER,
                dispatch_id=dispatch_id,
                call=fence.call,
            )
            pending = await request_use_approval(
                tx,
                uses.approvals,
                admission=admission,
                dispatch_id=dispatch_id,
                principal=REQUESTER,
                action=open_action(),
                reason="refund",
            )
            await machine.create(tx, dispatch_id=dispatch_id, subject="use-audit", action="broker")
            if awaiting:
                await machine.await_approval(tx, dispatch_id)
            await fence.check_authority(tx, await machine.get(tx, dispatch_id))
    await uses.approvals.deliver(pending.pending)
    return audit, view, pending, machine, dispatch_id


async def test_approved_records_original_requester_and_sole_retained_proof_commitment(uses):
    audit, view, pending, _, _ = await composition(uses)
    with audit.prepared_view(view):
        await approve(uses, pending, "finance@acme.com")
    events = await envelopes(uses.world.db)
    assert [e["payload"]["action"] for e in events] == ["approval_requested", "approval_decided"]
    result = events[-1]
    assert result["actor"]["did_key"] == REQUESTER.did_key
    assert result["payload"]["approval_decision"] == "approved"
    approval = await uses.approvals.get(pending.pending.approval.approval_id)
    decided = approval.decided_by
    expected = await uses.world.passkeys.evidence_commitment(
        decided.evidence_ref,
        context=PasskeyInstallationContext(
            app_id="secrets",
            team_id=TEAM,
            installation_id=INSTALLATION_ID,
            generation=uses.world.admitted.generation,
        ),
        scope=decided.scope,
        subject=decided.subject,
        purpose="approve",
    )
    assert result["payload"]["approval_evidence_sha256"] == expected
    assert "approval_credential_id" not in result["payload"]
    assert decided.evidence_ref not in repr(events) and decided.subject not in repr(events)
    proof = await uses.world.db.fetch_one("SELECT * FROM {{tables.use_approval_audit_proofs}}")
    assert (proof["commitment"], proof["purpose"]) == (expected, "approve")


async def test_positive_decision_rolls_back_without_a_target_but_rejection_records(uses):
    audit, view, pending, _, _ = await composition(uses)
    with audit.prepared_view(replace(view, registrations=())):
        with pytest.raises(Refused) as refused:
            await approve(uses, pending, "finance@acme.com")
    assert refused.value.code == "audit_target_unavailable"
    assert (
        await uses.approvals.get(pending.pending.approval.approval_id)
    ).state is ApprovalState.PENDING
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.use_approval_audit_proofs}}")
        == 0
    )
    assert len(await envelopes(uses.world.db)) == 1
    await approve(uses, pending, "finance@acme.com", decision=Decision.REJECT)
    assert (await envelopes(uses.world.db))[-1]["payload"]["approval_decision"] == "denied"


async def test_revocation_records_without_prepared_targets_and_does_not_replace_proof(uses):
    audit, view, pending, _, _ = await composition(uses)
    with audit.prepared_view(view):
        await approve(uses, pending, "finance@acme.com")
    before = await uses.world.db.fetch_one("SELECT * FROM {{tables.use_approval_audit_proofs}}")
    await uses.approvals.revoke_many(
        [pending.pending.approval.approval_id], revoked_by="test", reason="grant_revoked"
    )
    assert (await envelopes(uses.world.db))[-1]["payload"]["approval_decision"] == "revoked"
    assert before == await uses.world.db.fetch_one(
        "SELECT * FROM {{tables.use_approval_audit_proofs}}"
    )


def test_run_slot_events_do_not_claim_the_broker_audit_branch():
    event = AuditEvent(
        AuditKind.APPROVAL_REQUESTED,
        "requester",
        "approval",
        datetime.now(UTC),
        approval_id="approval",
        details={"policy_ref": "secrets.run|installation|team|grant|digest|-|-|-"},
    )
    assert not is_use_approval(event)
    assert is_use_approval(
        replace(event, details={"policy_ref": "secrets.use|installation|team|grant|digest"})
    )


@pytest.mark.parametrize(
    "decision,state",
    [
        ("denied", State.APPROVAL_DENIED),
        ("expired", State.APPROVAL_EXPIRED),
        ("revoked", State.CANCELLED),
    ],
)
async def test_s3_closes_after_the_actual_matching_use_lifecycle_record(uses, decision, state):
    audit, _, pending, machine, dispatch_id = await composition(uses)
    approval_id = pending.pending.approval.approval_id
    async with uses.world.db.transaction() as tx:
        assert (await machine.get(tx, dispatch_id)).state is State.AWAITING_APPROVAL
    if decision == "denied":
        await approve(uses, pending, "finance@acme.com", decision=Decision.REJECT)
    elif decision == "revoked":
        await uses.approvals.revoke_many([approval_id], revoked_by="test", reason="grant_revoked")
    else:
        uses.clock.now += timedelta(seconds=901)
    before = await uses.world.db.fetch_one(
        "SELECT * FROM {{tables.approvals}} WHERE approval_id=$1", approval_id
    )
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.check(tx, uses.world.admitted)
        await uses.approvals.lock_many(tx, [approval_id])
        if decision == "expired":
            await audit.expired(tx, approval_id)
        await machine.close(tx, dispatch_id, state)
        assert (await machine.get(tx, dispatch_id)).state is state
    assert before == await uses.world.db.fetch_one(
        "SELECT * FROM {{tables.approvals}} WHERE approval_id=$1", approval_id
    )
    assert [e["payload"].get("approval_decision") for e in await envelopes(uses.world.db)] == [
        None,
        decision,
    ]


@pytest.mark.parametrize("state", [State.APPROVAL_DENIED, State.APPROVAL_EXPIRED, State.CANCELLED])
async def test_s3_cannot_close_without_the_matching_lifecycle_receipt(uses, state):
    _, _, _, machine, dispatch_id = await composition(uses)
    with pytest.raises(ValueError):
        async with uses.world.db.transaction() as tx:
            await machine.close(tx, dispatch_id, state)
    async with uses.world.db.transaction() as tx:
        assert (await machine.get(tx, dispatch_id)).state is State.AWAITING_APPROVAL


async def test_s3_cannot_start_waiting_when_the_requested_receipt_is_missing(uses):
    _, _, _, machine, dispatch_id = await composition(uses, awaiting=False)
    # Remove the operational receipt from an actual mint. The signed outbox
    # remains; a missing original receipt must still refuse this transition.
    await uses.world.db.execute(
        "DELETE FROM {{tables.broker_use_events}} WHERE dispatch_id=$1", dispatch_id
    )
    with pytest.raises(ValueError):
        async with uses.world.db.transaction() as tx:
            await machine.await_approval(tx, dispatch_id)
    async with uses.world.db.transaction() as tx:
        assert (await machine.get(tx, dispatch_id)).state is State.RECEIVED


async def test_expiry_cannot_be_recorded_before_the_live_b2_deadline(uses):
    audit, _, pending, _, _ = await composition(uses)
    with pytest.raises(UseAuditUnavailable):
        async with uses.world.db.transaction() as tx:
            await audit.expired(tx, pending.pending.approval.approval_id)
    assert len(await envelopes(uses.world.db)) == 1
