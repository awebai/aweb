"""Real B2/B3 controls bind one owner/outcome, with local-only ceremony audit."""

from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from aweb_naapp.dispatch import State
from aweb_naapp.runtime.approvals import Assurance, Decision, PgApprovalStore
from aweb_naapp.runtime.approvals.request import request_sha256
from aweb_naapp.runtime.audit import AuditEvent, AuditKind

from aweb_secrets.owners import owner_scope
from aweb_secrets.reconciliation_control_audit import (
    ReconciliationAudit,
    apply_reconciliation_migrations,
    is_reconciliation_control,
)
from aweb_secrets.reconciliation_policy import (
    ReconciliationApprovers,
    ReconciliationPolicies,
    reconciliation_policy_ref,
    reconciliation_request,
)
from aweb_secrets.reconciliation_reads import ReconciliationReads
from aweb_secrets.use_audit import UseAuditUnavailable
from tests.test_broker_audit import envelopes
from tests.test_change_sets import ALICE, TEAM
from tests.test_run_dispatch_service import decide, setup
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def control_world(uses, *, approval_required=False):
    context = await setup(uses, approval_required=approval_required)
    if approval_required:
        pending = await context.service.submit(
            job=context.job.job_id, submission=context.submission
        )
        await decide(context, pending, Decision.APPROVE)
    admitted, _, _ = await context.assigned()
    db = uses.world.db
    uses.approvals = context.arguments["approvals"]
    await db.execute(
        "UPDATE {{tables.dispatches}} SET sweep_after=clock_timestamp()-interval '1 second'"
    )
    assert await context.service.sweep() == 1
    await apply_reconciliation_migrations(db)
    scope = uses.world.admitted
    reads = ReconciliationReads(enable_runs=True)
    store = PgApprovalStore(db)

    async def approval(tx, approval_id):
        return await store.get_in(approval_id, tx)

    audit = ReconciliationAudit(
        reads=reads, approval=approval, passkeys=lambda: uses.world.passkeys
    )
    policies = ReconciliationPolicies(db, owners=uses.world.directory)
    approvers = ReconciliationApprovers(owners=uses.world.directory)
    # Actual shared services, with only the root's provider/classifier routing
    # adapted here. No second store, authenticator, approval service or outbox.
    prior_policies, prior_approvers, prior_audit = (
        uses.approvals._policies,
        uses.approvals._approvers,
        uses.approvals._audit,
    )

    class Policies:
        async def current(self, ref):
            if ref.startswith("secrets.reconcile|"):
                return await policies.current(ref)
            return await prior_policies.current(ref)

    class Approvers:
        async def candidates(self, policy, request):
            if policy.policy_ref.startswith("secrets.reconcile|"):
                return await approvers.candidates(policy, request)
            return await prior_approvers.candidates(policy, request)

        async def is_current(self, scope, subject):
            return await prior_approvers.is_current(scope, subject)

    class Audit:
        async def emit(self, event, tx):
            if is_reconciliation_control(event):
                await audit.emit(event, tx)
            else:
                await prior_audit.emit(event, tx)

    uses.approvals._policies, uses.approvals._approvers, uses.approvals._audit = (
        Policies(),
        Approvers(),
        Audit(),
    )
    async with db.transaction() as tx:
        view = await reads.get(tx, scope=scope, reconcile_ref=admitted.body["request_ref"])
    assert view is not None and view.state is State.OUTCOME_UNKNOWN
    named_scope = owner_scope(scope.installation_id, TEAM, ALICE.principal_did)
    owner = await uses.world.passkeys.designated_approver(named_scope)
    assert owner is not None
    request = reconciliation_request(
        view.original,
        control_id=uuid4(),
        outcome="completed",
        owner_scope=owner.scope,
        owner_subject=owner.subject,
    )
    return context, view, request, audit, policies, approvers


async def test_fresh_control_approve_is_outcome_bound_local_audit_without_hook_or_settlement(uses):
    context, original, request, audit, _, _ = await control_world(uses)
    db, scope = uses.world.db, uses.world.admitted
    before = await envelopes(db)
    async with db.transaction() as tx:
        pending = await uses.approvals.mint(
            request=request,
            policy_ref=reconciliation_policy_ref(request),
            requested_by=ALICE.principal_did,
            tx=tx,
        )
        control = await audit.control(tx, scope=scope, approval_id=pending.approval.approval_id)
        assert control is not None and control.original == original.original
        assert control.outcome == "completed" and control.control_id == UUID(request["control_id"])
        for changed in (
            {**request, "outcome": "failed"},
            {**request, "control_id": str(uuid4())},
            {**request, "original": {**request["original"], "reconcile_ref": "other"}},
        ):
            assert request_sha256(changed) != request_sha256(request)
    assert await envelopes(db) == before
    await uses.approvals.deliver(pending)
    [delivery] = pending.deliveries
    challenge = await uses.approvals.challenge(
        pending.approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        link_token=delivery.link_token,
    )
    async with db.transaction() as tx:
        await uses.approvals.decide(
            pending.approval.approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            uses.world.devices["alice@acme.com"].get(dict(challenge)),
            link_token=delivery.link_token,
            tx=tx,
        )
    rows = await db.fetch_all("SELECT * FROM {{tables.reconciliation_control_proofs}}")
    assert len(rows) == 1
    assert rows[0]["purpose"] == "approve" and len(rows[0]["commitment"]) == 64
    assert delivery.link_token not in repr(rows)
    assert context.credential not in repr(rows)
    assert await envelopes(db) == before
    async with db.transaction() as tx:
        live = await ReconciliationReads(enable_runs=True).get(
            tx, scope=scope, reconcile_ref=original.original.reconcile_ref
        )
        assert live is not None and live.state is State.OUTCOME_UNKNOWN
        assert (
            await audit.control(
                tx,
                scope=replace(scope, team_id="foreign"),
                approval_id=pending.approval.approval_id,
            )
            is None
        )


async def test_control_directory_has_one_exact_owner_and_never_falls_back(uses):
    _, _, request, _, policies, approvers = await control_world(uses)
    policy = await policies.current(reconciliation_policy_ref(request))
    assert policy is not None and policy.allow_requester_approval
    candidates = await approvers.candidates(policy, request)
    assert [(c.scope, c.subject) for c in candidates] == [
        (request["owner"]["scope"], request["owner"]["subject"])
    ]
    for changed in (
        {**request, "owner": {**request["owner"], "subject": str(uuid4())}},
        {**request, "type": "aweb.secrets.use-approval"},
        {**request, "unexpected": True},
    ):
        assert await approvers.candidates(policy, changed) == []


async def test_control_association_and_audit_roll_back_with_the_b2_mint(uses):
    _, _, request, audit, _, _ = await control_world(uses)
    db = uses.world.db
    with pytest.raises(RuntimeError, match="rollback"):
        async with db.transaction() as tx:
            await uses.approvals.mint(
                request=request,
                policy_ref=reconciliation_policy_ref(request),
                requested_by=ALICE.principal_did,
                tx=tx,
            )
            raise RuntimeError("rollback")
    assert await db.fetch_value("SELECT count(*) FROM {{tables.reconciliation_controls}}") == 0
    assert (
        await db.fetch_value("SELECT count(*) FROM {{tables.reconciliation_control_events}}") == 0
    )
    with pytest.raises(UseAuditUnavailable):
        async with db.transaction() as tx:
            await audit.emit(
                AuditEvent(AuditKind.APPROVAL_REQUESTED, "other", "other", uses.clock()), tx
            )
