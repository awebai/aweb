"""Derived coverage and containment through real stored ancestry, B2 and passkeys."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.approvals import ApprovalState, DispatchOutcome
from aweb_naapp.runtime.audit import AuditKind
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import derived_lineage, records, use_approvals
from aweb_secrets.admission import AdmissionRefused, admit_use
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_approval import UseApprovalRefused
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_use_approvals import (
    POLICY_BODY,
    REQUESTER,
    SECRET,
    SECRET_ID,
    approve,
    designate,
    install,
    open_action,
    use_request,
    uses,  # noqa: F401
)


def grant_record(grant_id, secret_id, policy_digest):
    return GrantRecord.from_after(
        {
            "v": 1,
            "grant_id": grant_id,
            "secret_id": secret_id,
            "subject": {"principal": principal_key(REQUESTER).principal_did},
            "capability": "use",
            "operations": [],
            "open_request": True,
            "jobs": [],
            "policy_digest": policy_digest,
        }
    )


async def seed(context):
    await designate(context, "finance", "finance@acme.com")
    policy = await install(context)
    return f"grt_{policy.digest[:10]}"


async def child(
    context, *, secret_id="sec_child001", parent=SECRET_ID, source_grant=None, listed=("finance",)
):
    policy = Policy.from_body({**POLICY_BODY, "approvers": list(listed), "rate": []})
    secret = SecretRecord.from_after({**SECRET, "secret_id": secret_id, "ref": secret_id.lower()})
    grant = grant_record("grt_" + secret_id[4:], secret_id, policy.digest)
    now = context.clock()
    async with context.world.db.transaction() as tx:
        if source_grant is None:
            source_grant = await tx.fetch_value(
                "SELECT grant_id FROM {{tables.grants}} WHERE secret_id=$1 ORDER BY grant_id LIMIT 1",
                parent,
            )
        source_policy = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id=$1", source_grant
        )
        version = await tx.fetch_value(
            "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1", parent
        )
        await records.create_secret(tx, INSTALLATION_ID, TEAM, secret)
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, secret_id, 1)
        await records.create_policy(tx, INSTALLATION_ID, policy)
        await records.create_grant(tx, INSTALLATION_ID, TEAM, grant)
        await derived_lineage.record_lineage(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=secret_id,
            parent_secret_id=parent,
            parent_version=version,
            source_dispatch_id=str(uuid.uuid4()),
            source_grant_id=source_grant,
            issuing_principal=principal_key(REQUESTER).principal_did,
            policy_digest=source_policy,
            dispatch_started_at=now,
            upstream_expires_at=now + timedelta(hours=1),
            expires_at=now + timedelta(minutes=30),
            clock=context.clock,
        )
    return secret, grant


async def request_child(context, secret, request_id=None, *, max_ttl_s=3600, started=None):
    dispatch_id = uuid.uuid4()
    async with context.world.db.transaction() as tx:
        if started is not None:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
        admission = await admit_use(
            tx,
            fence=context.world.fence,
            grant=context.grant,
            principal=REQUESTER,
            request=replace(use_request(request_id or str(uuid.uuid4())), secret_ref=secret.ref),
            attestation=None,
            now=context.clock(),
            clock=context.clock,
        )
        pending = await use_approvals.request_use_approval(
            tx,
            context.approvals,
            admission=admission,
            dispatch_id=dispatch_id,
            principal=REQUESTER,
            action=open_action(),
            reason="derived use",
            max_ttl_s=max_ttl_s,
        )
    await context.approvals.deliver(pending.pending)
    return admission, dispatch_id, pending


async def admit(context, admission, dispatch_id, *, max_ttl_s=3600, started=None):
    async with context.world.db.transaction() as tx:
        if started is not None:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
        await context.world.fence.admit(tx, context.grant)
        return await use_approvals.admit_approved_use(
            tx,
            context.approvals,
            intent_id=admission.intent_id,
            dispatch_id=dispatch_id,
            max_ttl_s=max_ttl_s,
        )


@pytest.mark.parametrize("depth", [1, 2])
async def test_a_listed_ancestor_approver_can_decide_a_child(uses, depth):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses)
    if depth == 2:
        secret, _ = await child(uses, secret_id="sec_grand001", parent=secret.secret_id)
    admission, dispatch_id, pending = await asyncio.wait_for(request_child(uses, secret), 5)
    assert [c.scope for c in pending.pending.approval.candidates]
    await approve(uses, pending, "finance@acme.com")
    result = await admit(uses, admission, dispatch_id)
    assert result.refusal is None and result.admission.first and result.admission.may_send


async def test_coverage_withdrawal_and_approval_revocation_do_not_deadlock_admission(uses):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, secret)
    await approve(uses, pending, "finance@acme.com")
    db = uses.world.db
    worker_pid = asyncio.get_running_loop().create_future()

    async def consumer():
        async with db.transaction() as tx:
            worker_pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await uses.world.fence.admit(tx, uses.grant)
            return await use_approvals.admit_approved_use(
                tx, uses.approvals, intent_id=admission.intent_id, dispatch_id=dispatch_id
            )

    task = None
    try:
        async with db.transaction() as withdrawal:
            withdrawing = await withdrawal.fetch_value("SELECT pg_backend_pid()")
            await withdrawal.execute(
                "UPDATE {{tables.approvers}} SET covers='[]' WHERE approver_ref='finance'"
            )
            task = asyncio.create_task(consumer())
            pid = await asyncio.wait_for(worker_pid, 5)
            async with asyncio.timeout(5):
                while withdrawing not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    await asyncio.sleep(0.01)
                # A backwards B2-before-coverage lock order deadlocks here.
                await uses.approvals.revoke_many(
                    [pending.pending.approval.approval_id],
                    revoked_by="owner",
                    reason="coverage_withdrawn",
                    tx=withdrawal,
                )
        result = await asyncio.wait_for(task, 5)
        assert result.refusal == "approval_revoked" and result.admission is None
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("stage", ["mint", "admission"])
async def test_the_current_deployment_ttl_cap_is_used(uses, stage):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses)
    if stage == "admission":
        admission, dispatch_id, pending = await request_child(uses, secret)
        await approve(uses, pending, "finance@acme.com")
    uses.clock.now += timedelta(seconds=61)
    if stage == "mint":
        with pytest.raises(UseApprovalRefused) as refused:
            await request_child(uses, secret, max_ttl_s=60)
        assert refused.value.code == "secret_disabled"
    else:
        assert (
            await admit(uses, admission, dispatch_id, max_ttl_s=60)
        ).refusal == "secret_disabled"


@pytest.mark.parametrize(
    "stage,lock", [("mint", "coverage"), ("admission", "coverage"), ("admission", "approval")]
)
async def test_expiry_during_a_later_lock_wait_refuses_new_authority(uses, stage, lock):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses)
    if stage == "admission":
        admission, dispatch_id, pending = await request_child(uses, secret)
        await approve(uses, pending, "finance@acme.com")
    db = uses.world.db
    started = asyncio.get_running_loop().create_future()
    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            if lock == "coverage":
                await holder.execute(
                    "UPDATE {{tables.approvers}} SET covers=covers WHERE approver_ref='finance'"
                )
            else:
                await holder.fetch_value(
                    "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE",
                    pending.pending.approval.approval_id,
                )
            operation = (
                request_child(uses, secret, max_ttl_s=60, started=started)
                if stage == "mint"
                else admit(uses, admission, dispatch_id, max_ttl_s=60, started=started)
            )
            task = asyncio.create_task(operation)
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    await asyncio.sleep(0.01)
            uses.clock.now += timedelta(seconds=61)
        if stage == "mint":
            with pytest.raises(UseApprovalRefused) as refused:
                await asyncio.wait_for(task, 5)
            assert refused.value.code == "secret_disabled"
        else:
            result = await asyncio.wait_for(task, 5)
            assert result.refusal == "secret_disabled" and result.admission is None
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("expires", [False, True])
async def test_expiry_during_b2_decider_read_rolls_back_send_authority(uses, retry, expires):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, secret)
    await approve(uses, pending, "finance@acme.com")
    approval_id = pending.pending.approval.approval_id
    if retry:
        assert (await admit(uses, admission, dispatch_id)).admission.may_send
        await uses.approvals.record_outcome(approval_id, str(dispatch_id), DispatchOutcome.NOT_SENT)
    db = uses.world.db
    dispatch_snapshot = (
        "SELECT consumed_operation_id, consumed_at, dispatch_outcome, outcome_at "
        "FROM {{tables.approvals}} WHERE approval_id=$1"
    )
    before = await db.fetch_one(dispatch_snapshot, approval_id)
    admitted_events = await db.fetch_value(
        "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind=$1",
        AuditKind.DISPATCH_ADMITTED.value,
    )
    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            # Only B2's decider read touches this table during admission.
            # Its plain SELECT must really wait, without replacing any adapter.
            await holder.execute("LOCK TABLE {{tables.passkey_approvers}} IN ACCESS EXCLUSIVE MODE")
            task = asyncio.create_task(admit(uses, admission, dispatch_id, max_ttl_s=60))
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE $1=ANY(pg_blocking_pids(pid)) "
                    "AND query LIKE '%passkey_approvers%')",
                    blocker,
                ):
                    await asyncio.sleep(0.01)
            if expires:
                uses.clock.now += timedelta(seconds=61)
        result = await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    after = await uses.approvals.get(approval_id)
    events_after = await db.fetch_value(
        "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind=$1",
        AuditKind.DISPATCH_ADMITTED.value,
    )
    if not expires:
        assert result.refusal is None and result.admission.may_send
        assert after.dispatch_outcome is DispatchOutcome.DISPATCHING
        assert events_after == admitted_events + 1
        return
    assert result.refusal == "secret_disabled" and result.admission is None
    assert dict(await db.fetch_one(dispatch_snapshot, approval_id)) == dict(before)
    assert events_after == admitted_events
    assert after.revoked_at is not None
    assert after.state is (ApprovalState.CONSUMED if retry else ApprovalState.REVOKED)


async def test_an_unlisted_ancestor_approver_is_refused_before_mint(uses):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses, listed=("unlisted",))
    with pytest.raises(UseApprovalRefused) as refused:
        await request_child(uses, secret)
    assert refused.value.code == "no_eligible_approver"
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.use_approvals}}") == 0


@pytest.mark.parametrize("stage", ["pending", "approved", "not_sent"])
async def test_withdrawn_coverage_voids_a_new_admission_or_unsent_retry(uses, stage):  # noqa: F811
    await seed(uses)
    secret, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, secret)
    if stage != "pending":
        await approve(uses, pending, "finance@acme.com")
    if stage == "not_sent":
        assert (await admit(uses, admission, dispatch_id)).admission.may_send
        await uses.approvals.record_outcome(
            pending.pending.approval.approval_id, str(dispatch_id), DispatchOutcome.NOT_SENT
        )
    async with uses.world.db.transaction() as tx:
        await tx.execute("UPDATE {{tables.approvers}} SET covers='[]' WHERE approver_ref='finance'")
    result = await admit(uses, admission, dispatch_id)
    assert result.refusal == "approval_revoked" and result.admission is None
    approval = await uses.approvals.get(pending.pending.approval.approval_id)
    assert approval.revoked_at is not None


@pytest.mark.parametrize("change", ["coverage", "source_grant", "expiry"])
async def test_stable_retrieval_survives_lost_ancestor_authority(uses, change):  # noqa: F811
    source = await seed(uses)
    secret, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, secret)
    await approve(uses, pending, "finance@acme.com")
    assert (await admit(uses, admission, dispatch_id)).admission.first
    async with uses.world.db.transaction() as tx:
        if change == "coverage":
            await tx.execute(
                "UPDATE {{tables.approvers}} SET covers='[]' WHERE approver_ref='finance'"
            )
        elif change == "source_grant":
            await records.revoke_grant(tx, INSTALLATION_ID, source)
    if change == "expiry":
        uses.clock.now += timedelta(hours=1)
    retrieved = await admit(uses, admission, dispatch_id)
    assert retrieved.refusal is None
    assert not retrieved.admission.first and not retrieved.admission.may_send
    assert retrieved.admission.dispatch_outcome is DispatchOutcome.DISPATCHING


async def test_an_ancestor_grant_revoked_before_mint_refuses_the_request(uses):  # noqa: F811
    source = await seed(uses)
    secret, _ = await child(uses)
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION_ID, source)
    with pytest.raises(AdmissionRefused) as refused:
        await request_child(uses, secret)
    assert refused.value.code == "grant_revoked"


@pytest.mark.parametrize(
    "change,code",
    [
        ("source_grant", "grant_revoked"),
        ("version", "secret_version_changed"),
        ("expiry", "secret_disabled"),
    ],
)
async def test_ancestor_authority_is_rechecked_before_first_admission(uses, change, code):  # noqa: F811
    source = await seed(uses)
    secret, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, secret)
    await approve(uses, pending, "finance@acme.com")
    async with uses.world.db.transaction() as tx:
        if change == "source_grant":
            await records.revoke_grant(tx, INSTALLATION_ID, source)
        elif change == "version":
            await records.set_active_version(tx, INSTALLATION_ID, TEAM, SECRET_ID, 5)
    if change == "expiry":
        uses.clock.now += timedelta(minutes=31)
    assert (await admit(uses, admission, dispatch_id)).refusal == code


async def test_scoped_invalidation_commits_with_grant_revoke_and_preserves_other_siblings(uses):  # noqa: F811
    source = await seed(uses)
    first, first_grant = await child(uses)
    grandchild, _ = await child(uses, secret_id="sec_grand001", parent=first.secret_id)
    async with uses.world.db.transaction() as tx:
        digest = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id=$1", source
        )
        other_source = grant_record("grt_sibling_source", SECRET_ID, digest)
        await records.create_grant(tx, INSTALLATION_ID, TEAM, other_source)
    sibling, _ = await child(uses, secret_id="sec_sibling01", source_grant=other_source.grant_id)
    # Cover the exact children too, so this selector test isolates invalidation
    # from ancestor-candidate selection.
    async with uses.world.db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.approvers}} SET covers=$1",
            json.dumps([SECRET_ID, first.secret_id, grandchild.secret_id, sibling.secret_id]),
        )
    waiting = await request_child(uses, first)
    approved = await request_child(uses, grandchild)
    await approve(uses, approved[2], "finance@acme.com")
    untouched = await request_child(uses, sibling)
    ids = [first.secret_id, grandchild.secret_id]

    async def invalidate(tx, installation=INSTALLATION_ID, team=TEAM):
        return await use_approvals.revoke_use_approvals(
            tx,
            uses.approvals,
            installation_id=installation,
            team_id=team,
            secret_ids=ids,
            revoked_by="owner",
            reason="grant_revoked",
        )

    async with uses.world.db.transaction() as tx:
        assert await invalidate(tx, installation="other-installation") == []
        assert await invalidate(tx, team="other:example.com") == []
    with pytest.raises(RuntimeError):
        async with uses.world.db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION_ID, source)
            await invalidate(tx)
            raise RuntimeError("rollback")
    assert (await uses.approvals.get(waiting[2].pending.approval.approval_id)).revoked_at is None
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION_ID, source)
        revoked = await invalidate(tx)
    assert set(revoked) == {
        waiting[2].pending.approval.approval_id,
        approved[2].pending.approval.approval_id,
    }
    for item in (waiting, approved):
        assert (
            await uses.approvals.get(item[2].pending.approval.approval_id)
        ).state is ApprovalState.REVOKED
    assert (await uses.approvals.get(untouched[2].pending.approval.approval_id)).revoked_at is None


@pytest.mark.parametrize("include_descendants", [False, True])
async def test_source_grant_union_is_scoped_and_atomic(uses, include_descendants):  # noqa: F811
    source = await seed(uses)
    root = SecretRecord.from_after(SECRET)
    direct_pending = await request_child(uses, root)
    direct_approved = await request_child(uses, root)
    await approve(uses, direct_approved[2], "finance@acme.com")
    derived, _ = await child(uses)
    descendant = await request_child(uses, derived)
    # This valid ID sorts before the source grant's hexadecimal digest suffix,
    # so real admission chooses it for the control approvals on the same secret.
    async with uses.world.db.transaction() as tx:
        digest = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id=$1", source
        )
        other_grant = grant_record("grt_----control", SECRET_ID, digest)
        await records.create_grant(tx, INSTALLATION_ID, TEAM, other_grant)
    controls = [await request_child(uses, root), await request_child(uses, root)]
    await approve(uses, controls[1][2], "finance@acme.com")
    assert all(item[0].grant_id == other_grant.grant_id for item in controls)
    assert direct_pending[0].grant_id == direct_approved[0].grant_id == source
    ids = [derived.secret_id, derived.secret_id] if include_descendants else []

    async def invalidate(tx, installation=INSTALLATION_ID, team=TEAM, grant=source):
        return await use_approvals.revoke_use_approvals(
            tx,
            uses.approvals,
            installation_id=installation,
            team_id=team,
            secret_ids=ids,
            source_grant_id=grant,
            revoked_by="owner",
            reason="grant_revoked",
        )

    expected = {item[2].pending.approval.approval_id for item in (direct_pending, direct_approved)}
    if include_descendants:
        expected.add(descendant[2].pending.approval.approval_id)
    async with uses.world.db.transaction() as tx:
        assert await invalidate(tx, installation="other-installation") == []
        assert await invalidate(tx, team="other:example.com") == []
    with pytest.raises(RuntimeError):
        async with uses.world.db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION_ID, source)
            assert set(await invalidate(tx)) == expected
            raise RuntimeError("rollback")
    for item in (direct_pending, direct_approved, descendant, *controls):
        assert (await uses.approvals.get(item[2].pending.approval.approval_id)).revoked_at is None
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION_ID, source)
        assert set(await invalidate(tx)) == expected
    for item in (direct_pending, direct_approved):
        assert (
            await uses.approvals.get(item[2].pending.approval.approval_id)
        ).state is ApprovalState.REVOKED
    for item in controls:
        assert (await uses.approvals.get(item[2].pending.approval.approval_id)).revoked_at is None
    assert (
        bool((await uses.approvals.get(descendant[2].pending.approval.approval_id)).revoked_at)
        is include_descendants
    )
