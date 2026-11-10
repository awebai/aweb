"""Decision authority prepares after real B3 verification and before B2 locks."""
# ruff: noqa: F811 -- pw is the imported real owner/passkey composition fixture.

import asyncio

import pytest

from aweb_naapp.runtime.approvals import ApprovalState, Assurance, Decision, Refusal
from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_passkeys import ceremony, enrol, mint, pw, refusal  # noqa: F401


class DecisionFenceRefused(Exception):
    """An application's final effect fence refused the decision."""


class DecisionFence:
    """Use actual B3 authority; the refusal case exercises callback rollback."""

    def __init__(self, world, approval, *, expected_tx=None, refuse=False):
        self.world, self.approval = world, approval
        self.expected_tx, self.refuse = expected_tx, refuse
        self.tx = None
        self.prepared = None
        self.calls = []
        self.started = asyncio.get_running_loop().create_future()

    async def prepare(self, tx):
        assert self.expected_tx is None or tx is self.expected_tx
        self.tx = tx
        self.calls.append("prepare")
        # Verification has committed its separate credential/assertion work.
        assert (
            await tx.fetch_value(
                "SELECT count(*) FROM {{tables.passkey_assertions}} WHERE purpose='approve'"
            )
            == 1
        )
        self.started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
        [candidate] = self.approval.candidates
        self.prepared = await self.world.passkeys.prepare_current_approvers(
            tx, [(candidate.scope, candidate.subject)]
        )
        # Prepare the final audit relation read as well.
        await tx.fetch_value("SELECT count(*) FROM {{tables.audit_outbox}}")

    async def check(self, tx):
        assert tx is self.tx
        self.calls.append("check")
        [candidate] = self.approval.candidates
        assert await self.world.passkeys.check_current_approver(
            tx, self.prepared, candidate.scope, candidate.subject
        )
        assert (
            await tx.fetch_value(
                "SELECT state FROM {{tables.approvals}} WHERE approval_id=$1",
                self.approval.approval_id,
            )
            == "approved"
        )
        assert (
            await tx.fetch_value(
                "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind='approval_decided'"
            )
            == 1
        )
        if self.refuse:
            raise DecisionFenceRefused()


async def decision(world, approval, proof, *, tx=None, fence=None):
    return await world.approvals.decide(
        approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        proof,
        link_token=world.contacts.by_approval[approval.approval_id],
        tx=tx,
        fence=fence,
    )


@pytest.mark.parametrize("caller_tx", [False, True], ids=["owned-tx", "caller-tx"])
async def test_decision_prepares_and_checks_the_same_effect_transaction(pw, caller_tx):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    if caller_tx:
        async with pw.passkeys.db.transaction() as tx:
            fence = DecisionFence(pw, approval, expected_tx=tx)
            decided = await decision(pw, approval, proof, tx=tx, fence=fence)
    else:
        fence = DecisionFence(pw, approval)
        decided = await decision(pw, approval, proof, fence=fence)
    assert fence.calls == ["prepare", "check"]
    assert decided.state is ApprovalState.APPROVED
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.APPROVED


@pytest.mark.parametrize("caller_tx", [False, True], ids=["owned-tx", "caller-tx"])
async def test_final_refusal_rolls_back_decision_and_audit_but_keeps_assertion_spent(pw, caller_tx):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    if caller_tx:
        async with pw.passkeys.db.transaction() as tx:
            fence = DecisionFence(pw, approval, expected_tx=tx, refuse=True)
            # Even a caller catching the refusal must not commit a B2 decision.
            with pytest.raises(DecisionFenceRefused):
                await decision(pw, approval, proof, tx=tx, fence=fence)
    else:
        fence = DecisionFence(pw, approval, refuse=True)
        with pytest.raises(DecisionFenceRefused):
            await decision(pw, approval, proof, fence=fence)
    assert fence.calls == ["prepare", "check"]
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
    db = pw.passkeys.db
    assert not await db.fetch_value(
        "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind='approval_decided'"
    )
    assert not await db.fetch_value(
        "SELECT count(*) FROM {{tables.approval_links}} WHERE approval_id=$1 AND used_at IS NOT NULL",
        approval.approval_id,
    )
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_assertions}} WHERE purpose='approve'"
        )
        == 1
    )
    assert await refusal(decision(pw, approval, proof)) is Refusal.AUTHENTICATION_FAILED


async def test_b3_wait_after_verification_leaves_the_first_b2_decision_lock_free(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    [candidate] = approval.candidates
    db = pw.passkeys.db
    fence = DecisionFence(pw, approval)
    task = None
    try:
        async with db.transaction() as blocker:
            holder = await blocker.fetch_value("SELECT pg_backend_pid()")
            await blocker.fetch_value(
                "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope=$1 AND subject=$2 "
                "FOR UPDATE",
                SCOPE,
                candidate.subject,
            )
            task = asyncio.create_task(decision(pw, approval, proof, fence=fence))
            waiter = await asyncio.wait_for(fence.started, 5)
            async with asyncio.timeout(5):
                while holder not in await db.fetch_value("SELECT pg_blocking_pids($1)", waiter):
                    if task.done():
                        await task
                        pytest.fail("decision finished before B3 preparation")
                    await asyncio.sleep(0.01)
            async with db.transaction() as observer:
                assert (
                    await observer.fetch_value(
                        "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 "
                        "FOR UPDATE NOWAIT",
                        approval.approval_id,
                    )
                    == approval.approval_id
                )
        assert (await asyncio.wait_for(task, 5)).state is ApprovalState.APPROVED
        assert fence.calls == ["prepare", "check"]
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
