"""Minting inside the app's own transaction: it commits with the app's writes,
and links are sent only once that transaction has committed."""

from __future__ import annotations

import pytest

from aweb_naapp.runtime.approvals import (
    ApprovalState,
    DeliveryStatus,
    PendingApproval,
    PresentationKind,
    RequesterView,
)
from tests.runtime.approvals.support import APPROVER, World, policy

REQUEST = {"operation": "deploy", "destination": {"host": "api.example.com"}, "executor": "broker"}


class Abandoned(Exception):
    pass


async def test_a_rolled_back_transaction_leaves_nothing_and_sends_nothing(world: World):
    with pytest.raises(Abandoned):
        async with world.store.db.transaction() as tx:
            pending = await world.approvals.mint(
                request=REQUEST, policy_ref="send-charge", requested_by="agent-1", tx=tx
            )
            raise Abandoned
    assert await world.approvals.for_request(pending.view.request_id) is None
    for table in ("approval_requests", "approvals", "approval_candidates", "approval_links"):
        assert await world.store.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == 0
    assert world.mailbox.sent == []
    assert await world.audit.rows() == []


async def test_links_are_sent_only_after_the_caller_commits_and_delivers(world: World):
    async with world.store.db.transaction() as tx:
        pending = await world.approvals.mint(
            request=REQUEST, policy_ref="send-charge", requested_by="agent-1", tx=tx
        )
        assert world.mailbox.sent == []
    assert world.mailbox.sent == []
    approval = await world.approvals.for_request(pending.view.request_id)
    assert approval.state is ApprovalState.PENDING
    assert pending.view.delivery_status is DeliveryStatus.PENDING
    view = await world.approvals.deliver(pending)
    assert [approver for approver, _ in world.mailbox.sent] == [APPROVER]
    assert view.delivery_status is DeliveryStatus.DELIVERED
    assert (
        await world.approvals.requester_view(view.request_id, "agent-1")
    ).delivery_status is DeliveryStatus.DELIVERED


async def test_a_task_presentation_minted_in_a_transaction_delivers_nothing(world: World):
    async with world.store.db.transaction() as tx:
        pending = await world.approvals.mint(
            request=REQUEST,
            policy_ref="send-charge",
            requested_by="agent-1",
            presentation=PresentationKind.TASK,
            presentation_ref="task-1",
            tx=tx,
        )
    assert pending.view.delivery_status is DeliveryStatus.NOT_REQUIRED
    assert (await world.approvals.deliver(pending)).delivery_status is DeliveryStatus.NOT_REQUIRED
    assert world.mailbox.sent == []


async def test_pending_deliveries_never_show_their_tokens(world: World):
    world.policies.set(policy())
    async with world.store.db.transaction() as tx:
        pending = await world.approvals.mint(
            request=REQUEST, policy_ref="send-charge", requested_by="agent-1", tx=tx
        )
    assert isinstance(pending, PendingApproval)
    await world.approvals.deliver(pending)
    [(_, token)] = world.mailbox.sent
    assert token not in repr(pending)
    assert token not in repr(pending.view)


async def test_without_a_transaction_mint_commits_and_delivers_at_once(world: World):
    view = await world.approvals.mint(
        request=REQUEST, policy_ref="send-charge", requested_by="agent-1"
    )
    assert isinstance(view, RequesterView)
    assert view.delivery_status is DeliveryStatus.DELIVERED
    assert [approver for approver, _ in world.mailbox.sent] == [APPROVER]
