"""Composition proof: real B2/containment and the shared signed lifecycle outbox.

The adapter here fixes one original use's metadata. S13 owns the production
audit sink and its retained passkey-evidence composition; this fixture does not
implement or claim that integration.
"""

import json
import os
from datetime import timedelta

import asyncpg
import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.approvals import ApprovalRevocation, ApprovalState, PgApprovalStore
from aweb_naapp.runtime.audit import AuditKind
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.broker_audit import _actor
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_containment import disable
from tests.test_use_approvals import (
    REQUESTER,
    SECRET_ID,
    designate,
    install,
    request,
    uses,  # noqa: F401
)

HOOK = "post-secret-use-hook"
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


class FrozenUseAudit:
    """Only the actual B2 revocation, attributed to its original use requester."""

    def __init__(self, producer, approval_id, scope, *, fault=None):
        self.producer, self.approval_id, self.scope = producer, approval_id, scope
        self.fault = fault

    async def emit(self, event, transaction):
        assert event.kind is AuditKind.APPROVAL_REVOKED
        assert event.approval_id == self.approval_id
        body = {
            **self.scope,
            "action": "approval_decided",
            "approval_decision": "revoked",
            "approval_id": event.approval_id,
        }
        if self.fault == "catalog":
            body["unexpected"] = "refused"
        await self.producer.enqueue_lifecycle(
            transaction,
            team_id=TEAM,
            payload=body,
            actor={} if self.fault == "envelope" else _actor(REQUESTER),
            occurred_at=event.occurred_at,
            result_status="denied",
            signed_trace_id=TRACE,
        )


async def composition(context, *, fault=None):
    await designate(context, "finance", "finance@acme.com")
    await install(context)
    admission, _, pending = await request(context)
    approval = pending.pending.approval
    producer = HookProducer(
        ServerProducer.app(
            origin="https://secrets.example.com",
            app_id="secrets",
            installation_id=INSTALLATION_ID,
            generation=1,
            kid="lifecycle-test",
            seed=b"" if fault == "key" else os.urandom(32),
        ),
        clock=context.clock,
    )
    scope = {
        "op_kind": "broker",
        "secret_id": SECRET_ID,
        "secret_version": 4,
        "grant_id": admission.grant_id,
        "policy_digest": admission.policy_digest,
        "request_sha256": approval.request_sha256,
    }
    context.approvals._revocation = ApprovalRevocation(
        PgApprovalStore(context.world.db),
        FrozenUseAudit(producer, approval.approval_id, scope, fault=fault),
        clock=context.clock,
    )
    return producer, approval, scope


def unavailable(context, kind):
    now = context.clock()
    registration = Registration(
        binding_id="6f9619ff-8b86-4011-b42d-00c04fc964ff",
        origin="https://logs.example.com",
        method="POST",
        path="/hooks/ingest",
        active_from=now - timedelta(days=1),
    )
    if kind == "missing":
        return None
    return RegistrationView(
        team_id=TEAM,
        hook=HOOK,
        as_of=now - timedelta(seconds=61) if kind == "stale" else now,
        max_age=timedelta(seconds=60),
        registrations=() if kind == "empty" else (registration,),
    )


async def revocations(db):
    rows = await db.fetch_all(
        "SELECT payload,signature,critical FROM {{tables.outbox_events}} ORDER BY position"
    )
    return [
        (verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields, row["critical"])
        for row in rows
        if json.loads(bytes(row["payload"]).split(b"\n", 1)[1])["payload"].get("approval_decision")
        == "revoked"
    ]


@pytest.mark.parametrize("target", ["missing", "empty", "stale", "stalled"])
async def test_real_containment_and_b2_revoke_commit_despite_audit_availability(uses, target):  # noqa: F811
    producer, approval, scope = await composition(uses)
    db = uses.world.db
    if target == "stalled":
        async with db.transaction() as tx:
            event_id = await producer.enqueue_refusal(
                tx,
                team_id=TEAM,
                payload={
                    "action": "refused",
                    "op_kind": "broker",
                    "refusal_code": "audit_delivery_stalled",
                },
                actor=_actor(REQUESTER),
                occurred_at=uses.clock() - timedelta(hours=2),
            )
            await tx.execute(
                "UPDATE {{tables.outbox_events}} SET created_at=$2 WHERE event_id=$1",
                event_id,
                uses.clock() - timedelta(hours=2),
            )
    # This very same target/backlog state refuses a new admission.
    with pytest.raises(Refused) as refused:
        async with db.transaction() as tx:
            await producer.require_admission(
                tx,
                team_id=TEAM,
                hook=HOOK,
                occurred_at=uses.clock(),
                view=unavailable(uses, target),
                max_backlog_age=timedelta(hours=1),
            )
    assert refused.value.code == (
        "audit_delivery_stalled" if target == "stalled" else "audit_target_unavailable"
    )
    async with db.transaction() as tx:
        await disable(uses, tx)
        # Both the B2 state and the event already exist in THIS transaction.
        assert (
            await tx.fetch_value(
                "SELECT state FROM {{tables.approvals}} WHERE approval_id=$1", approval.approval_id
            )
            == "revoked"
        )
        assert (
            await tx.fetch_value(
                "SELECT count(*) FROM {{tables.outbox_events}} WHERE critical=false"
            )
            == 1
        )
        # An independent reader sees neither until commit.
        assert (await uses.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
        assert await revocations(db) == []
    assert (await uses.approvals.get(approval.approval_id)).state is ApprovalState.REVOKED
    assert (
        await db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "disabled"
    )
    [(event, critical)] = await revocations(db)
    assert critical is False
    assert event["actor"] == _actor(REQUESTER)
    assert event["trace"] == {"id": TRACE, "origin": "signed_request"}
    assert event["payload"] == {
        **scope,
        "action": "approval_decided",
        "approval_decision": "revoked",
        "approval_id": approval.approval_id,
    }


@pytest.mark.parametrize("fault", ["rollback", "storage", "catalog", "envelope", "key"])
async def test_actual_b2_and_secret_transition_roll_back_with_failed_local_recording(uses, fault):  # noqa: F811
    _, approval, _ = await composition(uses, fault=fault)
    db = uses.world.db
    if fault == "storage":
        await db.execute(
            "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_lifecycle "
            "CHECK (kind <> 'post-secret-use-hook')"
        )
    expected = (
        RuntimeError
        if fault == "rollback"
        else asyncpg.CheckViolationError
        if fault == "storage"
        else ValueError
    )
    with pytest.raises(expected):
        async with db.transaction() as tx:
            await disable(uses, tx)
            if fault == "rollback":
                raise RuntimeError("caller aborted its containment transaction")
    assert (await uses.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
    assert (
        await db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "active"
    )
    assert await revocations(db) == []
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_sequences}}") == 0
