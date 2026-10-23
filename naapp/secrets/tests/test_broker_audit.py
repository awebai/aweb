"""S3 and real signed hook outbox records commit together, without effect inputs."""

import copy
import json
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import asyncpg
import pytest
from aweb_naapp.dispatch import Dispatches, State
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.installation import InstallationFence

from aweb_secrets import records
from aweb_secrets.admission import UseRequest
from aweb_secrets.broker_audit import BrokerAudit, freeze_broker_audit
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.use_context import UseCommitments, apply_use_context_migrations, store_use_context
from tests.test_admission import (
    ALICE,
    NOW,
    POLICY_BODY,
    SECRET,
    TEAM,
    _admit,
    _grant_source_grant,
    _install,
)
from tests.test_admission import db as db
from tests.test_broker_fence import PARAMS, authority
from tests.test_operation_record import REFUND

INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"


class Installed:
    async def grant_for(self, team_id):
        return _grant_source_grant(installation_id=INSTALLATION) if team_id == TEAM else None


@pytest.fixture
def fence(db):
    return InstallationFence(db, app_id="secrets", grants=Installed())


async def setup(db, fence, *, open_call=None, policy_changes=None):
    import hashlib

    operation = OperationTemplate.from_after(copy.deepcopy(REFUND))
    pin = {"operation_id": operation.operation_id, "digest": operation.digest}
    await _install(
        db,
        installation_id=INSTALLATION,
        policy_body={
            **POLICY_BODY,
            "operations": [pin] if open_call is None else [],
            **(policy_changes or {}),
        },
        operations=[pin] if open_call is None else [],
        open_request=open_call is not None,
    )
    destination = DestinationRecord.from_after(
        {
            "v": 1,
            "destination_id": "dst_broker01",
            "secret_id": SECRET["secret_id"],
            "scheme": "https",
            "host": operation.after["url"]["host"],
            "port": 443,
            "path": "/v1/**",
            "methods": ["POST"],
            "query_rules": {},
            "header_allow": ["idempotency-key", "stripe-version", "x-request-id"],
            "network": "public",
            "cidr": None,
        },
        internal_destinations=InternalDestinations.DISABLED,
    )
    async with db.transaction() as tx:
        await records.create_operation(tx, INSTALLATION, TEAM, operation)
        await records.create_destination(tx, INSTALLATION, TEAM, destination)
    request = UseRequest(
        SECRET["ref"],
        "broker-request",
        hashlib.sha256(b"request").digest(),
        operation.operation_id if open_call is None else None,
        PARAMS if open_call is None else None,
    )
    admitted = await _admit(
        db,
        fence,
        request=request,
        grant=_grant_source_grant(installation_id=INSTALLATION),
        clock=lambda: NOW,
    )
    from aweb_naapp.dispatch import apply_dispatch_migrations

    await apply_dispatch_migrations(db)
    return operation, request, admitted


def source(installation_id, generation):
    return HookProducer(
        ServerProducer.app(
            origin="https://secrets.example.com",
            app_id="secrets",
            installation_id=installation_id,
            generation=generation,
            kid="secrets-hook-event-1",
            seed=bytes(range(32)),
        ),
    )


def view():
    return RegistrationView(
        TEAM,
        "post-secret-use-hook",
        datetime.now(UTC),
        timedelta(seconds=60),
        (Registration(str(uuid4()), "https://logs.example.com", "POST", "/hooks/ingest", NOW),),
    )


def machine(audit):
    return Dispatches(
        on_transition=audit, max_dispatch=timedelta(seconds=30), sweep_margin=timedelta(seconds=5)
    )


async def prepared(db, fence, *, open_call=None, policy_changes=None, signed_trace_id=None):
    _, request, admitted = await setup(
        db, fence, open_call=open_call, policy_changes=policy_changes
    )
    await apply_outbox_migrations(db)
    await apply_use_context_migrations(db)
    dispatch_id = uuid4()
    audit = BrokerAudit(producer=source, view=view())
    state = machine(audit)
    async with db.transaction() as tx:
        prepared_fence = authority(fence, admitted, request, dispatch_id, open_call=open_call)
        await prepared_fence.prepare(tx)
        await store_use_context(
            tx,
            admission=admitted,
            dispatch_id=dispatch_id,
            commitments=UseCommitments(
                CommitmentContext(
                    "secrets", TEAM, INSTALLATION, admitted.installation.generation, "request"
                ),
                "a" * 64,
                "b" * 64,
            ),
        )
        await freeze_broker_audit(
            tx,
            admission=admitted,
            principal=ALICE,
            dispatch_id=dispatch_id,
            call=prepared_fence.call,
            signed_trace_id=signed_trace_id,
        )
        await state.create(tx, dispatch_id=dispatch_id, subject="broker-subject", action="refund")
    return request, admitted, dispatch_id, state


async def envelopes(db):
    rows = await db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} ORDER BY position"
    )
    return [verify(bytes(r["payload"]), r["signature"], team_id=TEAM).fields for r in rows]


async def test_real_transitions_record_frozen_authority_actor_macs_and_original_start(db, fence):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    assert await envelopes(db) == []  # RECEIVED is not a catalog action.
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        final = authority(fence, admitted, request, dispatch_id)
        current = await state.begin_dispatch(tx, dispatch_id, fence=final)
        await final.check(tx, current)  # caller's final check follows the awaited enqueue.
    records = await envelopes(db)
    assert [e["payload"]["action"] for e in records] == ["admitted", "dispatching"]
    for event in records:
        p = event["payload"]
        assert p["secret_id"] == "sec_19ab42" and p["secret_version"] == 4
        assert p["grant_id"] == admitted.grant_id
        assert p["policy_digest"] == admitted.policy_digest
        assert p["request_sha256"] == "a" * 64 and p["params_sha256"] == "b" * 64
        assert event["actor"]["did_key"] == ALICE.did_key
        assert event["actor"]["certificate_id"] == ALICE.certificate_id
        assert p["target_path_template"] == "/v1/charges/{charge}/refunds"
        assert "params" not in p and "url" not in p
    started = await db.fetch_value("SELECT dispatch_started_at FROM {{tables.use_contexts}}")
    assert started is not None
    assert await db.fetch_value("SELECT count(*) FROM {{tables.broker_use_events}}") == 2


async def test_outbox_storage_failure_rolls_back_s3_and_operational_record_and_start(db, fence):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    # Real constraint failure inside the shared producer, rather than a substituted enqueue.
    await db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_hook CHECK (kind <> 'post-secret-use-hook') NOT VALID"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        async with db.transaction() as tx:
            await state.begin_dispatch(
                tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
            )
    async with db.transaction() as tx:
        assert (await state.get(tx, dispatch_id)).state is State.ADMITTED
    assert await db.fetch_value("SELECT count(*) FROM {{tables.broker_use_events}}") == 1
    assert await db.fetch_value("SELECT dispatch_started_at FROM {{tables.use_contexts}}") is None


@pytest.mark.parametrize("target", ["missing", "stale"])
@pytest.mark.parametrize("outcome", ["completed", "not_sent", "outcome_unknown", "reconciled"])
async def test_post_dispatch_recording_survives_target_loss_without_authorizing_retry(
    db, fence, target, outcome
):
    from aweb_naapp.hooks.strictjson import Refused

    request, admitted, dispatch_id, state = await prepared(db, fence, signed_trace_id="a" * 32)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        await state.begin_dispatch(
            tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
        )
    current = None if target == "missing" else replace(view(), as_of=NOW - timedelta(seconds=61))
    recorder = machine(
        BrokerAudit(producer=source, view=current, completed={"disposition": "withheld"})
    )
    async with db.transaction() as tx:
        if outcome == "reconciled":
            await recorder.outcome_unknown(tx, dispatch_id, {"state": "unknown"})
            await recorder.reconcile(
                tx, dispatch_id, State.RECONCILED_COMPLETED, {"state": "owner_resolved"}
            )
        else:
            method = recorder.complete if outcome == "completed" else getattr(recorder, outcome)
            assert await method(tx, dispatch_id, {"state": outcome})
    records = await envelopes(db)
    assert records[-1]["payload"]["action"] == outcome
    assert records[-1]["actor"] == records[0]["actor"]
    assert records[-1]["trace"] == {"id": "a" * 32, "origin": "signed_request"}
    assert records[-1]["payload"]["request_sha256"] == "a" * 64
    assert records[-1]["payload"]["grant_id"] == admitted.grant_id
    assert (
        await db.fetch_value(
            "SELECT critical FROM {{tables.outbox_events}} ORDER BY position DESC LIMIT 1"
        )
        is False
    )
    if outcome == "not_sent":
        # Recording a no-send fact cannot grant a new dispatch. The actual S3
        # retry still runs the real authority fence and the target gate.
        with pytest.raises(Refused) as refused:
            async with db.transaction() as tx:
                await recorder.begin_dispatch(
                    tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
                )
        assert refused.value.code == "audit_target_unavailable"
        async with db.transaction() as tx:
            assert (await recorder.get(tx, dispatch_id)).state is State.NOT_SENT
        assert len(await envelopes(db)) == 3


async def test_failed_post_dispatch_outbox_insert_preserves_dispatching_for_reconciliation(
    db, fence
):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        await state.begin_dispatch(
            tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
        )
    await db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_result "
        "CHECK (kind <> 'post-secret-use-hook') NOT VALID"
    )
    recorder = machine(
        BrokerAudit(producer=source, view=None, completed={"disposition": "withheld"})
    )
    with pytest.raises(asyncpg.CheckViolationError):
        async with db.transaction() as tx:
            await recorder.complete(tx, dispatch_id, {"state": "withheld"})
    async with db.transaction() as tx:
        assert (await recorder.get(tx, dispatch_id)).state is State.DISPATCHING
    assert len(await envelopes(db)) == 2
    assert await db.fetch_value("SELECT count(*) FROM {{tables.broker_use_events}}") == 2


async def test_no_target_refusal_is_recorded_without_send_authority(db, fence):
    request, admitted, dispatch_id, _ = await prepared(db, fence)
    state = machine(
        BrokerAudit(producer=source, view=None, refusal_code="audit_target_unavailable")
    )
    async with db.transaction() as tx:
        await state.refuse(tx, dispatch_id)
    (event,) = await envelopes(db)
    assert event["payload"]["action"] == "refused"
    assert event["payload"]["refusal_code"] == "audit_target_unavailable"
    assert event["result_status"] == "denied"
    async with db.transaction() as tx:
        assert (await state.get(tx, dispatch_id)).state is State.REFUSED


async def test_missing_recording_details_or_view_rolls_back_instead_of_silent_transition(db, fence):
    from aweb_naapp.hooks.strictjson import Refused

    request, admitted, dispatch_id, _ = await prepared(db, fence)
    state = machine(BrokerAudit(producer=source, view=None))
    with pytest.raises(Refused):
        async with db.transaction() as tx:
            await state.admit(
                tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
            )
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await state.refuse(tx, dispatch_id)
    assert await envelopes(db) == []


async def test_completed_metadata_cannot_replace_frozen_target_identity_or_commitments(db, fence):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        await state.begin_dispatch(
            tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
        )
    canary = secrets.token_urlsafe(32)
    with pytest.raises(ValueError):
        BrokerAudit(producer=source, view=view(), completed={"target_path_template": "/" + canary})
    audit = BrokerAudit(
        producer=source,
        view=view(),
        completed={
            "disposition": "withheld",
            "undeclared_credential": True,
            "upstream_status_code": 200,
            "upstream_bytes": 12,
            "upstream_truncated": False,
            "redaction_count": 1,
        },
    )
    async with db.transaction() as tx:
        await machine(audit).complete(tx, dispatch_id, {"state": "result_withheld"})
    p = (await envelopes(db))[-1]["payload"]
    assert p["action"] == "completed" and p["disposition"] == "withheld"
    assert "returned_hmac" not in p and "refusal_code" not in p
    assert canary not in json.dumps(await envelopes(db))


async def test_snapshot_is_immutable_and_foreign_principal_cannot_freeze_it(db, fence):
    from tests.test_admission import BOB

    request, admitted, dispatch_id, _ = await prepared(db, fence)
    with pytest.raises(asyncpg.RaiseError):
        async with db.transaction() as tx:
            await tx.execute("UPDATE {{tables.broker_audit_contexts}} SET payload='{}'")
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            f = authority(fence, admitted, request, dispatch_id)
            await f.prepare(tx)
            await freeze_broker_audit(
                tx, admission=admitted, principal=BOB, dispatch_id=dispatch_id, call=f.call
            )
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            f = authority(fence, admitted, request, dispatch_id)
            await f.prepare(tx)
            await freeze_broker_audit(
                tx,
                admission=replace(admitted, grant_id="grt_other"),
                principal=ALICE,
                dispatch_id=dispatch_id,
                call=f.call,
            )


async def test_concrete_credential_shaped_path_and_body_never_enter_audit_storage(db, fence):
    from aweb_secrets.use_approval import BrokerOpen

    canary = secrets.token_urlsafe(30)
    raw_path = "/v1/bot123:" + canary + "/sendMessage"
    opened = BrokerOpen("POST", "https://api.payments.example" + raw_path, (), canary.encode())
    request, admitted, dispatch_id, state = await prepared(db, fence, open_call=opened)
    async with db.transaction() as tx:
        await state.admit(
            tx,
            dispatch_id,
            fence=authority(fence, admitted, request, dispatch_id, open_call=opened),
        )
    (event,) = await envelopes(db)
    assert event["payload"]["target_path_template"] == "/v1/**"
    raw = await db.fetch_value("SELECT payload::text FROM {{tables.broker_audit_contexts}}")
    assert canary not in raw and raw_path not in raw
    assert canary not in json.dumps(await envelopes(db))
    assert "operation_digest" not in event["payload"]


@pytest.mark.parametrize("terminal", [State.NOT_SENT, State.OUTCOME_UNKNOWN])
async def test_transport_failure_records_only_its_phase_and_late_completion_does_not_duplicate(
    db, fence, terminal
):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        await state.begin_dispatch(
            tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
        )
    async with db.transaction() as tx:
        settle = state.not_sent if terminal is State.NOT_SENT else state.outcome_unknown
        assert await settle(tx, dispatch_id, {"state": terminal.value})
    event = (await envelopes(db))[-1]
    assert event["payload"]["action"] == terminal.value
    assert "refusal_code" not in event["payload"]
    assert "returned_hmac" not in event["payload"]
    if terminal is State.OUTCOME_UNKNOWN:
        count = len(await envelopes(db))
        async with db.transaction() as tx:
            assert not await state.complete(tx, dispatch_id, {"state": "completed"})
        assert len(await envelopes(db)) == count
        async with db.transaction() as tx:
            row = await state.get(tx, dispatch_id)
        assert row.state is State.OUTCOME_UNKNOWN and len(row.late_results) == 1


async def test_operational_record_failure_rolls_back_the_signed_outbox_and_transition(db, fence):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    await db.execute(
        "ALTER TABLE {{tables.broker_use_events}} ADD CONSTRAINT fail_activity CHECK (false)"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        async with db.transaction() as tx:
            await state.admit(
                tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
            )
    assert await envelopes(db) == []
    async with db.transaction() as tx:
        assert (await state.get(tx, dispatch_id)).state is State.RECEIVED
    assert await db.fetch_value("SELECT count(*) FROM {{tables.broker_use_events}}") == 0


async def test_wrong_producer_scope_and_unsupported_approval_transition_cannot_commit(db, fence):
    request, admitted, dispatch_id, _ = await prepared(db, fence)

    def wrong(installation_id, generation):
        return source(installation_id, generation + 1)

    state = machine(BrokerAudit(producer=wrong, view=view()))
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await state.admit(
                tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
            )
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await machine(BrokerAudit(producer=source, view=view())).await_approval(tx, dispatch_id)
    assert await envelopes(db) == []


async def test_a_later_snapshot_attempt_keeps_original_actor_and_committed_macs(db, fence):
    request, admitted, dispatch_id, state = await prepared(db, fence)
    async with db.transaction() as tx:
        f = authority(fence, admitted, request, dispatch_id)
        await f.prepare(tx)
        await store_use_context(
            tx,
            admission=admitted,
            dispatch_id=dispatch_id,
            commitments=UseCommitments(
                CommitmentContext(
                    "secrets", TEAM, INSTALLATION, admitted.installation.generation, "request"
                ),
                "c" * 64,
                "d" * 64,
            ),
        )
        await freeze_broker_audit(
            tx,
            admission=admitted,
            principal=replace(ALICE, alias="renamed"),
            dispatch_id=dispatch_id,
            call=f.call,
        )
        await state.admit(tx, dispatch_id, fence=f)
    (event,) = await envelopes(db)
    assert event["actor"]["alias"] == ALICE.alias
    assert event["payload"]["request_sha256"] == "a" * 64
    assert event["payload"]["params_sha256"] == "b" * 64


@pytest.mark.parametrize("valid", [False, True])
async def test_returned_completion_requires_its_keyed_response_commitment(db, fence, valid):
    import base64
    import hashlib
    import hmac

    from aweb_naapp.hooks.catalog import PayloadRefused

    request, admitted, dispatch_id, state = await prepared(db, fence)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        await state.begin_dispatch(
            tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
        )
    details = {"disposition": "returned", "undeclared_credential": False}
    if valid:
        details["returned_hmac"] = (
            base64.urlsafe_b64encode(
                hmac.digest(secrets.token_bytes(32), b"projected bytes", hashlib.sha256)
            )
            .decode()
            .rstrip("=")
        )
    state = machine(BrokerAudit(producer=source, view=view(), completed=details))
    if valid:
        async with db.transaction() as tx:
            assert await state.complete(tx, dispatch_id, {"state": "completed"})
        assert (await envelopes(db))[-1]["payload"]["returned_hmac"] == details["returned_hmac"]
    else:
        with pytest.raises(PayloadRefused):
            async with db.transaction() as tx:
                await state.complete(tx, dispatch_id, {"state": "completed"})
        async with db.transaction() as tx:
            assert (await state.get(tx, dispatch_id)).state is State.DISPATCHING
        assert len(await envelopes(db)) == 2


@pytest.mark.parametrize("cross_deadline", [False, True])
async def test_final_fence_after_real_outbox_wait_rolls_back_crossed_policy_window(
    db, fence, cross_deadline
):
    import asyncio

    from aweb_secrets.admission import AdmissionRefused
    from tests.test_derived_lineage import _wait_for_database_lock

    request, admitted, dispatch_id, state = await prepared(
        db,
        fence,
        policy_changes={
            "windows": {
                "time_zone": "UTC",
                "ranges": [{"days": ["tue"], "from": "12:00", "to": "13:00"}],
            },
        },
    )
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    at = NOW
    pid = asyncio.Future()

    async def dispatch():
        async with db.transaction() as tx:
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            final = authority(fence, admitted, request, dispatch_id, clock=lambda: at)
            current = await state.begin_dispatch(tx, dispatch_id, fence=final)
            await final.check(tx, current)
            return current

    async with db.transaction() as blocker:
        await blocker.fetch_value(
            "SELECT last_seq FROM {{tables.outbox_sequences}} WHERE scope=$1 AND team_id=$2 FOR UPDATE",
            "app:secrets:post-secret-use-hook",
            TEAM,
        )
        task = asyncio.create_task(dispatch())
        try:
            await _wait_for_database_lock(db, await asyncio.wait_for(asyncio.shield(pid), 3))
            if cross_deadline:
                at = NOW + timedelta(hours=1)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if cross_deadline:
        with pytest.raises(AdmissionRefused) as refused:
            await task
        assert refused.value.code == "policy_window_closed"
    else:
        assert (await task).state is State.DISPATCHING
    async with db.transaction() as tx:
        assert (await state.get(tx, dispatch_id)).state is (
            State.ADMITTED if cross_deadline else State.DISPATCHING
        )
    assert len(await envelopes(db)) == (1 if cross_deadline else 2)
    assert (
        await db.fetch_value("SELECT dispatch_started_at FROM {{tables.use_contexts}}") is None
    ) == cross_deadline


async def test_outer_admission_refusal_survives_rolled_back_inner_claim_without_an_intent(
    db, fence
):
    from aweb_naapp.dispatch import apply_dispatch_migrations

    from aweb_secrets.admission import AdmissionRefused, admit_use
    from aweb_secrets.broker_audit import record_broker_refusal
    from tests.test_admission import BOB, _request

    await _install(db, installation_id=INSTALLATION)
    await apply_dispatch_migrations(db)
    await apply_outbox_migrations(db)
    await apply_use_context_migrations(db)
    grant = _grant_source_grant(installation_id=INSTALLATION)
    async with db.transaction() as tx:
        scope = await fence.admit(tx, grant)
        with pytest.raises(AdmissionRefused) as refused:
            await admit_use(
                tx,
                fence=fence,
                grant=grant,
                principal=BOB,
                request=_request(),
                attestation=None,
                now=NOW,
                clock=lambda: NOW,
            )
        assert refused.value.code == "grant_missing"
        await record_broker_refusal(
            tx,
            producer=source(INSTALLATION, scope.generation),
            principal=BOB,
            commitments=UseCommitments(
                CommitmentContext("secrets", TEAM, INSTALLATION, scope.generation, "request"),
                None,
                None,
            ),
            code=refused.value.code,
            occurred_at=datetime.now(UTC),
        )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 0
    (event,) = await envelopes(db)
    assert event["payload"] == {
        "action": "refused",
        "op_kind": "broker",
        "refusal_code": "grant_missing",
    }
    assert event["actor"]["did_key"] == BOB.did_key
    row = await db.fetch_one("SELECT * FROM {{tables.broker_use_events}}")
    assert row["dispatch_id"] is None and row["installation_id"] == INSTALLATION
    assert row["team_id"] == TEAM and row["install_generation"] == scope.generation


async def test_outer_admission_trace_input_is_not_retained_as_free_text(db, fence):
    canary = "private_" + secrets.token_urlsafe(24)
    request, admitted, dispatch_id, state = await prepared(db, fence, signed_trace_id=canary)
    assert (
        await db.fetch_value("SELECT signed_trace_id FROM {{tables.broker_audit_contexts}}") is None
    )
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    (event,) = await envelopes(db)
    assert event["trace"]["origin"] == "producer"
    assert canary not in json.dumps(event)
