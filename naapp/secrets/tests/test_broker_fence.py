"""The real dispatch state machine checks CURRENT use authority before sending."""

import asyncio
import copy
import hashlib
from datetime import timedelta
from uuid import uuid4

import pytest
from aweb_naapp.dispatch import Dispatches, State, apply_dispatch_migrations
from aweb_naapp.egress import InternalDestinations

from aweb_secrets import records
from aweb_secrets.admission import AdmissionRefused, UseRequest
from aweb_secrets.broker_fence import BrokerFence
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.use_approval import BrokerOpen
from tests.test_admission import (
    ALICE,
    INSTALLATION,
    NOW,
    POLICY_BODY,
    SECRET,
    TEAM,
    _admit,
    _install,
)
from tests.test_admission import db as db
from tests.test_admission import fence as fence
from tests.test_operation_record import REFUND

PARAMS = {"charge": "ch_original", "amount_minor_units": 50, "currency": "EUR"}


async def setup(db, fence, *, policy_changes=None):
    operation = OperationTemplate.from_after(copy.deepcopy(REFUND))
    pin = {"operation_id": operation.operation_id, "digest": operation.digest}
    await _install(
        db,
        policy_body={**POLICY_BODY, "operations": [pin], **(policy_changes or {})},
        operations=[pin],
        open_request=False,
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
        operation.operation_id,
        PARAMS,
    )
    admitted = await _admit(db, fence, request=request, clock=lambda: NOW)
    await apply_dispatch_migrations(db)
    return operation, request, admitted


def authority(fence, admission, request, dispatch_id, **options):
    return BrokerFence(
        fence,
        admission=admission,
        principal=ALICE,
        request=request,
        dispatch_id=dispatch_id,
        headers=(),
        attestation=None,
        clock=options.pop("clock", lambda: NOW),
        derived_max_ttl_s=3600,
        internal_destinations=InternalDestinations.DISABLED,
        **options,
    )


async def machine(db, dispatch_id):
    async def transition(tx, event):
        pass

    result = Dispatches(
        on_transition=transition,
        max_dispatch=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=5),
    )
    async with db.transaction() as tx:
        await result.create(tx, dispatch_id=dispatch_id, subject="broker-subject", action="refund")
    return result


async def test_s3_prepares_all_authority_before_its_own_locks(db, fence):
    operation, request, admitted = await setup(db, fence)
    dispatch_id = uuid4()
    state = await machine(db, dispatch_id)
    async with db.transaction() as tx:
        prepared = authority(fence, admitted, request, dispatch_id)
        await state.admit(tx, dispatch_id, fence=prepared)
    async with db.transaction() as tx:
        prepared = authority(fence, admitted, request, dispatch_id)
        result = await state.begin_dispatch(tx, dispatch_id, fence=prepared)
        assert result.state is State.DISPATCHING
        assert prepared.call.secret.version == 4
        assert prepared.call.operation.digest == operation.digest
        assert ("Idempotency-Key", f"secrets-{dispatch_id}") in prepared.call.rendered.headers
        assert prepared.call.target_path_template == operation.after["url"]["path"]
        assert "ch_original" not in prepared.call.target_path_template


@pytest.mark.parametrize(
    "change,code",
    [
        ("version", "secret_version_changed"),
        ("disabled", "secret_disabled"),
        ("grant", "grant_revoked"),
        ("operation", "operation_not_allowed"),
        ("destination", "destination_not_in_scope"),
        ("installation", "installation_disabled"),
    ],
)
async def test_a_previously_admitted_use_is_refused_at_the_final_dispatch_fence(
    db, fence, change, code
):
    operation, request, admitted = await setup(db, fence)
    dispatch_id = uuid4()
    state = await machine(db, dispatch_id)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        if change == "version":
            await records.set_active_version(tx, INSTALLATION, TEAM, SECRET["secret_id"], 5)
        elif change == "disabled":
            await tx.execute("UPDATE {{tables.secrets}} SET state='disabled'")
        elif change == "grant":
            await records.revoke_grant(tx, INSTALLATION, admitted.grant_id)
        elif change == "operation":
            body = copy.deepcopy(operation.after)
            body["timeout_s"] -= 1
            await records.create_operation(
                tx, INSTALLATION, TEAM, OperationTemplate.from_after(body)
            )
        elif change == "destination":
            await records.remove_destination(tx, INSTALLATION, "dst_broker01")
        else:
            await tx.execute(
                "INSERT INTO {{tables.containment_installations}} (installation_id,team_id,disabled_at) VALUES($1,$2,now())",
                INSTALLATION,
                TEAM,
            )
    with pytest.raises(AdmissionRefused) as refused:
        async with db.transaction() as tx:
            await state.begin_dispatch(
                tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
            )
    assert refused.value.code == code
    async with db.transaction() as tx:
        assert (await state.get(tx, dispatch_id)).state is State.ADMITTED


async def test_onepassword_never_uses_a_native_fence_without_the_live_item_version_check(db, fence):
    from aweb_secrets.secret import SecretRecord

    _, request, admitted = await setup(db, fence)
    async with db.transaction() as tx:
        await records.update_secret(
            tx, INSTALLATION, TEAM, SecretRecord.from_after({**SECRET, "backend": "onepassword"})
        )
    dispatch_id = uuid4()
    state = await machine(db, dispatch_id)
    with pytest.raises(AdmissionRefused) as refused:
        async with db.transaction() as tx:
            await state.admit(
                tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id)
            )
    assert refused.value.code == "custody_unavailable"
    async with db.transaction() as tx:
        assert (await state.get(tx, dispatch_id)).state is State.RECEIVED


@pytest.mark.parametrize("expired", [False, True])
async def test_policy_window_is_checked_after_a_real_s3_row_lock_wait(db, fence, expired):
    from tests.test_derived_lineage import _wait_for_database_lock

    _, request, admitted = await setup(
        db,
        fence,
        policy_changes={
            "windows": {
                "time_zone": "UTC",
                "ranges": [{"days": ["tue"], "from": "12:00", "to": "13:00"}],
            }
        },
    )
    dispatch_id = uuid4()
    state = await machine(db, dispatch_id)
    async with db.transaction() as tx:
        await state.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    at = NOW
    pid = asyncio.Future()

    async def dispatch():
        async with db.transaction() as tx:
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            return await state.begin_dispatch(
                tx,
                dispatch_id,
                fence=authority(fence, admitted, request, dispatch_id, clock=lambda: at),
            )

    async with db.transaction() as blocker:
        await blocker.fetch_value(
            "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
            dispatch_id,
        )
        task = asyncio.create_task(dispatch())
        try:
            await _wait_for_database_lock(db, await asyncio.wait_for(asyncio.shield(pid), 3))
            if expired:
                at = NOW + timedelta(hours=1)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if expired:
        with pytest.raises(AdmissionRefused) as refused:
            await task
        assert refused.value.code == "policy_window_closed"
    else:
        assert (await task).state is State.DISPATCHING
    async with db.transaction() as tx:
        current = await state.get(tx, dispatch_id)
        assert current.state is (State.ADMITTED if expired else State.DISPATCHING)
        assert current.attempts == (0 if expired else 1)


async def test_open_request_is_bounded_and_has_no_token_issuing_authority(db, fence):
    await _install(db, policy_body={**POLICY_BODY, "result": {"max_bytes": 1024}})
    destination = DestinationRecord.from_after(
        {
            "v": 1,
            "destination_id": "dst_open001",
            "secret_id": SECRET["secret_id"],
            "scheme": "https",
            "host": "api.example",
            "port": 443,
            "path": "/v1/**",
            "methods": ["GET"],
            "query_rules": {},
            "header_allow": [],
            "network": "public",
            "cidr": None,
        },
        internal_destinations=InternalDestinations.DISABLED,
    )
    async with db.transaction() as tx:
        await records.create_destination(tx, INSTALLATION, TEAM, destination)
    request = UseRequest(
        SECRET["ref"], "open-request", hashlib.sha256(b"open").digest(), None, None
    )
    admitted = await _admit(db, fence, request=request, clock=lambda: NOW)
    await apply_dispatch_migrations(db)
    dispatch_id = uuid4()
    state = await machine(db, dispatch_id)
    async with db.transaction() as tx:
        prepared = authority(
            fence,
            admitted,
            request,
            dispatch_id,
            open_call=BrokerOpen("GET", "https://api.example/v1/status", (), b""),
        )
        await state.admit(tx, dispatch_id, fence=prepared)
        assert prepared.call.operation is None
        assert prepared.call.rendered.token_issuing is False
        assert prepared.call.rendered.projection is None
        assert prepared.call.rendered.bounds.max_response_bytes == 1024
        assert prepared.call.rendered.max_bytes == 1024
        assert prepared.call.target_path_template == "/v1/**"
