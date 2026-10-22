"""Children use their own authority and share recorded ancestor limits."""

import asyncio
from datetime import timedelta

import pytest

from aweb_secrets import derived_lineage, records
from aweb_secrets.admission import AdmissionRefused
from aweb_secrets.secret import SecretRecord
from tests.test_admission import (
    ALICE,
    BOB,
    INSTALLATION,
    NOW,
    POLICY_BODY,
    SECRET,
    TEAM,
    _define,
    _grant_source_grant,
    _install,
    _operation,
    _request,
)
from tests.test_admission import (
    _admit as _base_admit,
)
from tests.test_admission import (
    db as db,
)
from tests.test_admission import (
    fence as fence,
)
from tests.test_derived_lineage import _wait_for_database_lock


async def _admit(db, fence, principal, request, *, now=NOW, **kwargs):
    return await _base_admit(db, fence, principal, request, now=now, clock=lambda: now, **kwargs)


async def _child(db, *, child_id="sec_child001", grant=True, policy=None, operations=None):
    child = {**SECRET, "secret_id": child_id, "ref": child_id}
    child_policy = policy or {**POLICY_BODY, "rate": []}
    if grant:
        await _install(
            db,
            secret=child,
            policy_body=child_policy,
            subject={"principal": BOB.did_aw},
            grant_id="grt_" + child_id,
            operations=operations or [],
            open_request=not bool(operations),
        )
    else:
        async with db.transaction() as tx:
            await records.create_secret(tx, INSTALLATION, TEAM, SecretRecord.from_after(child))
            await records.set_active_version(tx, INSTALLATION, TEAM, child_id, 4)
    async with db.transaction() as tx:
        source_policy = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id='grt_alice001'"
        )
        await derived_lineage.record_lineage(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id=child_id,
            parent_secret_id=SECRET["secret_id"],
            parent_version=4,
            source_dispatch_id="dispatch-" + child_id,
            source_grant_id="grt_alice001",
            issuing_principal=ALICE.did_aw,
            policy_digest=source_policy,
            dispatch_started_at=NOW,
            upstream_expires_at=NOW + timedelta(hours=2),
            expires_at=NOW + timedelta(hours=1),
            clock=lambda: NOW,
        )
    return child


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("disabled", "secret_disabled"),
        ("rotated", "secret_version_changed"),
        ("revoked", "grant_revoked"),
        ("expired", "secret_disabled"),
    ],
)
async def test_child_admission_refuses_lost_ancestor_authority(db, fence, mutation, code) -> None:
    await _install(db)
    child = await _child(db)
    async with db.transaction() as tx:
        if mutation == "disabled":
            await tx.execute(
                "UPDATE {{tables.secrets}} SET state='disabled' WHERE secret_id=$1",
                SECRET["secret_id"],
            )
        elif mutation == "rotated":
            await records.set_active_version(tx, INSTALLATION, TEAM, SECRET["secret_id"], 5)
        elif mutation == "revoked":
            await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
    with pytest.raises(AdmissionRefused) as refused:
        await _admit(
            db,
            fence,
            BOB,
            _request(secret_ref=child["ref"]),
            now=NOW + timedelta(hours=1) if mutation == "expired" else NOW,
        )
    assert refused.value.code == code


async def test_child_never_inherits_a_parent_grant(db, fence) -> None:
    await _install(db)
    child = await _child(db, grant=False)
    with pytest.raises(AdmissionRefused) as refused:
        await _admit(db, fence, ALICE, _request(secret_ref=child["ref"]))
    assert refused.value.code == "grant_missing"


async def test_fanout_and_changed_subject_do_not_reset_parent_rate_buckets(db, fence) -> None:
    await _install(
        db,
        policy_body={
            **POLICY_BODY,
            "rate": [{"per": "principal_secret", "capacity": 1, "window_s": 3600}],
        },
    )
    first = await _child(db)
    second = await _child(db, child_id="sec_child002")
    admitted = await _admit(db, fence, BOB, _request(secret_ref=first["ref"]))
    assert (
        await _admit(db, fence, BOB, _request(secret_ref=first["ref"]))
    ).intent_id == admitted.intent_id
    with pytest.raises(AdmissionRefused) as refused:
        await _admit(db, fence, BOB, _request("req_2", secret_ref=second["ref"]))
    assert refused.value.code == "policy_rate_limited"


async def test_child_resolves_current_ancestor_operation_and_refuses_edit(db, fence) -> None:
    operation = _operation()
    pin = {"operation_id": operation.operation_id, "digest": operation.digest}
    await _install(db)
    await _define(db, operation)
    child = await _child(
        db, policy={**POLICY_BODY, "rate": [], "operations": [pin]}, operations=[pin]
    )
    request = _request(
        secret_ref=child["ref"], operation_id=operation.operation_id, params={"charge": "ch_1"}
    )
    await _admit(db, fence, BOB, request)
    edited = _operation(response={**operation.after["response"], "max_bytes": 1024})
    await _define(db, edited)
    with pytest.raises(AdmissionRefused) as refused:
        await _admit(
            db,
            fence,
            BOB,
            _request(
                "req_2",
                secret_ref=child["ref"],
                operation_id=operation.operation_id,
                params=request.params,
            ),
        )
    assert refused.value.code == "operation_not_allowed"


@pytest.mark.parametrize("expire", [True, False])
async def test_expiry_during_rate_wait_rolls_back_the_admission(db, fence, expire):
    from aweb_secrets.admission import admit_use

    await _install(db)
    child = await _child(db)
    at = NOW
    pid = asyncio.Future()

    async def submit():
        async with db.transaction() as tx:
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            return await admit_use(
                tx,
                fence=fence,
                grant=_grant_source_grant(),
                principal=BOB,
                request=_request(secret_ref=child["ref"]),
                attestation=None,
                now=NOW,
                clock=lambda: at,
            )

    async with db.transaction() as blocker:
        await blocker.execute("LOCK TABLE {{tables.rate_buckets}} IN ACCESS EXCLUSIVE MODE")
        task = asyncio.create_task(submit())
        try:
            await _wait_for_database_lock(db, await pid)
            if expire:
                at = NOW + timedelta(hours=1)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if expire:
        with pytest.raises(AdmissionRefused) as refused:
            await task
        assert refused.value.code == "secret_disabled"
        assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 0
        assert await db.fetch_value("SELECT count(*) FROM {{tables.rate_buckets}}") == 0
        # A rolled-back idempotency claim cannot turn this into a replay.
        admitted = await _admit(db, fence, BOB, _request(secret_ref=child["ref"]))
        assert not admitted.replayed
    else:
        admitted = await task
        assert not admitted.replayed
        assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 1


async def test_current_cap_is_rechecked_on_new_and_replayed_child_admission(db, fence):
    await _install(db)
    child = await _child(db)
    request = _request(secret_ref=child["ref"])
    await _admit(db, fence, BOB, request)
    for candidate in (request, _request("req_new", secret_ref=child["ref"])):
        with pytest.raises(AdmissionRefused) as refused:
            await _admit(
                db,
                fence,
                BOB,
                candidate,
                now=NOW + timedelta(seconds=61),
                derived_max_ttl_s=60,
            )
        assert refused.value.code == "secret_disabled"
