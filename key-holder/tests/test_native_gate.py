"""Default-off authority on genuine public DNS/AWID and signed holder HTTP.

No approval service exists in this component stack. The joined product journey
additionally proves that stopping the actual service does not affect off.
"""

from datetime import UTC, datetime

import httpx
import pytest
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.http import create_app
from awid.controller_signing import (
    parse_controller_object,
    parse_controller_request,
    sign_controller_object,
)
from policy_inputs import policy_file
from test_native_holder import call, commit_identity, register_identity
from test_native_review import first_person, revoke


async def request_add(holder, own, target):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        return await call(
            client,
            "/v1/humans",
            {
                "person": target[2],
                "identity_key": target[1],
                "approver": own["identity"],
            },
            **own,
        )


def without_approval(holder):
    policy_file(holder.human_approval_config, holder.store.descriptor().domain, None)
    return Holder(
        holder.store,
        registry=holder.registry,
        origin=holder.origin,
        human_approval_config=holder.human_approval_config,
    )


@pytest.mark.asyncio
async def test_off_accepts_a_current_person_without_enrollment_and_refuses_agent_and_no_standing(
    native_holder,
):
    old, registry = native_holder.holder, native_holder.registry
    holder = without_approval(old)
    root = holder.store.descriptor()
    await registry.controller_request(
        parse_controller_request(
            {
                "operation": "namespace_register",
                "domain": root.domain,
                "controller_did": root.did_key,
            }
        ),
        controllers={"controller": root},
        signer=lambda ctx: holder.store.sign_controller(ctx, actor="operator"),
    )
    seed, key, person = await register_identity(registry)
    issued = await holder.issue_person(person, key)
    own = {
        "seed": seed,
        "key": key,
        "identity": person,
        "chain": [issued["certificate"]],
    }
    await commit_identity(registry, {"id_chain": own["chain"]}, seed, key)
    assert holder.approval_origin is None and holder.grading is None
    with holder.store._connection() as db:
        assert db.execute("SELECT count(*) FROM enrollments").fetchone()[0] == 0
    target = await register_identity(registry)
    result = await request_add(holder, own, target)
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "issued" and "intent" not in result.json()

    agent_seed, agent_key, agent = await register_identity(registry)
    certificate = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": agent,
        "domain": root.domain,
        "parent": {"kind": "namespace", "id": root.domain},
        "kind": "agent",
        "issuer_key": root.did_key,
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed = await sign_controller_object(
        parse_controller_object(
            {
                "operation": "namespace_id_issue",
                "domain": root.domain,
                "kind": "agent",
                "certificate": certificate,
            }
        ),
        controller=root,
        signer=lambda ctx: holder.store.sign_controller(ctx, actor="operator"),
    )
    await commit_identity(registry, {"id_chain": [signed]}, agent_seed, agent_key)
    stranger_seed, stranger_key, stranger = await register_identity(registry)
    for caller in (
        {"seed": agent_seed, "key": agent_key, "identity": agent, "chain": [signed]},
        {"seed": stranger_seed, "key": stranger_key, "identity": stranger, "chain": []},
    ):
        before = holder.store.audit()
        refused = await request_add(holder, caller, await register_identity(registry))
        assert refused.status_code in (401, 403), refused.text
        assert holder.store.audit() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("withdrawal", ["retired", "revoked"])
async def test_off_refuses_a_retired_or_revoked_current_key(native_holder, withdrawal):
    old = native_holder.holder
    own, _, _, _ = await first_person(native_holder, activate=True)
    if withdrawal == "retired":
        old.store.retire_person(own["identity"])
    else:
        await revoke(native_holder.registry, old, own)
    holder = without_approval(old)
    before = holder.store.audit()
    target = await register_identity(native_holder.registry)
    refused = await request_add(holder, own, target)
    assert refused.status_code in (401, 403), refused.text
    assert holder.store.audit() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["deadline", "policy"])
async def test_receipt_is_rechecked_after_the_actual_effect_lock_wait(
    native_holder, change
):
    import asyncio
    import threading
    import time
    from approval_service.canonical import canonical
    from approval_service.encoding import encode
    from approval_service.seams import check_presentation
    from awid.id_certificates import id_certificate_id

    holder = native_holder.holder
    own, device, confirmation, _ = await first_person(native_holder, activate=True)
    _, key, target = await register_identity(native_holder.registry)
    trust = await holder.public.person(
        own["chain"],
        person=own["identity"],
        identity_key=own["key"],
        organisation=holder.store.descriptor().domain,
    )
    # SQLite's production busy timeout is one second. Align the real clock so
    # a still-valid integer-second deadline expires during a shorter lock wait.
    if change == "deadline":
        while time.time() % 1 < 0.55:
            await asyncio.sleep(0.01)
    start = int(time.time())
    with holder.store._connection() as db:
        certificate = holder._certificate(
            holder.store._descriptor(db), target, key, start
        )
        request = holder._request(
            db,
            purpose="act_approval",
            operation="human.add",
            requester={"kind": "identity", "id": own["identity"], "key": own["key"]},
            approver=own["identity"],
            target={
                "person": target,
                "identity_key": key,
                "certificate": id_certificate_id(certificate),
            },
            start=start,
            deadline=start + (1 if change == "deadline" else 600),
        )
        nonce_keys = holder._nonce_keys(db)
    raw = encode(canonical(request))
    receipt = {
        "version": 1,
        "request_bytes": raw,
        "binding": confirmation["binding"],
        "id_chain": own["chain"],
        "assertion": device.assert_request(request),
    }
    presentation = {"version": 1, "request_bytes": raw, "receipt": receipt}
    # Prove a genuine valid neighbor before the lock; do not start expired.
    check_presentation(
        presentation,
        expected_request=request,
        presenter=request["requester"],
        origin=holder.approval_origin,
        now=int(time.time()),
        trust=trust,
        required_grade="passkey_uv",
        nonce_keys=nonce_keys,
    )
    before = holder.store.audit()
    held, release = threading.Event(), threading.Event()

    def locker():
        with holder.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            held.set()
            assert release.wait(10), "test_lock_not_released"

    thread = threading.Thread(target=locker)
    thread.start()

    def change_and_release():
        if change == "policy":
            policy_file(
                holder.human_approval_config,
                holder.store.descriptor().domain,
                "hardware",
            )
        release.set()

    delay = request["deadline"] + 0.05 - time.time() if change == "deadline" else 0.5
    timer = threading.Timer(delay, change_and_release)
    entered = time.monotonic()
    try:
        assert held.wait(2), "actual_sqlite_lock_not_held"
        timer.start()
        assert int(time.time()) < request["deadline"]
        response = await request_add_presentation(holder, own, presentation)
    finally:
        release.set()
        timer.cancel()
        thread.join(2)
    assert not thread.is_alive()
    assert time.monotonic() - entered >= delay * 0.8, "effect_did_not_wait_for_lock"
    assert response.status_code != 200
    assert response.json()["error"]["code"] == (
        "request_expired" if change == "deadline" else "grade_insufficient"
    )
    # A rejected effect cannot issue or consume its nonce. The failed transaction
    # also rolls back the attempted policy audit; it will be applied on the next use.
    assert holder.store.audit() == before
    with holder.store._connection() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM consumed WHERE nonce=?",
                (request["nonce"]["value"],),
            ).fetchone()[0]
            == 0
        )


async def request_add_presentation(holder, own, presentation):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        return await call(client, "/v1/humans", presentation, **own)
