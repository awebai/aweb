"""Real customer AWID/PG and existing B3: production operator -> mailed link -> UV.

Execution belongs on the existing Hetzner VM, never an unplaced local DB run.
"""

import asyncio
from dataclasses import replace

import httpx
import pytest
from aweb_naapp.runtime.passkeys import EnrolmentRefused
from aweb_naapp.runtime.protected_signer import SignerRefused

from aweb.protected_signing.bootstrap import initialise, prepare_completion
from tests.test_independent_protected_signer import HUMAN_ORIGIN, ORIGIN
from tests.test_protected_host_native import host_for

pytest_plugins = ("tests.test_independent_protected_signer",)
CONTACT = "operator@customer.example"


async def empty_authority(w):
    # Destructive reset ONLY inside world fixture's isolated test database.
    # Existing registry/H/team/member authorities stay real and registered.
    await w.db.execute("TRUNCATE {{tables.passkey_approvers}} CASCADE")
    await w.db.execute("TRUNCATE {{tables.protected_authorizer_bindings}} CASCADE")
    await w.db.execute("TRUNCATE {{tables.protected_operator_bootstraps}}")
    await w.db.execute("TRUNCATE {{tables.protected_local_audit}}")


async def first(w):
    await empty_authority(w)
    result = await initialise(w.app, requester=w.root_id, contact=CONTACT)
    return result, w.delivery.enrolment


async def complete(w, token, **device_options):
    options = await w.app.passkeys.enrolment_options(token)
    attestation = w.device.create(options, **device_options)
    fence = await prepare_completion(w.app, token)
    return await w.app.passkeys.complete_enrolment(token, attestation, fence=fence)


@pytest.mark.asyncio
async def test_local_operator_real_host_mailed_link_uv_login_and_bootstrap_consumption(
    world, tmp_path
):
    w = world
    result, token = await first(w)
    assert result["delivery"] == "delivered"
    assert "token" not in result
    host = host_for(w, tmp_path)
    async with host.api_app.router.lifespan_context(host.api_app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host)) as client:
            assert (await client.get(ORIGIN + "/enrolment")).status_code == 404
            page = await client.get(HUMAN_ORIGIN + "/enrolment")
            assert page.status_code == 200
            assert 'data-ceremony="enrolment"' in page.text
            assert "no-store" in page.headers["cache-control"]
            options = await client.post(
                HUMAN_ORIGIN + "/enrolment/options", json={"link_token": token}
            )
            assert options.status_code == 200, options.text
            enrolled = await client.post(
                HUMAN_ORIGIN + "/enrolment",
                json={
                    "link_token": token,
                    "credential": w.device.create(options.json()),
                },
            )
            assert enrolled.status_code == 200, enrolled.text
            assert enrolled.json() == {"scope": result["scope"]}
            assert "set-cookie" not in enrolled.headers
            login_options = await client.post(
                HUMAN_ORIGIN + "/login/options", json={"scope": result["scope"]}
            )
            login = await client.post(
                HUMAN_ORIGIN + "/login",
                json={
                    "scope": result["scope"],
                    "assertion": w.device.get(login_options.json()),
                },
            )
            assert login.status_code == 200, login.text
            # B3 token and once-only binding are both consumed. No second key.
            replay = await client.post(
                HUMAN_ORIGIN + "/enrolment/options", json={"link_token": token}
            )
            assert replay.status_code == 403
    assert await w.db.fetch_value(
        "SELECT consumed_at IS NOT NULL FROM {{tables.protected_operator_bootstraps}}"
    )
    assert (
        await w.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}")
        == 1
    )
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='approver_enrolled'"
        )
        == 1
    )
    with pytest.raises((SignerRefused, EnrolmentRefused)):
        await initialise(w.app, requester=w.root_id, contact=CONTACT)


@pytest.mark.asyncio
async def test_pending_repeat_resumes_exact_subject_but_not_contact_or_authority(world):
    w = world
    result, old_token = await first(w)
    row = await w.db.fetch_one("SELECT * FROM {{tables.protected_operator_bootstraps}}")
    repeated = await initialise(w.app, requester=w.root_id, contact=CONTACT)
    assert repeated["scope"] == result["scope"]
    assert (
        await w.db.fetch_one("SELECT * FROM {{tables.protected_operator_bootstraps}}")
    )["subject"] == row["subject"]
    with pytest.raises(EnrolmentRefused):
        await w.app.passkeys.enrolment_options(old_token)
    with pytest.raises(SignerRefused, match="bootstrap_conflict"):
        await initialise(w.app, requester=w.root_id, contact="other@customer.example")
    await complete(w, w.delivery.enrolment)


@pytest.mark.asyncio
async def test_existing_authority_is_never_adopted_as_initial_bootstrap(world):
    with pytest.raises(SignerRefused, match="bootstrap_existing_authority"):
        await initialise(world.app, requester=world.root_id, contact=CONTACT)
    assert not await world.db.fetch_value(
        "SELECT 1 FROM {{tables.protected_operator_bootstraps}}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["no_uv", "wrong_origin", "policy", "retired"])
async def test_enrollment_refusal_retains_pending_record_without_credential(
    world, change
):
    w = world
    _, token = await first(w)
    options = await w.app.passkeys.enrolment_options(token)
    attestation = w.device.create(
        options,
        user_verified=change != "no_uv",
        **({"origin": "https://other.example"} if change == "wrong_origin" else {}),
    )
    fence = await prepare_completion(w.app, token)
    if change == "policy":
        await w.db.execute(
            "UPDATE {{tables.protected_authorizer_bindings}} SET policy_version=2"
        )
        # Production from_profile pins version 1; the legacy world constructor
        # does not, so explicitly select the same policy adapter expectation.
        w.app.signer.policies.expected_version = 1
    if change == "retired":
        await w.db.execute(
            "UPDATE {{tables.protected_authorizer_bindings}} SET active=false"
        )
    with pytest.raises((EnrolmentRefused, SignerRefused)):
        await w.app.passkeys.complete_enrolment(token, attestation, fence=fence)
    assert not await w.db.fetch_value("SELECT 1 FROM {{tables.passkey_credentials}}")
    assert not await w.db.fetch_value(
        "SELECT consumed_at FROM {{tables.protected_operator_bootstraps}}"
    )
    assert not await w.db.fetch_value(
        "SELECT used_at FROM {{tables.passkey_enrolments}} WHERE revoked_at IS NULL"
    )


@pytest.mark.asyncio
async def test_changed_profile_generation_refuses_pending_subject(world):
    w = world
    _, token = await first(w)
    w.app.context = replace(w.context, generation=2)
    with pytest.raises(EnrolmentRefused):
        await complete(w, token)
    assert not await w.db.fetch_value("SELECT 1 FROM {{tables.passkey_credentials}}")


@pytest.mark.asyncio
async def test_concurrent_initial_operator_calls_resume_one_pending_subject(world):
    w = world
    await empty_authority(w)
    results = await asyncio.gather(
        *[initialise(w.app, requester=w.root_id, contact=CONTACT) for _ in range(2)]
    )
    assert results[0]["scope"] == results[1]["scope"]
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_authorizer_bindings}}"
        )
        == 1
    )
    assert (
        await w.db.fetch_value("SELECT count(*) FROM {{tables.passkey_approvers}}") == 1
    )
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_operator_bootstraps}}"
        )
        == 1
    )


@pytest.mark.asyncio
async def test_audit_failure_rolls_back_credential_link_and_bootstrap_then_retry(world):
    w = world
    _, token = await first(w)
    original = w.app.audit.emit

    async def failure(event, tx):
        if event.kind == "approver_enrolled":
            raise RuntimeError("injected local audit failure")
        await original(event, tx)

    w.app.audit.emit = failure
    with pytest.raises(RuntimeError, match="injected local audit"):
        await complete(w, token)
    assert not await w.db.fetch_value("SELECT 1 FROM {{tables.passkey_credentials}}")
    assert not await w.db.fetch_value(
        "SELECT consumed_at FROM {{tables.protected_operator_bootstraps}}"
    )
    w.app.audit.emit = original
    await complete(w, token)  # fresh challenge, same pending association/link


@pytest.mark.asyncio
@pytest.mark.parametrize("elapsed,allowed", [(59, True), (61, False)])
async def test_bootstrap_registry_deadline_survives_confirmed_sql_wait(
    world, elapsed, allowed
):
    w = world
    _, token = await first(w)
    now = 0
    w.app.authority.timer = lambda: now
    options = await w.app.passkeys.enrolment_options(token)
    attestation = w.device.create(options)
    fence = await prepare_completion(w.app, token)
    task = None
    try:
        async with w.db.transaction() as blocker:
            await blocker.fetch_one(
                "SELECT * FROM {{tables.protected_operator_bootstraps}} FOR UPDATE"
            )
            task = asyncio.create_task(
                w.app.passkeys.complete_enrolment(token, attestation, fence=fence)
            )
            waiting = False
            for _ in range(200):
                await blocker.execute("SELECT pg_stat_clear_snapshot()")
                waiting = await blocker.fetch_value(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                    "AND wait_event_type='Lock' AND query LIKE '%protected_operator_bootstraps%' "
                    "AND pid <> pg_backend_pid()"
                )
                if waiting:
                    break
                if task.done():
                    await task
                    pytest.fail("enrollment did not wait on the bootstrap fence")
                await asyncio.sleep(0.01)
            assert waiting, "PostgreSQL bootstrap lock wait was not established"
            now = elapsed
        if allowed:
            assert (await task).scope
        else:
            with pytest.raises(SignerRefused, match="evidence_unavailable"):
                await task
            assert not await w.db.fetch_value(
                "SELECT 1 FROM {{tables.passkey_credentials}}"
            )
            assert not await w.db.fetch_value(
                "SELECT consumed_at FROM {{tables.protected_operator_bootstraps}}"
            )
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
