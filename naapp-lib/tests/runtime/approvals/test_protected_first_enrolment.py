"""A protected authority's first approver, designated on its own once-only
local bootstrap instead of a team owner act: first only, bound to the
transaction that admitted the bootstrap, and enrolled through B3's usual link
and ceremony. Real WebAuthn on real PostgreSQL."""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest
import pytest_asyncio
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.runtime.passkeys import DesignationRefused, ProtectedBootstrap
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    PasskeyWorld,
    designate,
    login,
    passkey_world,
    retire,
)

SCOPE = "protected.signer.authority-1"
CONTACT = "operator@example.com"


@pytest_asyncio.fixture
async def pw(test_db_factory, registry) -> PasskeyWorld:
    return await passkey_world(test_db_factory, registry)


async def bootstrap_in(tx, bootstrap_id: str = "bootstrap-1") -> ProtectedBootstrap:
    """What .4's local bootstrap admits in its own original transaction."""
    return ProtectedBootstrap(
        bootstrap_id=bootstrap_id,
        actor="operator_bootstrap",
        transaction_id=int(await tx.fetch_value("SELECT txid_current()")),
    )


async def first(
    pw: PasskeyWorld,
    scope: str = SCOPE,
    bootstrap_id: str = "bootstrap-1",
    subject: str | None = None,
):
    async with pw.passkeys.db.transaction() as tx:
        designation = await pw.passkeys.designate_first(
            tx,
            scope=scope,
            subject=subject or str(uuid.uuid4()),
            contact=CONTACT,
            evidence=await bootstrap_in(tx, bootstrap_id),
        )
    return designation


async def approvers(pw: PasskeyWorld, scope: str = SCOPE) -> int:
    return await pw.passkeys.db.fetch_value(
        "SELECT count(*) FROM {{tables.passkey_approvers}} WHERE scope = $1", scope
    )


async def test_a_bootstrap_designates_the_first_approver_who_enrols_and_logs_in(pw):
    designation = await first(pw, subject="pending-human-1")
    assert designation.approver.subject == "pending-human-1"
    assert designation.effective_at == pw.clock()
    assert pw.contacts.inbox.get(CONTACT) is None
    await pw.passkeys.deliver(designation)
    token = pw.contacts.last(CONTACT)
    device = SoftAuthenticator(ORIGIN)
    approver = await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    assert approver.subject == designation.approver.subject
    assert (await login(pw, device, scope=SCOPE)).subject == approver.subject
    [designated] = [r for r in await pw.audit.rows() if r["kind"] == "approver_designated"]
    details = json.loads(designated["details"])
    assert (designated["actor"], details["owner_act_kind"], details["owner_act_id"]) == (
        "operator_bootstrap",
        "protected-bootstrap",
        "bootstrap:bootstrap-1",
    )


async def test_a_bootstrap_admitted_in_another_transaction_is_refused(pw):
    async with pw.passkeys.db.transaction() as elsewhere:
        stale = await bootstrap_in(elsewhere)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate_first(
                tx, scope=SCOPE, subject="pending-human-1", contact=CONTACT, evidence=stale
            )
    assert await approvers(pw) == 0


async def test_a_bootstrap_takes_effect_once(pw):
    await first(pw)
    with pytest.raises(DesignationRefused):
        await first(pw, scope="protected.signer.authority-2")
    assert await approvers(pw, "protected.signer.authority-2") == 0


async def test_a_bootstrap_never_replaces_an_approver(pw):
    await first(pw)
    with pytest.raises(DesignationRefused):
        await first(pw, bootstrap_id="bootstrap-2")
    assert await approvers(pw) == 1


async def test_a_scope_that_ever_had_an_approver_is_not_bootstrapped_again(pw):
    designation = await designate(pw, CONTACT, scope=SCOPE)
    await retire(pw, designation.approver.subject, scope=SCOPE)
    with pytest.raises(DesignationRefused):
        await first(pw, bootstrap_id="bootstrap-2")
    assert await approvers(pw) == 1


async def test_only_a_protected_bootstrap_designates_first(pw):
    with pytest.raises(TypeError):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate_first(
                tx, scope=SCOPE, subject="pending-human-1", contact=CONTACT, evidence=object()
            )
    assert await approvers(pw) == 0


async def test_a_rolled_back_bootstrap_leaves_nothing_and_can_run_again(pw):
    with pytest.raises(RuntimeError):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate_first(
                tx,
                scope=SCOPE,
                subject="pending-human-1",
                contact=CONTACT,
                evidence=await bootstrap_in(tx),
            )
            raise RuntimeError("the bootstrap's own effect failed")
    assert await approvers(pw) == 0
    await first(pw, subject="pending-human-1")
    assert await approvers(pw) == 1


async def test_a_subject_that_already_exists_is_refused(pw):
    designation = await designate(pw, CONTACT, scope="app.installation-1")
    with pytest.raises(DesignationRefused):
        await first(pw, subject=designation.approver.subject)
    assert await approvers(pw) == 0
    await first(pw, subject="pending-human-1")
    with pytest.raises(DesignationRefused):
        await first(
            pw,
            scope="protected.signer.authority-2",
            bootstrap_id="bootstrap-2",
            subject="pending-human-1",
        )
    assert await approvers(pw, "protected.signer.authority-2") == 0


async def concurrently(pw: PasskeyWorld, *calls: dict) -> list:
    """Run each bootstrap in its own transaction, all at once."""

    async def one(call: dict):
        async with pw.passkeys.db.transaction() as tx:
            return await pw.passkeys.designate_first(
                tx,
                scope=call["scope"],
                subject=call["subject"],
                contact=CONTACT,
                evidence=await bootstrap_in(tx, call["bootstrap_id"]),
            )

    return await asyncio.gather(*(one(call) for call in calls), return_exceptions=True)


def outcomes(results: list) -> tuple[int, list[type]]:
    refused = [type(r) for r in results if isinstance(r, BaseException)]
    return len(results) - len(refused), refused


async def test_concurrent_bootstraps_of_one_scope_designate_one_approver(pw):
    results = await concurrently(
        pw,
        {"scope": SCOPE, "subject": "pending-human-1", "bootstrap_id": "bootstrap-1"},
        {"scope": SCOPE, "subject": "pending-human-2", "bootstrap_id": "bootstrap-2"},
    )
    assert outcomes(results) == (1, [DesignationRefused])
    assert await approvers(pw) == 1


async def test_concurrent_uses_of_one_bootstrap_take_effect_once(pw):
    results = await concurrently(
        pw,
        {"scope": SCOPE, "subject": "pending-human-1", "bootstrap_id": "bootstrap-1"},
        {
            "scope": "protected.signer.authority-2",
            "subject": "pending-human-2",
            "bootstrap_id": "bootstrap-1",
        },
    )
    assert outcomes(results) == (1, [DesignationRefused])
    assert await approvers(pw) + await approvers(pw, "protected.signer.authority-2") == 1


async def test_concurrent_bootstraps_of_one_subject_designate_it_once(pw):
    results = await concurrently(
        pw,
        {"scope": SCOPE, "subject": "pending-human-1", "bootstrap_id": "bootstrap-1"},
        {
            "scope": "protected.signer.authority-2",
            "subject": "pending-human-1",
            "bootstrap_id": "bootstrap-2",
        },
    )
    assert outcomes(results) == (1, [DesignationRefused])
