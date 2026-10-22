"""Actual assertion persistence/CAS and lifecycle, using real PG and passkeys."""

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest
from asyncpg import CheckViolationError, RaiseError
from webauthn.helpers import base64url_to_bytes

from aweb_naapp.runtime.approvals import Assurance, AuthenticationFailed, Decision, Purpose
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    ProofContextUnavailable,
    passkey_evidence_commitment,
)
from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_passkeys import (
    ceremony,
    enrol,
    mint,
    pw,  # noqa: F401
)

CONTEXT = PasskeyInstallationContext("fixture", "team", "installation", 1)


async def verified_login(pw):  # noqa: F811
    approver, device = await enrol(pw)
    options = await pw.passkeys.login_options(SCOPE)
    assertion = device.get(dict(options))
    login = await pw.passkeys.verify_login(SCOPE, assertion)
    return approver, device, assertion, login


async def test_login_retains_exact_assertion_and_original_context(pw):  # noqa: F811
    approver, device = await enrol(pw)
    options = await pw.passkeys.login_options(SCOPE)
    async with pw.passkeys.db.transaction() as tx:
        await tx.execute("UPDATE {{tables.proof_test_context}} SET generation=2")
    assertion = device.get(dict(options))
    login = await pw.passkeys.verify_login(SCOPE, assertion)
    retained = await pw.passkeys.retained_proof(login.evidence_ref)
    assert retained.context["generation"] == 1
    for key, field in (
        ("authenticatorData", "authenticator_data"),
        ("clientDataJSON", "client_data_json"),
        ("signature", "signature"),
    ):
        assert getattr(retained, field) == base64url_to_bytes(assertion["response"][key])
    digest = await pw.passkeys.evidence_commitment(
        login.evidence_ref, context=CONTEXT, scope=SCOPE, subject=approver.subject, purpose="login"
    )
    assert digest == passkey_evidence_commitment(retained)
    with pytest.raises(PasskeyProofUnavailable):
        await pw.passkeys.evidence_commitment(
            login.evidence_ref,
            context=replace(CONTEXT, generation=2),
            scope=SCOPE,
            subject=approver.subject,
            purpose="login",
        )


async def test_approval_retains_exact_b2_covered_bytes_and_task_null(pw):  # noqa: F811
    approver, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    decided = await pw.approvals.decide(
        approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        proof,
        link_token=pw.contacts.by_approval[approval.approval_id],
    )
    retained = await pw.passkeys.retained_proof(decided.decided_by.evidence_ref)
    assert retained.covered_request == await pw.approvals._store.request_canonical(
        approval.request_ref
    )
    assert b'"task_answer_ref":null' in retained.challenge_preimage
    assert "task_answer_ref" not in retained.metadata
    assert retained.metadata["subject"] == approver.subject
    assert len(passkey_evidence_commitment(retained)) == 64


async def test_proof_insert_failure_rolls_back_counter_and_summary(pw):  # noqa: F811
    _, device = await enrol(pw)
    options = await pw.passkeys.login_options(SCOPE)
    before = await pw.passkeys.db.fetch_all("SELECT * FROM {{tables.passkey_credentials}}")
    async with pw.passkeys.db.transaction() as tx:
        await tx.execute(
            "ALTER TABLE {{tables.passkey_proofs}} ADD CONSTRAINT injected_failure CHECK(false) NOT VALID"
        )
    with pytest.raises(CheckViolationError):
        await pw.passkeys.verify_login(SCOPE, device.get(dict(options)))
    assert await pw.passkeys.db.fetch_all("SELECT * FROM {{tables.passkey_credentials}}") == before
    assert (
        await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_assertions}}") == 0
    )
    assert await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_proofs}}") == 0


async def test_retirement_preserves_proof_and_lifecycle_deletion_removes_it(pw):  # noqa: F811
    approver, _, _, login = await verified_login(pw)
    original = await pw.passkeys.retained_proof(login.evidence_ref)
    async with pw.passkeys.db.transaction() as tx:
        await pw.passkeys.retire_in(
            tx, scope=SCOPE, subject=approver.subject, authorized_by="owner"
        )
    assert await pw.passkeys.retained_proof(login.evidence_ref) == original
    async with pw.passkeys.db.transaction() as tx:
        assert (
            await pw.passkeys.delete_proofs_in(
                tx, context=replace(CONTEXT, installation_id="other")
            )
            == 0
        )
        assert await pw.passkeys.delete_proofs_in(tx, context=CONTEXT) == 1
    with pytest.raises(PasskeyProofUnavailable):
        await pw.passkeys.retained_proof(login.evidence_ref)
    assert await pw.passkeys.evidence(login.evidence_ref) is not None


async def test_missing_context_refuses_before_challenge_write(pw):  # noqa: F811
    await enrol(pw)
    before = await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
    async with pw.passkeys.db.transaction() as tx:
        await tx.execute("DELETE FROM {{tables.proof_test_context}}")
    with pytest.raises(ProofContextUnavailable):
        await pw.passkeys.login_options(SCOPE)
    assert (
        await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
        == before
    )


async def test_commitment_rejects_every_wrong_binding_without_relabelling(pw):  # noqa: F811
    approver, _, _, login = await verified_login(pw)
    args = dict(context=CONTEXT, scope=SCOPE, subject=approver.subject, purpose="login")
    for wrong in (
        {"context": replace(CONTEXT, app_id="other")},
        {"context": replace(CONTEXT, team_id="other")},
        {"context": replace(CONTEXT, installation_id="other")},
        {"context": replace(CONTEXT, generation=2)},
        {"scope": "other"},
        {"subject": "other"},
        {"purpose": "approve"},
    ):
        with pytest.raises(PasskeyProofUnavailable) as refusal:
            await pw.passkeys.evidence_commitment(login.evidence_ref, **{**args, **wrong})
        assert refusal.value.code == "passkey_proof_unavailable"
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(RaiseError):
            async with tx.transaction() as attempt:
                await attempt.execute("UPDATE {{tables.passkey_proofs}} SET commitment='changed'")
        assert len(await pw.passkeys.evidence_commitment(login.evidence_ref, **args, tx=tx)) == 64


async def test_lifecycle_deletion_uses_callers_rollback_boundary(pw):  # noqa: F811
    _, _, _, login = await verified_login(pw)
    proof = await pw.passkeys.retained_proof(login.evidence_ref)

    class Rollback(Exception):
        pass

    with pytest.raises(Rollback):
        async with pw.passkeys.db.transaction() as tx:
            assert await pw.passkeys.delete_proofs_in(tx, context=CONTEXT) == 1
            raise Rollback()
    assert await pw.passkeys.retained_proof(login.evidence_ref) == proof


@pytest.mark.parametrize("expire", [False, True])
async def test_counter_lock_wait_uses_live_verification_time(pw, expire):  # noqa: F811
    _, device = await enrol(pw)
    assertion = device.get(dict(await pw.passkeys.login_options(SCOPE)))
    db = pw.passkeys.db
    before = await db.fetch_all("SELECT * FROM {{tables.passkey_credentials}}")
    task = None
    try:
        async with db.transaction() as hold:
            blocker = await hold.fetch_value("SELECT pg_backend_pid()")
            await hold.fetch_all("SELECT * FROM {{tables.passkey_credentials}} FOR UPDATE")
            task = asyncio.create_task(pw.passkeys.verify_login(SCOPE, assertion))
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() "
                    "AND $1=ANY(pg_blocking_pids(pid)) "
                    "AND query LIKE 'UPDATE %passkey_credentials%SET sign_count%')",
                    blocker,
                ):
                    await asyncio.sleep(0.01)
            assert not task.done()
            if expire:
                pw.clock.advance(timedelta(minutes=6))
        if expire:
            with pytest.raises(PasskeyProofUnavailable):
                await asyncio.wait_for(task, 5)
            assert await db.fetch_all("SELECT * FROM {{tables.passkey_credentials}}") == before
            assert await db.fetch_value("SELECT count(*) FROM {{tables.passkey_assertions}}") == 0
            assert await db.fetch_value("SELECT count(*) FROM {{tables.passkey_proofs}}") == 0
        else:
            login = await asyncio.wait_for(task, 5)
            assert await pw.passkeys.retained_proof(login.evidence_ref)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_missing_approval_sidecar_refuses_before_challenge_write(pw):  # noqa: F811
    await enrol(pw)
    approval = await mint(pw)
    before = await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
    with pytest.raises(PasskeyProofUnavailable):
        await pw.passkeys.approval_options(approval, approval.candidates[0], Purpose.APPROVE, None)
    assert (
        await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
        == before
    )


async def test_racing_assertions_retain_only_the_winning_counter_cas(pw):  # noqa: F811
    _, device = await enrol(pw)
    assertions = [device.get(dict(await pw.passkeys.login_options(SCOPE))) for _ in range(2)]
    db = pw.passkeys.db
    tasks = []
    try:
        async with db.transaction() as hold:
            await hold.fetch_all("SELECT * FROM {{tables.passkey_credentials}} FOR UPDATE")
            for assertion in assertions:
                tasks.append(asyncio.create_task(pw.passkeys.verify_login(SCOPE, assertion)))
                async with asyncio.timeout(5):
                    while await db.fetch_value(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                        "AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0 "
                        "AND query LIKE 'UPDATE %passkey_credentials%SET sign_count%'",
                    ) < len(tasks):
                        await asyncio.sleep(0.01)
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 5)
        assert sum(isinstance(result, AuthenticationFailed) for result in results) == 1
        assert await db.fetch_value("SELECT count(*) FROM {{tables.passkey_assertions}}") == 1
        assert await db.fetch_value("SELECT count(*) FROM {{tables.passkey_proofs}}") == 1
        winner = next(result for result in results if not isinstance(result, Exception))
        proof = await pw.passkeys.retained_proof(winner.evidence_ref)
        assert proof.metadata["sign_count_before"] == 0
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
