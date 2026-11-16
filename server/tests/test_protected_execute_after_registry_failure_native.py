"""aweb-adbb D2c: one registry read that fails after the owner's touch.

The owner approves with a fresh passkey assertion; the signer records the
decision and then reads the registry for current authority. If that one read
fails, the approval is not spent: inside the gesture's original window the
owner's page finishes it, reloaded or not, and the act is signed once. Asking
again answers "approved" instead of a new challenge; it grants nothing, and
execute rechecks everything. Deny never becomes Approve, an empty assertion
before any approval signs nothing, and past the window nothing finishes."""

import asyncio
from datetime import timedelta

import pytest
from aweb_naapp.runtime.approvals.model import ApprovalRefused, Decision
from awid.registry_types import RegistryError

from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_admission_native import prepare, root_operation

pytest_plugins = ("tests.test_independent_protected_signer",)


async def stored_signatures(a, operation_id):
    return await a.w.db.fetch_value(
        "SELECT count(*) FROM {{tables.protected_signer_operations}} "
        "WHERE operation_id=$1 AND (result IS NOT NULL OR signed_result IS NOT NULL)", operation_id)


async def touched_then_failed(a, monkeypatch):
    """Prepare, approve with a real assertion, and fail the one registry read
    after the decision. Returns the operation, its signer, the assertion and
    the list of real custody signing calls."""
    from aweb_naapp.runtime.protected_signer import SignerRefused

    operation = root_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    signer = a.human.signer
    proof = a.device.get(dict(await signer.approval_options(operation.operation_id, human=a.actor)))

    registry, resolve = a.w.registry, a.w.registry.resolve_key_fresh
    failing = {"armed": False}

    async def once_after_the_decision(*args, **kwargs):
        if failing["armed"]:
            failing["armed"] = False
            raise RegistryError("registry unavailable", status_code=503)
        return await resolve(*args, **kwargs)

    decide = signer.approvals.decide

    async def decided(*args, **kwargs):
        result = await decide(*args, **kwargs)
        failing["armed"] = True  # the very next registry read fails, once
        return result

    signs = []
    sign = signer._sign_artifact

    def counted(*args, **kwargs):
        signs.append(args[0].operation_id if args else None)  # every real custody signing call
        return sign(*args, **kwargs)

    monkeypatch.setattr(registry, "resolve_key_fresh", once_after_the_decision)
    monkeypatch.setattr(signer.approvals, "decide", decided)
    monkeypatch.setattr(signer, "_sign_artifact", counted)
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await signer.execute(operation.operation_id, proof, human=a.actor)
    assert await stored_signatures(a, operation.operation_id) == 0 and signs == []
    refusal = await a.w.db.fetch_value(
        "SELECT refusal_code FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id)
    assert refusal is None
    return operation, signer, proof, signs


@pytest.mark.asyncio
async def test_retrying_with_the_held_assertion_signs_once(admissions, monkeypatch):
    a = admissions
    operation, signer, proof, signs = await touched_then_failed(a, monkeypatch)
    receipt = await signer.execute(operation.operation_id, proof, human=a.actor)
    assert receipt.state == "committed", receipt
    assert len(signs) == 1 and await stored_signatures(a, operation.operation_id) == 1


@pytest.mark.asyncio
async def test_a_reopened_page_finishes_the_approval_without_a_new_gesture(admissions, monkeypatch):
    a = admissions
    operation, signer, _, signs = await touched_then_failed(a, monkeypatch)
    # The reopened page asks for options: already approved, no new challenge.
    options = await signer.approval_options(operation.operation_id, human=a.actor)
    assert dict(options) == {"state": "approved"}
    receipt = await signer.execute(operation.operation_id, {}, human=a.actor)
    assert receipt.state == "committed", receipt
    assert len(signs) == 1 and await stored_signatures(a, operation.operation_id) == 1


@pytest.mark.asyncio
async def test_concurrent_retries_sign_once(admissions, monkeypatch):
    a = admissions
    operation, signer, proof, signs = await touched_then_failed(a, monkeypatch)
    receipts = await asyncio.gather(*(signer.execute(operation.operation_id, proof, human=a.actor) for _ in range(3)),
                                    return_exceptions=True)
    assert any(getattr(r, "state", None) == "committed" for r in receipts), receipts
    assert len(signs) == 1 and await stored_signatures(a, operation.operation_id) == 1


@pytest.mark.asyncio
async def test_deny_after_the_failure_never_becomes_approve(admissions, monkeypatch):
    a = admissions
    operation, signer, _, signs = await touched_then_failed(a, monkeypatch)
    with pytest.raises(ApprovalRefused):
        await signer.approval_options(operation.operation_id, human=a.actor, decision=Decision.REJECT)
    assert signs == []


@pytest.mark.asyncio
async def test_past_the_gesture_window_nothing_finishes(admissions, monkeypatch):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    a = admissions
    operation, signer, proof, signs = await touched_then_failed(a, monkeypatch)
    later = signer.clock() + timedelta(seconds=301)
    monkeypatch.setattr(signer, "clock", lambda: later)
    options = None
    try:
        options = await signer.approval_options(operation.operation_id, human=a.actor)
    except (ApprovalRefused, SignerRefused):
        pass
    assert options is None or dict(options) != {"state": "approved"}
    receipt = await signer.execute(operation.operation_id, proof, human=a.actor)
    assert receipt.state != "committed", receipt
    assert signs == [] and await stored_signatures(a, operation.operation_id) == 0


@pytest.mark.asyncio
async def test_an_empty_assertion_before_any_approval_signs_nothing(admissions, monkeypatch):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    a = admissions
    operation = root_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    signer = a.human.signer
    assert "state" not in dict(await signer.approval_options(operation.operation_id, human=a.actor))
    try:
        receipt = await signer.execute(operation.operation_id, {}, human=a.actor)
        assert receipt.state != "committed", receipt
    except (SignerRefused, ApprovalRefused):
        pass
    assert await stored_signatures(a, operation.operation_id) == 0


@pytest.mark.asyncio
async def test_a_credential_revoked_after_the_touch_finishes_nothing(admissions, monkeypatch):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    a = admissions
    operation, signer, proof, signs = await touched_then_failed(a, monkeypatch)
    async with signer.passkeys.db.transaction() as tx:
        await signer.passkeys.revoke_passkey_in(tx, scope=a.actor.b3_scope, subject=a.actor.subject,
            credential_id=next(iter(a.device.credentials)), authorized_by="owner")
    options = None
    try:
        options = await signer.approval_options(operation.operation_id, human=a.actor)
    except (ApprovalRefused, SignerRefused):
        pass
    assert options is None or dict(options) != {"state": "approved"}
    try:
        receipt = await signer.execute(operation.operation_id, proof, human=a.actor)
        assert receipt.state != "committed", receipt
    except (ApprovalRefused, SignerRefused):
        pass
    assert signs == [] and await stored_signatures(a, operation.operation_id) == 0


@pytest.mark.asyncio
async def test_another_candidate_is_never_told_the_act_is_approved(admissions, monkeypatch):
    from dataclasses import replace

    from aweb_naapp.runtime.protected_signer import SignerRefused

    a = admissions
    operation, signer, _, signs = await touched_then_failed(a, monkeypatch)
    other = replace(a.actor, subject="another-candidate")
    options = None
    try:
        options = await signer.approval_options(operation.operation_id, human=other)
    except (ApprovalRefused, SignerRefused):
        pass
    assert options is None or dict(options) != {"state": "approved"}
    try:
        receipt = await signer.execute(operation.operation_id, {}, human=other)
        assert receipt.state != "committed", receipt
    except (ApprovalRefused, SignerRefused):
        pass
    assert signs == [] and await stored_signatures(a, operation.operation_id) == 0
