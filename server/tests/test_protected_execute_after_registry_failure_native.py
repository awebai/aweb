"""aweb-adbb D2c: one registry read that fails after the owner's touch.

The owner approves with a fresh passkey assertion; the signer records the
decision and then reads the registry for current authority. If that one read
fails, the approval must not be spent: a retry inside the gesture's original
window signs the operation exactly once."""

import pytest
from awid.registry_types import RegistryError

from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_admission_native import prepare, root_operation

pytest_plugins = ("tests.test_independent_protected_signer",)


async def signatures(a, operation_id):
    return await a.w.db.fetch_value(
        "SELECT count(*) FROM {{tables.protected_signer_operations}} "
        "WHERE operation_id=$1 AND (result IS NOT NULL OR signed_result IS NOT NULL)", operation_id)


@pytest.mark.asyncio
async def test_a_registry_read_failing_after_the_touch_does_not_spend_the_approval(admissions, monkeypatch):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    a = admissions
    operation = root_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    signer = a.human.signer
    options = await signer.approval_options(operation.operation_id, human=a.actor)
    proof = a.device.get(dict(options))

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

    monkeypatch.setattr(registry, "resolve_key_fresh", once_after_the_decision)
    monkeypatch.setattr(signer.approvals, "decide", decided)

    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await signer.execute(operation.operation_id, proof, human=a.actor)
    assert await signatures(a, operation.operation_id) == 0
    refusal = await a.w.db.fetch_value(
        "SELECT refusal_code FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id)
    assert refusal is None

    # The owner's page retries with what it holds: the same exact-act assertion.
    receipt = await signer.execute(operation.operation_id, proof, human=a.actor)
    assert receipt.state == "committed", receipt
    assert await signatures(a, operation.operation_id) == 1
