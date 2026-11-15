"""Real isolated-custody executor proofs accepted by real protected AWID."""

import base64
import json
from datetime import timedelta

import pytest
from nacl.signing import SigningKey

from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.protected_effect import HEADER
from awid.registry_types import RegistryError
from awid_service.protected_teams import provision_team_protection
from tests.test_independent_protected_signer import DOMAIN, did
from tests.test_protected_admission_native import admit_operation, endorse, execute, prepare
from tests.test_protected_removal_native import removal

from tests.protected_consumer_support import activate

pytest_plugins = ("tests.test_protected_admission_native",)




@pytest.mark.asyncio
@pytest.mark.parametrize("lost_answer", [False, True, "purged"])
async def test_genuine_retained_admission_and_exact_confirmation(admissions, tmp_path, monkeypatch, lost_answer):
    a = admissions
    await endorse(a)  # Actual B3/UV endorsement authorizes the bounded root.
    custody = await activate(a, tmp_path)
    sends = []
    deliver = custody.deliver_retained

    async def release(operation, retained):
        sends.append(retained.fields())
        await deliver(operation, retained)
        if lost_answer:
            raise SignerRefused("receipt_unavailable")  # Lose only the applied answer.

    monkeypatch.setattr(custody, "deliver_retained", release)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    response = await execute(a, operation)
    if lost_answer:
        assert response.status_code == 503, response.text
        if lost_answer == "purged":
            await a.w.host.db.execute("DELETE FROM {{tables.protected_effect_receipts}} WHERE operation_id=$1::uuid", operation.operation_id)
        else:
            async with a.w.host.db.transaction() as tx:
                await provision_team_protection(tx, domain=DOMAIN, name="engineering", service_id=a.w.context.service_id,
                    service_did_key=did(SigningKey.generate()), expected_generation=1, approval_ref="native-service-key-transition")
        original_clock = a.w.app.signer.clock
        monkeypatch.setattr(a.w.app.signer, "clock", lambda: original_clock() + timedelta(hours=2))
        response = await execute(a, operation)
    assert response.status_code == 200, response.text
    if lost_answer == "purged":
        assert response.json()["state"] == "unknown"
        assert response.json()["code"] == "external_effect_unresolved"
        assert len(sends) == 1
        return
    result = response.json()["result"]
    assert result["v"] == 2 and result["delivery"]["state"] == "applied"
    assert set(result) == {"v", "type", "artifact", "delivery"}
    assert HEADER not in json.dumps(result)
    artifact = json.loads(base64.b64decode(result["artifact"]["signing"]))
    certificate = {**artifact, "signature": base64.b64encode(base64.b64decode(result["artifact"]["signature"])).rstrip(b"=").decode()}
    records = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=False)
    assert len([r for r in records if r.certificate_id == artifact["certificate_id"] and r.revoked_at is None]) == 1
    assert len(sends) == 1
    row = await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        operation.operation_id,
    )
    assert row["delivery_claim"] is not None and json.loads(row["retained_effect"]) == sends[0]
    assert json.loads(row["signed_result"]) == result["artifact"]
    if lost_answer:
        assert (await execute(a, operation)).json() == response.json()
        assert len(sends) == 1
        return
    # The original typed artifact/controller signature alone is still refused.
    with pytest.raises(RegistryError) as refused:
        await custody.register_admission(a.w.registry, operation, artifact, result["artifact"])
    assert refused.value.status_code == 403
    removed = removal(a, certificate)
    assert (await prepare(a, removed)).status_code == 200
    removed_response = await execute(a, removed)
    assert removed_response.status_code == 200, removed_response.text
    assert removed_response.json()["result"]["v"] == 2
    assert len(sends) == 2
    status = await a.w.registry.get_team_certificate_status_fresh(DOMAIN, "engineering", artifact["certificate_id"])
    assert status["status"] == "revoked"

@pytest.mark.asyncio
async def test_cache_wait_expiry_keeps_original_bundle_claim_and_never_sends(admissions, tmp_path, monkeypatch):
    a = admissions
    await endorse(a)
    custody = await activate(a, tmp_path)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    original_clock = a.w.app.signer.clock
    original_request = custody._request_effect
    original_invalidate = a.w.registry.invalidate_team_certificate_cache
    original_deliver = custody.deliver_retained
    refusals = []
    invalidations, sends = [], []

    async def invalidate(*args):
        invalidations.append(args)
        await original_invalidate(*args)
        monkeypatch.setattr(a.w.app.signer, "clock", lambda: original_clock() + timedelta(hours=2))

    async def request(delivery, **kwargs):
        if not kwargs.get("receipt"):
            sends.append(delivery)
        return await original_request(delivery, **kwargs)

    async def deliver(operation, retained):
        try:
            await original_deliver(operation, retained)
        except SignerRefused as exc:
            refusals.append(exc.code)
            raise

    monkeypatch.setattr(custody, "deliver_retained", deliver)
    monkeypatch.setattr(a.w.registry, "invalidate_team_certificate_cache", invalidate)
    monkeypatch.setattr(custody, "_request_effect", request)
    response = await execute(a, operation)
    assert response.status_code == 200 and response.json()["code"] == "external_effect_unresolved", response.text
    assert refusals == ["operation_expired"]
    assert sends == [] and len(invalidations) == 2
    before = await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        operation.operation_id)
    assert all(before[k] is not None for k in ("signed_result", "retained_effect", "delivery_claim"))
    recovered = await execute(a, operation)
    assert recovered.status_code == 200 and recovered.json()["code"] == "external_effect_unresolved"
    after = await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        operation.operation_id)
    assert dict(after) == dict(before) and sends == [] and len(invalidations) == 2
