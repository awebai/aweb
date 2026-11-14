"""Real owner UV and isolated executor proofs at the protected AWID consumer.

These component controls use the definition's actual issued artifact and
retained HTTP request; they do not claim the pending intent_v1 client handoff.
"""

import hashlib
import json
from datetime import timedelta

import pytest
from awid.protected_effect import HEADER
from awid.registry_types import RegistryError

from tests.test_protected_admission_native import execute, prepare
from tests.test_protected_boundary_retention_native import activate
from tests.test_protected_owner_removal_native import (
    legacy_member,
    owner_execute,
    owner_removal,
    revoked,
)
from tests.test_protected_removal_native import signature_count

pytest_plugins = ("tests.test_protected_admission_native",)


async def retained_row(a, operation):
    return await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} "
        "WHERE operation_id=$1", operation.operation_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["local", "agent", "unknown"])
@pytest.mark.parametrize("lost_answer", [False, True])
async def test_owner_uv_reaches_marked_revocation_with_exact_proof_and_receipt(
    admissions, tmp_path, monkeypatch, kind, lost_answer
):
    a = admissions
    _, certificate = await legacy_member(a, kind)
    custody = await activate(a, tmp_path)
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    no_uv = await execute(a, operation)
    assert no_uv.status_code == 403 and no_uv.json()["detail"] == "live_approval_required"
    assert await signature_count(a, operation) == 0
    assert not await revoked(a, certificate)
    invalidations, sends = [], []
    original_invalidate = a.w.registry.invalidate_team_certificate_cache
    original_request = custody._request_effect

    async def invalidate(*args):
        invalidations.append(args)
        await original_invalidate(*args)

    async def request(delivery, **kwargs):
        if not kwargs.get("receipt"):
            sends.append(delivery)
        result = await original_request(delivery, **kwargs)
        if not kwargs.get("receipt") and lost_answer:
            raise RegistryError("applied answer lost", status_code=503)
        return result

    monkeypatch.setattr(a.w.registry, "invalidate_team_certificate_cache", invalidate)
    monkeypatch.setattr(custody, "_request_effect", request)
    if lost_answer:
        with pytest.raises(RegistryError, match="applied answer lost"):
            await owner_execute(a, operation)
        before = await retained_row(a, operation)
        clock = a.w.app.signer.clock
        monkeypatch.setattr(a.w.app.signer, "clock", lambda: clock() + timedelta(hours=2))
        result = await a.w.app.signer.receipt(operation.operation_id, reader=a.w.reader)
        assert dict(await retained_row(a, operation)) == dict(before)
    else:
        result = await owner_execute(a, operation)
    assert result.state == "committed", result
    assert result.result["v"] == 2 and result.result["delivery"]["state"] == "applied"
    assert await revoked(a, certificate)
    assert await signature_count(a, operation) == 1
    assert len(sends) == 1 and len(invalidations) == 2
    row = await retained_row(a, operation)
    retained = json.loads(row["retained_effect"])
    assert row["delivery_claim"] is not None
    # The real consumer validated the signature, current binding and exact
    # request; its committed receipt must associate this same proof and act.
    receipt = await a.w.host.db.fetch_one(
        "SELECT * FROM {{tables.protected_effect_receipts}} WHERE operation_id=$1::uuid",
        operation.operation_id)
    assert receipt["operation"] == "team.agent.remove" and receipt["variant"] == "owner_approved"
    assert receipt["artifact_sha256"] == retained["artifact_sha256"]
    assert receipt["header_sha256"] == hashlib.sha256(sends[0].headers[HEADER].encode()).hexdigest()
    assert retained["attestation"] == sends[0].headers[HEADER]
    assert result.result["artifact"] == json.loads(row["signed_result"])
    assert HEADER not in json.dumps(result.result)
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("cache_failure", ["expiry", "before_send", "after_send"])
async def test_owner_removal_cache_fences_keep_original_retention_and_single_release(
    admissions, tmp_path, monkeypatch, cache_failure
):
    a = admissions
    _, certificate = await legacy_member(a, "local")
    custody = await activate(a, tmp_path)
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    clock = a.w.app.signer.clock
    invalidations, sends = [], []
    original_invalidate = a.w.registry.invalidate_team_certificate_cache
    original_request = custody._request_effect

    async def invalidate(*args):
        invalidations.append(args)
        await original_invalidate(*args)
        if cache_failure == "expiry" and len(invalidations) == 1:
            monkeypatch.setattr(a.w.app.signer, "clock", lambda: clock() + timedelta(hours=2))
        if (cache_failure == "before_send" and len(invalidations) == 1
            or cache_failure == "after_send" and len(invalidations) == 2):
            raise RegistryError("cache unavailable", status_code=503)

    async def request(delivery, **kwargs):
        if not kwargs.get("receipt"):
            sends.append(delivery)
        return await original_request(delivery, **kwargs)

    monkeypatch.setattr(a.w.registry, "invalidate_team_certificate_cache", invalidate)
    monkeypatch.setattr(custody, "_request_effect", request)
    if cache_failure == "expiry":
        result = await owner_execute(a, operation)
        assert (result.state, result.code) == ("unknown", "external_effect_unresolved")
    else:
        with pytest.raises(RegistryError, match="cache unavailable"):
            await owner_execute(a, operation)
    before = await retained_row(a, operation)
    assert all(before[name] is not None for name in ("signed_result", "retained_effect", "delivery_claim"))
    monkeypatch.setattr(a.w.app.signer, "clock", lambda: clock() + timedelta(hours=2))
    recovered = await a.w.app.signer.receipt(operation.operation_id, reader=a.w.reader)
    if cache_failure == "after_send":
        assert recovered.state == "committed" and len(sends) == 1
        assert await revoked(a, certificate)
    else:
        assert (recovered.state, recovered.code) == ("unknown", "external_effect_unresolved")
        assert sends == [] and not await revoked(a, certificate)
    assert len(invalidations) == (1 if cache_failure == "before_send" else 2)
    assert dict(await retained_row(a, operation)) == dict(before)
