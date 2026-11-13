"""Pinned recovery transport accepts exact history without refreshing authority."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from aweb.protected_signing.effects import ProtectedEffectCustody
from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.retention import FrozenDelivery, RetainedEffect
from awid.protected_effect import HEADER
from awid.protected_receipts import PATH

ID = "11111111-1111-4111-8111-111111111111"


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["exact", "404", "503", "redirect", "wrong_id", "wrong_digest", "extra", "duplicate", "slow"])
async def test_confirmation_is_pinned_exact_and_original_deadline(case):
    now = datetime(2026, 11, 13, tzinfo=UTC)
    requests = []
    async def respond(request):
        nonlocal now
        requests.append(request)
        assert request.method == "GET"
        assert str(request.url) == "https://consumer.example" + PATH + "/" + ID
        assert request.headers[HEADER] == "retained-private-proof"
        assert "authorization" not in request.headers
        result = {"v": 1, "operation_id": ID, "artifact_sha256": "a" * 64}
        if case == "wrong_id": result["operation_id"] = "other"
        if case == "wrong_digest": result["artifact_sha256"] = "b" * 64
        if case == "extra": result["secret"] = "no"
        if case == "slow": now += timedelta(seconds=60)
        if case in {"404", "503"}: return httpx.Response(int(case))
        if case == "redirect": return httpx.Response(302, headers={"Location": "https://other.example"})
        raw = json.dumps(result)
        if case == "duplicate": raw = raw[:-1] + ', "v":1}'
        return httpx.Response(200, content=raw)
    effect = RetainedEffect(ID, b"artifact", b"s" * 64, "a" * 64, now - timedelta(hours=2),
        FrozenDelivery("https://consumer.example", "POST", "/effect", {HEADER: "retained-private-proof", "Authorization": "private-auth"}, b"exact"),
        "retained-private-proof")
    custody = ProtectedEffectCustody()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        custody.configure_effects(registry=None, clients={"https://consumer.example": client}, clock=lambda: now)
        if case in {"exact", "404"}:
            confirmation = await custody.confirm_retained(SimpleNamespace(operation_id=ID), effect)
            if case == "exact":
                assert confirmation.operation_id == ID
                assert confirmation.valid_until == now + timedelta(seconds=60)
            else: assert confirmation is None
        else:
            with pytest.raises(SignerRefused, match="evidence_unavailable"):
                await custody.confirm_retained(SimpleNamespace(operation_id=ID), effect)
    assert len(requests) == 1
