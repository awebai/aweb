"""Known registry throttling crosses the existing fixed 503 surface safely."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from starlette.requests import Request

from aweb_naapp.runtime.protected_signer import ProtectedOperationsHTTP, SignerRefused
from aweb_naapp.runtime.protected_signer.http import _http
from awid.registry_types import RegistryError, RegistryThrottled

from aweb.protected_signing.authority import IndependentAuthority
from aweb.protected_signing.composition import IndependentProtectedSigner
from tests.test_protected_service_profile import FIXTURE
from aweb.protected_signing.profile import ProtectedServiceProfile

PROFILE = ProtectedServiceProfile.from_json(FIXTURE.read_bytes())


def refusal(hint):
    error = SignerRefused("evidence_unavailable")
    error.retry_after_seconds = hint
    return error


@pytest.mark.parametrize("hint,header", [(7, "7"), (7.01, "8"), (0, "0"), (None, None)])
def test_standard_retry_hint_preserves_the_fixed_503(hint, header):
    result = _http(refusal(hint))
    assert result.status_code == 503
    assert result.detail == "receipt_unavailable"
    assert (result.headers or {}).get("Retry-After") == header


@pytest.mark.parametrize(
    "hint", ["7", True, -1, float("nan"), float("inf"), 1e300, {}, 2**31]
)
def test_malformed_hint_cannot_mask_or_change_the_original_refusal(hint):
    result = _http(refusal(hint))
    assert result.status_code == 503 and result.detail == "receipt_unavailable"
    assert not result.headers


def test_other_refusals_never_become_retry_invitations():
    error = SignerRefused("proof_invalid")
    error.retry_after_seconds = 7
    result = _http(error)
    assert result.status_code == 403 and not result.headers


class Limiter:
    async def admit(self, *args, **kwargs):
        pass


@pytest.mark.asyncio
async def test_receipt_route_transmits_only_the_known_hint_and_existing_body():
    async def unavailable(*args):
        raise refusal(7.01)

    signer = SimpleNamespace(
        passkeys=SimpleNamespace(rp=SimpleNamespace(origin=PROFILE.human_origin))
    )
    mount = ProtectedOperationsHTTP(
        signer,
        request_origin=PROFILE.request_origin,
        requester=unavailable,
        reader=unavailable,
        limiter=Limiter(),
    )
    app = FastAPI()
    app.include_router(mount.api_router())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=PROFILE.request_origin
    ) as client:
        response = await client.get(
            "/protected-operations/00000000-0000-4000-8000-000000000001"
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "receipt_unavailable"}
    assert response.headers["retry-after"] == "8"
    assert "rate_limited" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("throttled", [True, False])
async def test_authority_observation_preserves_only_known_throttling(throttled):
    context = PROFILE.bindings[0].context()

    class Registry:
        async def resolve_key_fresh(self, principal):
            if throttled:
                raise RegistryThrottled(
                    retry_after_seconds=7.2, attempts=1, reason="elapsed_budget"
                )
            raise RegistryError("unavailable", status_code=503)

    custody = SimpleNamespace(
        service_id=context.service_id, team_id=context.authority_id
    )
    authority = IndependentAuthority(
        object(), context=context, registry=Registry(), custody=custody
    )
    with pytest.raises(SignerRefused) as caught:
        await authority.observe(context, purpose="receipt")
    response = _http(caught.value)
    assert response.status_code == 503
    assert (response.headers or {}).get("Retry-After") == ("8" if throttled else None)


@pytest.mark.asyncio
async def test_requester_current_key_lookup_preserves_the_hint_after_proof(monkeypatch):
    import aweb.protected_signing.composition as module

    context = PROFILE.bindings[0].context()

    class Registry:
        async def resolve_key_fresh(self, principal):
            raise RegistryThrottled(
                retry_after_seconds=7, attempts=1, reason="elapsed_budget"
            )

    async def proof(*args, **kwargs):
        return "proof-already-verified"

    monkeypatch.setattr(module, "verify_protected_request", proof)
    # Negative adapter proof only. No principal/authority actor is admitted.
    composition = IndependentProtectedSigner.__new__(IndependentProtectedSigner)
    composition.context = context
    composition.registry = Registry()
    composition.request_origin = PROFILE.request_origin

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/protected-operations/id",
            "headers": [],
            "query_string": b"",
        },
        receive,
    )
    with pytest.raises(SignerRefused) as caught:
        await composition.requester(
            request, principal=context.human_id, operation="protected_operation_receipt"
        )
    assert _http(caught.value).headers == {"Retry-After": "7"}
