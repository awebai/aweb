"""The shared HTTP mount with the independent profile/current-authority adapter."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from aweb_naapp.console import (
    ClientIdentity,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
)
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.signing import canonical_json_bytes
from fastapi import FastAPI

from aweb.protected_signing.composition import IndependentProtectedSigner
from aweb.protected_signing.profile import ProtectedServiceProfile
from tests.test_independent_protected_signer import (
    ORIGIN,
    did,
    proof_request,
)
from tests.test_protected_service_profile import FIXTURE

pytest_plugins = ("tests.test_independent_protected_signer",)


def profile_for(w):
    fields = json.loads(FIXTURE.read_bytes())
    fields["registry_origin"] = w.registry.registry_url
    fields["namespace_authorities"] = [
        {"domain": domain, "controller_did": key}
        for domain, key in w.registry.namespace_keys.items()
    ]
    fields["bindings"][0]["scope"] = w.context.fields()
    fields["bindings"][0]["authority_key_did"] = did(w.controller)
    return ProtectedServiceProfile.from_json(canonical_json_bytes(fields))


def mount(w, profile, *, human=False, consumer=None):
    composition = IndependentProtectedSigner.from_profile(
        w.db,
        profile=profile,
        scope=profile.bindings[0].scope.model_dump(mode="json"),
        registry_client=w.registry,
        custody=w.app.authority.custody,
        delivery=w.delivery,
        consumer_clients={w.operation.audience: consumer.client} if consumer is not None else None,
        receipt_origins=frozenset({w.operation.audience}) if consumer is not None else frozenset(),
    )
    limiter = LoginLimiter(
        w.db, client_identity=ClientIdentity(), limit=100, window=timedelta(minutes=1)
    )
    app = FastAPI()
    sessions = composition.protected_sessions() if human else None
    shared = composition.operations_http(
        limiter=limiter,
        human_sessions=sessions,
        human_csrf_key="protected-human-csrf" if human else None,
    )
    app.include_router(shared.api_router())
    if human:
        app.include_router(console_login_router(sessions=sessions, limiter=limiter))
        app.include_router(shared.human_router())
    app.state.protected_operations = shared
    return composition, app


def headers(w, *, body=b"", method="POST", path="/protected-operations", context=None):
    request = proof_request(
        w,
        body=body,
        method=method,
        path=path,
        context=context,
        operation="protected_operation_prepare"
        if method == "POST"
        else "protected_operation_receipt",
    )
    return {
        **dict(request.headers),
        "X-AWEB-DID-AW": w.root_id,
        "Content-Type": "application/json",
    }


@pytest_asyncio.fixture
async def http_world(world, tmp_path, test_db_factory):
    from tests.protected_consumer_support import ready_owner_act_consumer

    async with ready_owner_act_consumer(world, tmp_path, test_db_factory) as consumer:
        w = world
        await apply_console_migrations(w.db)
        profile = profile_for(w)
        composition, app = mount(w, profile, consumer=consumer)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN
        ) as client:
            yield SimpleNamespace(
                w=w, composition=composition, profile=profile, client=client, consumer=consumer
            )


async def post(h, operation=None):
    body = canonical_json_bytes((operation or h.w.operation).intent())
    return await h.client.post(
        "/protected-operations", content=body, headers=headers(h.w, body=body)
    )


@pytest.mark.asyncio
async def test_actual_profile_shared_http_uv_and_exact_receipt(http_world):
    h, w = http_world, http_world.w
    assert h.composition.registry.client is w.registry
    response = await post(h)
    assert response.status_code == 200, response.text
    prepared = response.json()
    assert prepared["payload"]["request"]["requester"] == w.root_id
    assert "url" not in prepared
    assert (await post(h)).json() == prepared
    options = await h.composition.signer.approval_options(
        prepared["operation_id"], human=w.human
    )
    committed = await h.composition.signer.execute(
        prepared["operation_id"], w.device.get(dict(options)), human=w.human
    )
    path = "/protected-operations/" + prepared["operation_id"]
    response = await h.client.get(path, headers=headers(w, method="GET", path=path))
    assert response.status_code == 200, response.text
    assert response.json() == {"state": "committed", "result": dict(committed.result)}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@pytest.mark.parametrize("principal", ["", "did:aw:../../namespaces"])
async def test_invalid_stable_requester_header_refuses_before_remote_work(
    http_world, principal
):
    h, w = http_world, http_world.w
    body = canonical_json_bytes(w.operation.intent())
    proof = headers(w, body=body)
    proof["X-AWEB-DID-AW"] = principal
    before = len(w.host.transport.calls)
    response = await h.client.post("/protected-operations", content=body, headers=proof)
    assert response.status_code == 401, response.text
    assert len(w.host.transport.calls) == before


@pytest.mark.asyncio
async def test_worker_proof_cannot_select_human_as_requester(http_world):
    h, w = http_world, http_world.w
    body = canonical_json_bytes(w.operation.intent())
    proof = headers(w, body=body)
    proof["X-AWEB-DID-AW"] = w.context.human_id
    response = await h.client.post("/protected-operations", content=body, headers=proof)
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_prepare_cannot_substitute_profile_scope(http_world):
    h, w = http_world, http_world.w
    operation = replace(w.operation, context=replace(w.context, generation=2))
    response = await post(h, operation)
    assert response.status_code == 403, response.text
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_signer_operations}}"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_resume_get_uses_retained_scope_after_current_profile_generation_changes(
    http_world,
):
    h, w = http_world, http_world.w
    prepared = (await post(h)).json()
    await w.db.execute(
        "UPDATE {{tables.protected_authorizer_bindings}} SET generation=2"
    )
    fields = h.profile.fields()
    fields["bindings"][0]["scope"]["generation"] = 2
    profile = ProtectedServiceProfile.from_json(canonical_json_bytes(fields))
    _, app = mount(w, profile, consumer=h.consumer)
    path = "/protected-operations/" + prepared["operation_id"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN
    ) as client:
        response = await client.get(path, headers=headers(w, method="GET", path=path))
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "pending"
        response = await client.get(
            path,
            headers=headers(
                w, method="GET", path=path, context=replace(w.context, generation=2)
            ),
        )
        assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_profile_current_policy_binding_is_rechecked_in_shared_effect(http_world):
    h, w = http_world, http_world.w
    await w.db.execute(
        "UPDATE {{tables.protected_authorizer_bindings}} SET policy_version=2"
    )
    response = await post(h)
    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "policy_changed"
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_signer_operations}}"
        )
        == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["key", "registry"])
async def test_profile_cannot_select_other_custody_or_registry(http_world, field):
    h = http_world
    fields = h.profile.fields()
    if field == "key":
        fields["bindings"][0]["authority_key_did"] = fields["namespace_authorities"][0][
            "controller_did"
        ]
    else:
        fields["registry_origin"] = "https://other-registry.customer.example"
    profile = ProtectedServiceProfile.from_json(canonical_json_bytes(fields))
    with pytest.raises(SignerRefused):
        mount(h.w, profile)


@pytest.mark.asyncio
async def test_unavailable_configured_registry_keeps_http_503(http_world):
    h = http_world
    h.w.host.transport.down = True
    response = await post(h)
    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "receipt_unavailable"


@pytest.mark.asyncio
async def test_real_human_login_and_separate_uv_reach_exact_agent_receipt(http_world):
    from tests.test_independent_protected_signer import HUMAN_ORIGIN

    h, w = http_world, http_world.w
    composition, app = mount(w, h.profile, human=True, consumer=h.consumer)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN
    ) as cli:
        body = canonical_json_bytes(w.operation.intent())
        response = await cli.post(
            "/protected-operations", content=body, headers=headers(w, body=body)
        )
        assert response.status_code == 200, response.text
        prepared = response.json()
        path = "/handoff/" + prepared["handoff_id"] + "/governance"
        routing = await app.state.protected_operations.page_context(
            prepared["handoff_id"]
        )
        assert routing == {"b3_scope": w.scope, "csrf_key": "protected-human-csrf"}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=HUMAN_ORIGIN
        ) as browser:
            assert (await browser.get(path)).status_code == 401
            login_options = await browser.post(
                "/login/options", json={"scope": w.scope}
            )
            assert login_options.status_code == 200, login_options.text
            login = await browser.post(
                "/login",
                json={
                    "scope": w.scope,
                    "assertion": w.device.get(login_options.json()),
                },
            )
            assert login.status_code == 200, login.text
            human_headers = {
                "Origin": HUMAN_ORIGIN,
                "X-CSRF-Token": login.json()["csrf_token"],
            }
            state = await browser.get(path)
            assert state.status_code == 200, state.text
            assert state.json()["payload"] == prepared["payload"]
            options = await browser.post(
                path + "/options", json={}, headers=human_headers
            )
            assert options.status_code == 200, options.text
            result = await browser.post(
                path + "/execute",
                json={"assertion": w.device.get(options.json())},
                headers=human_headers,
            )
            assert result.status_code == 200, result.text
            assert result.json()["state"] == "committed"
        receipt_path = "/protected-operations/" + prepared["operation_id"]
        receipt = await cli.get(
            receipt_path, headers=headers(w, method="GET", path=receipt_path)
        )
        assert receipt.status_code == 200, receipt.text
        assert receipt.json() == {
            "state": "committed",
            "result": result.json()["result"],
        }
        assert composition.registry.client is w.registry


@pytest.mark.asyncio
async def test_scope_admission_comes_from_current_provisioning_not_a_label(http_world):
    h, w = http_world, http_world.w
    sessions = h.composition.protected_sessions()
    assert await sessions.scopes(w.scope)
    assert not await sessions.scopes("other-scope")
    await w.db.execute(
        "UPDATE {{tables.protected_authorizer_bindings}} SET active=false"
    )
    assert not await sessions.scopes(w.scope)
