"""Presence and request snapshots borrow the identical configured registry."""

import httpx
import pytest
from aweb.internal_auth import ProxyHeaderTrust, ProxyVerificationConfig
from aweb.application_state import RegistryClientUnavailable, application_registry_client
from aweb.embedding import EmbeddedResources, OutboxRecoveryOwnership, native_resources
from aweb.service_errors import INTERNAL_SERVICE_ERROR_MESSAGE, ServiceError
from awid.registry import CachedRegistryClient, RegistryClient
from fastapi import FastAPI
from redis.asyncio import Redis


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True])
async def test_initialized_legacy_state_returns_its_client_without_other_resources(cached):
    redis = Redis.from_url("redis://unused:6379")
    client = (
        CachedRegistryClient(redis_client=redis, registry_url="https://registry.example.test")
        if cached else RegistryClient(registry_url="https://registry.example.test")
    )
    app = FastAPI()
    app.state.awid_registry_client = client
    before = dict(app.state._state)
    try:
        assert application_registry_client(app.state) is client
        assert app.state._state == before
        assert not hasattr(app.state, "native_resources")
    finally:
        await client.aclose()
        await redis.aclose()


@pytest.mark.asyncio
async def test_native_registry_reference_wins_over_all_conflicting_shadow_fields():
    redis = Redis.from_url("redis://unused:6379")
    client = RegistryClient(registry_url="https://native-registry.example.test")
    shadow = RegistryClient(registry_url="https://shadow-registry.example.test")
    api, host = FastAPI(), FastAPI()
    resources = EmbeddedResources(
        api_app=api, db_infra=None, redis=redis, registry_client=client,
        public_origin="https://native.example.test", outbox_recovery=OutboxRecoveryOwnership.HOST,
        on_mutation=None,
        proxy_verification=ProxyVerificationConfig(trust=ProxyHeaderTrust.DISABLED),
    )
    for app in (api, host):
        app.state.native_resources = resources
        app.state.awid_registry_client = shadow
    try:
        for app in (api, host):
            before = dict(app.state._state)
            assert application_registry_client(app.state) is native_resources(app).registry_client
            assert application_registry_client(app.state) is client
            assert app.state._state == before
        # A resource reference is authoritative even before full MCP/wake startup.
        assert resources.mcp_app is None
    finally:
        await client.aclose()
        await shadow.aclose()
        await redis.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("resource_reference", [False, True])
@pytest.mark.parametrize("selected_client", [None, "invalid registry client"])
async def test_missing_selected_registry_is_one_typed_actionable_503(resource_reference, selected_client):
    app = FastAPI()
    redis = Redis.from_url("redis://unused:6379")
    shadow = RegistryClient(registry_url="https://shadow-registry.example.test")
    if resource_reference:
        app.state.awid_registry_client = shadow
        app.state.native_resources = EmbeddedResources(
            api_app=FastAPI(), db_infra=None, redis=redis, registry_client=selected_client,
            public_origin="https://native.example.test", outbox_recovery=OutboxRecoveryOwnership.HOST,
            on_mutation=None,
        proxy_verification=ProxyVerificationConfig(trust=ProxyHeaderTrust.DISABLED),
        )
    else:
        app.state.awid_registry_client = selected_client
    before = dict(app.state._state)
    try:
        with pytest.raises(RegistryClientUnavailable) as refused:
            application_registry_client(app.state)
        assert isinstance(refused.value, ServiceError)
        assert refused.value.status_code == 503
        assert refused.value.code == "registry_client_unavailable"
        assert refused.value.message == refused.value.detail["message"]
        assert refused.value.detail["code"] == "registry_client_unavailable"
        assert refused.value.detail["message"].endswith(
            "Configure the serving registry client and start the application before retrying."
        )
        assert app.state._state == before
    finally:
        await shadow.aclose()
        await redis.aclose()


@pytest.mark.asyncio
async def test_native_http_mapping_preserves_the_expected_configuration_503():
    from aweb.api import create_app

    app = create_app()

    @app.get("/serving-registry-test")
    async def selected_registry():
        application_registry_client(app.state)
        return {"configured": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/serving-registry-test")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "registry_client_unavailable"
    assert response.json()["detail"]["message"].endswith(
        "Configure the serving registry client and start the application before retrying."
    )


@pytest.mark.asyncio
async def test_unknown_service_error_503_keeps_the_existing_generic_mask():
    from aweb.api import create_app

    class UnknownServiceError(ServiceError):
        status_code = 503

    app = create_app()

    @app.get("/unknown-service-error-test")
    async def unknown_failure():
        raise UnknownServiceError("private upstream failure detail")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/unknown-service-error-test")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error", "message": INTERNAL_SERVICE_ERROR_MESSAGE}
