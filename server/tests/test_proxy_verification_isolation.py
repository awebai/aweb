"""Two live native HTTP/MCP apps keep their own host-auth configuration."""

import os
from contextlib import AsyncExitStack
from uuid import uuid4

import httpx
import pytest
import test_dashboard_privacy
from fastapi import FastAPI

from aweb.embedding import EmbeddingStartupError, OutboxRecoveryOwnership, ResourceStartupStage, default_mcp_factory, embedded_aweb
from aweb.internal_auth import ProxyHeaderTrust, ProxyVerificationConfig, build_internal_auth_header_value
from test_member_team_key import _connect

privacy_app = test_dashboard_privacy.privacy_app


@pytest.mark.asyncio
async def test_two_live_apps_and_failed_startup_keep_http_mcp_proxy_isolation(privacy_app, monkeypatch, caplog):
    env = privacy_app
    actor = env.actors["alice"]
    response = await _connect(env, (actor.sk, actor.did, "alice"), actor.certificate)
    assert response.status_code == 200, response.text
    principal = str(uuid4())
    configs = [ProxyVerificationConfig(trust=ProxyHeaderTrust.SHARED_SECRET, shared_secret=value)
               for value in ("first-live-private-value", "second-live-private-value")]
    arguments = dict(db_infra=env.infra, redis=env.redis, registry_client=env.app.state.awid_registry_client,
                     public_origin=str(env.client.base_url).rstrip("/"), mcp_factory=default_mcp_factory,
                     outbox_recovery=OutboxRecoveryOwnership.HOST)
    async with AsyncExitStack() as cleanup:
        resources = [await cleanup.enter_async_context(embedded_aweb(**arguments, proxy_verification=config))
                     for config in configs]
        host = FastAPI()
        for index, native in enumerate(resources):
            assert native.proxy_verification is configs[index]
            assert native.api_app.state.proxy_verification is configs[index]
            assert native.mcp_app.app.proxy_verification is configs[index]
            native.api_app.mount("/mcp", native.mcp_app)
            host.mount(f"/app-{index}", native.api_app)
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "0")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "unrelated-process-private-value")

        def headers(secret):
            return {"X-Team-ID": test_dashboard_privacy.TEAM, "X-User-ID": principal,
                    "X-AWEB-Actor-ID": str(actor.id), "Accept": "application/json, text/event-stream",
                    "X-AWEB-Auth": build_internal_auth_header_value(secret=secret,
                        team_id=test_dashboard_privacy.TEAM, principal_type="u", principal_id=principal, actor_id=str(actor.id))}

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host), base_url="http://native.test") as client:
            async def verify_pair():
                for index, config in enumerate(configs):
                    for secret, status in ((config.shared_secret, 200), (configs[1-index].shared_secret, 401)):
                        http = await client.get(f"/app-{index}/v1/events/subscriptions", headers=headers(secret))
                        assert http.status_code == status, http.text
                        mcp = await client.post(f"/app-{index}/mcp/", headers=headers(secret),
                                                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                        assert mcp.status_code == status, mcp.text
                        if status == 200:
                            assert mcp.json()["result"]["tools"]
            await verify_pair()
            before = dict(os.environ)

            def refusing_factory(_resources):
                raise RuntimeError("extended manager construction refused")

            with pytest.raises(EmbeddingStartupError) as failed:
                async with embedded_aweb(**{**arguments, "mcp_factory": refusing_factory}, proxy_verification=configs[0]):
                    pytest.fail("failed startup yielded resources")
            assert failed.value.readiness.stage is ResourceStartupStage.MCP
            assert dict(os.environ) == before
            assert env.infra.is_initialized
            await verify_pair()
    assert not any(config.shared_secret in caplog.text for config in configs)
    assert env.infra.is_initialized
