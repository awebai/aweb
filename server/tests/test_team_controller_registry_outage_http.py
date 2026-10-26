"""Controller routes honor the SDK outage grace and never fall back to DB hints."""

import httpx
import pytest

import awid.registry as registry_module
from awid.registry import CachedRegistryClient
from test_dashboard_privacy import TEAM_NAME, privacy_app  # noqa: F401
from test_team_controller_rotation_http import _controller_action, rotation_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["replace_key", "status_host"])
@pytest.mark.parametrize("age", [899, 901])
async def test_controller_authority_outage_is_bounded(rotation_app, monkeypatch, operation, age):
    env = rotation_app
    now = 1_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    assert await env.app.state.awid_registry_client.get_team_public_key("example.test", TEAM_NAME) == env.team_did
    now += age
    unavailable = CachedRegistryClient(
        registry_url=env.app.state.awid_registry_client.registry_url, redis_client=env.redis,
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(503, json={"detail": "registry unavailable"}),
        ),
    )
    monkeypatch.setattr(env.app.state, "awid_registry_client", unavailable)
    try:
        response, stored, expected = await _controller_action(env, operation, env.team_sk, env.team_did)
        assert response.status_code == (200 if age <= 900 else 503), response.text
        if age <= 900:
            assert stored == expected
        else:
            assert stored != expected
            assert "AWID team key resolution" in response.json()["detail"]
    finally:
        await unavailable.aclose()
