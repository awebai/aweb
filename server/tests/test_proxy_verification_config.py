"""Proxy configuration belongs to the constructed application, not the process."""

from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aweb.api import create_app
from aweb.internal_auth import build_internal_auth_header_value, parse_internal_auth_context


TEAM = "proxy:example.test"
PRINCIPAL = str(uuid4())
ACTOR = str(uuid4())


def proxy_request(app, secret):
    headers = {
        "X-Team-ID": TEAM,
        "X-User-ID": PRINCIPAL,
        "X-AWEB-Actor-ID": ACTOR,
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret=secret, team_id=TEAM, principal_type="u", principal_id=PRINCIPAL, actor_id=ACTOR,
        ),
    }
    return Request({"type": "http", "app": app, "path": "/v1/events/subscriptions",
                    "headers": [(name.lower().encode(), value.encode()) for name, value in headers.items()]})


def test_each_app_keeps_environment_configuration_captured_at_construction(monkeypatch):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "first-app-only")
    first = create_app()
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "second-app-only")
    second = create_app()
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "0")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "subsequent-process-value")
    expected = dict(team_id=TEAM, principal_type="u", principal_id=PRINCIPAL, actor_id=ACTOR)
    assert parse_internal_auth_context(proxy_request(first, "first-app-only")) == expected
    assert parse_internal_auth_context(proxy_request(second, "second-app-only")) == expected
    for app, other_secret in ((first, "second-app-only"), (second, "first-app-only")):
        with pytest.raises(HTTPException) as refused:
            parse_internal_auth_context(proxy_request(app, other_secret))
        assert refused.value.status_code == 401
        assert refused.value.detail == "Authentication required"


def test_enabled_without_secret_refuses_construction_without_process_changes(monkeypatch):
    import os

    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.delenv("AWEB_INTERNAL_AUTH_SECRET", raising=False)
    before = dict(os.environ)
    with pytest.raises(ValueError, match="Configure a nonempty shared secret or disable proxy header trust before constructing the application"):
        create_app()
    assert dict(os.environ) == before


def test_explicit_disabled_and_enabled_apps_ignore_later_environment(monkeypatch):
    from dataclasses import FrozenInstanceError
    from aweb.internal_auth import ProxyHeaderTrust, ProxyVerificationConfig

    config = ProxyVerificationConfig(trust=ProxyHeaderTrust.SHARED_SECRET, shared_secret="explicit-private-value")
    enabled = create_app(proxy_verification=config)
    disabled = create_app(proxy_verification=ProxyVerificationConfig(trust=ProxyHeaderTrust.DISABLED))
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "other-private-value")
    assert enabled.state.proxy_verification is config
    assert parse_internal_auth_context(proxy_request(enabled, "explicit-private-value"))["actor_id"] == ACTOR
    assert parse_internal_auth_context(proxy_request(disabled, "other-private-value")) is None
    assert "explicit-private-value" not in repr(config)
    with pytest.raises(FrozenInstanceError):
        config.shared_secret = "replacement"


@pytest.mark.asyncio
async def test_public_mcp_middleware_captures_its_exact_configuration(monkeypatch):
    from aweb.internal_auth import ProxyHeaderTrust, ProxyVerificationConfig
    from aweb.mcp.auth import MCPAuthMiddleware

    config = ProxyVerificationConfig(trust=ProxyHeaderTrust.SHARED_SECRET, shared_secret="middleware-private-value")
    app = create_app(proxy_verification=config)
    middleware = MCPAuthMiddleware(app, None, proxy_verification=config)
    assert middleware.proxy_verification is config
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "0")
    monkeypatch.delenv("AWEB_INTERNAL_AUTH_SECRET", raising=False)
    with pytest.raises(HTTPException) as refused:
        await middleware._resolve_auth(proxy_request(app, "another-private-value"))
    assert refused.value.status_code == 401
    assert refused.value.detail == "Authentication required"


def test_resource_configuration_wins_and_missing_resource_never_uses_shadow():
    from types import SimpleNamespace
    from aweb.internal_auth import ProxyHeaderTrust, ProxyVerificationConfig, ProxyVerificationConfigurationError

    native = ProxyVerificationConfig(trust=ProxyHeaderTrust.SHARED_SECRET, shared_secret="native-private-value")
    shadow = ProxyVerificationConfig(trust=ProxyHeaderTrust.SHARED_SECRET, shared_secret="shadow-private-value")
    app = create_app(proxy_verification=shadow)
    app.state.native_resources = SimpleNamespace(proxy_verification=native)
    assert parse_internal_auth_context(proxy_request(app, "native-private-value"))["actor_id"] == ACTOR
    with pytest.raises(HTTPException) as refused:
        parse_internal_auth_context(proxy_request(app, "shadow-private-value"))
    assert refused.value.status_code == 401
    app.state.native_resources = SimpleNamespace(proxy_verification=None)
    with pytest.raises(ProxyVerificationConfigurationError) as unavailable:
        parse_internal_auth_context(proxy_request(app, "shadow-private-value"))
    assert str(unavailable.value) == "Configure proxy verification through the application constructor before serving requests."


@pytest.mark.parametrize("trust,secret", [("injected-private-value", "hidden-private-value"), (None, "hidden-private-value")])
def test_configuration_diagnostic_never_discloses_values(trust, secret, caplog):
    from aweb.internal_auth import ProxyVerificationConfig, ProxyVerificationConfigurationError

    with pytest.raises(ProxyVerificationConfigurationError) as refused:
        ProxyVerificationConfig(trust=trust, shared_secret=secret)
    assert str(refused.value) == "Choose ProxyHeaderTrust.DISABLED or SHARED_SECRET before constructing the application."
    assert "private-value" not in str(refused.value) + caplog.text
