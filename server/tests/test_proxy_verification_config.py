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
