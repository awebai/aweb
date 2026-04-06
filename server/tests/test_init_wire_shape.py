"""Verify the bootstrap/init wire shape matches the aw client contract."""

import pytest
from pydantic import ValidationError
from starlette.requests import Request
from types import SimpleNamespace

from aweb.awid import CachedRegistryClient, RegistryClient
from aweb.routes.init import CreateProjectRequest, InitRequest, InitResponse, _registry_client_for_request


def test_create_project_request_requires_project_slug():
    with pytest.raises(ValidationError, match="Field required"):
        CreateProjectRequest(alias="alice")


def test_create_project_request_allows_server_assigned_ephemeral_alias():
    req = CreateProjectRequest(project_slug="my-project")
    assert req.project_slug == "my-project"
    assert req.alias is None
    assert req.name is None
    assert req.lifetime == "ephemeral"


def test_create_project_request_accepts_owner_scope_fields():
    req = CreateProjectRequest(
        project_slug="my-project",
        owner_type="organization",
        owner_ref="acme",
    )
    assert req.owner_type == "organization"
    assert req.owner_ref == "acme"


def test_create_project_request_requires_owner_fields_together():
    with pytest.raises(ValidationError, match="owner_type and owner_ref must be provided together"):
        CreateProjectRequest(project_slug="my-project", owner_ref="acme")


def test_create_project_request_requires_name_for_persistent():
    with pytest.raises(ValidationError, match="name is required for persistent identities"):
        CreateProjectRequest(project_slug="my-project", alias="alice", lifetime="persistent")


def test_create_project_request_rejects_both_alias_and_name():
    with pytest.raises(ValidationError, match="provide either alias or name, not both"):
        CreateProjectRequest(
            project_slug="my-project",
            alias="alice",
            name="alice",
        )


def test_init_request_accepts_aw_client_fields():
    """InitRequest must accept all fields the aw client sends."""
    req = InitRequest(
        project_slug="my-project",
        namespace_slug="example",
        name="alice",
        address_reachability="public",
        human_name="Alice Agent",
        agent_type="agent",
        did="did:key:z6Mktest",
        public_key="z6Mktest",
        custody="self",
        lifetime="persistent",
    )
    # namespace_slug should be normalized to namespace
    assert req.namespace == "example"
    assert req.name == "alice"
    assert req.alias is None


def test_init_request_accepts_namespace_directly():
    """InitRequest still accepts the namespace field directly."""
    req = InitRequest(
        project_slug="my-project",
        namespace="example",
    )
    assert req.namespace == "example"


def test_init_request_namespace_slug_does_not_override_namespace():
    """When both namespace and namespace_slug are provided, namespace wins."""
    req = InitRequest(
        project_slug="my-project",
        namespace="primary",
        namespace_slug="secondary",
    )
    assert req.namespace == "primary"


def test_init_request_accepts_coordination_extension_fields():
    """InitRequest accepts coordination fields alongside protocol fields."""
    req = InitRequest(
        project_slug="my-project",
        project_id="550e8400-e29b-41d4-a716-446655440000",
        repo_origin="https://github.com/test/repo.git",
        role="agent",
        hostname="dev-machine",
        workspace_path="/home/user/repo",
    )
    assert req.project_id == "550e8400-e29b-41d4-a716-446655440000"


def test_init_response_includes_identity_id():
    """InitResponse returns identity_id alongside agent_id for aw compat."""
    resp = InitResponse(
        created_at="2026-01-01T00:00:00Z",
        api_key="aw_sk_test",
        project_id="550e8400-e29b-41d4-a716-446655440000",
        project_slug="my-project",
        identity_id="660e8400-e29b-41d4-a716-446655440000",
        agent_id="660e8400-e29b-41d4-a716-446655440000",
        alias="alice-01-agent",
    )
    data = resp.model_dump()
    assert data["identity_id"] == data["agent_id"]
    assert "namespace_slug" in data
    assert "name" in data
    assert "server_url" in data


def test_registry_client_factory_uses_cached_client_when_redis_available(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
    singleton = CachedRegistryClient(
        registry_url="https://api.awid.ai",
        redis_client=object(),
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("api.example", 443),
            "client": ("127.0.0.1", 12345),
            "app": SimpleNamespace(
                state=SimpleNamespace(redis=object(), awid_registry_client=singleton)
            ),
        }
    )

    client = _registry_client_for_request(request)

    assert client is singleton


def test_registry_client_factory_uses_plain_client_without_redis(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("api.example", 443),
            "client": ("127.0.0.1", 12345),
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )

    client = _registry_client_for_request(request)

    assert type(client) is RegistryClient
