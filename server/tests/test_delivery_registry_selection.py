"""Serving-resource selection is configuration, never identity or admission proof."""

import json
from types import SimpleNamespace

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request

from awid.did import did_from_public_key, generate_keypair
from awid.registry import RegistryClient
from aweb.federation.envelope import FederatedDeliveryRequest
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools.federation import mcp_messaging_runtime
from aweb.messaging.runtime import messaging_runtime
from aweb.routes.federation import receive_federated_message
from test_federation_envelope import _envelope, _sign


@pytest_asyncio.fixture
async def registry_clients():
    clients = []

    def create(origin):
        client = RegistryClient(registry_url=origin)
        clients.append(client)
        return client

    yield create
    for client in clients:
        await client.aclose()


def _root(selected, shadow):
    native = FastAPI()
    native.state.awid_registry_client = shadow
    root = FastAPI()
    root.state.awid_registry_client = shadow
    # The lower-layer configuration seam needs no R7 lifecycle or auth artifact.
    root.state.native_resources = SimpleNamespace(
        api_app=native, registry_client=selected
    )
    return root


def _runtime(kind, app):
    if kind == "native":
        return messaging_runtime(app.state)
    return mcp_messaging_runtime(
        AuthContext(
            team_id=None,
            agent_id=None,
            alias=None,
            did_key="",
            request=Request({"type": "http", "app": app, "headers": []}),
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["native", "mcp"])
async def test_root_runtime_selects_exact_resource_over_both_shadow_slots(
    registry_clients, kind
):
    selected = registry_clients("https://selected.example")
    shadow = registry_clients("https://shadow.example")
    assert _runtime(kind, _root(selected, shadow)).registry_client is selected


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["native", "mcp"])
async def test_missing_resource_client_never_falls_through_to_shadow(
    registry_clients, kind
):
    shadow = registry_clients("https://shadow.example")
    assert _runtime(kind, _root(None, shadow)).registry_client is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["native", "mcp"])
async def test_unembedded_runtime_keeps_selected_client_and_optional_absence(
    registry_clients, kind
):
    native = FastAPI()
    assert _runtime(kind, native).registry_client is None
    client = registry_clients("https://native.example")
    native.state.awid_registry_client = client
    assert _runtime(kind, native).registry_client is client


@pytest.mark.asyncio
async def test_explicit_mcp_foreign_client_wins_even_without_resource_client(
    registry_clients,
):
    explicit = registry_clients("https://foreign.example")
    root = _root(None, registry_clients("https://shadow.example"))
    auth = AuthContext(
        team_id=None,
        agent_id=None,
        alias=None,
        did_key="",
        request=Request({"type": "http", "app": root, "headers": []}),
    )
    assert (
        mcp_messaging_runtime(auth, registry_client=explicit).registry_client
        is explicit
    )
    assert (
        mcp_messaging_runtime(
            AuthContext(team_id=None, agent_id=None, alias=None, did_key="")
        ).registry_client
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [True, False])
async def test_root_ingress_preserves_signature_and_missing_registry_refusals(
    registry_clients, configured
):
    selected = registry_clients("https://selected.example") if configured else None
    root = _root(selected, None)
    if not configured:
        # A valid shadow cannot rescue a missing selected resource.
        root.state.awid_registry_client = registry_clients("https://shadow.example")
    _, public = generate_keypair()
    wrong_key, _ = generate_keypair()
    envelope = _envelope(did_from_public_key(public))
    payload = FederatedDeliveryRequest(
        envelope=envelope, signature=_sign(envelope, wrong_key)
    )
    request = Request({"type": "http", "app": root, "headers": []})
    # Direct route boundary: invalid integrity must refuse before any database
    # access or admission. This is not successful federation authority evidence.
    result = await receive_federated_message(request, payload, db=None)
    body = json.loads(result.body)
    if configured:
        assert result.status_code == 422
        assert body["reason"] == "federation_signature_invalid"
        assert body["retryable"] is False
    else:
        assert result.status_code == 503
        assert body["reason"] == "federation_authority_coordination_unavailable"
        assert body["retryable"] is True
        # This coordination reason is retryable but, unlike rate limiting,
        # has no Retry-After requirement in federation-error-reference.md:29.
        assert "Retry-After" not in result.headers
