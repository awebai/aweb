"""Native serving helpers consume one host resource reference without copies."""

import pytest
from fastapi import FastAPI
from starlette.requests import Request
from redis.asyncio import Redis

from awid.registry import RegistryClient
from aweb.internal_auth import application_proxy_verification
from aweb.agent_wake import AgentWakePublisher, agent_wake_publisher
from aweb.embedding import EmbeddedResources, OutboxRecoveryOwnership
from aweb.federation.origins import application_public_origins
from aweb.hooks import mutation_callback
from aweb.identity_binding import identity_binding_cache
from aweb.mcp.mutations import mutation_callback_from_scope
from aweb.messaging.runtime import messaging_runtime


@pytest.mark.asyncio
async def test_host_reference_selects_same_native_serving_facts():
    # A plumbing unit test: no clients connect, and no identity proof is made.
    registry = RegistryClient(registry_url="https://registry.example.test")
    redis = Redis.from_url("redis://unused:6379")
    api, host = FastAPI(), FastAPI()

    async def on_mutation(_event, _payload):
        return None

    publisher = AgentWakePublisher(redis)
    api.state.awid_registry_client = registry
    api.state.agent_wake_publisher = publisher
    api.state.on_mutation = on_mutation
    api.state.public_origin = "https://native.example.test"
    resources = EmbeddedResources(
        api, None, redis, registry, api.state.public_origin, OutboxRecoveryOwnership.HOST, on_mutation,
        proxy_verification=application_proxy_verification(api.state),
    )
    host.state.native_resources = resources
    try:
        assert agent_wake_publisher(host.state) is publisher
        runtime = messaging_runtime(host.state)
        assert runtime.registry_client is registry
        assert runtime.agent_wake_publisher is publisher
        assert runtime.on_mutation is on_mutation
        assert runtime.public_origin == api.state.public_origin
        assert runtime.identity_binding_cache is identity_binding_cache(host.state)
        assert runtime.identity_binding_cache is identity_binding_cache(api.state)
        assert application_public_origins(host.state) == {api.state.public_origin}
        assert mutation_callback_from_scope({"app": host}) is on_mutation
        request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "app": host})
        assert mutation_callback(request) is on_mutation
        assert agent_wake_publisher(api.state) is publisher
        assert messaging_runtime(api.state).registry_client is registry
        assert mutation_callback_from_scope({"app": api}) is on_mutation
        assert not hasattr(host.state, "agent_wake_publisher")
        assert not hasattr(host.state, "awid_registry_client")
    finally:
        await redis.aclose()
        await registry.aclose()
