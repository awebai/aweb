"""Embedding uses the actual native resources and extended MCP session app."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Route

from awid.registry import RegistryClient
from aweb.embedding import (
    EmbeddingStartupError,
    OutboxRecoveryOwnership,
    ResourceStartupStage,
    embedded_aweb,
    native_resources,
)
from aweb.mcp.server import ManagedMCPApp
from aweb.mcp.mutations import mutation_callback_from_scope
from aweb.messaging.runtime import messaging_runtime
from aweb.db import DatabaseInfra
from test_awid_transport import awid, db_infra

__all__ = ["awid", "db_infra"]


def _extended_mcp(resources):
    host_context = FastAPI()
    host_context.state.native_resources = resources
    mcp = FastMCP(
        "host extension",
        streamable_http_path="/",
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )

    @mcp.tool()
    async def hosted_extension() -> str:
        """A host's tool must survive native resource startup."""
        assert (
            resources.agent_wake_publisher
            is resources.api_app.state.agent_wake_publisher
        )
        runtime = messaging_runtime(host_context.state)
        assert runtime.registry_client is resources.registry_client
        assert runtime.agent_wake_publisher is resources.agent_wake_publisher
        assert runtime.public_origin == resources.public_origin
        assert (
            mutation_callback_from_scope({"app": host_context}) is resources.on_mutation
        )
        return "host extension present"

    return ManagedMCPApp(mcp.streamable_http_app(), mcp.session_manager)


def test_resource_accessor_requires_the_native_owner():
    with pytest.raises(EmbeddingStartupError) as refused:
        native_resources(FastAPI())
    assert refused.value.stage is ResourceStartupStage.CONFIGURATION
    assert str(refused.value).endswith(
        "Start native resources for this application before retrying."
    )


@pytest.mark.asyncio
async def test_missing_native_migrations_refuse_before_serving(awid, shared_test_pool):
    database = DatabaseInfra()
    await database.initialize(shared_pool=shared_test_pool, run_migrations=False)
    registry = RegistryClient(
        registry_url="http://registry.test", transport=awid.transport
    )
    try:
        with pytest.raises(EmbeddingStartupError) as refused:
            async with embedded_aweb(
                db_infra=database,
                redis=awid.redis,
                registry_client=registry,
                public_origin="https://host.example.test",
                mcp_factory=_extended_mcp,
                outbox_recovery=OutboxRecoveryOwnership.HOST,
            ):
                raise AssertionError("An unmigrated native service must not start")
        assert refused.value.stage is ResourceStartupStage.DATABASE
        assert str(refused.value).endswith(
            "Run apply_native_migrations(db) before serving traffic."
        )
        assert await database.get_manager("aweb").fetch_value("SELECT 1") == 1
    finally:
        await registry.aclose()
        await database.close()


@pytest.mark.asyncio
async def test_actual_extended_mcp_and_native_api_share_borrowed_resources(
    awid, db_infra
):
    registry = RegistryClient(
        registry_url="http://registry.test", transport=awid.transport
    )
    supplied = []

    def factory(resources):
        assert resources.agent_wake_publisher is not None
        supplied.append(_extended_mcp(resources))
        return supplied[-1]

    try:
        async with embedded_aweb(
            db_infra=db_infra,
            redis=awid.redis,
            registry_client=registry,
            public_origin="https://host.example.test",
            mcp_factory=factory,
            outbox_recovery=OutboxRecoveryOwnership.HOST,
        ) as resources:
            assert resources.readiness.ready
            assert resources.mcp_app is supplied[0]
            assert native_resources(resources.api_app) is resources
            assert resources.api_app.state.awid_registry_client is registry
            assert (
                resources.api_app.state.federation_authority
                is resources.federation_authority
            )
            assert (
                getattr(resources.api_app.state, "outbox_recovery_task", None) is None
            )
            host = FastAPI()
            host.mount("/api", resources.api_app)
            host.mount("/mcp", resources.mcp_app)
            # Delegate the unchanged public path to the same native handlers.
            host.router.routes.append(
                Route("/v1/federation/messages", resources.api_app, methods=["POST"])
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=host), base_url="http://host.test"
            ) as client:
                assert (await client.get("/api/ready")).status_code == 200
                tools = await client.post(
                    "/mcp/",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Accept": "application/json, text/event-stream"},
                )
                assert tools.status_code == 200, tools.text
                assert "hosted_extension" in {
                    tool["name"] for tool in tools.json()["result"]["tools"]
                }
                called = await client.post(
                    "/mcp/",
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "hosted_extension", "arguments": {}},
                    },
                    headers={"Accept": "application/json, text/event-stream"},
                )
                assert called.status_code == 200, called.text
                assert "host extension present" in called.text
                root = await client.post(
                    "/v1/federation/messages",
                    json={},
                    headers={"X-Correlation-ID": "same-native-refusal"},
                )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=resources.api_app),
                base_url="http://host.test",
            ) as direct:
                native = await direct.post(
                    "/v1/federation/messages",
                    json={},
                    headers={"X-Correlation-ID": "same-native-refusal"},
                )
            assert root.status_code == native.status_code >= 400
            assert root.json() == native.json()
        assert not resources.readiness.ready
        assert resources.readiness.stage is ResourceStartupStage.CLOSED
        assert await awid.redis.ping()
        assert await db_infra.get_manager("aweb").fetch_value("SELECT 1") == 1
        await registry.health()
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_partial_start_failure_cleans_native_tasks_and_keeps_borrowed_clients(
    awid, db_infra
):
    registry = RegistryClient(
        registry_url="http://registry.test", transport=awid.transport
    )
    captured = []
    prior_hubs = {
        task for task in asyncio.all_tasks() if task.get_name() == "agent-wake-hub"
    }

    def broken_factory(resources):
        captured.append(resources)
        raise RuntimeError("host MCP construction failed")

    try:
        with pytest.raises(EmbeddingStartupError) as refused:
            async with embedded_aweb(
                db_infra=db_infra,
                redis=awid.redis,
                registry_client=registry,
                public_origin="https://host.example.test",
                mcp_factory=broken_factory,
                outbox_recovery=OutboxRecoveryOwnership.HOST,
            ):
                raise AssertionError(
                    "A failed construction must not yield ready resources"
                )
        assert refused.value.stage is ResourceStartupStage.MCP
        assert str(refused.value).endswith(
            "Check this resource and restart native startup before serving traffic."
        )
        assert isinstance(refused.value.__cause__, RuntimeError)
        assert not captured[0].readiness.ready
        assert {
            task for task in asyncio.all_tasks() if task.get_name() == "agent-wake-hub"
        } == prior_hubs
        assert await awid.redis.ping()
        await registry.health()
        assert await db_infra.get_manager("aweb").fetch_value("SELECT 1") == 1
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_native_recovery_ownership_starts_once_and_stopped_resources_cannot_report_ready(
    awid, db_infra
):
    registry = RegistryClient(
        registry_url="http://registry.test", transport=awid.transport
    )
    try:
        async with embedded_aweb(
            db_infra=db_infra,
            redis=awid.redis,
            registry_client=registry,
            public_origin="https://host.example.test",
            mcp_factory=_extended_mcp,
            outbox_recovery=OutboxRecoveryOwnership.NATIVE,
        ) as resources:
            recovery = resources.api_app.state.outbox_recovery_task
            assert not recovery.done()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=resources.api_app),
                base_url="http://host.test",
            ) as client:
                assert (await client.get("/ready")).status_code == 200
                assert resources.api_app.state.outbox_recovery_task is recovery
                await resources.mcp_app.shutdown()
                stopped = await client.get("/ready")
                assert stopped.status_code == 503
                assert stopped.json()["message"].endswith(
                    "Restart native startup and verify the API and MCP mounts before serving traffic."
                )
        assert recovery.done()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=resources.api_app),
            base_url="http://host.test",
        ) as client:
            assert (await client.get("/ready")).status_code == 503
        assert resources.api_app.state.outbox_recovery_task is recovery
    finally:
        await registry.aclose()
