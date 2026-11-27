"""One native resource lifecycle for standalone and embedding hosts.

Hosts own their clients, policy/wrappers and actual mount registrations. This
owner borrows those clients and starts/closes only native serving resources.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from awid.registry import RegistryClient
from fastapi import FastAPI
from redis.asyncio import Redis

from aweb.agent_wake import AgentWakeHub, AgentWakePublisher
from aweb.attachments import AttachmentBackend
from aweb.db import DatabaseInfrastructure
from aweb.federation.activation import (
    FederationAuthorityActivation,
    build_federation_authority_activation,
)
from aweb.hooks import MutationCallback
from aweb.internal_auth import ProxyVerificationConfig, application_proxy_verification
from aweb.mcp.server import ManagedMCPApp, create_mcp_app
from aweb.migrations import pending_native_migrations
from aweb.mutation_hooks import create_mutation_handler
from aweb.outbox_recovery import start_outbox_recovery, stop_outbox_recovery
from aweb.resource_startup import (
    start_agent_wakes,
    stop_agent_wakes,
    validate_awid_registry_client,
)

logger = logging.getLogger(__name__)


class OutboxRecoveryOwnership(StrEnum):
    HOST = "host"
    NATIVE = "native"


class ResourceStartupStage(StrEnum):
    CONFIGURATION = "configuration"
    DATABASE = "database"
    REGISTRY = "registry"
    FEDERATION = "federation"
    WAKES = "wakes"
    MCP = "mcp"
    RECOVERY = "recovery"
    READY = "ready"
    CLOSED = "closed"


@dataclass(frozen=True)
class NativeResourceReadiness:
    ready: bool
    stage: ResourceStartupStage
    message: str


class EmbeddingStartupError(RuntimeError):
    def __init__(self, stage: ResourceStartupStage, message: str | None = None):
        self.stage = stage
        message = message or (
            f"Native {stage.value} startup failed. "
            "Check this resource and restart native startup before serving traffic."
        )
        self.readiness = NativeResourceReadiness(False, stage, message)
        super().__init__(message)


@dataclass
class EmbeddedResources:
    api_app: FastAPI
    db_infra: DatabaseInfrastructure
    redis: Redis
    registry_client: RegistryClient
    public_origin: str
    outbox_recovery: OutboxRecoveryOwnership
    on_mutation: MutationCallback
    proxy_verification: ProxyVerificationConfig
    federation_authority: FederationAuthorityActivation | None = None
    agent_wake_publisher: AgentWakePublisher | None = None
    agent_wake_hub: AgentWakeHub | None = None
    mcp_app: ManagedMCPApp | None = None
    _stage: ResourceStartupStage = ResourceStartupStage.CONFIGURATION
    _failure: NativeResourceReadiness | None = None

    @property
    def readiness(self) -> NativeResourceReadiness:
        """Report the current native startup stage and required resource readiness."""
        if self._failure is not None:
            return self._failure
        if self._stage is ResourceStartupStage.CLOSED:
            return NativeResourceReadiness(
                False,
                self._stage,
                "Native resources have stopped. Restart native startup and verify the API and MCP mounts before serving traffic.",
            )
        if self._stage is not ResourceStartupStage.READY:
            return NativeResourceReadiness(
                False,
                self._stage,
                f"Native {self._stage.value} resources are starting.",
            )
        failed = None
        if self.mcp_app is None or not self.mcp_app.is_running:
            failed = ResourceStartupStage.MCP
        elif self.agent_wake_hub is None or not self.agent_wake_hub.is_running:
            failed = ResourceStartupStage.WAKES
        elif self.outbox_recovery is OutboxRecoveryOwnership.NATIVE:
            recovery = getattr(self.api_app.state, "outbox_recovery_task", None)
            if recovery is None or recovery.done():
                failed = ResourceStartupStage.RECOVERY
        if failed is not None:
            return NativeResourceReadiness(
                False,
                failed,
                f"Native {failed.value} resources are not running. Restart native startup and verify the API and MCP mounts before serving traffic.",
            )
        return NativeResourceReadiness(
            True,
            ResourceStartupStage.READY,
            "Native resources are running. Verify the host's actual API and MCP mounts before serving traffic.",
        )


class MCPFactory(Protocol):
    def __call__(self, resources: EmbeddedResources) -> ManagedMCPApp: ...


def native_resources(app: FastAPI) -> EmbeddedResources:
    """The one typed reference a host may share with wrappers and adapters."""
    resources = getattr(app.state, "native_resources", None)
    if not isinstance(resources, EmbeddedResources):
        raise EmbeddingStartupError(
            ResourceStartupStage.CONFIGURATION,
            "Native resources are unavailable. Start native resources for this application before retrying.",
        )
    return resources


def default_mcp_factory(resources: EmbeddedResources) -> ManagedMCPApp:
    """Build the native managed MCP app from the shared serving references."""
    return create_mcp_app(
        db_infra=resources.db_infra,
        redis=resources.redis,
        registry_client=resources.registry_client,
        federation_authority=resources.federation_authority,
        public_origin=resources.public_origin,
        streamable_http_path="/",
        proxy_verification=resources.proxy_verification,
    )


@asynccontextmanager
async def start_native_resources(
    *,
    api_app: FastAPI,
    db_infra: DatabaseInfrastructure,
    redis: Redis,
    registry_client: RegistryClient,
    mcp_factory: MCPFactory,
    outbox_recovery: OutboxRecoveryOwnership,
    on_mutation: MutationCallback | None = None,
) -> AsyncIterator[EmbeddedResources]:
    """Shared native owner; caller retains DB, Redis and registry lifecycles."""

    if type(outbox_recovery) is not OutboxRecoveryOwnership:
        raise EmbeddingStartupError(
            ResourceStartupStage.CONFIGURATION,
            "Outbox recovery ownership is required. Select HOST or NATIVE ownership and restart native startup before serving traffic.",
        )
    existing = getattr(api_app.state, "native_resources", None)
    if (
        isinstance(existing, EmbeddedResources)
        and existing._stage is not ResourceStartupStage.CLOSED
        and existing._failure is None
    ):
        raise EmbeddingStartupError(
            ResourceStartupStage.CONFIGURATION,
            "This application already owns native resources. Stop its current native context before starting another one.",
        )
    resources = EmbeddedResources(
        api_app,
        db_infra,
        redis,
        registry_client,
        api_app.state.public_origin,
        outbox_recovery,
        create_mutation_handler(redis, db_infra)
        if on_mutation is None
        else on_mutation,
        proxy_verification=application_proxy_verification(api_app.state),
    )
    api_app.state.native_resources = resources
    yielded = False
    try:
        async with AsyncExitStack() as cleanup:
            resources._stage = ResourceStartupStage.DATABASE
            await db_infra.get_manager("aweb").fetch_value("SELECT 1")
            migrations = await pending_native_migrations(db_infra.get_manager("aweb"))
            if not migrations.ready:
                raise EmbeddingStartupError(
                    ResourceStartupStage.DATABASE, migrations.message
                )
            resources._stage = ResourceStartupStage.REGISTRY
            await validate_awid_registry_client(registry_client)
            api_app.state.db = db_infra
            api_app.state.redis = redis
            api_app.state.awid_registry_client = registry_client
            api_app.state.on_mutation = resources.on_mutation
            resources._stage = ResourceStartupStage.FEDERATION
            resources.federation_authority = build_federation_authority_activation(
                db_infra, public_origin=resources.public_origin
            )
            cleanup.push_async_callback(resources.federation_authority.aclose)
            api_app.state.federation_authority = resources.federation_authority
            resources._stage = ResourceStartupStage.WAKES
            cleanup.push_async_callback(stop_agent_wakes, api_app)
            await start_agent_wakes(api_app, redis)
            resources.agent_wake_publisher = api_app.state.agent_wake_publisher
            resources.agent_wake_hub = api_app.state.agent_wake_hub
            resources._stage = ResourceStartupStage.MCP
            resources.mcp_app = mcp_factory(resources)
            if not isinstance(resources.mcp_app, ManagedMCPApp):
                raise TypeError("mcp_factory must return the actual ManagedMCPApp")
            cleanup.push_async_callback(resources.mcp_app.shutdown)
            await resources.mcp_app.startup()
            api_app.state.mcp_app = resources.mcp_app
            resources._stage = ResourceStartupStage.RECOVERY
            if outbox_recovery is OutboxRecoveryOwnership.NATIVE:
                cleanup.push_async_callback(stop_outbox_recovery, api_app)
                start_outbox_recovery(api_app)
            resources._stage = ResourceStartupStage.READY
            yielded = True
            try:
                yield resources
            finally:
                resources._stage = ResourceStartupStage.CLOSED
    except Exception as exc:
        if yielded:
            raise
        error = (
            exc
            if isinstance(exc, EmbeddingStartupError)
            else EmbeddingStartupError(resources._stage)
        )
        resources._failure = error.readiness
        logger.exception("Native resource startup failed at %s", error.stage.value)
        if error is exc:
            raise
        raise error from exc


@asynccontextmanager
async def embedded_aweb(
    *,
    db_infra: DatabaseInfrastructure,
    redis: Redis,
    registry_client: RegistryClient,
    public_origin: str,
    mcp_factory: MCPFactory,
    outbox_recovery: OutboxRecoveryOwnership,
    on_mutation: MutationCallback | None = None,
    attachment_backend: AttachmentBackend | None = None,
    proxy_verification: ProxyVerificationConfig | None = None,
) -> AsyncIterator[EmbeddedResources]:
    """Create/start native API and the actual host-supplied extended MCP app.

    Mount the yielded handles under host wrappers/paths and verify those actual
    registrations separately. This context never closes borrowed input clients.
    """
    from aweb.api import create_app

    if type(outbox_recovery) is not OutboxRecoveryOwnership:
        raise EmbeddingStartupError(
            ResourceStartupStage.CONFIGURATION,
            "Outbox recovery ownership is required. Select HOST or NATIVE ownership and restart native startup before serving traffic.",
        )
    try:
        api_app = create_app(
            db_infra=db_infra,
            redis=redis,
            public_origin=public_origin,
            host_runs_outbox_recovery=outbox_recovery is OutboxRecoveryOwnership.HOST,
            attachment_backend=attachment_backend,
            proxy_verification=proxy_verification,
        )
    except Exception as exc:
        logger.exception("Native application construction failed")
        raise EmbeddingStartupError(ResourceStartupStage.CONFIGURATION) from exc
    async with start_native_resources(
        api_app=api_app,
        db_infra=db_infra,
        redis=redis,
        registry_client=registry_client,
        mcp_factory=mcp_factory,
        outbox_recovery=outbox_recovery,
        on_mutation=on_mutation,
    ) as resources:
        yield resources
