"""Environment entry point for the customer-run service, using the sole root."""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from aweb_naapp.egress.send import Resolver
from aweb_naapp.runtime.hook_egress import HookEgress, HookEgressSettings
from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aweb_secrets.app import SecretsService
from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings


class DeploymentSettings(ServiceSettings, HookEgressSettings):
    """Explicit hook options; broker trust and switches are independent."""

    model_config = SettingsConfigDict(hide_input_in_errors=True)

    database_url: str = Field(min_length=1)
    public_origin: str = Field(min_length=1)
    console_origin: str = Field(min_length=1)
    app_id: str = Field(min_length=1)
    awid_registry_url: str = Field(min_length=1)


def create_deployment(
    settings: DeploymentSettings | None = None,
    *,
    resolver: Resolver | None = None,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
) -> SecretsService:
    """Build the real root; validate every internal origin before its lifespan."""
    settings = settings if settings is not None else DeploymentSettings(_env_file=None)
    hooks = HookEgress.from_settings(settings, resolver=resolver)
    service = create_service(
        settings,
        awid_transport=awid_transport,
        team_server_transport=team_server_transport,
        hook_egress=hooks.egress,
        hook_internal_cidr=hooks.internal_cidr,
        hook_internal_origins=hooks.internal_origins,
    )
    lifespan = service.api_app.router.lifespan_context

    @asynccontextmanager
    async def checked_lifespan(app):
        await hooks.preflight()
        async with lifespan(app) as state:
            yield state

    service.api_app.router.lifespan_context = checked_lifespan
    return service


def create_app() -> SecretsService:
    """Uvicorn factory; deployment reads environment only, never an ambient .env."""
    return create_deployment()
