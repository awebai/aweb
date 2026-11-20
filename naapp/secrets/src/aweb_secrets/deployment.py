"""Environment entry point for the customer-run service, using the sole root."""

from __future__ import annotations

import httpx
from aweb_naapp.egress.send import Resolver
from aweb_naapp.runtime.operator_egress import OperatorEgress
from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aweb_secrets.app import SecretsService
from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings


class DeploymentSettings(ServiceSettings):
    """The customer-run service's settings, read from the environment only;
    broker trust and switches are independent of the operator network."""

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
) -> SecretsService:
    """Build the real root. The runtime checks every listed internal origin
    before its lifespan serves anything."""
    settings = settings if settings is not None else DeploymentSettings(_env_file=None)
    return create_service(
        settings,
        awid_transport=awid_transport,
        egress=OperatorEgress.from_settings(settings, resolver=resolver),
    )


def create_app() -> SecretsService:
    """Uvicorn factory; deployment reads environment only, never an ambient .env."""
    return create_deployment()
