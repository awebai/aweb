"""Environment entry point for the customer-run service, using the sole root."""

from __future__ import annotations

import asyncio
import ssl
from contextlib import asynccontextmanager
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Literal, Self

import httpx
from aweb_naapp.egress import (
    AddressPolicy,
    DnsResolver,
    Egress,
    EgressRefused,
    InternalDestinations,
)
from aweb_naapp.egress.addresses import check_internal_cidr
from aweb_naapp.egress.send import Resolver
from aweb_naapp.egress.urls import canonical_url
from awid.log import canonical_server_origin
from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from aweb_secrets.app import SecretsService
from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings


class DeploymentSettings(ServiceSettings):
    """Explicit hook options; broker trust and switches are independent."""

    model_config = SettingsConfigDict(hide_input_in_errors=True)

    database_url: str = Field(min_length=1)
    public_origin: str = Field(min_length=1)
    console_origin: str = Field(min_length=1)
    app_id: str = Field(min_length=1)
    awid_registry_url: str = Field(min_length=1)
    hook_internal_destinations: Literal["allowed"] | None = None
    hook_internal_cidr: IPv4Network | IPv6Network | None = None
    hook_internal_origins: frozenset[str] | None = None
    hook_ca_file: Path | None = None

    @field_validator("hook_internal_origins", mode="before")
    @classmethod
    def exact_origins(cls, value):
        if value is None:
            return None
        if not isinstance(value, (list, tuple, set, frozenset)) or not value:
            raise ValueError("hook_internal_origins must list exact HTTPS origins")
        origins = set()
        for origin in value:
            if not isinstance(origin, str):
                raise ValueError("hook_internal_origins must list exact HTTPS origins")
            normalized = canonical_server_origin(origin)
            try:
                canonical_url(normalized)
            except EgressRefused:
                raise ValueError("hook_internal_origins must list exact HTTPS origins") from None
            origins.add(normalized)
        return frozenset(origins)

    @model_validator(mode="after")
    def complete_internal_configuration(self) -> Self:
        supplied = (
            self.hook_internal_destinations is not None,
            self.hook_internal_cidr is not None,
            self.hook_internal_origins is not None,
        )
        if any(supplied) and not all(supplied):
            raise ValueError("all three hook internal settings must be supplied together")
        if self.hook_internal_cidr is not None:
            try:
                check_internal_cidr(self.hook_internal_cidr)
            except EgressRefused:
                raise ValueError("hook_internal_cidr must be a permitted exact network") from None
        return self


def create_deployment(
    settings: DeploymentSettings | None = None,
    *,
    resolver: Resolver | None = None,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
) -> SecretsService:
    """Build the real root; validate every internal origin before its lifespan."""
    settings = settings if settings is not None else DeploymentSettings(_env_file=None)
    if settings.hook_ca_file is not None:
        # Refuse missing/malformed trust material at startup. The actual Egress
        # also adds this CA to system trust when making each verified request.
        ssl.create_default_context().load_verify_locations(cafile=str(settings.hook_ca_file))
    guard = Egress(
        addresses=AddressPolicy(
            internal_destinations=(
                InternalDestinations.ALLOWED
                if settings.hook_internal_destinations == "allowed"
                else InternalDestinations.DISABLED
            ),
            denied=settings.egress_denied_networks,
        ),
        resolver=resolver if resolver is not None else DnsResolver(),
        user_agent="aweb-naapp/hooks",
        ca_file=settings.hook_ca_file,
    )
    service = create_service(
        settings,
        awid_transport=awid_transport,
        team_server_transport=team_server_transport,
        hook_egress=guard,
        hook_internal_cidr=settings.hook_internal_cidr,
        hook_internal_origins=settings.hook_internal_origins or frozenset(),
    )
    lifespan = service.api_app.router.lifespan_context

    @asynccontextmanager
    async def checked_lifespan(app):
        # This is a preflight, not an address pin: Egress re-resolves and checks
        # every address on every delivery, including after DNS changes.
        async with asyncio.timeout(10):
            for origin in sorted(settings.hook_internal_origins or ()):
                parsed = canonical_url(origin)
                addresses = (
                    [parsed.ip]
                    if parsed.ip is not None
                    else await guard.resolver.resolve(parsed.host)
                )
                guard.addresses.check(addresses, internal=settings.hook_internal_cidr)
        async with lifespan(app) as state:
            yield state

    service.api_app.router.lifespan_context = checked_lifespan
    return service


def create_app() -> SecretsService:
    """Uvicorn factory; deployment reads environment only, never an ambient .env."""
    return create_deployment()
