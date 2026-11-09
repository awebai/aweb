"""The egress guard a deployed naapp delivers its hook events through, built
from the operator's settings.

An app's settings class mixes in :class:`HookEgressSettings` under its own
environment prefix. :meth:`HookEgress.from_settings` builds the guard and the
internal destinations the runtime's hook transport takes, and
:meth:`HookEgress.preflight` checks every listed internal origin's current DNS
answers before the app starts its stores.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Literal, Self

from awid.log import canonical_server_origin
from pydantic import BaseModel, field_validator, model_validator

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

# How long the startup check of the internal origins may take, in seconds.
PREFLIGHT_SECONDS = 10


class EgressDeniedNetworks(BaseModel):
    """Networks the app's egress never reaches, whatever a destination resolves to."""

    egress_denied_networks: tuple[IPv4Network | IPv6Network, ...] = ()

    @field_validator("egress_denied_networks", mode="before")
    @classmethod
    def network_inputs(cls, value):
        # ipaddress also accepts integer/bool inputs; operator entries are
        # address/CIDR strings or already validated network objects only.
        if not isinstance(value, (list, tuple)) or any(
            not isinstance(entry, (str, IPv4Network, IPv6Network)) for entry in value
        ):
            raise ValueError("egress_denied_networks must list IP addresses or strict CIDRs")
        return value


class HookEgressSettings(EgressDeniedNetworks):
    """Explicit hook options; broker trust and switches are independent."""

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


@dataclass(frozen=True)
class HookEgress:
    """The hook guard and the internal destinations it may reach."""

    egress: Egress
    internal_cidr: IPv4Network | IPv6Network | None
    internal_origins: frozenset[str]

    @classmethod
    def from_settings(
        cls, settings: HookEgressSettings, *, resolver: Resolver | None = None
    ) -> HookEgress:
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
        return cls(
            egress=guard,
            internal_cidr=settings.hook_internal_cidr,
            internal_origins=settings.hook_internal_origins or frozenset(),
        )

    async def preflight(self) -> None:
        """Refuse an internal origin whose addresses the guard would refuse.

        This is a preflight, not an address pin: Egress re-resolves and checks
        every address on every delivery, including after DNS changes.
        """
        async with asyncio.timeout(PREFLIGHT_SECONDS):
            for origin in sorted(self.internal_origins):
                parsed = canonical_url(origin)
                addresses = (
                    [parsed.ip]
                    if parsed.ip is not None
                    else await self.egress.resolver.resolve(parsed.host)
                )
                self.egress.addresses.check(addresses, internal=self.internal_cidr)
