"""The one egress guard a deployed naapp sends through, built from the
operator's settings: its hook deliveries and its reads of team servers.

Every naapp's settings carry :class:`OperatorNetworkSettings`, under the app's
own environment prefix. :meth:`OperatorEgress.from_settings` builds the guard
and, for each purpose, the exact origins it may reach inside the operator's
network (:mod:`aweb_naapp.egress.internal`), and :meth:`OperatorEgress.preflight`
checks every listed origin's current DNS answers before the app starts its
stores.

The operator's network is one switch and one CIDR
(``HOOK_INTERNAL_DESTINATIONS``, ``HOOK_INTERNAL_CIDR``), named for the hooks
that first used them and shared by both purposes. Each purpose has its own
origin list, so listing a team server grants a hook binding nothing, and the
reverse.
"""

from __future__ import annotations

import asyncio
import logging
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
from aweb_naapp.egress.internal import InternalReach
from aweb_naapp.egress.send import Resolver
from aweb_naapp.egress.urls import canonical_url

logger = logging.getLogger(__name__)

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


def _exact_https_origins(value: object, name: str) -> frozenset[str]:
    """``value`` as canonical exact https origins, or a refusal naming ``name``."""
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{name} must list exact HTTPS origins")
    origins = set()
    for origin in value:
        if not isinstance(origin, str):
            raise ValueError(f"{name} must list exact HTTPS origins")
        try:
            normalized = canonical_server_origin(origin)
            canonical_url(normalized)
        except (ValueError, EgressRefused):
            raise ValueError(f"{name} must list exact HTTPS origins") from None
        origins.add(normalized)
    return frozenset(origins)


class OperatorNetworkSettings(EgressDeniedNetworks):
    """The operator's network, and the exact origins each purpose may reach in it."""

    hook_internal_destinations: Literal["allowed"] | None = None
    hook_internal_cidr: IPv4Network | IPv6Network | None = None
    hook_internal_origins: frozenset[str] = frozenset()
    team_server_internal_origins: frozenset[str] = frozenset()
    hook_ca_file: Path | None = None

    @field_validator("hook_internal_origins", mode="before")
    @classmethod
    def exact_hook_origins(cls, value: object) -> frozenset[str]:
        return _exact_https_origins(value, "hook_internal_origins")

    @field_validator("team_server_internal_origins", mode="before")
    @classmethod
    def exact_team_server_origins(cls, value: object) -> frozenset[str]:
        return _exact_https_origins(value, "team_server_internal_origins")

    @model_validator(mode="after")
    def complete_internal_configuration(self) -> Self:
        network = (self.hook_internal_destinations is not None, self.hook_internal_cidr is not None)
        if any(network) and not all(network):
            raise ValueError(
                "hook_internal_destinations and hook_internal_cidr must be supplied together"
            )
        listed = bool(self.hook_internal_origins or self.team_server_internal_origins)
        if listed and not all(network):
            raise ValueError(
                "hook_internal_origins and team_server_internal_origins need the operator's "
                "network: hook_internal_destinations=allowed and hook_internal_cidr"
            )
        if all(network) and not listed:
            raise ValueError(
                "the operator's network (hook_internal_destinations, hook_internal_cidr) "
                "names no origin to reach in it"
            )
        if self.hook_internal_cidr is not None:
            try:
                check_internal_cidr(self.hook_internal_cidr)
            except EgressRefused:
                raise ValueError("hook_internal_cidr must be a permitted exact network") from None
        return self


@dataclass(frozen=True)
class OperatorEgress:
    """The guard, and what each purpose may reach inside the operator's network."""

    egress: Egress
    hooks: InternalReach | None
    team_servers: InternalReach | None

    @classmethod
    def from_settings(
        cls, settings: OperatorNetworkSettings, *, resolver: Resolver | None = None
    ) -> OperatorEgress:
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
            user_agent="aweb-naapp",
            ca_file=settings.hook_ca_file,
        )
        cidr = settings.hook_internal_cidr
        for purpose, origins in (
            ("hook deliveries", settings.hook_internal_origins),
            ("team-server reads", settings.team_server_internal_origins),
        ):
            if origins:
                # Visible in every deployment's log: a hosted one lists none.
                logger.warning(
                    "Origins reached inside the operator's network %s for %s: %s",
                    cidr,
                    purpose,
                    ", ".join(sorted(origins)),
                )
        return cls(
            egress=guard,
            hooks=InternalReach.of(cidr, settings.hook_internal_origins),
            team_servers=InternalReach.of(cidr, settings.team_server_internal_origins),
        )

    async def preflight(self) -> None:
        """Refuse a listed origin whose addresses the guard would refuse.

        This is a preflight, not an address pin: Egress re-resolves and checks
        every address on every send, including after DNS changes.
        """
        async with asyncio.timeout(PREFLIGHT_SECONDS):
            for reach in (self.hooks, self.team_servers):
                if reach is None:
                    continue
                for authority in sorted(reach.authorities):
                    parsed = canonical_url(f"https://{authority}")
                    addresses = (
                        [parsed.ip]
                        if parsed.ip is not None
                        else await self.egress.resolver.resolve(parsed.host)
                    )
                    self.egress.addresses.check(addresses, internal=reach.cidr)
