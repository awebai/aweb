"""A team's coordination server as an operator runs it for its own apps.

The server is a real ASGI app behind a real TLS listener on this host's
private address, under a name that only the site's own DNS server answers,
with a certificate from a disposable CA. An app reaches it through its
deployment's egress guard and nothing else: the listed origin, the
operator's network (exactly this address) and the CA come from the app's own
settings, and the resolver is the one the production factories take.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from aweb_naapp.egress import DnsResolver
from aweb_naapp.runtime.operator_egress import OperatorEgress, OperatorNetworkSettings
from aweb_naapp_testing.network import (
    DnsServer,
    Reply,
    Seen,
    TlsServer,
    local_address,
    make_certificates,
)

SITE_NAME = "coord.team-server.test"


@dataclass
class TeamServerSite:
    """The listener, its DNS and its CA; ``tls.seen`` records every request."""

    name: str
    host: str
    tls: TlsServer
    dns: DnsServer
    ca_file: Path

    @property
    def origin(self) -> str:
        return f"https://{self.name}:{self.tls.port}"

    def settings(self, *, listed: bool = True) -> dict[str, Any]:
        """An app's settings for this site: listed as the operator's own team
        server, inside a network of exactly its address, or not listed."""
        if not listed:
            return {"hook_ca_file": self.ca_file}
        return {
            "hook_internal_destinations": "allowed",
            "hook_internal_cidr": f"{self.host}/32",
            "team_server_internal_origins": [self.origin],
            "hook_ca_file": self.ca_file,
        }

    def resolver(self) -> DnsResolver:
        return DnsResolver(nameservers=["127.0.0.1"], port=self.dns.port)

    def egress(self, settings: OperatorNetworkSettings) -> OperatorEgress:
        """The app's guard, as its production factory builds it from ``settings``."""
        return OperatorEgress.from_settings(settings, resolver=self.resolver())


def asgi_reply(app: Any) -> Any:
    """Answer each request the listener reads with ``app``'s response to it."""
    transport = httpx.ASGITransport(app=app)

    async def respond(seen: Seen) -> Reply:
        method, target, _ = seen.request_line.split(" ")
        host = next(value for name, value in seen.headers if name.lower() == "host")
        async with httpx.AsyncClient(transport=transport, base_url=f"https://{host}") as client:
            response = await client.request(
                method,
                target,
                headers=[(name, value) for name, value in seen.headers if name.lower() != "host"],
                content=seen.body,
            )
        headers = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in ("content-length", "connection", "transfer-encoding")
        ]
        return response.status_code, response.content, headers

    return respond


@asynccontextmanager
async def team_server_site(
    directory: Path, app: Any, *, name: str = SITE_NAME
) -> AsyncIterator[TeamServerSite]:
    """``app`` served at ``https://<name>:<port>`` until the context ends."""
    host = local_address()
    # The refusals mean something only for an address the public policy denies.
    if not ipaddress.ip_address(host).is_private:
        raise RuntimeError(f"the team-server site needs a private address on this host, not {host}")
    certificates = make_certificates(directory, [name], [host])
    dns = DnsServer(records={(name, "A"): [host]})
    tls = TlsServer(certificates, host)
    tls.respond = asgi_reply(app)
    await dns.start()
    await tls.start()
    try:
        yield TeamServerSite(name, host, tls, dns, certificates.ca_file)
    finally:
        dns.close()
        await tls.close()
