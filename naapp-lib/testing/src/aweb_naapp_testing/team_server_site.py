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
    Certificates,
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
    # Its certificate also names the ``also_names`` of team_server_site, so
    # another of the app's destinations on this host can share the one CA.
    certificates: Certificates

    @property
    def ca_file(self) -> Path:
        return self.certificates.ca_file

    @property
    def origin(self) -> str:
        return f"https://{self.name}:{self.tls.port}"

    def settings(self, *, listed: bool = True) -> dict[str, Any]:
        """An app's settings for this site: listed as the operator's own team
        server, inside a network of exactly its address, or not listed."""
        if not listed:
            return {"hook_ca_file": self.ca_file}
        # Typed as the settings hold them, so a settings copy can take them too.
        return {
            "hook_internal_destinations": "allowed",
            "hook_internal_cidr": ipaddress.ip_network(f"{self.host}/32"),
            "team_server_internal_origins": frozenset({self.origin}),
            "hook_ca_file": self.ca_file,
        }

    def resolver(self) -> DnsResolver:
        return DnsResolver(nameservers=["127.0.0.1"], port=self.dns.port)

    def egress(self, settings: OperatorNetworkSettings) -> OperatorEgress:
        """The app's guard, as its production factory builds it from ``settings``."""
        return OperatorEgress.from_settings(settings, resolver=self.resolver())

    def stop_answering(self) -> None:
        """Close every connection without an answer: the server is down, and
        a read sent to it fails without a response."""

        async def drop(seen: Seen) -> Reply:
            raise ConnectionResetError("the team server is down")

        self.tls.respond = drop

    def serve(self, app: Any) -> None:
        """Answer every request with ``app``: a server whose public origin is
        this site's, so it can only be built once the site listens."""
        self.tls.respond = asgi_reply(app)

    def serve_transport(self, transport: httpx.AsyncBaseTransport) -> None:
        """Answer every request through ``transport``, see :func:`transport_reply`."""
        self.tls.respond = transport_reply(transport)


def asgi_reply(app: Any) -> Any:
    """Answer each request the listener reads with ``app``'s response to it."""
    return transport_reply(httpx.ASGITransport(app=app))


def transport_reply(transport: httpx.AsyncBaseTransport) -> Any:
    """Answer each request the listener reads with ``transport``'s response:
    a recording or faulting transport in front of a real app keeps its
    behaviour behind the TLS listener. A transport that cannot answer closes
    the connection without a response, as a server that is down does."""

    async def respond(seen: Seen) -> Reply:
        host = next(value for name, value in seen.headers if name.lower() == "host")
        try:
            async with httpx.AsyncClient(transport=transport, base_url=f"https://{host}") as client:
                response = await client.request(
                    seen.method,
                    seen.target,
                    headers=[
                        (name, value) for name, value in seen.headers if name.lower() != "host"
                    ],
                    content=seen.body,
                )
        except httpx.TransportError as unanswered:
            raise ConnectionResetError(str(unanswered)) from unanswered
        headers = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in ("content-length", "connection", "transfer-encoding")
        ]
        return response.status_code, response.content, headers

    return respond


@asynccontextmanager
async def team_server_site(
    directory: Path, app: Any = None, *, name: str = SITE_NAME, also_names: tuple[str, ...] = ()
) -> AsyncIterator[TeamServerSite]:
    """``app`` served at ``https://<name>:<port>`` until the context ends;
    without ``app``, whatever :meth:`TeamServerSite.serve` is given. Each of
    ``also_names`` resolves to the same address and is on the certificate."""
    host = local_address()
    # The refusals mean something only for an address the public policy denies.
    if not ipaddress.ip_address(host).is_private:
        raise RuntimeError(f"the team-server site needs a private address on this host, not {host}")
    directory.mkdir(parents=True, exist_ok=True)
    certificates = make_certificates(directory, [name, *also_names], [host])
    dns = DnsServer(records={(each, "A"): [host] for each in (name, *also_names)})
    tls = TlsServer(certificates, host)
    site = TeamServerSite(name, host, tls, dns, certificates)
    if app is not None:
        site.serve(app)
    await dns.start()
    await tls.start()
    try:
        yield site
    finally:
        dns.close()
        await tls.close()
