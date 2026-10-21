"""The S19 upstream served over TLS where the real egress guard reaches it.

The upstream listens on this host's own non-loopback address and is reached
as an internal destination with that address's exact CIDR, under
``internal_destinations: allowed``, by a name a local DNS server answers. The
credentials are generated when the test runs.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aweb_naapp.egress import (
    AddressPolicy,
    Destination,
    DnsResolver,
    Egress,
    InternalDestinations,
    parse_destination,
)
from aweb_naapp_testing.network import DnsServer, local_address, make_certificates
from fastapi import FastAPI
from upstream.app import UpstreamCredentials, create_upstream
from upstream.serve import serving

NAME = "upstream.secrets.test"
OTHER = "other.secrets.test"


@dataclass
class Upstream:
    creds: UpstreamCredentials
    egress: Egress
    port: int
    host: str
    app: FastAPI
    # The Host header of every request the upstream received.
    requests: list[str]
    # The path of every request the upstream received.
    paths: list[str]

    def issued(self) -> int:
        """How many access tokens the upstream's token endpoint has issued."""
        return int(self.app.state.stats["issued"])

    def url(self, path: str, name: str = NAME) -> str:
        return f"https://{name}:{self.port}{path}"

    def destination(self, name: str = NAME, **entry: object) -> Destination:
        return parse_destination(
            {
                "host": name,
                "port": self.port,
                "path": "/**",
                "methods": ["GET", "POST"],
                "network": "internal",
                "cidr": f"{self.host}/32",
                **entry,
            },
            internal_destinations=InternalDestinations.ALLOWED,
        )


def credentials() -> UpstreamCredentials:
    return UpstreamCredentials(
        bearer=secrets.token_urlsafe(24),
        basic_username="svc-" + secrets.token_hex(4),
        basic_password=secrets.token_urlsafe(24),
        header_name="X-Upstream-Key",
        header_prefix="Key ",
        header_value=secrets.token_urlsafe(24),
        query_param="key",
        query_value=secrets.token_urlsafe(24),
        oauth_client_id="client-" + secrets.token_hex(4),
        oauth_client_secret=secrets.token_urlsafe(24),
        oauth_scope="read:things",
        sigv4_access_key_id="AKIA" + secrets.token_hex(8).upper(),
        sigv4_secret_access_key=secrets.token_urlsafe(30),
        sigv4_region="eu-west-1",
        sigv4_service="execute-api",
    )


@asynccontextmanager
async def running_upstream(tmp_path: Path, **options: Any) -> AsyncIterator[Upstream]:
    """The S19 upstream over TLS, and an egress that reaches it by NAME (and
    by OTHER, which is never a destination). ``options`` go to create_upstream."""
    host = local_address()
    certificates = make_certificates(tmp_path, [NAME, OTHER], [])
    creds = credentials()
    app = create_upstream(creds, **options)
    requests: list[str] = []
    paths: list[str] = []

    @app.middleware("http")
    async def record(request, call_next):
        requests.append(request.headers.get("host", ""))
        paths.append(request.url.path)
        return await call_next(request)

    dns = DnsServer(records={(NAME, "A"): [host], (OTHER, "A"): [host]})
    await dns.start()
    try:
        async with serving(app, certificates, host) as port:
            egress = Egress(
                addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
                resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
                user_agent="aweb-secrets/test",
                ca_file=certificates.ca_file,
            )
            yield Upstream(creds, egress, port, host, app, requests, paths)
    finally:
        dns.close()
