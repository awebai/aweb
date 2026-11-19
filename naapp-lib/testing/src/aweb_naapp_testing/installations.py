"""A naapp installed into a team's coordination server, the way ``aw plugin install`` does it.

:func:`app_origin` serves a naapp's ASGI app at a real local HTTPS origin,
behind a throwaway CA, and points the coordination server's manifest fetcher
at it through the destination and egress that ``aweb.app_manifests.ManifestFetcher``
takes from a host. The server then fetches, verifies and pins the naapp's own
manifest, as it does for an app on the internet.

:class:`Installations` is the one place tests install, uninstall and reinstall
a naapp. Each act is a team-signed request to the server's public routes
(``POST /v1/apps/install`` and ``POST /v1/apps/{app_id}/uninstall``), made by a
member the server operator made an install admin through ``aweb install-admin
grant``. Nothing here writes the server's tables.

Load it beside the ``coordination`` fixture (the ``server`` extra).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from aweb.app_manifests import ManifestFetcher
from aweb.cli import app as aweb_cli
from typer.testing import CliRunner

from aweb_naapp.egress import (
    AddressPolicy,
    DnsResolver,
    Egress,
    InternalDestinations,
    parse_destination,
)
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import Seen, TlsServer, local_address, make_certificates
from aweb_naapp_testing.server import Coordination


@dataclass
class AppOrigin:
    """A naapp's ASGI app served at ``url``, a real HTTPS origin on this host."""

    url: str
    ca_file: Path
    app: Any = None
    _server: TlsServer | None = field(default=None, repr=False)

    def serve(self, app: Any) -> None:
        """Serves ``app`` at this origin from now on. The app's own settings name
        ``url`` as its public origin, so it is built after the origin exists."""
        self.app = app

    async def _forward(self, seen: Seen) -> tuple[int, bytes, list[tuple[str, str]]]:
        if self.app is None:
            return 503, b"no app is served at this origin yet", []
        method, target, _ = seen.request_line.split(" ", 2)
        headers = [(name, value) for name, value in seen.headers if name.lower() != "host"]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=self.url
        ) as client:
            response = await client.request(method, target, headers=headers, content=seen.body)
        passed = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in {"content-length", "connection", "transfer-encoding"}
        ]
        return response.status_code, response.content, passed


@asynccontextmanager
async def app_origin(coordination: Coordination, directory: Path) -> AsyncIterator[AppOrigin]:
    """A local HTTPS origin whose manifests ``coordination``'s server fetches.

    The egress guard refuses loopback, so the origin listens on this host's own
    address; it is the server's one internal destination, and every other
    origin stays refused."""
    host = local_address()
    certificates = make_certificates(directory, [host], [host])
    origin = AppOrigin(url="", ca_file=certificates.ca_file)
    server = TlsServer(certificates=certificates, host=host, respond=origin._forward)
    await server.start()
    origin.url = f"https://{host}:{server.port}"
    origin._server = server
    destination = parse_destination(
        {
            "host": host,
            "port": server.port,
            "path": "/**",
            "methods": ["GET"],
            "network": "internal",
            "cidr": host + "/32",
        },
        internal_destinations=InternalDestinations.ALLOWED,
    )
    coordination.server.app.state.manifest_fetcher = ManifestFetcher(
        destination=destination,
        egress=Egress(
            addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
            resolver=DnsResolver(),
            user_agent="aweb-naapp-testing/installations",
            ca_file=certificates.ca_file,
        ),
    )
    try:
        yield origin
    finally:
        await server.close()


class InstallRefused(Exception):
    """The server refused an install act; ``status`` and ``body`` are its answer."""

    def __init__(self, act: str, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"{act} answered {status}: {body}")


@dataclass
class Installations:
    """Installs, uninstalls and reinstalls naapps for ``admin``'s team.

    :meth:`admit` makes ``admin`` the team's install owner through the server
    operator's own CLI, run against the coordination server's database."""

    coordination: Coordination
    admin: Member

    async def admit(self) -> None:
        """Registers the admin in AWID, publishes the server as the team's,
        connects the admin there and makes it the team's install owner."""
        await self.coordination.add_member(self.admin)
        await self.coordination.publish_server(self.admin)
        await self.coordination.connect(self.admin)
        await asyncio.to_thread(self._grant_owner)

    def _grant_owner(self) -> None:
        # The operator's own command, run as the server's operator would.
        result = CliRunner().invoke(
            aweb_cli,
            [
                "install-admin",
                "grant",
                "--team-id",
                self.admin.team_id,
                "--principal-did",
                self.admin.did_key,
                "--role",
                "owner",
            ],
            env={"AWEB_DATABASE_URL": self.coordination.server_database_url},
        )
        if result.exit_code != 0:
            raise InstallRefused("aweb install-admin grant", result.exit_code, result.output)

    async def install(
        self,
        origin: AppOrigin,
        *,
        app_id: str,
        manifest: bytes,
        granted_scopes: list[str],
        expected_generation: int | None = None,
    ) -> dict[str, Any]:
        """Installs the app ``origin`` serves, pinning ``manifest`` by digest.
        Over a retained installation, ``expected_generation`` names its current
        generation, as the server requires of a reinstall."""
        body: dict[str, Any] = {
            "app_id": app_id,
            "origin": origin.url,
            "digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
            "granted_scopes": granted_scopes,
        }
        if expected_generation is not None:
            body["expected_generation"] = expected_generation
        return await self._act("/v1/apps/install", body)

    async def uninstall(self, *, app_id: str, expected_generation: int) -> dict[str, Any]:
        """Uninstalls the app at its current ``expected_generation``."""
        return await self._act(
            f"/v1/apps/{app_id}/uninstall", {"expected_generation": expected_generation}
        )

    async def _act(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode()
        # The server signs over the raw request target, query included.
        target = path + "?team_id=" + quote(self.admin.team_id, safe="")
        headers = self.admin.headers(
            aud=self.coordination.server.url, method="POST", path=target, body=body
        )
        async with self.coordination.server.client() as client:
            response = await client.post(
                target, content=body, headers={**headers, "Content-Type": "application/json"}
            )
        if response.is_error:
            raise InstallRefused(path, response.status_code, response.text)
        return response.json()
