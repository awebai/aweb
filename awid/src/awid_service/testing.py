"""AWID in-process, for the tests of the services that rely on it.

:func:`running_registry` serves AWID's own registry routes (``mount_registry``)
on a database the test owns, with AWID's migrations applied. A relying service
reaches it through :attr:`Registry.transport`, an in-process transport that
records every request. A test may set ``fault`` to change a response after the
real handler produced it, ``down`` to make AWID unreachable, or ``delay`` to
hold each response, so the code under test, the routes and the database all
stay real.

No rate limit applies. Nothing here is used by the registry service itself.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from awid.did import did_from_public_key
from awid.ratelimit import NoOpRateLimiter
from awid.registry import RegistryClient
from awid.signing import sign_message
from awid.team_server_record import record_signing_bytes

from .db import AwidDatabaseInfra
from .main import mount_registry

REGISTRY_URL = "https://registry.example"
SERVICE_TOKEN = "awid-testing-service-token-32-bytes"

# Changes the real response in place, or returns a response to send instead.
ResponseFault = Callable[[httpx.Request, httpx.Response], httpx.Response | None]


class ServiceTransport(httpx.AsyncBaseTransport):
    """Delivers each request to a real in-process service and records it."""

    def __init__(self, app: FastAPI) -> None:
        self._inner = httpx.ASGITransport(app=app)
        self.calls: list[httpx.Request] = []
        self.fault: ResponseFault | None = None
        self.down = False
        self.delay = 0.0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.down:
            raise httpx.ConnectError("service unreachable", request=request)
        if self.delay:
            await asyncio.sleep(self.delay)
        response = await self._inner.handle_async_request(request)
        if self.fault is None:
            return response
        await response.aread()
        replacement = self.fault(request, response)
        return response if replacement is None else replacement


def _did_key(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


@dataclass
class Registry:
    """A running in-process AWID: its app, its database and its transport."""

    app: FastAPI
    db: AsyncDatabaseManager
    transport: ServiceTransport

    async def add_team(self, team_id: str, team_did_key: str, *, visibility: str = "public") -> None:
        name, domain = team_id.split(":", 1)
        await self.db.execute(
            "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ($1, $2, $3, $4)",
            domain, name, team_did_key, visibility,
        )

    async def rotate_team_key(self, team_id: str, team_did_key: str) -> None:
        name, domain = team_id.split(":", 1)
        await self.db.execute(
            "UPDATE {{tables.teams}} SET team_did_key = $3 WHERE domain = $1 AND name = $2",
            domain, name, team_did_key,
        )

    async def add_certificate(self, cert: dict[str, Any]) -> None:
        name, domain = cert["team_id"].split(":", 1)
        await self.db.execute(
            "INSERT INTO {{tables.team_certificates}} "
            "(team_uuid, certificate_id, member_did_key, alias, issued_at) "
            "SELECT team_uuid, $3, $4, $5, now() FROM {{tables.teams}} WHERE domain = $1 AND name = $2",
            domain, name, cert["certificate_id"], cert["member_did_key"], cert["alias"],
        )

    async def revoke(self, certificate_id: str) -> None:
        await self.db.execute(
            "UPDATE {{tables.team_certificates}} SET revoked_at = now() WHERE certificate_id = $1",
            certificate_id,
        )

    def _client(self) -> RegistryClient:
        return RegistryClient(registry_url=REGISTRY_URL, transport=self.transport)

    async def register_did(self, key: SigningKey) -> str:
        """Registers ``key`` as a new did:aw through AWID's own route; returns the did:aw."""
        mapping = await self._client().register_did(_did_key(key), bytes(key))
        return mapping.did_aw

    async def rotate_did(self, did_aw: str, old: SigningKey, new: SigningKey) -> None:
        await self._client().rotate_key(did_aw, _did_key(new), bytes(old), bytes(new))

    async def publish_team_server(
        self, team_id: str, team_key: SigningKey, *, server_url: str, issued_at: datetime | None = None
    ) -> None:
        """Publishes the team's ``aweb.team-server/1`` record, signed by its
        team key, through AWID's own route."""
        name, domain = team_id.split(":", 1)
        body = signed_team_server_record(
            team_id, team_key, server_url=server_url, issued_at=issued_at or datetime.now(UTC)
        )
        async with httpx.AsyncClient(transport=self.transport, base_url=REGISTRY_URL) as client:
            response = await client.put(f"/v1/namespaces/{domain}/teams/{name}/server", json=body)
        response.raise_for_status()


def signed_team_server_record(
    team_id: str, team_key: SigningKey, *, server_url: str, issued_at: datetime
) -> dict[str, Any]:
    """A team's ``aweb.team-server/1`` record and its team-key signature, as AWID's route takes them."""
    record = {
        "v": 1,
        "type": "aweb.team-server",
        "team_id": team_id,
        "team_did_key": _did_key(team_key),
        "server_url": server_url,
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return {"record": record, "signature": sign_message(bytes(team_key), record_signing_bytes(record))}


@asynccontextmanager
async def running_registry(
    database_url: str, *, service_token: str | None = SERVICE_TOKEN
) -> AsyncIterator[Registry]:
    """AWID, with its migrations applied, on the empty database at ``database_url``."""
    pool = await AsyncDatabaseManager.create_shared_pool(
        DatabaseConfig(connection_string=database_url, schema=None)
    )
    infra = AwidDatabaseInfra(schema="awid")
    try:
        await infra.initialize(shared_pool=pool, run_migrations=True)
        app = FastAPI()
        app.state.db = infra
        app.state.db_schema = infra.schema
        app.state.rate_limiter = NoOpRateLimiter()
        app.state.awid_service_token = service_token
        mount_registry(app)
        yield Registry(app=app, db=infra.get_manager("aweb"), transport=ServiceTransport(app))
    finally:
        await infra.close()
        await pool.close()
