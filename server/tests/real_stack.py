"""Real AWID and the real aweb app in one process, joined by a published team-server record.

The naapp clients of this server's app API (aweb_naapp.runtime) are driven
against it here. AWID's real routes run on their own real database; the aweb
app runs this server's real routes, verifier and writers on the test database.
A client reaches aweb only through team-server discovery: the team's
``aweb.team-server/1`` record, signed by its team key and stored in AWID.

Each service is reached through an in-process ASGI transport that records the
requests it carries. A test may set ``fault`` to change a response after the
real handler produced it, ``down`` to make the service unreachable, or
``delay`` to hold each response that many seconds, so the
code under test, the routes and the databases all stay real.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
import pytest_asyncio
from awid.ratelimit import NoOpRateLimiter
from awid.signing import sign_message
from awid.team_server_record import record_signing_bytes
from awid_service.db import AwidDatabaseInfra
from awid_service.routes.attestation_records import router as awid_attestation_records_router
from awid_service.routes.did import router as awid_did_router
from awid_service.routes.teams import router as awid_teams_router
from fastapi import FastAPI
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from aweb.routes.app_hooks import router as app_hooks_router
from aweb.routes.apps import router as apps_router
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_server import TeamServerDirectory
from tests.test_app_events_http import _build_events_app, _seed_team_and_agent

REGISTRY_URL = "https://registry.example"
AWEB_URL = "https://aweb.example"

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


@dataclass
class RealStack:
    aweb_db: object
    awid_db: object
    awid: ServiceTransport
    aweb: ServiceTransport
    service_token: str

    async def add_team(self, team_id: str) -> SigningKey:
        """Create the team in AWID and in aweb; returns its team key."""
        team_key = SigningKey.generate()
        name, domain = team_id.split(":", 1)
        await self.awid_db.execute(
            "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ($1, $2, $3, 'public')",
            domain,
            name,
            did_from_public_key(bytes(team_key.verify_key)),
        )
        await _seed_team_and_agent(self.aweb_db, team_id=team_id)
        return team_key

    async def publish_server(
        self, team_id: str, team_key: SigningKey, *, server_url: str = AWEB_URL, issued_at: datetime | None = None
    ) -> None:
        """Publish the team's aweb.team-server/1 record through AWID's own route."""
        name, domain = team_id.split(":", 1)
        record = {
            "v": 1,
            "type": "aweb.team-server",
            "team_id": team_id,
            "team_did_key": did_from_public_key(bytes(team_key.verify_key)),
            "server_url": server_url,
            "issued_at": (issued_at or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        body = {"record": record, "signature": sign_message(bytes(team_key), record_signing_bytes(record))}
        async with httpx.AsyncClient(transport=self.awid) as client:
            response = await client.put(f"{REGISTRY_URL}/v1/namespaces/{domain}/teams/{name}/server", json=body)
        response.raise_for_status()

    def directory(
        self, *, clock: Callable[[], float] | None = None, ttl_seconds: int | None = None
    ) -> TeamServerDirectory:
        """Team-server discovery against the stack's AWID."""

        async def no_registry_override(domain: str) -> str | None:
            return None

        team_cache = AWIDTeamCache(
            registry_url=REGISTRY_URL, ttl_seconds=60, service_token=self.service_token, transport=self.awid
        )
        options: dict = {} if clock is None else {"clock": clock}
        if ttl_seconds is not None:
            options["ttl_seconds"] = ttl_seconds
        return TeamServerDirectory(
            team_cache=team_cache, transport=self.awid, registry_override=no_registry_override, **options
        )


@pytest_asyncio.fixture
async def real_stack(aweb_cloud_db, test_db_factory, monkeypatch) -> AsyncIterator[RealStack]:
    service_token = os.environ["AWID_SERVICE_TOKEN"]
    awid_database = await test_db_factory.create_db(suffix="aweb_real_stack_awid")
    infra = AwidDatabaseInfra(schema="awid")
    monkeypatch.setenv("AWID_DATABASE_URL", awid_database.config.get_dsn())
    await infra.initialize(run_migrations=True)
    awid_app = FastAPI()
    awid_app.state.db = infra
    awid_app.state.rate_limiter = NoOpRateLimiter()
    awid_app.state.awid_service_token = service_token
    awid_app.include_router(awid_teams_router)
    awid_app.include_router(awid_attestation_records_router)
    awid_app.include_router(awid_did_router)

    aweb_app = _build_events_app(aweb_cloud_db.aweb_db, public_origin=AWEB_URL)
    aweb_app.include_router(apps_router)
    aweb_app.include_router(app_hooks_router)
    try:
        yield RealStack(
            aweb_db=aweb_cloud_db.aweb_db,
            awid_db=infra.get_manager("aweb"),
            awid=ServiceTransport(awid_app),
            aweb=ServiceTransport(aweb_app),
            service_token=service_token,
        )
    finally:
        await infra.close()
