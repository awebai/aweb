"""Real AWID routes on real PostgreSQL, and a signer for team-auth v2 requests.

The verifier reaches AWID through an in-process ASGI transport. Faults, when a
test asks for them, are applied to a response only after the real AWID handler
has produced it, so the cache code, the database and the pagination stay real.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest_asyncio
from awid.did import did_from_public_key
from awid.ratelimit import NoOpRateLimiter
from awid.signing import canonical_json_bytes, sign_message
from awid_service.db import AwidDatabaseInfra
from awid_service.routes.teams import router as awid_teams_router
from fastapi import FastAPI, Request
from nacl.signing import SigningKey

from aweb_naapp.runtime.team_auth import AWIDTeamCache, Principal, authenticate_request

REGISTRY_URL = "https://registry.example"
SERVICE_TOKEN = "runtime-test-service-token-32-bytes"

ResponseFault = Callable[[httpx.Request, httpx.Response], None]


class RecordingTransport(httpx.AsyncBaseTransport):
    """Delivers every request to real AWID, records it, then applies `fault`."""

    def __init__(self, app: FastAPI) -> None:
        self._inner = httpx.ASGITransport(app=app)
        self.calls: list[httpx.Request] = []
        self.fault: ResponseFault | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        response = await self._inner.handle_async_request(request)
        if self.fault is None:
            return response
        await response.aread()
        self.fault(request, response)
        return response


@dataclass
class Registry:
    db: Any
    transport: RecordingTransport

    async def add_team(self, team_id: str, team_did_key: str, *, visibility: str = "public") -> None:
        name, domain = team_id.split(":", 1)
        await self.db.execute(
            "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ($1, $2, $3, $4)",
            domain, name, team_did_key, visibility,
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

    async def rotate_team_key(self, team_id: str, team_did_key: str) -> None:
        name, domain = team_id.split(":", 1)
        await self.db.execute(
            "UPDATE {{tables.teams}} SET team_did_key = $3 WHERE domain = $1 AND name = $2",
            domain, name, team_did_key,
        )


@pytest_asyncio.fixture
async def registry(test_db_factory, monkeypatch) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="naapp_awid")
    infra = AwidDatabaseInfra(schema="awid")
    monkeypatch.setenv("AWID_DATABASE_URL", registry_db.config.get_dsn())
    await infra.initialize(run_migrations=True)
    app = FastAPI()
    app.state.db = infra
    app.state.rate_limiter = NoOpRateLimiter()
    app.state.awid_service_token = SERVICE_TOKEN
    app.include_router(awid_teams_router)
    try:
        yield Registry(db=infra.get_manager("aweb"), transport=RecordingTransport(app))
    finally:
        await infra.close()


def did_key(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


def utc_timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class Member:
    """A team key and one member certificate signed by it."""

    team_id: str
    team_key: SigningKey = field(default_factory=SigningKey.generate)
    member_key: SigningKey = field(default_factory=SigningKey.generate)
    certificate_id: str = "cert-1"
    alias: str = "alice"
    extra_cert_fields: dict[str, Any] = field(default_factory=dict)

    @property
    def team_did_key(self) -> str:
        return did_key(self.team_key)

    @property
    def did_key(self) -> str:
        return did_key(self.member_key)

    def certificate(self) -> dict[str, Any]:
        cert = {
            "version": 1,
            "certificate_id": self.certificate_id,
            "team_id": self.team_id,
            "team_did_key": self.team_did_key,
            "member_did_key": self.did_key,
            "alias": self.alias,
            "lifetime": "persistent",
            "issued_at": "2026-01-01T00:00:00Z",
            **self.extra_cert_fields,
        }
        cert["signature"] = sign_message(bytes(self.team_key), canonical_json_bytes(cert))
        return cert

    def headers(
        self,
        *,
        aud: str,
        method: str,
        path: str,
        body: bytes = b"",
        timestamp: str | None = None,
        payload_changes: dict[str, Any] | None = None,
        cert: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        timestamp = timestamp or utc_timestamp(datetime.now(UTC))
        payload: dict[str, Any] = {
            "v": 2,
            "aud": aud,
            "method": method,
            "path": path,
            "team_id": self.team_id,
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        for name, value in (payload_changes or {}).items():
            if value is None:
                payload.pop(name, None)
            else:
                payload[name] = value
        canonical = canonical_json_bytes(payload)
        return envelope_headers(
            did_key=self.did_key,
            signature=sign_message(bytes(self.member_key), canonical),
            timestamp=timestamp,
            signed_payload=canonical,
            cert=cert if cert is not None else self.certificate(),
        )


def envelope_headers(
    *, did_key: str, signature: str, timestamp: str, signed_payload: bytes, cert: dict[str, Any]
) -> dict[str, str]:
    return {
        "Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(signed_payload).rstrip(b"=").decode(),
        "X-AWID-Team-Certificate": base64.b64encode(json.dumps(cert).encode()).decode(),
    }


@asynccontextmanager
async def relying_app(
    registry: Registry,
    *,
    public_origin: str,
    cache: AWIDTeamCache | None = None,
    now: Callable[[], datetime] | None = None,
    timestamp_skew_seconds: int | None = None,
    root_path: str = "",
    on_principal: Callable[[Request, Principal], Any] | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, AWIDTeamCache]]:
    """A naapp whose every route authenticates the request and echoes the principal."""
    cache = cache or AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)
    app = FastAPI()

    @app.api_route("/{route:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def relying(request: Request):
        kwargs: dict[str, Any] = {"now": now} if now is not None else {}
        if timestamp_skew_seconds is not None:
            kwargs["timestamp_skew_seconds"] = timestamp_skew_seconds
        principal = await authenticate_request(request, public_origin=public_origin, team_cache=cache, **kwargs)
        if on_principal is not None:
            return await on_principal(request, principal)
        return {
            "team_id": principal.team_id,
            "did_key": principal.did_key,
            "did_aw": principal.did_aw,
            "address": principal.address,
            "alias": principal.alias,
            "certificate_id": principal.certificate_id,
            "team_did_key": principal.team_did_key,
            "cached_body": request.state.cached_body.decode(),
        }

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, root_path=root_path), base_url=public_origin) as client:
        yield client, cache
