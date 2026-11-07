"""The reader routes on logs' agent origin, with real B1 team-auth, a real
in-process AWID registry and real PostgreSQL: issuing a reader slot."""

from __future__ import annotations

import hashlib
import json
import socket
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from aweb_naapp import ratelimit
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing import Member
from awid_service.testing import REGISTRY_URL, Registry, running_registry
from fastapi import FastAPI

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.config import LogsSettings
from aweb_logs.read_routes import reader_slot_router
from aweb_logs.readers import ReaderDirectory, is_reader_scope

from .deployment import TEST_APP_ID, template, write_key_file

API = "https://logs.example.test"
CONSOLE = "https://console.logs.example.test"
TEAM = "demo:example.com"
INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
PATH = "/v1/reader-slots"
CONTACT_SHA256 = hashlib.sha256(b"m@example.com").hexdigest()
SLOT_LIMIT = 3

READER_SLOT_TOOL = {
    "name": "reader-slot",
    "description": "Issue a pending reader slot for the contact the owner will designate.",
    "method": "POST",
    "path": PATH,
    "input_schema": {
        "type": "object",
        "properties": {"contact_sha256": {"type": "string"}},
        "required": ["contact_sha256"],
        "additionalProperties": False,
    },
    "params": [{"name": "contact_sha256", "in": "body"}],
    "scopes": ["logs.readers"],
    "mutation": True,
    "body": {"mode": "json"},
    "invocation_contexts": ["agent"],
}


class Installations:
    """logs' installation in TEAM as the team server reports it, granting ``scopes``."""

    def __init__(self, scopes: frozenset[str]) -> None:
        self.scopes = scopes

    @property
    def grant(self) -> Grant:
        return Grant(
            team_id=TEAM,
            installation_id=INSTALLATION,
            generation=1,
            scopes=self.scopes,
            fresh_until=time.monotonic_ns() + seconds_to_ns(55),
        )

    async def grant_for(self, team_id: str, certificate_id: str | None = None) -> Grant | None:
        return self.grant if team_id == TEAM else None

    async def status_for(self, team_id: str) -> SimpleNamespace | None:
        if team_id != TEAM:
            return None
        return SimpleNamespace(
            team_id=TEAM,
            app_id=TEST_APP_ID,
            state="active",
            installation_id=INSTALLATION,
            generation=1,
            granted_scopes=self.scopes,
            fresh_until=self.grant.fresh_until,
        )


async def allow_members(request: Any, principal: Any, tool: Any) -> bool:
    return True


@contextmanager
def blocked_dns() -> Iterator[list[str]]:
    """Refuse and record every name lookup but the local database's."""
    original = socket.getaddrinfo
    looked_up: list[str] = []

    def refuse(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in ("localhost", "127.0.0.1", "::1", None):
            return original(host, *args, **kwargs)
        looked_up.append(str(host))
        raise socket.gaierror(f"blocked DNS lookup of {host}")

    socket.getaddrinfo = refuse  # type: ignore[assignment]
    try:
        yield looked_up
    finally:
        socket.getaddrinfo = original  # type: ignore[assignment]


def test_the_dns_tracer_refuses_and_records_a_real_lookup() -> None:
    with blocked_dns() as looked_up:
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("logs.example.test", 443)
    assert looked_up == ["logs.example.test"]


@pytest.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="logs_awid")
    async with running_registry(registry_db.config.get_dsn()) as running:
        yield running


@pytest.fixture
async def db(test_db_factory):
    return await test_db_factory.create_db(suffix="logs_reader_routes")


def _manifest(directory: Path) -> Path:
    manifest = template()
    manifest["app_keys"].append({"kid": "logs-grants", "purposes": ["app-grant-read"]})
    manifest["tools"].append(READER_SLOT_TOOL)
    path = directory / "aweb-app.json"
    path.write_text(json.dumps(manifest))
    return path


@asynccontextmanager
async def running(
    db, registry: Registry, tmp_path: Path, *, scopes: frozenset[str]
) -> AsyncIterator[tuple[httpx.AsyncClient, Any]]:
    kids = [entry["kid"] for entry in template()["app_keys"]] + ["logs-grants"]
    settings = LogsSettings(
        _env_file=None,
        database_url=db.config.get_dsn(),
        db_schema=db.schema or "public",
        public_origin=API,
        app_id=TEST_APP_ID,
        awid_registry_url=REGISTRY_URL,
        app_key_files={kid: write_key_file(tmp_path / f"key-{i}") for i, kid in enumerate(kids)},
    )
    runtime = NaappRuntime(
        settings,
        module_name=MIGRATIONS_MODULE,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=_manifest(tmp_path),
        awid_transport=registry.transport,
    )
    grants = Installations(scopes)
    api = FastAPI(lifespan=runtime.lifespan)
    async with runtime.lifespan(api):
        await apply_installation_migrations(runtime.db())
        await ratelimit.apply_ratelimit_migrations(runtime.db())
        fence = InstallationFence(runtime.db(), app_id=TEST_APP_ID, grants=grants)
        api.include_router(
            reader_slot_router(
                ReaderDirectory(runtime.db()),
                authorized=runtime.authorized(grants=grants, policy=allow_members),
                fence=fence,
                limit=SLOT_LIMIT,
            )
        )
        app = split_origins(api, FastAPI(), agent_origin=API, human_origin=CONSOLE)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=API
        ) as client:
            yield client, runtime.db()


async def _member(registry: Registry) -> Member:
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key)
    await registry.add_certificate(member.certificate())
    return member


async def _post(
    client: httpx.AsyncClient, member: Member, value: Any, *, base: str = API
) -> httpx.Response:
    body = json.dumps(value).encode()
    headers = member.headers(aud=API, method="POST", path=PATH, body=body)
    return await client.post(
        base + PATH, content=body, headers={**headers, "Content-Type": "application/json"}
    )


async def test_a_member_granted_logs_readers_gets_a_pending_slot_for_its_team(
    db, registry: Registry, tmp_path: Path
) -> None:
    member = await _member(registry)
    with blocked_dns() as looked_up:
        async with running(db, registry, tmp_path, scopes=frozenset({"logs.readers"})) as (
            client,
            logs_db,
        ):
            response = await _post(client, member, {"contact_sha256": CONTACT_SHA256})
            assert response.status_code == 200, response.text
            slot = response.json()
            assert set(slot) == {"scope", "expires_at"}
            assert is_reader_scope(slot["scope"])
            row = await logs_db.fetch_one(
                "SELECT installation_id, team_id, contact_sha256, claimed_at"
                " FROM {{tables.readers}} WHERE scope = $1",
                slot["scope"],
            )
            assert dict(row) == {
                "installation_id": INSTALLATION,
                "team_id": TEAM,
                "contact_sha256": CONTACT_SHA256,
                "claimed_at": None,
            }
    assert looked_up == []


async def test_a_member_without_the_scope_gets_no_slot(
    db, registry: Registry, tmp_path: Path
) -> None:
    member = await _member(registry)
    async with running(db, registry, tmp_path, scopes=frozenset({"logs.ingest"})) as (
        client,
        logs_db,
    ):
        response = await _post(client, member, {"contact_sha256": CONTACT_SHA256})
        assert response.status_code == 403
        assert await logs_db.fetch_value("SELECT count(*) FROM {{tables.readers}}") == 0


async def test_an_unsigned_request_or_the_console_origin_gets_no_slot(
    db, registry: Registry, tmp_path: Path
) -> None:
    member = await _member(registry)
    async with running(db, registry, tmp_path, scopes=frozenset({"logs.readers"})) as (
        client,
        logs_db,
    ):
        unsigned = await client.post(
            PATH,
            content=json.dumps({"contact_sha256": CONTACT_SHA256}).encode(),
            headers={"Content-Type": "application/json", "Cookie": "__Host-console=x"},
        )
        assert unsigned.status_code == 401
        on_console = await client.post(
            CONSOLE + PATH,
            content=json.dumps({"contact_sha256": CONTACT_SHA256}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert on_console.status_code == 404
        assert (
            await _post(client, member, {"contact_sha256": CONTACT_SHA256}, base=CONSOLE)
        ).status_code == 403
        assert await logs_db.fetch_value("SELECT count(*) FROM {{tables.readers}}") == 0


@pytest.mark.parametrize(
    "value",
    [
        {"contact_sha256": "m@example.com"},
        {"contact_sha256": CONTACT_SHA256.upper()},
        {"contact_sha256": CONTACT_SHA256, "scope": "logs.reader." + "0" * 32},
        {},
    ],
)
async def test_a_malformed_slot_request_is_refused_without_echo(
    db, registry: Registry, tmp_path: Path, value: dict[str, str]
) -> None:
    member = await _member(registry)
    async with running(db, registry, tmp_path, scopes=frozenset({"logs.readers"})) as (
        client,
        logs_db,
    ):
        response = await _post(client, member, value)
        assert response.status_code in (400, 422)
        assert "m@example.com" not in response.text
        assert await logs_db.fetch_value("SELECT count(*) FROM {{tables.readers}}") == 0


async def test_slots_are_rate_limited_per_member(db, registry: Registry, tmp_path: Path) -> None:
    member = await _member(registry)
    async with running(db, registry, tmp_path, scopes=frozenset({"logs.readers"})) as (
        client,
        logs_db,
    ):
        for _ in range(SLOT_LIMIT):
            assert (
                await _post(client, member, {"contact_sha256": CONTACT_SHA256})
            ).status_code == 200
        refused = await _post(client, member, {"contact_sha256": CONTACT_SHA256})
        assert refused.status_code == 429
        assert int(refused.headers["Retry-After"]) >= 1
        assert await logs_db.fetch_value("SELECT count(*) FROM {{tables.readers}}") == SLOT_LIMIT
