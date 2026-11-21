"""App-event emits on the shared outbox, against real Postgres and a real HTTP
endpoint standing in for the core app-events origin.

No ``from __future__ import annotations``: FastAPI resolves the route's
``Depends(runtime.db)`` annotation at definition time.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import threading
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, verify_did_key_signature
from fastapi import Depends, FastAPI
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import Manifest, canonical_bytes, load_manifest, write_manifest_file
from aweb_naapp.outbox import (
    Acked,
    OutboxEvent,
    Permanent,
    Retryable,
    StoredEvent,
    apply_outbox_migrations,
    drain,
    enqueue,
    mint_event_id,
)
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_keys import AppKeyError
from aweb_naapp.runtime.event_emit import (
    APP_EVENTS_CHANNEL,
    AppEvents,
    app_event_body,
    build_emit_request,
)
from aweb_naapp.runtime.settings import NaappSettings

_TEAM = "default:example.test"
_KID = "example:emit-1"
_EVENT = dict(
    event_type="example/thing.changed",
    resource_ref="thing-1",
    delivery_intent="wake",
    payload={"version": "3"},
)


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/example"
    public_origin: str = "https://example.test"
    app_id: str = "example"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("EXAMPLE_"):
            monkeypatch.delenv(name)


@dataclass
class Receiver:
    """A real HTTP endpoint standing in for the core app-events origin."""

    origin: str
    status: int = 202
    requests: list[tuple[str, dict[str, str], bytes]] = field(default_factory=list)
    received: threading.Event = field(default_factory=threading.Event)


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    state = Receiver(origin="")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state.requests.append((self.path, dict(self.headers), body))
            self.send_response(state.status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            state.received.set()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.origin = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_app_events")
    await apply_outbox_migrations(database)
    yield database


@pytest.fixture
def seed() -> str:
    return secrets.token_hex(32)


def _did_key(seed_hex: str) -> str:
    return did_from_public_key(bytes(SigningKey(bytes.fromhex(seed_hex)).verify_key))


def _loaded(document: dict[str, Any]) -> Manifest:
    return load_manifest(canonical_bytes(document))


def _manifest_document(seed_hex: str) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "app": {"id": "example", "origin": "https://example.test"},
        "tools": [],
        "event_emitters": [{"kid": _KID, "did_key": _did_key(seed_hex)}],
    }


def _manifest(seed_hex: str) -> Manifest:
    return _loaded(_manifest_document(seed_hex))


def _v2_manifest(*purposes_by_kid: tuple[str, str, list[str]]) -> Manifest:
    return _loaded({
        "manifest_version": 2,
        "app": {"id": "example", "origin": "https://example.test"},
        "tools": [],
        "app_keys": [{"kid": kid, "did_key": did, "purposes": p} for kid, did, p in purposes_by_kid],
    })


def _settings(seed_hex: str, origin: str | None = "https://core.example.test", **values: object):
    configured: dict[str, object] = {
        "app_events_origin": origin,
        "app_emit_kid": _KID,
        "app_emit_key_seed_hex": seed_hex,
    }
    configured.update(values)
    return ExampleSettings(_env_file=None, **configured)


def _app_events(seed_hex: str, origin: str | None = "https://core.example.test") -> AppEvents:
    return AppEvents.from_settings(_settings(seed_hex, origin), _manifest(seed_hex))


def _signed_payload(headers: dict[str, str]) -> bytes:
    raw = headers["X-AWEB-Signed-Payload"]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _assert_signed_for(headers: dict[str, str], body: bytes, did_key: str) -> dict[str, Any]:
    signed_bytes = _signed_payload(headers)
    signed = json.loads(signed_bytes)
    assert signed["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert signed["did_key"] == did_key
    scheme, key_type, header_did, signature = headers["Authorization"].split(" ")
    assert (scheme, key_type, header_did) == ("AWEB-App", "DIDKey", did_key)
    verify_did_key_signature(did_key=did_key, payload=signed_bytes, signature_b64=signature)
    return signed


def _closed_origin() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def _stored(body: bytes) -> StoredEvent:
    return StoredEvent(
        event_id=mint_event_id(),
        team_id=_TEAM,
        kind="example/thing.changed",
        occurred_at=datetime.now(UTC),
        payload=body,
        signature=None,
        critical=False,
        producer={},
        channel=APP_EVENTS_CHANNEL,
    )


def test_app_event_body_is_canonical_metadata() -> None:
    body = app_event_body(**_EVENT)
    assert json.loads(body) == {
        "type": "example/thing.changed",
        "resource_ref": "thing-1",
        "delivery_intent": "wake",
        "payload": {"version": "3"},
    }
    assert body == canonical_json_bytes(json.loads(body))


def test_build_emit_request_signs_the_exact_body_for_the_app(seed: str) -> None:
    events = _app_events(seed)
    assert events.key is not None
    body = app_event_body(**_EVENT)
    url, headers = build_emit_request(
        origin="https://core.example.test",
        app_id="example",
        key=events.key,
        team_id=_TEAM,
        body=body,
        timestamp="2026-06-19T12:00:00Z",
    )
    assert url == "https://core.example.test/v1/events/app"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-AWEB-App-ID"] == "example"
    assert headers["X-AWEB-App-Key-ID"] == _KID
    assert headers["X-AWEB-Team-ID"] == _TEAM
    assert headers["X-AWEB-Timestamp"] == "2026-06-19T12:00:00Z"
    signed = _assert_signed_for(headers, body, _did_key(seed))
    assert (signed["app_id"], signed["kid"], signed["team_id"]) == ("example", _KID, _TEAM)
    assert (signed["method"], signed["aud"], signed["path"]) == (
        "POST",
        "https://core.example.test",
        "/v1/events/app",
    )


def test_an_app_without_an_app_events_origin_emits_nothing(seed: str) -> None:
    events = AppEvents.from_settings(ExampleSettings(_env_file=None), _manifest(seed))
    assert events.key is None


def test_a_v2_app_key_declared_for_app_event_emits(seed: str) -> None:
    manifest = _v2_manifest((_KID, _did_key(seed), ["app-event", "app-request"]))
    events = AppEvents.from_settings(_settings(seed), manifest)
    assert events.key is not None and events.key.did_key == _did_key(seed)


def test_a_v2_app_that_declares_no_app_event_key_needs_no_app_event_settings() -> None:
    events = AppEvents.from_settings(ExampleSettings(_env_file=None), _v2_manifest())
    assert events.key is None


def test_an_app_events_origin_with_no_key_declared_for_app_event_refuses_to_start(seed: str) -> None:
    manifest = _v2_manifest((_KID, _did_key(seed), ["app-request"]))
    with pytest.raises(AppKeyError, match="app-event"):
        AppEvents.from_settings(_settings(seed), manifest)


def test_an_app_events_origin_without_a_declared_key_refuses_to_start(seed: str) -> None:
    settings = ExampleSettings(_env_file=None, app_events_origin="https://core.example.test")
    with pytest.raises(AppKeyError):
        AppEvents.from_settings(settings, _manifest(seed))


@pytest.mark.parametrize("values", [{"app_emit_kid": _KID}, {"app_key_files": {}}])
def test_an_app_event_key_without_an_origin_refuses_to_start(
    seed: str, values: dict[str, object]
) -> None:
    settings = _settings(seed, origin=None, **values)
    with pytest.raises(AppKeyError, match="APP_EVENTS_ORIGIN"):
        AppEvents.from_settings(settings, _manifest(seed))


@pytest.mark.parametrize(
    "origin",
    [
        "not-a-valid-origin",
        "ftp://core.example.test",
        "http://core.example.test",
        "http://10.0.0.5:8000",
        "http://localhost.example.test",
    ],
)
def test_an_invalid_app_events_origin_refuses_to_start(seed: str, origin: str) -> None:
    with pytest.raises(ValueError, match="APP_EVENTS_ORIGIN"):
        _app_events(seed, origin)


@pytest.mark.parametrize(
    "origin",
    [
        "https://core.example.test",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://localhost:8000",
        "http://core.localhost",
    ],
)
def test_https_or_loopback_http_app_events_origins_are_accepted(seed: str, origin: str) -> None:
    assert _app_events(seed, origin).key is not None


async def test_an_emit_commits_with_the_callers_transaction(
    db: AsyncDatabaseManager, seed: str
) -> None:
    events = _app_events(seed)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await events.emit(tx, team_id=_TEAM, **_EVENT)
            raise RuntimeError("the operation failed")
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0

    async with db.transaction() as tx:
        event_id = await events.emit(tx, team_id=_TEAM, **_EVENT)
    row = await db.fetch_one("SELECT * FROM {{tables.outbox_events}}")
    assert row["event_id"] == event_id
    assert (row["team_id"], row["kind"], row["channel"]) == (
        _TEAM,
        "example/thing.changed",
        APP_EVENTS_CHANNEL,
    )
    assert bytes(row["payload"]) == app_event_body(**_EVENT)


async def test_an_app_without_an_app_events_origin_enqueues_nothing(
    db: AsyncDatabaseManager, seed: str
) -> None:
    events = AppEvents.from_settings(ExampleSettings(_env_file=None), _manifest(seed))
    async with db.transaction() as tx:
        assert await events.emit(tx, team_id=_TEAM, **_EVENT) is None
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


async def test_the_drain_delivers_the_signed_event(
    db: AsyncDatabaseManager, receiver: Receiver, seed: str
) -> None:
    events = _app_events(seed, receiver.origin)
    async with db.transaction() as tx:
        await events.emit(tx, team_id=_TEAM, **_EVENT)
    async with httpx.AsyncClient() as client:
        result = await drain(db, **events.drain_options(client))
    assert result.delivered == 1
    [(path, headers, body)] = receiver.requests
    assert path == "/v1/events/app"
    assert body == app_event_body(**_EVENT)
    assert headers["X-AWEB-Team-ID"] == _TEAM
    _assert_signed_for(headers, body, _did_key(seed))
    state = await db.fetch_value("SELECT state FROM {{tables.outbox_deliveries}}")
    assert state == "delivered"


async def test_app_events_drain_only_their_own_channel(
    db: AsyncDatabaseManager, receiver: Receiver, seed: str
) -> None:
    other = OutboxEvent(
        event_id=mint_event_id(),
        team_id=_TEAM,
        kind="hook",
        occurred_at=datetime.now(UTC),
        payload=b"{}",
        channel="hooks",
    )
    async with db.transaction() as tx:
        await enqueue(tx, other)
    events = _app_events(seed, receiver.origin)
    async with httpx.AsyncClient() as client:
        result = await drain(db, **events.drain_options(client))
    assert result.materialized == 0
    assert receiver.requests == []


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (200, Acked),
        (202, Acked),
        (429, Retryable),
        (500, Retryable),
        (503, Retryable),
        (400, Permanent),
        (401, Permanent),
        (403, Permanent),
    ],
)
async def test_the_core_answer_classifies_the_delivery(
    receiver: Receiver, seed: str, status: int, outcome: type
) -> None:
    receiver.status = status
    events = _app_events(seed, receiver.origin)
    async with httpx.AsyncClient() as client:
        transport = events.drain_options(client)["transport"]
        result = await transport.deliver(_stored(app_event_body(**_EVENT)), None)
    assert isinstance(result, outcome)
    if not isinstance(result, Acked):
        assert str(status) in result.error_class


async def test_an_unreachable_core_is_retried(seed: str) -> None:
    events = _app_events(seed, _closed_origin())
    async with httpx.AsyncClient() as client:
        transport = events.drain_options(client)["transport"]
        result = await transport.deliver(_stored(app_event_body(**_EVENT)), None)
    assert isinstance(result, Retryable)


async def test_each_attempt_is_signed_afresh_over_the_stored_bytes(
    receiver: Receiver, seed: str
) -> None:
    events = _app_events(seed, receiver.origin)
    stored = _stored(app_event_body(**_EVENT))
    async with httpx.AsyncClient() as client:
        transport = events.drain_options(client)["transport"]
        await transport.deliver(stored, None)
        await transport.deliver(stored, None)
    assert [body for _, _, body in receiver.requests] == [stored.payload, stored.payload]
    for _, headers, body in receiver.requests:
        signed = _assert_signed_for(headers, body, _did_key(seed))
        assert signed["timestamp"] == headers["X-AWEB-Timestamp"]


async def test_failed_deliveries_log_no_key_material(
    db: AsyncDatabaseManager, seed: str, caplog: pytest.LogCaptureFixture
) -> None:
    events = _app_events(seed, _closed_origin())
    async with db.transaction() as tx:
        await events.emit(tx, team_id=_TEAM, **_EVENT)
    with caplog.at_level(logging.DEBUG):
        async with httpx.AsyncClient() as client:
            result = await drain(db, **events.drain_options(client))
    assert result.failed == 1
    rendered = caplog.text + repr(events) + str(events)
    assert seed not in rendered
    assert seed.upper() not in rendered


async def test_the_runtime_drains_app_events_while_the_app_runs(
    tmp_path: Path, receiver: Receiver, seed: str, app_database_url: str
) -> None:
    manifest_path = tmp_path / "aweb-app.json"
    template = {**_manifest_document(seed), "event_emitters": [{"kid": _KID}]}
    write_manifest_file(manifest_path, template)
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    settings = _settings(seed, receiver.origin, database_url=app_database_url)
    runtime = NaappRuntime(
        settings, module_name="example", migrations_path=migrations, manifest_path=manifest_path
    )
    app = FastAPI(lifespan=runtime.lifespan)

    @app.post("/v1/things")
    async def create_thing(db: Annotated[AsyncDatabaseManager, Depends(runtime.db)]) -> dict:
        async with db.transaction() as tx:
            event_id = await runtime.app_events.emit(tx, team_id=_TEAM, **_EVENT)
        return {"event_id": str(event_id)}

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://example.test"
        ) as client:
            assert (await client.post("/v1/things")).status_code == 200
        assert await asyncio.to_thread(receiver.received.wait, 10)
    [(_, headers, body)] = receiver.requests
    assert body == app_event_body(**_EVENT)
    _assert_signed_for(headers, body, _did_key(seed))


@pytest.fixture
async def app_database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="naapp_app")
    return database.config.get_dsn()
