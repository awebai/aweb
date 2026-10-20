from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from awid.signing import canonical_json_bytes, verify_did_key_signature
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.event_emit import app_event_body, build_emit_request, emit_app_event
from aweb_naapp.runtime.settings import NaappSettings

_TEAM = "default:example.test"
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


@dataclass
class Receiver:
    """A real HTTP endpoint standing in for the core app-events origin."""

    origin: str
    status: int = 202
    requests: list[tuple[str, dict[str, str], bytes]] = field(default_factory=list)


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

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.origin = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


def _closed_origin() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def _emit_settings(
    origin: str = "https://core.example.test", **overrides: object
) -> ExampleSettings:
    values: dict[str, object] = {
        "app_events_origin": origin,
        "app_emit_kid": "example:emit-1",
        "app_emit_key_seed_hex": secrets.token_hex(32),
    }
    values.update(overrides)
    return ExampleSettings(_env_file=None, **values)


def _signed_payload(headers: dict[str, str]) -> bytes:
    raw = headers["X-AWEB-Signed-Payload"]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def test_app_event_body_is_canonical_metadata() -> None:
    body = app_event_body(**_EVENT)
    assert json.loads(body) == {
        "type": "example/thing.changed",
        "resource_ref": "thing-1",
        "delivery_intent": "wake",
        "payload": {"version": "3"},
    }
    assert body == canonical_json_bytes(json.loads(body))


def test_build_emit_request_signs_the_exact_body_for_the_app() -> None:
    request = build_emit_request(
        settings=_emit_settings(), team_id=_TEAM, timestamp="2026-06-19T12:00:00Z", **_EVENT
    )
    assert request is not None
    url, body, headers = request
    assert url == "https://core.example.test/v1/events/app"
    assert body == app_event_body(**_EVENT)
    assert headers["Content-Type"] == "application/json"
    assert headers["X-AWEB-App-ID"] == "example"
    assert headers["X-AWEB-App-Key-ID"] == "example:emit-1"
    assert headers["X-AWEB-Team-ID"] == _TEAM
    assert headers["X-AWEB-Timestamp"] == "2026-06-19T12:00:00Z"

    signed_bytes = _signed_payload(headers)
    signed = json.loads(signed_bytes)
    assert (signed["app_id"], signed["kid"], signed["team_id"]) == (
        "example",
        "example:emit-1",
        _TEAM,
    )
    assert (signed["method"], signed["aud"], signed["path"]) == (
        "POST",
        "https://core.example.test",
        "/v1/events/app",
    )
    assert signed["body_sha256"] == hashlib.sha256(body).hexdigest()
    scheme, key_type, did_key, signature = headers["Authorization"].split(" ")
    assert (scheme, key_type, did_key) == ("AWEB-App", "DIDKey", signed["did_key"])
    verify_did_key_signature(did_key=did_key, payload=signed_bytes, signature_b64=signature)


def test_build_emit_request_is_deterministic() -> None:
    settings = _emit_settings()
    kwargs = dict(settings=settings, team_id=_TEAM, timestamp="2026-06-19T12:00:00Z", **_EVENT)
    assert build_emit_request(**kwargs) == build_emit_request(**kwargs)


@pytest.mark.parametrize("missing", ["app_events_origin", "app_emit_kid", "app_emit_key_seed_hex"])
def test_build_emit_request_is_none_without_a_complete_emit_key(missing: str) -> None:
    settings = _emit_settings(**{missing: None})
    assert (
        build_emit_request(
            settings=settings, team_id=_TEAM, timestamp="2026-06-19T12:00:00Z", **_EVENT
        )
        is None
    )


async def test_emit_app_event_posts_the_signed_event(receiver: Receiver) -> None:
    settings = _emit_settings(receiver.origin)
    await emit_app_event(settings=settings, team_id=_TEAM, **_EVENT)
    assert len(receiver.requests) == 1
    path, headers, body = receiver.requests[0]
    assert path == "/v1/events/app"
    assert body == app_event_body(**_EVENT)
    signed_bytes = _signed_payload(headers)
    signed = json.loads(signed_bytes)
    assert signed["body_sha256"] == hashlib.sha256(body).hexdigest()
    verify_did_key_signature(
        did_key=signed["did_key"],
        payload=signed_bytes,
        signature_b64=headers["Authorization"].split(" ")[3],
    )


async def test_emit_app_event_sends_nothing_when_unconfigured(receiver: Receiver) -> None:
    settings = _emit_settings(receiver.origin, app_emit_kid=None)
    await emit_app_event(settings=settings, team_id=_TEAM, **_EVENT)
    assert receiver.requests == []


async def test_emit_app_event_logs_a_rejection_without_raising(
    receiver: Receiver, caplog: pytest.LogCaptureFixture
) -> None:
    receiver.status = 403
    with caplog.at_level(logging.WARNING):
        await emit_app_event(settings=_emit_settings(receiver.origin), team_id=_TEAM, **_EVENT)
    assert len(receiver.requests) == 1
    assert any("403" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize(
    "overrides",
    [
        {"app_events_origin": "closed"},
        {"app_emit_key_seed_hex": "nothex-nothex-nothex"},
        {"app_events_origin": "not-a-valid-origin"},
    ],
)
async def test_emit_app_event_never_raises_or_logs_the_seed(
    overrides: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    if overrides.get("app_events_origin") == "closed":
        overrides = {"app_events_origin": _closed_origin()}
    settings = _emit_settings(**overrides)
    with caplog.at_level(logging.WARNING):
        await emit_app_event(settings=settings, team_id=_TEAM, **_EVENT)
    assert caplog.records
    seed = settings.app_emit_key_seed_hex or ""
    assert all(seed not in record.getMessage() for record in caplog.records)
