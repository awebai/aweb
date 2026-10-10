from __future__ import annotations

import base64
import hashlib
import json
import logging
from types import SimpleNamespace

import httpx
import pytest
from awid.signing import canonical_json_bytes
from fastapi.testclient import TestClient

import folio.api as folio_api
from folio.config import Settings
from folio.event_emit import (
    UninstalledTeams,
    build_emit_request,
    doc_changed_event_body,
    emit_doc_changed,
)

# A TEST emit key (NOT a real provisioned key) — 32-byte ed25519 seed.
_TEST_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
_TEAM = "default:atext.aweb.ai"


def _emit_settings(**overrides) -> Settings:
    base = {
        "app_events_origin": "https://core.aweb.ai",
        "app_emit_kid": "emit-test",
        "app_emit_key_seed_hex": _TEST_SEED_HEX,
    }
    base.update(overrides)
    return Settings(**base)


def _decode_signed_payload(headers: dict[str, str]) -> dict:
    raw = headers["X-AWEB-Signed-Payload"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def _fake_document(slug: str, body: str, version: int) -> dict:
    return {
        "document_id": "11111111-1111-4111-8111-111111111111",
        "slug": slug,
        "title": "Pitch",
        "body": body,
        "current_version": version,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "latest": {
            "version_id": "22222222-2222-4222-8222-222222222222",
            "version_number": version,
            "body": body,
            "created_by_did_key": "did:key:zAgent",
            "created_by_alias": "agent",
            "certificate_id": "cert",
            "created_at": "2026-01-01T00:00:00Z",
        },
    }


def _template_route_app(settings: Settings, monkeypatch, *, version: int = 3):
    """A folio app whose template-append route is stubbed to succeed, so a test
    can observe only the emit side-effect."""
    app = folio_api.create_app(settings)
    route = next(
        r for r in app.routes if getattr(r, "path", None) == "/v1/documents/{slug}/versions/template"
    )
    app.dependency_overrides[route.dependant.dependencies[0].call] = lambda: SimpleNamespace(team_id=_TEAM)
    app.dependency_overrides[route.dependant.dependencies[1].call] = lambda: object()

    async def fake_append_version(_database, *, principal, settings, slug: str, body: str) -> dict:
        return _fake_document(slug, body, version)

    monkeypatch.setattr(folio_api, "append_version", fake_append_version)
    return app


def test_doc_changed_event_body_is_canonical_and_metadata_only() -> None:
    body = doc_changed_event_body(slug="pitch", version=7, source="present-link")
    obj = json.loads(body)
    assert obj == {
        "type": "folio/doc.changed",
        "resource_ref": "pitch",
        "delivery_intent": "wake",
        "payload": {"version": "7", "source": "present-link"},
    }
    # No document body, no secrets — metadata only.
    assert set(obj["payload"]) == {"version", "source"}
    # Uses the shared canonical-JSON primitive.
    assert body == canonical_json_bytes(obj)


def test_build_emit_request_signs_doc_changed_with_app_emit_credential() -> None:
    settings = _emit_settings()
    request = build_emit_request(
        settings=settings,
        team_id=_TEAM,
        slug="pitch",
        version=7,
        source="api",
        timestamp="2026-06-17T12:00:00Z",
    )
    assert request is not None
    url, body, headers = request

    assert url == "https://core.aweb.ai/v1/events/app"
    assert body == doc_changed_event_body(slug="pitch", version=7, source="api")
    assert headers["Content-Type"] == "application/json"
    assert headers["X-AWEB-App-ID"] == "folio"
    assert headers["X-AWEB-App-Key-ID"] == "emit-test"
    assert headers["X-AWEB-Team-ID"] == _TEAM
    assert headers["X-AWEB-Timestamp"] == "2026-06-17T12:00:00Z"
    assert headers["Authorization"].startswith("AWEB-App DIDKey did:key:")

    signed = _decode_signed_payload(headers)
    assert signed["app_id"] == "folio"
    assert signed["kid"] == "emit-test"
    assert signed["team_id"] == _TEAM
    assert signed["method"] == "POST"
    assert signed["path"] == "/v1/events/app"
    assert signed["aud"] == "https://core.aweb.ai"
    # The credential binds the exact body bytes that get POSTed.
    assert signed["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_build_emit_request_is_deterministic() -> None:
    settings = _emit_settings()
    kwargs = dict(team_id=_TEAM, slug="pitch", version=7, source="api", timestamp="2026-06-17T12:00:00Z")
    first = build_emit_request(settings=settings, **kwargs)
    second = build_emit_request(settings=settings, **kwargs)
    assert first == second


def test_build_emit_request_returns_none_when_no_emit_key_configured() -> None:
    # folio emits nothing unless an emit key is configured.
    assert (
        build_emit_request(
            settings=Settings(),
            team_id=_TEAM,
            slug="pitch",
            version=1,
            source="api",
            timestamp="2026-06-17T12:00:00Z",
        )
        is None
    )


async def test_emit_doc_changed_noop_when_unconfigured(monkeypatch) -> None:
    posted = False

    async def fake_post(*args, **kwargs):  # pragma: no cover - must not be called
        nonlocal posted
        posted = True
        raise AssertionError("emit must not POST when unconfigured")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    await emit_doc_changed(
        settings=Settings(), uninstalled=_uninstalled(), team_id=_TEAM, slug="pitch", version=1, source="api"
    )
    assert posted is False


async def test_emit_doc_changed_swallows_transport_errors(monkeypatch) -> None:
    async def boom(*args, **kwargs):
        raise httpx.ConnectError("channel down")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    # A doc write must succeed even if the channel is unreachable — no exception escapes.
    await emit_doc_changed(
        settings=_emit_settings(), uninstalled=_uninstalled(), team_id=_TEAM, slug="pitch", version=1, source="api"
    )


def test_append_route_emits_doc_changed_when_configured(monkeypatch) -> None:
    captured_url = ""
    captured_headers: dict[str, str] = {}
    captured_content = b""

    class _Resp:
        status_code = 200
        text = ""

    async def capture_post(self, url, content=None, headers=None, **kwargs):
        nonlocal captured_url, captured_headers, captured_content
        captured_url = url
        captured_headers = dict(headers or {})
        captured_content = content or b""
        return _Resp()

    monkeypatch.setattr(httpx.AsyncClient, "post", capture_post)

    app = _template_route_app(_emit_settings(), monkeypatch, version=3)

    response = TestClient(app).post(
        "/v1/documents/pitch/versions/template",
        json={"name": "pitch", "slots": {"cover": {"title": "Q3"}}},
    )
    assert response.status_code == 200, response.text

    # The append fired a folio/doc.changed emit over the wire with the credential headers.
    assert captured_url == "https://core.aweb.ai/v1/events/app"
    assert captured_headers["X-AWEB-App-ID"] == "folio"
    assert captured_headers["X-AWEB-Team-ID"] == _TEAM
    assert captured_headers["Authorization"].startswith("AWEB-App DIDKey did:key:")
    emitted = json.loads(captured_content)
    assert emitted["type"] == "folio/doc.changed"
    assert emitted["resource_ref"] == "pitch"
    assert emitted["payload"] == {"version": "3", "source": "api"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"app_emit_key_seed_hex": "nothex-nothex-nothex"},  # unparseable seed
        {"app_events_origin": "not-a-valid-origin"},  # no scheme/host
    ],
)
def test_append_route_swallows_misconfigured_emit(monkeypatch, caplog, overrides) -> None:
    # A configured-but-invalid emit (bad seed or origin) must NOT break the write:
    # construction happens inside the best-effort boundary, logged and swallowed.
    settings = _emit_settings(**overrides)
    app = _template_route_app(settings, monkeypatch, version=4)

    with caplog.at_level(logging.WARNING):
        response = TestClient(app).post(
            "/v1/documents/pitch/versions/template",
            json={"name": "pitch", "slots": {"cover": {"title": "Q3"}}},
        )

    assert response.status_code == 200, response.text
    assert any("emit failed" in record.getMessage() for record in caplog.records)
    # The configured seed must never be echoed into logs.
    assert all(_TEST_SEED_HEX not in record.getMessage() for record in caplog.records)
    if "app_emit_key_seed_hex" in overrides:
        assert all(overrides["app_emit_key_seed_hex"] not in record.getMessage() for record in caplog.records)


_NOT_REGISTERED = {"detail": "App emit key is not registered"}


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _uninstalled(clock: _Clock | None = None) -> UninstalledTeams:
    return UninstalledTeams(ttl_seconds=600, clock=clock or _Clock())


def _record_posts(monkeypatch, response_for_team) -> list[str]:
    """Patch the emit transport; each POST returns response_for_team(team_id)."""
    posted_teams: list[str] = []

    async def fake_post(self, url, content=None, headers=None, **kwargs):
        team_id = (headers or {})["X-AWEB-Team-ID"]
        posted_teams.append(team_id)
        return response_for_team(team_id)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    return posted_teams


async def _emit(team_id: str, uninstalled: UninstalledTeams, version: int = 1) -> None:
    await emit_doc_changed(
        settings=_emit_settings(),
        uninstalled=uninstalled,
        team_id=team_id,
        slug="pitch",
        version=version,
        source="api",
    )


async def test_emit_doc_changed_logs_rejection_without_raising(monkeypatch, caplog) -> None:
    posted = _record_posts(
        monkeypatch, lambda _team: httpx.Response(401, json={"detail": "Invalid app event signature"})
    )
    uninstalled = _uninstalled()
    with caplog.at_level(logging.INFO):
        await _emit(_TEAM, uninstalled, version=2)
        await _emit(_TEAM, uninstalled, version=3)
    # Any failure other than "not installed" keeps today's warning on every write.
    assert posted == [_TEAM, _TEAM]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "emit rejected" in r.getMessage()]
    assert len(warnings) == 2


async def test_uninstalled_team_emits_once_then_skips_within_ttl(monkeypatch, caplog) -> None:
    posted = _record_posts(monkeypatch, lambda _team: httpx.Response(403, json=_NOT_REGISTERED))
    uninstalled = _uninstalled()
    with caplog.at_level(logging.INFO):
        for version in (1, 2, 3):
            await _emit(_TEAM, uninstalled, version=version)
    assert posted == [_TEAM]
    messages = [r.getMessage() for r in caplog.records if r.name == "folio.event_emit"]
    assert len(messages) == 1
    assert caplog.records[-1].levelno == logging.INFO
    assert _TEAM in messages[0] and "not installed" in messages[0]
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


async def test_uninstalled_team_is_retried_once_after_ttl(monkeypatch, caplog) -> None:
    posted = _record_posts(monkeypatch, lambda _team: httpx.Response(403, json=_NOT_REGISTERED))
    clock = _Clock()
    uninstalled = _uninstalled(clock)
    with caplog.at_level(logging.INFO):
        await _emit(_TEAM, uninstalled)
        clock.now += 599
        await _emit(_TEAM, uninstalled)
        clock.now += 2
        await _emit(_TEAM, uninstalled)
        await _emit(_TEAM, uninstalled)
    assert posted == [_TEAM, _TEAM]
    assert len([r for r in caplog.records if r.name == "folio.event_emit"]) == 2


async def test_installed_team_still_emits_every_write(monkeypatch) -> None:
    posted = _record_posts(monkeypatch, lambda _team: httpx.Response(202, json={"event_id": "e"}))
    uninstalled = _uninstalled()
    for version in (1, 2, 3):
        await _emit(_TEAM, uninstalled, version=version)
    assert posted == [_TEAM, _TEAM, _TEAM]


async def test_uninstalled_team_does_not_silence_other_teams(monkeypatch) -> None:
    installed = "backend:acme.example"
    posted = _record_posts(
        monkeypatch,
        lambda team: httpx.Response(403, json=_NOT_REGISTERED)
        if team == _TEAM
        else httpx.Response(202, json={"event_id": "e"}),
    )
    uninstalled = _uninstalled()
    for version in (1, 2):
        await _emit(_TEAM, uninstalled, version=version)
        await _emit(installed, uninstalled, version=version)
    assert posted == [_TEAM, installed, installed]


def test_append_route_shares_one_uninstalled_cache_across_writes(monkeypatch) -> None:
    posted = _record_posts(monkeypatch, lambda _team: httpx.Response(403, json=_NOT_REGISTERED))
    client = TestClient(_template_route_app(_emit_settings(), monkeypatch, version=5))
    for _ in range(3):
        response = client.post(
            "/v1/documents/pitch/versions/template",
            json={"name": "pitch", "slots": {"cover": {"title": "Q3"}}},
        )
        assert response.status_code == 200, response.text
    assert posted == [_TEAM]
