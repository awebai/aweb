from __future__ import annotations

import base64
import hashlib
import json

import httpx

from library.config import Settings
from library.event_emit import app_event_body, build_emit_request, emit_app_event

# A TEST emit key (NOT a real provisioned key) — 32-byte ed25519 seed.
_TEST_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
_TEAM = "default:atext.aweb.ai"


def _emit_settings(**overrides) -> Settings:
    base = {
        "app_events_origin": "https://core.aweb.ai",
        "app_emit_kid": "library:emit-1",
        "app_emit_key_seed_hex": _TEST_SEED_HEX,
    }
    base.update(overrides)
    return Settings(**base)


def test_app_event_body_is_canonical() -> None:
    body = app_event_body(
        event_type="library/example",
        resource_ref="pack-1",
        delivery_intent="ambient",
        payload={"k": "v"},
    )
    assert json.loads(body) == {
        "type": "library/example",
        "resource_ref": "pack-1",
        "delivery_intent": "ambient",
        "payload": {"k": "v"},
    }


def test_build_emit_request_signs_with_app_emit_credential() -> None:
    request = build_emit_request(
        settings=_emit_settings(),
        team_id=_TEAM,
        event_type="library/example",
        resource_ref="pack-1",
        delivery_intent="ambient",
        payload={"k": "v"},
        timestamp="2026-06-19T12:00:00Z",
    )
    assert request is not None
    url, body, headers = request
    assert url == "https://core.aweb.ai/v1/events/app"
    assert headers["X-AWEB-App-ID"] == "library"
    assert headers["X-AWEB-App-Key-ID"] == "library:emit-1"
    assert headers["X-AWEB-Team-ID"] == _TEAM
    assert headers["Authorization"].startswith("AWEB-App DIDKey did:key:")
    raw = headers["X-AWEB-Signed-Payload"]
    signed = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    assert signed["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert signed["app_id"] == "library"


def test_build_emit_request_returns_none_when_unconfigured() -> None:
    assert (
        build_emit_request(
            settings=Settings(),
            team_id=_TEAM,
            event_type="library/example",
            resource_ref="pack-1",
            delivery_intent="ambient",
            payload={},
            timestamp="2026-06-19T12:00:00Z",
        )
        is None
    )


async def test_emit_app_event_noop_when_unconfigured(monkeypatch) -> None:
    async def fail_post(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("must not POST when unconfigured")

    monkeypatch.setattr(httpx.AsyncClient, "post", fail_post)
    await emit_app_event(
        settings=Settings(),
        team_id=_TEAM,
        event_type="library/example",
        resource_ref="pack-1",
        delivery_intent="ambient",
        payload={},
    )


async def test_emit_app_event_swallows_transport_and_misconfig(monkeypatch) -> None:
    async def boom(*args, **kwargs):
        raise httpx.ConnectError("channel down")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    # Transport failure is swallowed.
    await emit_app_event(
        settings=_emit_settings(),
        team_id=_TEAM,
        event_type="library/example",
        resource_ref="pack-1",
        delivery_intent="ambient",
        payload={},
    )
    # A misconfigured (unparseable) seed is also swallowed, never raised.
    await emit_app_event(
        settings=_emit_settings(app_emit_key_seed_hex="nothex"),
        team_id=_TEAM,
        event_type="library/example",
        resource_ref="pack-1",
        delivery_intent="ambient",
        payload={},
    )
