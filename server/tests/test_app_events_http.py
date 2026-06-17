from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

import aweb.routes.events as events_routes
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.app_events import current_app_events_for_agent
from aweb.app_registry import AppEmitKey, AppEventType, install_app
from aweb.internal_auth import build_internal_auth_header_value
from aweb.routes.events import router as events_router
from aweb.team_auth_deps import TeamIdentity

TEAM_ID = "backend:acme.com"
AGENT_ID = UUID("00000000-0000-0000-0000-000000000123")
DIGEST = "sha256:" + "c" * 64


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


class _FakeSSERequest:
    async def is_disconnected(self):
        return False


def _cached_body_receive(body: bytes):
    replayed = False

    async def _receive():
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    return _receive


def _build_events_app(aweb_db) -> FastAPI:
    app = FastAPI()
    app.include_router(events_router)
    app.state.db = _DbShim(aweb_db)
    app.state.redis = object()
    app.state.public_origin = "http://test"

    @app.middleware("http")
    async def cache_body_middleware(request, call_next):
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        request._receive = _cached_body_receive(body)
        return await call_next(request)

    return app


async def _fake_actionable_chat(*args, **kwargs):
    return []


async def _fake_team_identity(request, db_infra) -> TeamIdentity:
    return TeamIdentity(
        team_id=TEAM_ID,
        alias="alice",
        did_key="did:key:z6Mkalice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
        agent_id=str(AGENT_ID),
        identity_scope="global",
        certificate_id="cert-001",
    )


async def _seed_team_and_agent(aweb_db) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        TEAM_ID,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, alias, human_name, status, identity_scope
        )
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', 'Alice', 'active', 'global')
        ON CONFLICT DO NOTHING
        """,
        AGENT_ID,
        TEAM_ID,
    )


def _make_app_keypair():
    signing_key = SigningKey.generate()
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    return bytes(signing_key), did_key


async def _install_folio(aweb_db, *, did_key: str) -> None:
    await install_app(
        aweb_db,
        team_id=TEAM_ID,
        app_id="folio",
        origin="https://folio.aweb.ai",
        app_version="1.x",
        manifest_version=1,
        digest=DIGEST,
        granted_scopes=["folio:read"],
        installed_by_agent_id=str(AGENT_ID),
        event_types=[
            AppEventType(type="doc.changed", default_delivery_intent="wake"),
            AppEventType(type="asset.video.status", default_delivery_intent="ambient"),
        ],
        emit_keys=[AppEmitKey(kid="emit-1", did_key=did_key)],
    )


def _signed_app_headers(*, signing_key: bytes, did_key: str, body: bytes, path: str = "/v1/events/app"):
    timestamp = datetime.now(timezone.utc).isoformat()
    canonical = canonical_json_bytes(
        {
            "v": 1,
            "auth": "app-event",
            "aud": "http://test",
            "method": "POST",
            "path": path,
            "team_id": TEAM_ID,
            "app_id": "folio",
            "kid": "emit-1",
            "did_key": did_key,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"AWEB-App DIDKey {did_key} {sign_message(signing_key, canonical)}",
        "X-AWEB-App-ID": "folio",
        "X-AWEB-App-Key-ID": "emit-1",
        "X-AWEB-Team-ID": TEAM_ID,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("="),
        "Content-Type": "application/json",
    }


@pytest.mark.asyncio
async def test_app_event_subscriptions_default_intent_and_matching(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(events_routes, "get_team_identity", _fake_team_identity)
    monkeypatch.setattr(events_routes, "_current_actionable_chat", _fake_actionable_chat)
    signing_key, did_key = _make_app_keypair()
    app = _build_events_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)
    await _install_folio(aweb_cloud_db.aweb_db, did_key=did_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        sub_resp = await client.post(
            "/v1/events/subscriptions",
            json={"type": "folio/doc.changed", "resource_ref": "pitch"},
        )
        body = json.dumps(
            {
                "type": "folio/doc.changed",
                "resource_ref": "pitch",
                "delivery_intent": "ambient",
                "payload": {"version": "7"},
            },
            separators=(",", ":"),
        ).encode()
        emit_resp = await client.post(
            "/v1/events/app",
            content=body,
            headers=_signed_app_headers(signing_key=signing_key, did_key=did_key, body=body),
        )

    stream = events_routes._sse_agent_events(
        request=_FakeSSERequest(),
        db=_DbShim(aweb_cloud_db.aweb_db),
        redis=object(),
        team_id=TEAM_ID,
        agent_id=str(AGENT_ID),
        identity=await _fake_team_identity(None, None),
        deadline=datetime.now(timezone.utc) + timedelta(milliseconds=50),
    )
    chunks = [await anext(stream), await anext(stream), await anext(stream)]
    await stream.aclose()

    assert sub_resp.status_code == 200, sub_resp.text
    assert sub_resp.json()["delivery_intent"] == "wake"
    assert emit_resp.status_code == 200, emit_resp.text
    assert emit_resp.json()["app_id"] == "folio"
    stream_text = "".join(chunks)
    assert "event: app_event" in stream_text
    assert '"delivery_intent": "wake"' in stream_text

    events = await current_app_events_for_agent(
        aweb_cloud_db.aweb_db,
        team_id=TEAM_ID,
        agent_id=str(AGENT_ID),
    )
    assert len(events) == 1
    assert events[0]["app_event_type"] == "folio/doc.changed"
    assert events[0]["delivery_intent"] == "wake"
    assert events[0]["producer_delivery_intent"] == "ambient"
    assert events[0]["payload"] == {"version": "7"}


@pytest.mark.asyncio
async def test_app_event_emit_rejects_uninstalled_or_wrong_namespace(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(events_routes, "get_team_identity", _fake_team_identity)
    signing_key, did_key = _make_app_keypair()
    app = _build_events_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)
    await _install_folio(aweb_cloud_db.aweb_db, did_key=did_key)

    body = json.dumps(
        {"type": "other/doc.changed", "resource_ref": "pitch", "payload": {}},
        separators=(",", ":"),
    ).encode()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/events/app",
            content=body,
            headers=_signed_app_headers(signing_key=signing_key, did_key=did_key, body=body),
        )

    assert resp.status_code == 403
    assert "own event namespace" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_subscription_get_accepts_internal_gateway_auth(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(events_routes, "get_team_identity", _fake_team_identity)
    signing_key, did_key = _make_app_keypair()
    app = _build_events_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)
    await _install_folio(aweb_cloud_db.aweb_db, did_key=did_key)
    secret = "test-internal-secret"
    user_id = "00000000-0000-0000-0000-000000000999"
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)
    auth = build_internal_auth_header_value(
        secret=secret,
        team_id=TEAM_ID,
        principal_type="u",
        principal_id=user_id,
        actor_id=str(AGENT_ID),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post(
            "/v1/events/subscriptions",
            json={"type": "folio/doc.changed", "delivery_intent": "ambient"},
        )
        listed = await client.get(
            "/v1/events/subscriptions",
            headers={
                "X-AWEB-Auth": auth,
                "X-Team-ID": TEAM_ID,
                "X-User-ID": user_id,
                "X-AWEB-Actor-ID": str(AGENT_ID),
            },
        )

    assert created.status_code == 200, created.text
    assert listed.status_code == 200, listed.text
    assert listed.json()["subscriptions"][0]["type"] == "folio/doc.changed"
