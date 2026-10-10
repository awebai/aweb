from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from library.auth import AWIDTeamCache, authenticate_request
from library.config import Settings


def registry(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(handler), **kw)
    )


@pytest.mark.parametrize("private,configured", [(True, True), (False, False), (True, False)])
@pytest.mark.parametrize("fault", [None, "body", "revoked", "certificate"])
async def test_team_request_authenticates(monkeypatch, private, configured, fault):
    token = secrets.token_urlsafe(24)
    team_key, member_key = SigningKey.generate(), SigningKey.generate()
    team_did = did_from_public_key(bytes(team_key.verify_key))
    member_did = did_from_public_key(bytes(member_key.verify_key))
    now = datetime.now(UTC).isoformat()
    cert = dict(
        version=1,
        certificate_id="synthetic-cert",
        team_id="team:example.com",
        team_did_key=team_did,
        member_did_key=member_did,
        alias="alice",
        lifetime="persistent",
        issued_at=now,
    )
    cert["signature"] = sign_message(bytes(team_key), canonical_json_bytes(cert))
    body = b"{}"
    payload = canonical_json_bytes(
        dict(
            v=2,
            aud="https://app.example.com",
            method="POST",
            path="/v1/test",
            team_id=cert["team_id"],
            timestamp=now,
            body_sha256=hashlib.sha256(body).hexdigest(),
        )
    )
    if fault == "certificate":
        cert["alias"] = "altered"
    headers = {
        "authorization": f"DIDKey {member_did} {sign_message(bytes(member_key), payload)}",
        "x-aweb-timestamp": now,
        "x-awid-team-certificate": base64.b64encode(json.dumps(cert).encode()).decode(),
        "x-aweb-signed-payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
    }

    async def receive():
        return {"type": "http.request", "body": b"tampered" if fault == "body" else body}

    request = Request(
        dict(
            type="http",
            method="POST",
            path="/v1/test",
            raw_path=b"/v1/test",
            query_string=b"",
            headers=[(k.encode(), v.encode()) for k, v in headers.items()],
        ),
        receive,
    )
    calls = []

    def handler(req):
        calls.append(req.url.path)
        assert req.headers.get("X-AWID-Service-Token") == (token if configured else None)
        if private and req.headers.get("X-AWID-Service-Token") != token:
            return httpx.Response(403, json={"detail": {"code": "team_private"}})
        return httpx.Response(
            200,
            json={
                "certificates": [{"certificate_id": "synthetic-cert", "revoked_at": now}]
                if fault == "revoked"
                else [],
                "has_more": False,
            }
            if req.url.path.endswith("/certificates")
            else {"team_did_key": team_did},
        )

    registry(monkeypatch, handler)
    kwargs = {"service_token": token} if configured else {}
    cache = AWIDTeamCache(registry_url="https://registry.example.com", ttl_seconds=60, **kwargs)
    db = AsyncMock()
    if fault is not None:
        with pytest.raises(HTTPException) as caught:
            await authenticate_request(
                request,
                settings=Settings(public_origin="https://app.example.com"),
                team_cache=cache,
                db=db,
            )
        assert caught.value.status_code == (
            403 if private and not configured and fault != "body" else 401
        )
        db.execute.assert_not_awaited()
        return
    if private and not configured:
        with pytest.raises(HTTPException) as caught:
            await authenticate_request(
                request,
                settings=Settings(public_origin="https://app.example.com"),
                team_cache=cache,
                db=db,
            )
        assert caught.value.status_code == 403
        assert caught.value.detail["code"] == "team_private_unreadable"
        db.execute.assert_not_awaited()
        return
    principal = await authenticate_request(
        request, settings=Settings(public_origin="https://app.example.com"), team_cache=cache, db=db
    )
    assert principal.team_id == cert["team_id"]
    assert len(calls) == 2
    assert calls[1].endswith("/certificates")
    assert db.execute.await_count == 2


@pytest.mark.parametrize("endpoint", ["team", "certificates"])
@pytest.mark.parametrize(
    "status,code,expected",
    [(403, "team_private", 403), (403, "other", 503), (500, "team_private", 503)],
)
async def test_registry_refusal_mapping(monkeypatch, endpoint, status, code, expected):
    def handler(req):
        if endpoint == "certificates" and not req.url.path.endswith("/certificates"):
            return httpx.Response(200, json={"team_did_key": "synthetic-team-key"})
        assert "X-AWID-Service-Token" not in req.headers
        return httpx.Response(status, json={"detail": {"code": code}})

    registry(monkeypatch, handler)
    cache = AWIDTeamCache(registry_url="https://registry.example.com", ttl_seconds=60)
    with pytest.raises(HTTPException) as caught:
        await cache.get("team:example.com")
    assert caught.value.status_code == expected
    if expected == 403:
        assert caught.value.detail["code"] == "team_private_unreadable"
    assert not cache._cache


async def test_registry_timeout_remains_unavailable(monkeypatch):
    def handler(req):
        raise httpx.ReadTimeout("synthetic timeout", request=req)

    registry(monkeypatch, handler)
    with pytest.raises(HTTPException) as caught:
        await AWIDTeamCache(registry_url="https://registry.example.com", ttl_seconds=60).get(
            "team:example.com"
        )
    assert caught.value.status_code == 503


def test_service_token_environment(monkeypatch):
    token = secrets.token_urlsafe(24)
    monkeypatch.setenv("LIBRARY_AWID_SERVICE_TOKEN", "  " + token + "  ")
    assert Settings(_env_file=None).awid_service_token == token
    monkeypatch.setenv("LIBRARY_AWID_SERVICE_TOKEN", "  ")
    assert Settings(_env_file=None).awid_service_token is None


@pytest.mark.parametrize(
    "payload", [None, [], {"detail": "team_private"}, {"detail": {"code": "other"}}]
)
async def test_unrecognized_forbidden_remains_unavailable(monkeypatch, payload):
    registry(monkeypatch, lambda req: httpx.Response(403, json=payload))
    with pytest.raises(HTTPException) as caught:
        await AWIDTeamCache(registry_url="https://registry.example.com", ttl_seconds=60).get(
            "team:example.com"
        )
    assert caught.value.status_code == 503


async def test_lifespan_passes_configured_token(monkeypatch):
    import library.api as api

    token = secrets.token_urlsafe(24)
    monkeypatch.setenv("LIBRARY_AWID_SERVICE_TOKEN", token)
    database = AsyncMock()
    monkeypatch.setattr(api, "LibraryDatabase", lambda settings: database)
    captured = []
    original = api.AWIDTeamCache

    def cache_factory(**kwargs):
        captured.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(api, "AWIDTeamCache", cache_factory)
    app = api.create_app(Settings(_env_file=None))
    async with app.router.lifespan_context(app):
        assert captured[0]["service_token"] == token
    database.disconnect.assert_awaited_once()
