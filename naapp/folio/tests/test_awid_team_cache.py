import httpx
import pytest
from fastapi import HTTPException
from test_auth_v2_envelope import PUBLIC_ORIGIN, TEAM_ID, FakeDB, _make_request

from folio.auth import AWIDTeamCache, authenticate_request
from folio.config import Settings


def mock_registry(monkeypatch, handler):
    client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.parametrize("private,token", [(True, "synthetic-token"), (True, None), (True, "wrong"), (False, None), (False, "  ")])
async def test_team_auth_service_token(monkeypatch, private, token):
    request, ctx = await _make_request()
    calls = []

    def registry(req):
        calls.append(req)
        if private and req.headers.get("X-AWID-Service-Token") != "synthetic-token":
            return httpx.Response(403, json={"detail": {"code": "team_private"}})
        if req.url.path.endswith("/certificates"):
            return httpx.Response(200, json={"certificates": [], "has_more": False})
        return httpx.Response(200, json={"team_did_key": ctx["team_did"]})

    mock_registry(monkeypatch, registry)
    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60, service_token=token)
    db = FakeDB()
    if private and token != "synthetic-token":
        with pytest.raises(HTTPException) as exc:
            await authenticate_request(request, settings=Settings(public_origin=PUBLIC_ORIGIN), team_cache=cache, db=db)
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] == "team_private_unreadable"
        assert not db.calls
        assert not cache._cache
    else:
        principal = await authenticate_request(request, settings=Settings(public_origin=PUBLIC_ORIGIN), team_cache=cache, db=db)
        assert principal.team_id == TEAM_ID
        assert principal.did_key == ctx["member_did"]
        assert len(calls) == 2
    assert all(req.headers.get("X-AWID-Service-Token") == (token.strip() or None if token else None) for req in calls)


@pytest.mark.parametrize("endpoint", ["team", "certificates"])
@pytest.mark.parametrize("failure", ["private", "outage", "timeout", "other_forbidden", "malformed_forbidden"])
async def test_registry_failures_remain_distinct(monkeypatch, endpoint, failure):
    def registry(req):
        if (endpoint == "certificates") != req.url.path.endswith("/certificates"):
            return httpx.Response(200, json={"team_did_key": "did:key:synthetic"})
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic timeout", request=req)
        if failure == "private":
            return httpx.Response(403, json={"detail": {"code": "team_private"}})
        if failure == "other_forbidden":
            return httpx.Response(403, json={"detail": "other denial"})
        if failure == "malformed_forbidden":
            return httpx.Response(403, text="not JSON")
        return httpx.Response(503, text="upstream outage")

    mock_registry(monkeypatch, registry)
    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60)
    with pytest.raises(HTTPException) as exc:
        await cache.get(TEAM_ID)
    assert exc.value.status_code == (403 if failure == "private" else 503)
    if failure == "private":
        assert exc.value.detail["code"] == "team_private_unreadable"
    assert not cache._cache


async def test_service_token_environment_wiring(monkeypatch):
    from folio import api

    monkeypatch.setenv("FOLIO_AWID_SERVICE_TOKEN", "synthetic-token")
    settings = Settings(_env_file=None)
    captured = {}

    class Database:
        def __init__(self, settings):
            pass

        async def connect(self):
            pass

        async def disconnect(self):
            pass

    def cache(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(api, "FolioDatabase", Database)
    monkeypatch.setattr(api, "AWIDTeamCache", cache)
    app = api.create_app(settings)
    async with app.router.lifespan_context(app):
        assert captured["service_token"] == "synthetic-token"
