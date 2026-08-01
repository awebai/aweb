from __future__ import annotations

import asyncio
import logging

import pytest
from httpx import ASGITransport, AsyncClient

from aweb.api import _cached_body_receive, create_app


class _FailingRedis:
    async def ping(self):
        raise RuntimeError("redis://secret@internal-host:6379/0 refused")


class _FailingDB:
    async def fetch_value(self, _query: str):
        raise RuntimeError("postgres://secret@db.internal/aweb refused")


class _DbInfra:
    is_initialized = True

    def __init__(self):
        self.db = _FailingDB()

    def get_manager(self, name: str = "aweb"):
        return self.db


@pytest.mark.asyncio
async def test_health_hides_internal_exception_details(monkeypatch, caplog):
    async def _noop_mount(_app, _db_infra, _redis, _registry_client):
        return None

    async def _noop_registry_validation(_registry_client):
        return None

    monkeypatch.setattr("aweb.api._mount_mcp_app", _noop_mount)
    monkeypatch.setattr("aweb.api._validate_awid_registry_client", _noop_registry_validation)
    caplog.set_level(logging.ERROR, logger="aweb.api")
    app = create_app(db_infra=_DbInfra(), redis=_FailingRedis())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "unhealthy",
        "checks": {
            "redis": "error",
            "database": "error",
        },
    }
    assert "redis://secret@internal-host:6379/0 refused" not in response.text
    assert "postgres://secret@db.internal/aweb refused" not in response.text
    assert "Health check failed for Redis" in caplog.text
    assert "Health check failed for database" in caplog.text


@pytest.mark.asyncio
async def test_mounted_request_triggers_lifecycle_outbox_replay(monkeypatch):
    replayed = asyncio.Event()
    redis = _FailingRedis()
    db_infra = _DbInfra()

    async def _capture_replay(db, captured_redis):
        assert db is db_infra.get_manager("aweb")
        assert captured_redis is redis
        replayed.set()

    monkeypatch.setattr("aweb.api.replay_lifecycle_side_effects", _capture_replay)
    app = create_app(db_infra=db_infra, redis=redis)
    app.state.db = db_infra
    app.state.redis = redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.get("/health")

    await asyncio.wait_for(replayed.wait(), timeout=1)


@pytest.mark.asyncio
async def test_cached_body_receive_terminates_after_replay():
    receive = _cached_body_receive(b'{"hello":"world"}')

    first = await receive()
    second = await receive()
    third = await receive()

    assert first == {"type": "http.request", "body": b'{"hello":"world"}', "more_body": False}
    assert second == {"type": "http.request", "body": b"", "more_body": False}
    assert third == {"type": "http.request", "body": b"", "more_body": False}
