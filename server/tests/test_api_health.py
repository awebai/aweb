from __future__ import annotations

import logging

import pytest
from httpx import ASGITransport, AsyncClient

from aweb.api import _cached_body_receive, create_app


class _FailingRedis:
    async def ping(self):
        raise RuntimeError("redis://secret@internal-host:6379/0 refused")


class _AnsweringRedis:
    async def ping(self):
        return True


class _FailingDB:
    async def fetch_value(self, _query: str):
        raise RuntimeError("postgres://secret@db.internal/aweb refused")


class _AnsweringDB:
    async def fetch_value(self, _query: str):
        return 1


class _DbInfra:
    is_initialized = True

    def __init__(self, db):
        self.db = db

    def get_manager(self, name: str = "aweb"):
        return self.db


def _app(monkeypatch, *, redis, db):
    async def _noop_mount(_app, _db_infra, _redis, _registry_client):
        return None

    async def _noop_registry_validation(_registry_client):
        return None

    monkeypatch.setattr("aweb.api._mount_mcp_app", _noop_mount)
    monkeypatch.setattr("aweb.api._validate_awid_registry_client", _noop_registry_validation)
    return create_app(db_infra=_DbInfra(db), redis=redis)


@pytest.mark.asyncio
async def test_health_hides_internal_exception_details(monkeypatch, caplog):
    caplog.set_level(logging.ERROR, logger="aweb.api")
    app = _app(monkeypatch, redis=_FailingRedis(), db=_FailingDB())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 503
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
@pytest.mark.parametrize(
    "redis,db,status_code,body",
    [
        (
            _AnsweringRedis(),
            _AnsweringDB(),
            200,
            {"status": "ok", "checks": {"redis": "ok", "database": "ok"}},
        ),
        (
            _AnsweringRedis(),
            _FailingDB(),
            503,
            {"status": "unhealthy", "checks": {"redis": "ok", "database": "error"}},
        ),
        (
            _FailingRedis(),
            _AnsweringDB(),
            503,
            {"status": "unhealthy", "checks": {"redis": "error", "database": "ok"}},
        ),
        (
            _FailingRedis(),
            _FailingDB(),
            503,
            {"status": "unhealthy", "checks": {"redis": "error", "database": "error"}},
        ),
    ],
    ids=["healthy", "database-fails", "redis-fails", "both-fail"],
)
async def test_health_and_ready_answer_503_when_a_dependency_fails_and_live_answers_200(
    monkeypatch, caplog, redis, db, status_code, body
):
    caplog.set_level(logging.ERROR, logger="aweb.api")
    app = _app(monkeypatch, redis=redis, db=db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        health = await client.get("/health")
        ready = await client.get("/ready")
        live = await client.get("/live")

    assert (health.status_code, health.json()) == (status_code, body)
    assert (ready.status_code, ready.json()) == (status_code, body)
    assert (live.status_code, live.json()) == (200, {"status": "ok"})
    assert ("Health check failed for Redis" in caplog.text) == (body["checks"]["redis"] == "error")
    assert ("Health check failed for database" in caplog.text) == (body["checks"]["database"] == "error")


@pytest.mark.asyncio
async def test_cached_body_receive_terminates_after_replay():
    receive = _cached_body_receive(b'{"hello":"world"}')

    first = await receive()
    second = await receive()
    third = await receive()

    assert first == {"type": "http.request", "body": b'{"hello":"world"}', "more_body": False}
    assert second == {"type": "http.request", "body": b"", "more_body": False}
    assert third == {"type": "http.request", "body": b"", "more_body": False}
