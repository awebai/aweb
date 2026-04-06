from __future__ import annotations

import logging

import pytest
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


class _FailingRedis:
    async def ping(self):
        raise RuntimeError("redis://secret@internal-host:6379/0 refused")


class _FailingDB:
    async def fetch_value(self, _query: str):
        raise RuntimeError("postgres://secret@db.internal/aweb refused")


class _DbInfra:
    is_initialized = True

    def get_manager(self, name: str = "aweb"):
        return _FailingDB()


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
