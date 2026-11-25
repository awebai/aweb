"""Embedded real services must leave the host's logging configuration intact."""

from __future__ import annotations

from contextlib import contextmanager
import logging
import os

from awid_service.main import create_app as create_registry
from awid_service.testing import REGISTRY_URL, running_registry
from httpx import ASGITransport, AsyncClient
import pytest
from redis.asyncio import Redis

from aweb.testing import running_server


@contextmanager
def host_logging(caplog):
    caplog.set_level(logging.WARNING)
    root = logging.getLogger()
    handlers = root.handlers[:]
    try:
        yield root, handlers
    finally:
        # A failed regression on old code must not poison subsequent tests.
        root.handlers[:] = handlers
        root.setLevel(logging.WARNING)


def assert_host_logging(root, handlers, caplog):
    assert root.level == logging.WARNING
    assert root.handlers == handlers
    logging.getLogger("embedding_host").warning(
        "Host warning after embedded service startup"
    )
    assert "Host warning after embedded service startup" in [
        record.getMessage() for record in caplog.records
    ]


@pytest.mark.asyncio
async def test_embedded_aweb_preserves_host_level_handlers_and_warning_capture(
    test_db_factory, monkeypatch, caplog
):
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWEB_LOG_LEVEL", "error")
    monkeypatch.setenv("AWID_REGISTRY_URL", REGISTRY_URL)
    registry_db = await test_db_factory.create_db(suffix="host_logging_awid")
    server_db = await test_db_factory.create_db(suffix="host_logging_aweb")
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
    ) as redis:
        async with running_registry(
            registry_db.config.get_dsn(), redis=redis
        ) as registry:
            with host_logging(caplog) as (root, handlers):
                async with running_server(
                    server_db.config.get_dsn(), redis, awid_transport=registry.transport
                ) as server:
                    async with server.client() as client:
                        assert (await client.get("/health")).status_code == 200
                    assert_host_logging(root, handlers, caplog)
                assert root.level == logging.WARNING
                assert root.handlers == handlers


@pytest.mark.asyncio
async def test_embedded_awid_preserves_host_level_handlers_and_warning_capture(
    test_db_factory, monkeypatch, caplog
):
    db = await test_db_factory.create_db(suffix="host_logging_registry")
    monkeypatch.setenv("AWID_DATABASE_URL", db.config.get_dsn())
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
    ) as redis:
        async with running_registry(db.config.get_dsn(), redis=redis) as registry:
            app = create_registry(db_infra=registry.app.state.db, redis=redis)
            with host_logging(caplog) as (root, handlers):
                async with app.router.lifespan_context(app):
                    async with AsyncClient(
                        transport=ASGITransport(app), base_url=REGISTRY_URL
                    ) as client:
                        assert (await client.get("/health")).status_code == 200
                    assert_host_logging(root, handlers, caplog)
                assert root.level == logging.WARNING
                assert root.handlers == handlers
