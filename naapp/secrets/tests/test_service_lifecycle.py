"""Root dependencies exist before routers mount, and share the runtime database."""

from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi import APIRouter

from aweb_secrets.app import create_app
from tests.test_app import API, CONSOLE, InstalledTeams, _settings, allow_all, kms_check


async def test_services_start_before_router_factories_and_cleanup_between_lifespans(
    registry, test_db_factory, tmp_path
):
    database = await test_db_factory.create_db(suffix="root_lifecycle")
    active = []
    closed = []

    @asynccontextmanager
    async def prepare(runtime):
        db = runtime.db()
        assert await db.fetch_value("SELECT 1") == 1
        active.append(db)
        try:
            yield
        finally:
            closed.append(active.pop())

    def human(runtime):
        assert active == [runtime.db()]
        router = APIRouter()

        @router.get("/")
        async def home():
            return {"connected": await active[0].fetch_value("SELECT 1") == 1}

        return router

    service = create_app(
        _settings(database.config.get_dsn(), tmp_path),
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        prepare=prepare,
        console_routers=(human,),
    )
    for _ in range(2):
        async with service.api_app.router.lifespan_context(service.api_app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(service), base_url=CONSOLE
            ) as client:
                assert (await client.get("/")).json() == {"connected": True}
                assert (await client.get(API + "/")).status_code == 404
            assert len([r for r in service.console_app.routes if r.path == "/"]) == 1
        assert active == []
        assert service.runtime.connected_db() is None
        assert not any(r.path == "/" for r in service.console_app.routes)
    assert len(closed) == 2


async def test_failed_service_startup_disconnects_runtime_and_leaves_no_console_routes(
    registry, test_db_factory, tmp_path
):
    database = await test_db_factory.create_db(suffix="root_failure")

    @asynccontextmanager
    async def prepare(runtime):
        assert await runtime.db().fetch_value("SELECT 1") == 1
        raise RuntimeError("required_audit_branch_unavailable")
        yield

    service = create_app(
        _settings(database.config.get_dsn(), tmp_path),
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        prepare=prepare,
    )
    with pytest.raises(RuntimeError, match="required_audit_branch_unavailable"):
        async with service.api_app.router.lifespan_context(service.api_app):
            pytest.fail("A missing required service must refuse startup")
    assert service.runtime.connected_db() is None
    assert not any(r.path == "/" for r in service.console_app.routes)
