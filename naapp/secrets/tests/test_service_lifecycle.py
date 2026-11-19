"""A failing public prepare hook disconnects its already-connected runtime."""

from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp.runtime.db import ApplyMigrations

from aweb_secrets.app import create_app
from tests.test_app import CONSOLE, InstalledTeams, _settings, allow_all, kms_check


async def test_failed_service_startup_disconnects_runtime_and_leaves_no_console_routes(
    registry, test_db_factory, tmp_path
):
    database = await test_db_factory.create_db(suffix="root_failure")

    @asynccontextmanager
    async def prepare(runtime):
        assert await runtime.db().fetch_value("SELECT 1") == 1
        raise RuntimeError("required_audit_branch_unavailable")
        # asynccontextmanager requires a generator even when entry always fails.
        yield

    service = create_app(
        _settings(database.config.get_dsn(), tmp_path),
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        prepare=prepare,
        schema_preparation=ApplyMigrations(),
    )
    with pytest.raises(RuntimeError, match="required_audit_branch_unavailable"):
        async with service.api_app.router.lifespan_context(service.api_app):
            pytest.fail("A missing required service must refuse startup")
    assert service.runtime.connected_db() is None
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(service), base_url=CONSOLE
    ) as client:
        assert (await client.get("/")).status_code == 404
