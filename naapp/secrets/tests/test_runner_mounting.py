"""The real root mounts runner adapters after preparation, outside member B1."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import pytest
from fastapi import APIRouter
from nacl.signing import SigningKey

from aweb_secrets.app import create_app
from aweb_secrets.runner_routes import runner_registration_router
from aweb_secrets.runners import apply_runner_migrations, create_runner
from tests.test_app import API, CONSOLE, InstalledTeams, _settings, allow_all, kms_check
from tests.test_runners import keys, record


async def test_runner_code_exchange_is_api_only_and_lives_with_prepared_services(
    registry, test_db_factory, tmp_path
):
    database = await test_db_factory.create_db(suffix="runner_root")
    active, closed = [], []
    service_key = SigningKey.generate()
    registration = {}

    @asynccontextmanager
    async def prepare(runtime):
        db = runtime.db()
        await apply_runner_migrations(db)
        runner = record()
        async with db.transaction() as tx:
            code = await create_runner(
                tx, "install-one", "team:acme.test", runner, now=datetime.now(UTC)
            )
        registration.update(runner_id=runner.runner_id, code=code)
        active.append(db)
        try:
            yield
        finally:
            closed.append(active.pop())

    def runner_factory(runtime):
        assert active == [runtime.db()]
        return runner_registration_router(db=runtime.db, origin=API, service_key=service_key)

    service = create_app(
        _settings(database.config.get_dsn(), tmp_path),
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        prepare=prepare,
        runner_routers=(runner_factory,),
    )
    for _ in range(2):
        async with service.api_app.router.lifespan_context(service.api_app):
            signing, encryption = keys()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(service), base_url=API
            ) as client:
                registered = await client.post(
                    "/runner/v1/register",
                    json={
                        "code": registration["code"],
                        "signing_key": signing,
                        "encryption_key": encryption,
                    },
                )
                assert registered.status_code == 200
                assert registered.json()["runner_id"] == registration["runner_id"]
                assert registered.headers["Cache-Control"] == "no-store"
                assert "set-cookie" not in registered.headers
                assert (
                    await client.post(CONSOLE + "/runner/v1/register", json={})
                ).status_code == 404
                assert (
                    await client.post("/v1/secrets/example/requests", json={})
                ).status_code == 401
                assert (
                    await client.post(
                        "/runner/v1/register",
                        json={
                            "code": registration["code"],
                            "signing_key": signing,
                            "encryption_key": encryption,
                        },
                    )
                ).status_code == 401
        assert active == []
        assert service.runtime.connected_db() is None
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(service), base_url=API
        ) as client:
            assert (await client.post("/runner/v1/register", json={})).status_code == 404
    assert len(closed) == 2


@pytest.mark.parametrize("kind", ["member-path", "non-http", "method", "duplicate"])
async def test_runner_factory_misconfiguration_refuses_before_serving(
    registry, test_db_factory, tmp_path, kind
):
    database = await test_db_factory.create_db(suffix="runner_root_invalid")

    def factory(runtime):
        assert runtime.db() is not None
        router = APIRouter()
        if kind == "non-http":

            @router.websocket("/runner/v1/socket")
            async def socket_route(websocket):
                await websocket.accept()
        else:
            path = "/v1/jobs/{job}/runs" if kind == "member-path" else "/runner/v1/claim"

            async def endpoint():
                return {}

            router.add_api_route(path, endpoint, methods=["GET" if kind == "method" else "POST"])

        return router

    service = create_app(
        _settings(database.config.get_dsn(), tmp_path),
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        runner_routers=(factory, factory) if kind == "duplicate" else (factory,),
    )
    with pytest.raises(ValueError):
        async with service.api_app.router.lifespan_context(service.api_app):
            pytest.fail("Invalid runner mounting must refuse startup")
    assert service.runtime.connected_db() is None
    async with httpx.AsyncClient(transport=httpx.ASGITransport(service), base_url=API) as client:
        assert (await client.post("/runner/v1/claim", json={})).status_code == 404
