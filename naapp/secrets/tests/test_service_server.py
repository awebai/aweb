"""Owned TCP/TLS lifecycles, including the real production Secrets constructor."""

import asyncio
import secrets
import socket
import ssl
from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp_testing.network import make_certificates
from aweb_naapp_testing.smtp import SmtpServer
from fastapi import FastAPI, Request
from service_server import Listener, ServiceServerError, serving

from aweb_secrets.composition import create_service
from tests.test_composition import settings


def no_owned_tasks():
    assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("s19-")]


@pytest.fixture
def tls(tmp_path):
    return make_certificates(tmp_path, ["localhost"], ["127.0.0.1"])


async def test_two_tls_listeners_share_one_factory_and_one_lifespan(tls):
    calls = {"factory": 0, "start": 0, "stop": 0}

    @asynccontextmanager
    async def lifespan(app):
        calls["start"] += 1
        try:
            yield {"start_count": calls["start"]}
        finally:
            calls["stop"] += 1

    app = FastAPI(lifespan=lifespan)

    @app.get("/probe")
    async def probe(request: Request):
        return {"starts": request.state.start_count}

    def factory(ports):
        calls["factory"] += 1
        assert len(ports) == 2 and ports[0] != ports[1]
        return app

    async with serving(
        factory,
        listeners=(Listener("127.0.0.1", 0), Listener("127.0.0.1", 0)),
        certificates=tls,
    ) as running:
        assert running.app is app
        async with httpx.AsyncClient(
            verify=ssl.create_default_context(cafile=tls.ca_file),
            trust_env=False,
        ) as client:
            for port in running.ports:
                response = await client.get(f"https://127.0.0.1:{port}/probe")
                assert response.json() == {"starts": 1}
        assert calls == {"factory": 1, "start": 1, "stop": 0}
    assert calls == {"factory": 1, "start": 1, "stop": 1}
    for port in running.ports:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
    no_owned_tasks()


async def test_startup_timeout_cancels_and_joins_the_owned_lifespan():
    entered, cleaned = asyncio.Event(), asyncio.Event()

    @asynccontextmanager
    async def lifespan(app):
        entered.set()
        try:
            await asyncio.Event().wait()
            yield
        finally:
            cleaned.set()

    with pytest.raises(ServiceServerError) as refused:
        async with serving(
            lambda ports: FastAPI(lifespan=lifespan),
            listeners=(Listener("127.0.0.1", 0),),
            startup_timeout=0.1,
        ):
            raise AssertionError("unready app was published")
    assert refused.value.code == "service_startup_failed"
    assert entered.is_set() and cleaned.is_set()
    no_owned_tasks()


async def test_startup_error_does_not_retain_or_log_the_apps_exception(capfd, caplog):
    private = secrets.token_urlsafe(24)

    @asynccontextmanager
    async def lifespan(app):
        raise RuntimeError(private)
        yield

    with pytest.raises(ServiceServerError) as refused:
        async with serving(
            lambda ports: FastAPI(lifespan=lifespan),
            listeners=(Listener("127.0.0.1", 0),),
        ):
            raise AssertionError("failed app was published")
    assert refused.value.code == "service_startup_failed"
    assert private not in str(refused.value)
    captured = capfd.readouterr()
    assert private not in captured.out + captured.err + caplog.text
    no_owned_tasks()


async def test_caller_failure_still_shuts_down_the_started_app():
    cleaned = asyncio.Event()

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            cleaned.set()

    with pytest.raises(LookupError):
        async with serving(
            lambda ports: FastAPI(lifespan=lifespan),
            listeners=(Listener("127.0.0.1", 0),),
        ):
            raise LookupError("caller failure")
    assert cleaned.is_set()
    no_owned_tasks()


@pytest.mark.parametrize("fault", ["timeout", "exception"])
async def test_shutdown_failure_is_bounded_sanitized_and_reaps_its_tasks(fault, caplog):
    cleaned = asyncio.Event()
    private = secrets.token_urlsafe(24)

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
            if fault == "exception":
                raise RuntimeError(private)
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    with pytest.raises(ServiceServerError) as refused:
        async with serving(
            lambda ports: FastAPI(lifespan=lifespan),
            listeners=(Listener("127.0.0.1", 0),),
            shutdown_timeout=0.1,
        ):
            pass
    assert refused.value.code == "service_shutdown_failed"
    assert cleaned.is_set()
    assert private not in str(refused.value) + caplog.text
    no_owned_tasks()


async def test_bind_failure_never_constructs_an_app():
    calls = []
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        with pytest.raises(ServiceServerError) as refused:
            async with serving(
                lambda ports: calls.append(ports),
                listeners=(
                    Listener("127.0.0.1", 0),
                    Listener("127.0.0.1", occupied.getsockname()[1]),
                ),
            ):
                raise AssertionError("occupied listener was published")
    assert refused.value.code == "service_bind_failed"
    assert calls == []
    no_owned_tasks()


async def test_actual_production_root_serves_both_tls_origins_once(
    test_db_factory,
    registry,
    tmp_path,
    tls,
):
    database = await test_db_factory.create_db(suffix="s19_real_startup")
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(24)) as smtp:
        configured = settings(database, tmp_path, smtp)

        def factory(ports):
            return create_service(
                configured.model_copy(
                    update={
                        "public_origin": f"https://127.0.0.1:{ports[0]}",
                        "console_origin": f"https://localhost:{ports[1]}",
                    }
                ),
                awid_transport=registry.transport,
            )

        async with serving(
            factory,
            listeners=(Listener("127.0.0.1", 0), Listener("127.0.0.1", 0)),
            certificates=tls,
        ) as running:
            service = running.app
            assert service.runtime.connected_db() is not None
            async with httpx.AsyncClient(
                verify=ssl.create_default_context(cafile=tls.ca_file),
                trust_env=False,
            ) as client:
                api, human = (
                    f"https://127.0.0.1:{running.ports[0]}",
                    f"https://localhost:{running.ports[1]}",
                )
                assert (await client.get(api + "/health")).json()["checks"]["kms"]["ok"]
                assert (await client.get(human + "/enrolment")).status_code == 200
                assert (await client.get(api + "/enrolment")).status_code == 404
                assert (await client.get(human + "/")).status_code == 303
                assert (await client.get(api + "/v1/secrets")).status_code == 401
        assert service.runtime.connected_db() is None
    no_owned_tasks()
