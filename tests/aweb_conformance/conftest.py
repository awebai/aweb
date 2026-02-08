from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
import time
from typing import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig

from ..db_utils import build_database_url
from .harness import (
    AwebOtherTarget,
    AwebTarget,
    bootstrap_target,
    maybe_other_target,
)

logger = logging.getLogger(__name__)

TEST_SERVER_PORT = 18766
TEST_SERVER_URL = f"http://localhost:{TEST_SERVER_PORT}"
TEST_REDIS_URL = os.getenv("AWEB_TEST_REDIS_URL", "redis://localhost:6379/15")


def _wait_for_server(url: str, timeout: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = httpx.get(f"{url}/health", timeout=1.0)
            if resp.status_code == 200:
                return True
        except httpx.RequestError:
            pass
        time.sleep(0.1)
    return False


async def _create_test_database() -> tuple[AsyncTestDatabase, str, str]:
    test_config = DatabaseTestConfig.from_env()
    test_db = AsyncTestDatabase(test_config)
    db_name = await test_db.create_test_database()
    database_url = build_database_url(test_config, db_name)
    return test_db, db_name, database_url


async def _drop_test_database(db_name: str) -> None:
    test_config = DatabaseTestConfig.from_env()
    test_db = AsyncTestDatabase(test_config)
    test_db._test_db_name = db_name
    await test_db.drop_test_database()


def _kill_stale_server(port: int) -> None:
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                    logger.warning(f"Killed stale process {pid} on port {port}")
                except (ProcessLookupError, ValueError):
                    pass
            time.sleep(0.5)
    except FileNotFoundError:
        pass


def _bootstrap_via_init(base_url: str) -> dict[str, str]:
    """Call /v1/init to create two projects with agents, return env vars dict."""
    env_vars: dict[str, str] = {}

    # Project 1: two agents
    resp1 = httpx.post(
        f"{base_url}/v1/init",
        json={
            "project_slug": "conformance-test",
            "project_name": "Conformance Test",
            "alias": "agent-1",
            "human_name": "Agent One",
            "agent_type": "agent",
        },
        timeout=5.0,
    )
    assert resp1.status_code == 200, f"Init agent-1 failed: {resp1.text}"
    d1 = resp1.json()
    env_vars["AWEB_AGENT_1_API_KEY"] = d1["api_key"]
    env_vars["AWEB_AGENT_1_ID"] = d1["agent_id"]
    env_vars["AWEB_AGENT_1_ALIAS"] = d1["alias"]

    # Second agent in same project — reuse the same project_slug.
    resp2 = httpx.post(
        f"{base_url}/v1/init",
        json={
            "project_slug": "conformance-test",
            "project_name": "Conformance Test",
            "alias": "agent-2",
            "human_name": "Agent Two",
            "agent_type": "agent",
        },
        timeout=5.0,
    )
    assert resp2.status_code == 200, f"Init agent-2 failed: {resp2.text}"
    d2 = resp2.json()
    env_vars["AWEB_AGENT_2_API_KEY"] = d2["api_key"]
    env_vars["AWEB_AGENT_2_ID"] = d2["agent_id"]
    env_vars["AWEB_AGENT_2_ALIAS"] = d2["alias"]

    # Other project (for cross-project isolation tests)
    resp3 = httpx.post(
        f"{base_url}/v1/init",
        json={
            "project_slug": "conformance-other",
            "project_name": "Conformance Other",
            "alias": "other-agent",
            "human_name": "Other Agent",
            "agent_type": "agent",
        },
        timeout=5.0,
    )
    assert resp3.status_code == 200, f"Init other-agent failed: {resp3.text}"
    d3 = resp3.json()
    env_vars["AWEB_OTHER_API_KEY"] = d3["api_key"]
    env_vars["AWEB_OTHER_AGENT_ID"] = d3["agent_id"]
    env_vars["AWEB_OTHER_AGENT_ALIAS"] = d3["alias"]

    return env_vars


@pytest.fixture(scope="session", autouse=True)
def aweb_server():
    """Start a local aweb server if AWEB_URL is not set.

    Creates a test database, starts the server subprocess, seeds via /v1/init,
    and sets the env vars that bootstrap_target reads. When AWEB_URL is already
    set, the fixture is a no-op (use external server).
    """
    if os.getenv("AWEB_URL"):
        yield
        return

    _kill_stale_server(TEST_SERVER_PORT)

    test_db, db_name, database_url = asyncio.run(_create_test_database())

    env = {
        **os.environ,
        "AWEB_DATABASE_URL": database_url,
        "REDIS_URL": TEST_REDIS_URL,
    }

    server_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "aweb.api:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(TEST_SERVER_PORT),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        if not _wait_for_server(TEST_SERVER_URL, timeout=15.0):
            server_proc.terminate()
            try:
                stdout, stderr = server_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                stdout, stderr = server_proc.communicate()
            pytest.fail(
                f"aweb server failed to start.\n"
                f"stdout: {stdout.decode()}\n"
                f"stderr: {stderr.decode()}"
            )

        # Seed via /v1/init and set env vars for bootstrap_target
        os.environ["AWEB_URL"] = TEST_SERVER_URL
        seed_vars = _bootstrap_via_init(TEST_SERVER_URL)
        for k, v in seed_vars.items():
            os.environ[k] = v

        yield TEST_SERVER_URL
    finally:
        server_proc.send_signal(signal.SIGTERM)
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait()

        # Clean up env vars
        for k in [
            "AWEB_URL",
            "AWEB_AGENT_1_API_KEY",
            "AWEB_AGENT_1_ID",
            "AWEB_AGENT_1_ALIAS",
            "AWEB_AGENT_2_API_KEY",
            "AWEB_AGENT_2_ID",
            "AWEB_AGENT_2_ALIAS",
            "AWEB_OTHER_API_KEY",
            "AWEB_OTHER_AGENT_ID",
            "AWEB_OTHER_AGENT_ALIAS",
        ]:
            os.environ.pop(k, None)

        try:
            asyncio.run(_drop_test_database(db_name))
        except Exception as e:
            logger.warning(f"Failed to drop test database {db_name}: {e}")


@pytest.fixture(scope="session")
def aweb_url(aweb_server) -> str:
    url = os.getenv("AWEB_URL", "").strip()
    if not url:
        pytest.skip("Set AWEB_URL to run aweb conformance tests")
    return url.rstrip("/")


@pytest_asyncio.fixture(scope="session")
async def aweb_target(aweb_url: str) -> AwebTarget:
    return await bootstrap_target(aweb_url)


@pytest.fixture(scope="session")
def aweb_other_target(aweb_target: AwebTarget) -> AwebOtherTarget | None:
    return maybe_other_target(aweb_target.base_url)


@pytest_asyncio.fixture
async def aweb_client(aweb_target: AwebTarget) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        base_url=aweb_target.base_url,
        headers={"Authorization": f"Bearer {aweb_target.agent_1_api_key}"},
        timeout=10.0,
    ) as client:
        yield client


@pytest_asyncio.fixture
async def aweb_client_2(aweb_target: AwebTarget) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        base_url=aweb_target.base_url,
        headers={"Authorization": f"Bearer {aweb_target.agent_2_api_key}"},
        timeout=10.0,
    ) as client:
        yield client


@pytest_asyncio.fixture
async def aweb_other_client(
    aweb_other_target: AwebOtherTarget | None,
) -> AsyncIterator[httpx.AsyncClient]:
    if aweb_other_target is None:
        pytest.skip("Set AWEB_OTHER_API_KEY/AWEB_OTHER_AGENT_* to run cross-project scoping tests")
    assert aweb_other_target is not None  # mypy: skip is NoReturn
    async with httpx.AsyncClient(
        base_url=aweb_other_target.base_url,
        headers={"Authorization": f"Bearer {aweb_other_target.api_key}"},
        timeout=10.0,
    ) as client:
        yield client
