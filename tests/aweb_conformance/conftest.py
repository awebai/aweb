from __future__ import annotations

import os
from typing import AsyncIterator

import httpx
import pytest
import pytest_asyncio

from .harness import AwebTarget, bootstrap_target, require_conformance_enabled
from .harness import AwebOtherTarget, maybe_other_target


@pytest.fixture(scope="session", autouse=True)
def _require_enabled() -> None:
    require_conformance_enabled()


@pytest.fixture(scope="session")
def aweb_url() -> str:
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
async def aweb_other_client(aweb_other_target: AwebOtherTarget | None) -> AsyncIterator[httpx.AsyncClient]:
    if aweb_other_target is None:
        pytest.skip("Set AWEB_OTHER_API_KEY/AWEB_OTHER_AGENT_* to run cross-project scoping tests")
    async with httpx.AsyncClient(
        base_url=aweb_other_target.base_url,
        headers={"Authorization": f"Bearer {aweb_other_target.api_key}"},
        timeout=10.0,
    ) as client:
        yield client
