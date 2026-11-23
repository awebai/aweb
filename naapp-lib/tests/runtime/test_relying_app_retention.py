"""A relying app's cache and registry are not kept alive by the app's routes.

FastAPI keeps every route endpoint it has classified; an endpoint that closes
over a test's cache would keep that test's world until the process ends."""

from __future__ import annotations

import gc
import weakref

from awid_service.main import mount_registry
from awid_service.testing import REGISTRY_URL, ServiceTransport
from fastapi import FastAPI

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from tests.runtime.conftest import relying_app

ORIGIN = "https://app.example.com"


async def _exercised_registry_app() -> weakref.ReferenceType[FastAPI]:
    registry_app = FastAPI()
    mount_registry(registry_app)
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=60, transport=ServiceTransport(registry_app)
    )
    async with relying_app(None, public_origin=ORIGIN, cache=cache) as (client, _):
        # No signature: the route runs and refuses before any registry read.
        response = await client.get("/v1/items")
    assert response.status_code == 401, response.text
    return weakref.ref(registry_app)


async def test_a_relying_app_does_not_keep_registry_apps_alive() -> None:
    registry_apps = [await _exercised_registry_app() for _ in range(60)]
    gc.collect()
    assert sum(app() is not None for app in registry_apps) == 0
