import gc
import weakref

import httpx
import pytest
from awid.ratelimit import NoOpRateLimiter
from awid_service.deps import get_domain_verifier
from awid_service.main import mount_registry
from awid_service.testing import REGISTRY_URL, Registry, ServiceTransport
from fastapi import FastAPI
from pgdbm import AsyncDatabaseManager, DatabaseConfig


async def _exercised_registry_app() -> weakref.ReferenceType[FastAPI]:
    app = FastAPI()
    app.state.db = None
    app.state.rate_limiter = NoOpRateLimiter()
    mount_registry(app)
    registry = Registry(
        app=app,
        db=AsyncDatabaseManager(DatabaseConfig()),
        transport=ServiceTransport(app),
    )
    registry._install_namespace_verifier()
    assert get_domain_verifier in app.dependency_overrides
    # The real route resolves its dependencies before rejecting the invalid body.
    # No database or network connection is needed to exercise callable caching.
    async with httpx.AsyncClient(transport=registry.transport, base_url=REGISTRY_URL) as client:
        response = await client.post("/v1/namespaces", json={})
    assert response.status_code == 422, response.text
    return weakref.ref(app)


@pytest.mark.asyncio
async def test_namespace_verifier_does_not_keep_registry_apps_alive():
    apps = [await _exercised_registry_app() for _ in range(60)]
    gc.collect()
    assert sum(app() is not None for app in apps) == 0
