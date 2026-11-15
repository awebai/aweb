"""A naapp's team-auth against the AWID release production runs, as
published, in its own process: the envelope tests run unchanged with the
registry swapped for that release."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from aweb_naapp_testing.production_registry import running_production_registry
from awid_service.testing import Registry

from tests.runtime.conftest import relying_app
from tests.runtime.test_team_auth_envelope import (  # noqa: F401  (collected here)
    ORIGIN,
    member,
    test_audience_compares_canonical_origins,
    test_signed_request_yields_the_certified_principal,
)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="naapp_production_awid")
    async with running_production_registry(registry_db.config.get_dsn()) as running:
        yield running


async def test_an_unreadable_production_awid_still_refuses_team_auth(registry, member):  # noqa: F811
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        registry.transport.down = True
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items")
        )
    assert response.status_code == 503, response.text
