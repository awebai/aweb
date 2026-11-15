"""Owner-act delivery against the AWID release production runs, as
published, in its own process: the router tests run unchanged with the
coordination's registry swapped for that release."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from aweb_naapp_testing.production_registry import running_production_registry
from awid_service.testing import Registry

from tests.runtime.test_owner_act_router import (  # noqa: F401  (collected here)
    human,
    registry,
    test_designation_commits_nonce_effect_and_outbox_once,
    test_revoke_needs_no_principal_membership_and_refuses_a_carried_certificate,
    world,
)

pytest_plugins = ("tests.runtime.test_human_member",)


@pytest_asyncio.fixture
async def coordination_registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="owner_acts_production_awid")
    async with running_production_registry(registry_db.config.get_dsn()) as running:
        yield running


async def test_an_unreadable_production_awid_still_refuses_owner_act_delivery(world):  # noqa: F811
    before = await world.counts()
    world.coordination.registry.transport.down = True
    response = await world.post(world.body())
    assert response.status_code == 503, response.text
    assert await world.counts() == before
