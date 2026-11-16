"""Secrets' owner acts through its production delivery route, against the AWID
release production runs, as published, in its own process.

The owner-delivery tests run unchanged with the registry they read swapped for
that release.
"""

from collections.abc import AsyncIterator

import pytest_asyncio
from aweb_naapp_testing.production_registry import running_production_registry
from awid_service.testing import Registry

from tests.test_owner_delivery import (  # noqa: F401  (collected here)
    pytestmark,
    test_controller_revoke_ends_the_holding_and_moves_the_revision,
    test_first_owner_is_designated_by_controller_act_and_can_log_in,
    test_replay_does_not_repeat_the_revision_or_governance_effect,
)
from tests.test_production_bootstrap import root as root


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="secrets_production_awid")
    async with running_production_registry(registry_db.config.get_dsn()) as running:
        yield running
