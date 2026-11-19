"""Logs' owner acts through its production reader service, against the AWID
release production runs, as published, in its own process.

The reader-service tests run unchanged with the coordination's registry swapped
for that release.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from aweb_naapp_testing.production_registry import running_production_registry
from awid_service.testing import Registry

from .test_reader_service import (  # noqa: F401  (collected here)
    deployment,
    test_a_member_removes_a_reader_but_never_the_last,
    test_an_owner_designated_reader_logs_in_with_its_bound_passkey_and_reads,
)


@pytest_asyncio.fixture
async def coordination_registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="logs_production_awid")
    async with running_production_registry(registry_db.config.get_dsn()) as running:
        yield running
