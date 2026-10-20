"""An approval world per test, on its own real PostgreSQL database."""

from __future__ import annotations

import pytest_asyncio

from tests.runtime.approvals.support import World, build_world


@pytest_asyncio.fixture
async def world(test_db_factory) -> World:
    db = await test_db_factory.create_db(suffix="approvals", schema="app")
    return await build_world(db)
