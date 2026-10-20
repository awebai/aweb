"""Shared fixtures: a real PostgreSQL database per test through pgdbm."""

from __future__ import annotations

import pytest_asyncio
from approvals_support import World, build_world

pytest_plugins = ("pgdbm.fixtures.conftest",)


@pytest_asyncio.fixture
async def world(test_db_factory) -> World:
    db = await test_db_factory.create_db(suffix="approvals", schema="app")
    return await build_world(db)
