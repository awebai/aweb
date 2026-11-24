"""Staged product migrations for pre-055 chat history tests."""

import pytest_asyncio
from aweb_naapp_contracts.hooks.owner_act_nonces import apply_owner_act_migrations
from tests.product_migration_support import stage_aweb_upgrade

COVERAGE_MIGRATION = "055_chat_conversation_coverage.sql"


@pytest_asyncio.fixture
async def chat_coverage_upgrade(shared_test_pool, tmp_path):
    async with stage_aweb_upgrade(
        shared_test_pool, tmp_path / "chat-coverage-migrations", COVERAGE_MIGRATION
    ) as upgrade:
        await apply_owner_act_migrations(upgrade.infra.get_manager())
        yield upgrade
