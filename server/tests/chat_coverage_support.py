"""Staged product migrations for pre-055 chat history tests."""

from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile

import pytest_asyncio
from pgdbm import AsyncMigrationManager

import aweb
from aweb.db import DatabaseInfra
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations

COVERAGE_MIGRATION = "055_chat_conversation_coverage.sql"
MIGRATIONS = Path(aweb.__file__).parent / "migrations" / "aweb"


@dataclass(frozen=True)
class ChatCoverageUpgrade:
    infra: DatabaseInfra
    manager: AsyncMigrationManager
    staged: Path

    async def apply(self) -> list[str]:
        copyfile(MIGRATIONS / COVERAGE_MIGRATION, self.staged / COVERAGE_MIGRATION)
        result = await self.manager.apply_pending_migrations()
        return [migration["filename"] for migration in result["applied"]]


@pytest_asyncio.fixture
async def chat_coverage_upgrade(shared_test_pool, tmp_path):
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=False)
    try:
        db = infra.get_manager()
        staged = tmp_path / "chat-coverage-migrations"
        staged.mkdir()
        for migration in sorted(MIGRATIONS.glob("*.sql")):
            if migration.name < COVERAGE_MIGRATION:
                copyfile(migration, staged / migration.name)
        manager = AsyncMigrationManager(
            db, migrations_path=str(staged), module_name="aweb-aweb"
        )
        await manager.apply_pending_migrations()
        assert set(await manager.get_applied_migrations()) == {
            migration.name for migration in staged.glob("*.sql")
        }
        await apply_owner_act_migrations(db)
        yield ChatCoverageUpgrade(infra, manager, staged)
    finally:
        await infra.close()
