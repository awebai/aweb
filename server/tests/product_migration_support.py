"""Stage one real aweb schema migration on an isolated test manager."""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile

from pgdbm import AsyncMigrationManager

import aweb
from aweb.db import DatabaseInfra

MIGRATIONS = Path(aweb.__file__).parent / "migrations" / "aweb"


@dataclass(frozen=True)
class StagedAwebUpgrade:
    infra: DatabaseInfra
    manager: AsyncMigrationManager
    staged: Path
    target: str

    async def apply(self) -> list[str]:
        copyfile(MIGRATIONS / self.target, self.staged / self.target)
        result = await self.manager.apply_pending_migrations()
        return [migration["filename"] for migration in result["applied"]]


@asynccontextmanager
async def stage_aweb_upgrade(shared_pool, staged: Path, target: str):
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=shared_pool, run_migrations=False)
    try:
        staged.mkdir()
        for migration in sorted(MIGRATIONS.glob("*.sql")):
            if migration.name < target:
                copyfile(migration, staged / migration.name)
        manager = AsyncMigrationManager(
            infra.get_manager(), migrations_path=str(staged), module_name="aweb-aweb"
        )
        await manager.apply_pending_migrations()
        assert set(await manager.get_applied_migrations()) == {
            migration.name for migration in staged.glob("*.sql")
        }
        yield StagedAwebUpgrade(infra, manager, staged, target)
    finally:
        await infra.close()
