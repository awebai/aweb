from __future__ import annotations

import pytest

import awid_service.db as db_module
from awid_service.db import AwidDatabaseInfra


@pytest.mark.asyncio
async def test_service_owned_shared_pool_unpins_search_path(monkeypatch):
    captured_configs = []

    class FakePool:
        async def close(self) -> None:
            pass

    class FakeSettings:
        database_url = "postgresql://registry.example/awid"

    class FakeDatabaseManager:
        def __init__(self, *, pool, schema: str) -> None:
            self.pool = pool
            self.schema = schema

        @classmethod
        async def create_shared_pool(cls, config):
            captured_configs.append(config)
            return FakePool()

        async def execute(self, _query: str) -> None:
            pass

    monkeypatch.setattr(db_module, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(db_module, "AsyncDatabaseManager", FakeDatabaseManager)

    infra = AwidDatabaseInfra(schema="awid")
    await infra.initialize(run_migrations=False)

    assert len(captured_configs) == 1
    assert captured_configs[0].shared_pool_search_path is None
