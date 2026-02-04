import logging
import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from pgdbm.fixtures.conftest import *  # noqa: F401,F403
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig
from redis.asyncio import Redis as AsyncRedis

from .db_utils import build_database_url

logger = logging.getLogger(__name__)

TEST_REDIS_URL = os.getenv(
    "AWEB_TEST_REDIS_URL", os.getenv("REDIS_URL", "redis://localhost:6379/15")
)


def auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest_asyncio.fixture
async def async_redis() -> AsyncGenerator[AsyncRedis, None]:
    try:
        redis = await AsyncRedis.from_url(TEST_REDIS_URL, decode_responses=True)
        await redis.ping()
    except Exception:
        pytest.skip("Redis is not available")
    await redis.flushdb()
    yield redis
    await redis.flushdb()
    await redis.aclose()


@pytest_asyncio.fixture
async def aweb_db_infra(monkeypatch) -> AsyncGenerator["aweb.db.DatabaseInfra", None]:  # noqa: F405
    from aweb.db import DatabaseInfra as AwebDatabaseInfra

    test_config = DatabaseTestConfig.from_env()
    test_db = AsyncTestDatabase(test_config)
    db_name = await test_db.create_test_database()

    database_url = build_database_url(test_config, db_name)
    monkeypatch.setenv("DATABASE_URL", database_url)

    infra = AwebDatabaseInfra()
    await infra.initialize()

    try:
        yield infra
    finally:
        await infra.close()
        await test_db.drop_test_database()
