from __future__ import annotations

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pgdbm import AsyncDatabaseManager

from aweb.awid.did import did_from_public_key, generate_keypair
from aweb.db_config import build_database_config
from aweb.deps import get_domain_verifier
from aweb.dns_verify import DomainAuthority

from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app

pytest_plugins = ("pgdbm.fixtures.conftest",)

os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("AWID_LOG_JSON", "false")
os.environ.setdefault("AWID_RATE_LIMIT_BACKEND", "redis")
os.environ.setdefault("AWID_DATABASE_URL", "postgresql://unused/test")


class FakeRedis:
    def __init__(self) -> None:
        self.eval_calls: list[tuple[tuple, tuple]] = []
        self._counts: dict[str, int] = {}

    async def ping(self) -> bool:
        return True

    async def eval(self, script, numkeys, key, ttl):
        self.eval_calls.append(((script, numkeys, key, ttl), ()))
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        return current

    async def aclose(self) -> None:
        return None


@pytest.fixture
def fake_redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture
def controller_identity():
    signing_key, public_key = generate_keypair()
    return signing_key, did_from_public_key(public_key)


@pytest.fixture
def fake_domain_verifier(controller_identity):
    _signing_key, did_key = controller_identity

    async def _verify_domain(domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=did_key,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}",
        )

    return _verify_domain


@pytest_asyncio.fixture
async def shared_test_pool(test_db_factory):
    db_manager = await test_db_factory.create_db(suffix="awid_service")
    config = build_database_config(
        connection_string=db_manager.config.get_dsn(),
        min_connections=2,
        max_connections=5,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    try:
        yield pool
    finally:
        await pool.close()


@pytest_asyncio.fixture
async def awid_db_infra(shared_test_pool):
    infra = AwidDatabaseInfra(schema="awid")
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        yield infra
    finally:
        await infra.close()


@pytest_asyncio.fixture
async def client(awid_db_infra, fake_redis, fake_domain_verifier):
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            yield test_client
