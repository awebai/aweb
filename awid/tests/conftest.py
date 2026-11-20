from __future__ import annotations

import os
import base64
import hashlib
import json
from types import SimpleNamespace

import httpx
from redis.asyncio import Redis
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pgdbm import AsyncDatabaseManager

from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from awid.db_config import build_database_config
from awid.dns_verify import DomainAuthority

from awid_service.db import AwidDatabaseInfra
from awid_service.deps import get_domain_verifier
from awid_service.main import create_app

pytest_plugins = ("awid_service.testing_postgres",)

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


def build_signed_headers(signing_key, did_key, *, domain, operation, **extra):
    """Build DIDKey Authorization + Timestamp headers for a signed request."""
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {"domain": domain, "operation": operation, "timestamp": ts}
    payload.update(extra)
    sig = sign_message(signing_key, canonical_json_bytes(payload))
    return {
        "Authorization": f"DIDKey {did_key} {sig}",
        "X-AWEB-Timestamp": ts,
    }


class ManualClock:
    """A settable UTC clock for the identity tree's post-lock witness times."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def manual_clock() -> ManualClock:
    return ManualClock(datetime(2026, 10, 26, 0, 0, 0, tzinfo=timezone.utc))


@pytest_asyncio.fixture
async def clocked_client(awid_db_infra, fake_redis, fake_domain_verifier, manual_clock):
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier
    app.state.id_tree_clock = manual_clock
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            test_client.app = app
            yield test_client


CONTROLLER_ORIGIN = 'http://registry.test'
CONTROLLER_REQUEST_TYPE = 'aweb.awid-controller-request'


def controller_keypair():
    key, public = generate_keypair()
    return key, did_from_public_key(public)


def controller_request_headers(key, did, claims, method, path, body=b'', *, covering=True, overrides=None, parent=False):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {**claims, 'timestamp': timestamp}
    if covering:
        payload.update(v=2, type=CONTROLLER_REQUEST_TYPE, aud=CONTROLLER_ORIGIN, method=method, path=path, body_sha256=hashlib.sha256(body).hexdigest())
    payload.update(overrides or {})
    canonical = canonical_json_bytes(payload)
    prefix = 'X-AWEB-Parent-' if parent else 'X-AWEB-'
    result = {
        'X-AWEB-Parent-Authorization' if parent else 'Authorization': f'DIDKey {did} {sign_message(key, canonical)}',
        prefix + 'Timestamp': timestamp,
    }
    if covering:
        result[prefix + 'Signed-Payload'] = base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()
    return result


async def send_controller_request(env, method, path, claims, body=None, *, signer=None, covering=True, overrides=None):
    content = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode() if body is not None else b''
    key, did = signer or env.controller
    signed = controller_request_headers(key, did, claims, method, path, content, covering=covering, overrides=overrides)
    return await env.client.request(method, path, content=content, headers={**signed, 'Content-Type': 'application/json'})


@pytest_asyncio.fixture
async def controller_app(awid_db_infra):
    # Real limiter and isolated client-IP bucket; remove only this fixture's keys.
    ip = '127.' + '.'.join(str(n) for n in os.urandom(3))
    async with Redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'), decode_responses=True) as redis:
        await redis.ping()
        app = create_app(db_infra=awid_db_infra, redis=redis)
        app.state.awid_public_origins = (CONTROLLER_ORIGIN,)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 12345)), base_url=CONTROLLER_ORIGIN) as client:
                env = SimpleNamespace(app=app, client=client, db=awid_db_infra.get_manager(), controller=controller_keypair(), team=controller_keypair())
                response = await send_controller_request(env, 'POST', '/v1/namespaces', {'domain': 'local', 'operation': 'register'}, {'domain': 'local'}, covering=False)
                assert response.status_code == 200, response.text
                response = await send_controller_request(env, 'POST', '/v1/namespaces/local/teams', {'domain': 'local', 'operation': 'create_team', 'name': 'base'}, {'name': 'base', 'team_did_key': env.team[1], 'visibility': 'public'}, covering=False)
                assert response.status_code == 200, response.text
                try:
                    yield env
                finally:
                    owned = [key async for key in redis.scan_iter(match=f'aweb:rl:*:{ip}:*')]
                    if owned:
                        await redis.delete(*owned)
