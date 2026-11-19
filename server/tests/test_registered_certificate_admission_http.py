"""A newly admitted verified global human connects behind a warm certificate list.

Real AWID/aweb HTTP apps, signatures, identity tree, PostgreSQL and Redis.
Authority and membership are created through signed registry APIs, not SQL.
DNS TXT authority is served over UDP; both complete applications listen on TCP.
"""
import asyncio
import json
import os
import socket
from contextlib import AsyncExitStack, asynccontextmanager
from uuid import UUID, uuid4

import dns.asyncresolver
import httpx
import pytest
import uvicorn
from aweb.testing import running_server
from aweb_naapp_testing.network import DnsServer
from awid.dns_verify import awid_txt_value
from awid.registry import RegistryClient
from awid_service.main import create_app as create_registry_app
from redis.asyncio import Redis
from test_id_chain_request_auth import (
    ALICE,
    ROOT,
    _fixture_signer,
    _signed_fixture_certificate,
)
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)


@asynccontextmanager
async def _listener(app, sock):
    ready = asyncio.Event()

    class Server(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            ready.set()

    server = Server(uvicorn.Config(app, lifespan="off", log_level="error", ws="none"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        assert server.started, "real HTTP listener did not start"
        yield
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 10)


def _socket(stack):
    sock = stack.enter_context(socket.socket())
    sock.bind(("127.0.0.1", 0))
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


class _CountLists(httpx.AsyncHTTPTransport):
    def __init__(self):
        super().__init__()
        self.reads = 0

    async def handle_async_request(self, request):
        if request.method == "GET" and request.url.path.endswith("/certificates"):
            self.reads += 1
        return await super().handle_async_request(request)


@pytest.mark.asyncio
async def test_newly_admitted_global_human_connects_behind_warm_strict_list(test_db_factory, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    monkeypatch.setenv("AWID_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setenv("AWEB_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.delenv("AWID_RATE_LIMIT_DISABLED", raising=False)
    token = "admission-tests-disposable-service-token"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    domain = f"awtest-admission-{uuid4().hex}.test"
    team_name = "admission"
    team_id = f"{team_name}:{domain}"
    team_sk, _, team_did = _make_keypair()
    certificate_id = f"admission-{uuid4()}"
    async with AsyncExitStack() as stack:
        db = await test_db_factory.create_db(suffix="certificate_admission")
        await db.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
        dsn = db.config.get_dsn()
        monkeypatch.setenv("AWID_DATABASE_URL", dsn)
        monkeypatch.setenv("AWEB_DATABASE_URL", dsn)
        monkeypatch.setenv("AWID_DB_SCHEMA", "admission_registry")
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("AWID_REDIS_URL", redis_url)
        redis = await stack.enter_async_context(Redis.from_url(redis_url, decode_responses=True))
        await redis.ping()
        registry_sock, registry_origin = _socket(stack)
        server_sock, server_origin = _socket(stack)
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
        monkeypatch.setenv("AWID_PUBLIC_ORIGINS", registry_origin)
        dns_server = DnsServer()
        await dns_server.start()
        stack.callback(dns_server.close)
        dns_server.records[(f"_awid.{domain}", "TXT")] = [
            f'"{awid_txt_value(ROOT["did_key"], registry_origin)}"',
        ]
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = dns_server.port
        resolver.timeout = resolver.lifetime = 1
        monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
        registry_app = create_registry_app()
        await stack.enter_async_context(registry_app.router.lifespan_context(registry_app))
        await stack.enter_async_context(_listener(registry_app, registry_sock))
        writer = RegistryClient(registry_origin, service_token=token)
        stack.push_async_callback(writer.aclose)
        transport = _CountLists()
        stack.push_async_callback(transport.aclose)
        await writer.register_did(ALICE["did_key"], bytes.fromhex(ALICE["seed_hex"]))
        await writer.register_namespace(domain, ROOT["did_key"], bytes.fromhex(ROOT["seed_hex"]))
        human = _signed_fixture_certificate("alice", domain=domain, identity=ALICE["did_aw"],
            parent={"kind": "namespace", "id": domain}, issuer="root")
        await writer.register_id_certificate(
            {"v": 1, "type": "aweb.id-chain", "certificates": [human]},
            signer=_fixture_signer("alice"), expected_head=None, invitation_id=None,
        )
        await writer.register_team(
            domain=domain, name=team_name, display_name="Admission test", team_did_key=team_did,
            visibility="public", namespace_controller_signing_key=bytes.fromhex(ROOT["seed_hex"]),
        )
        server = await stack.enter_async_context(running_server(
            dsn, redis, awid_transport=transport, public_origin=server_origin,
        ))
        await stack.enter_async_context(_listener(server.app, server_sock))
        client = await stack.enter_async_context(httpx.AsyncClient(base_url=server_origin, timeout=10))
        cached = server.app.state.awid_registry_client
        before = await cached.list_team_certificates(domain, team_name, active_only=False)
        assert certificate_id not in {cert.certificate_id for cert in before}
        reads_before = transport.reads
        certificate = _encode_certificate(_make_certificate(
            team_sk, team_did, ALICE["did_key"], team_id=team_id, alias="new-human",
            member_did_aw=ALICE["did_aw"], identity_scope="global", certificate_id=certificate_id,
        ))
        await writer.register_team_certificate(
            domain, team_name, team_controller_signing_key=team_sk,
            certificate_id=certificate_id, member_did_key=ALICE["did_key"],
            member_did_aw=ALICE["did_aw"], member_address="", alias="new-human",
            identity_scope="global", certificate=certificate,
        )
        authoritative = await writer.list_team_certificates(domain, team_name, active_only=False)
        admitted = next(cert for cert in authoritative if cert.certificate_id == certificate_id)
        assert admitted.revoked_at is None
        # Independent writer did not invalidate this reader's Redis snapshot.
        still_cached = await cached.list_team_certificates(domain, team_name, active_only=False)
        assert certificate_id not in {cert.certificate_id for cert in still_cached}
        assert transport.reads == reads_before
        body = json.dumps({"agent_type": "human"}).encode()
        headers = {**_signed_team_headers(bytes.fromhex(ALICE["seed_hex"]), ALICE["did_key"],
            team_id, certificate, body), "Content-Type": "application/json"}
        response = await client.post("/v1/connect", content=body, headers=headers)
        assert response.status_code == 200, response.text
        assert transport.reads == reads_before + 1
        row = await server.db.get_manager("aweb").fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1",
                                     UUID(response.json()["agent_id"]))
        assert row["certificate_id"] == certificate_id
        assert row["agent_type"] == "human"
        assert row["human_verified_key"] == ALICE["did_key"]
        again = await client.post("/v1/connect", content=body, headers=headers)
        assert again.status_code == 200, again.text
        assert transport.reads == reads_before + 1
        assert dns_server.queries[(f"_awid.{domain}", "TXT")] > 0
