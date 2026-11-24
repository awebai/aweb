"""A newly admitted verified global human connects behind a warm certificate list.

Real AWID/aweb HTTP apps, signatures, identity tree, PostgreSQL and Redis.
The global-human case creates authority through signed registry APIs with
UDP DNS and live TCP listeners for both applications.
"""

import asyncio
import json
import os
import socket
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import awid.registry as registry_module
import dns.asyncresolver
import httpx
import pytest
import uvicorn
from aweb_naapp_contracts_testing.network import DnsServer
from awid.dns_verify import DomainAuthority, awid_txt_value
from awid.registry import RegistryClient
from awid_service.deps import get_domain_verifier
from awid_service.main import create_app as create_registry_app
from awid_service.testing import TXTAnswers
from certificate_read_support import scheduled_certificate_readers
from dashboard_test_support import _JWT_SECRET, _make_jwt
from redis.asyncio import Redis
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
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

from aweb.api import _build_awid_registry_client
from aweb.team_key_pins import AdmittedTeamKeys, pinned_team_key
from aweb.testing import running_server

__all__ = ["privacy_app"]


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
        self.point_reads = 0
        self.point_unavailable = False
        self.point_throttled = False
        self.before_standing_read = None

    async def handle_async_request(self, request):
        path = request.url.path
        list_read = request.method == "GET" and path.endswith("/certificates")
        point_read = request.method == "GET" and "/certificates/" in path and path.endswith("/status")
        if list_read or point_read:
            if self.before_standing_read is not None:
                before_read, self.before_standing_read = self.before_standing_read, None
                await before_read()
        if list_read:
            self.reads += 1
        if point_read:
            self.point_reads += 1
            if self.point_unavailable:
                raise httpx.ConnectError("Test registry point route unavailable", request=request)
            if self.point_throttled:
                return httpx.Response(429, headers={"Retry-After": "0"})
        return await super().handle_async_request(request)


@asynccontextmanager
async def _local_admissions(env, monkeypatch):
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    transport = _CountLists()
    domain = "example.test"
    async with registry_listener(env) as (writer, origin):
        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(env.namespace_did, origin, "_awid." + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
        cached = _build_awid_registry_client(env.app, redis=env.redis, transport=transport)
        object.__setattr__(cached, "_domain_verifier", exact_dns)
        env.app.state.awid_registry_client = cached
        client_type = type(cached)
        admit_read = client_type._admit_team_certificate_read
        window_key: str | None = None
        point_admitted = None

        async def observe_admission(client, key, *, allow_point):
            nonlocal window_key
            admission = await admit_read(client, key, allow_point=allow_point)
            if client is cached and allow_point:
                window_key = key
                if point_admitted is not None:
                    await point_admitted(admission)
            return admission

        @asynccontextmanager
        async def point_window(*, after_admission=None):
            nonlocal point_admitted
            key = window_key
            assert key is not None
            # The setup list has already run. Control the next lease transition
            # explicitly while the real Redis script owns every slot decision.
            assert await env.redis.set(key, 0, ex=timedelta(days=1))
            point_admitted = after_admission
            try:
                yield key
            finally:
                point_admitted = None
                await env.redis.delete(key)

        monkeypatch.setattr(client_type, "_admit_team_certificate_read", observe_admission)
        try:
            await cached.list_team_certificates(domain, TEAM_NAME, active_only=False)
            transport.reads = 0
            body = b"{}"

            async def member(alias, *, register=True):
                seed, _, did = _make_keypair()
                cert_id = str(uuid4())
                certificate = _encode_certificate(_make_certificate(
                    env.team_sk, env.team_did, did, team_id=TEAM, alias=alias,
                    identity_scope="local", certificate_id=cert_id,
                ))
                if register:
                    await writer.register_team_certificate(
                        domain, TEAM_NAME, team_controller_signing_key=env.team_sk,
                        certificate_id=cert_id, member_did_key=did, member_did_aw=None,
                        member_address=None, alias=alias, identity_scope="local", certificate=certificate,
                    )
                return cert_id, seed, did, certificate

            async def connect(credential, *, status=200):
                cert_id, seed, did, certificate = credential
                headers = _signed_team_headers(seed, did, TEAM, certificate, body)
                response = await env.client.post(
                    "/v1/connect", content=body, headers={**headers, "Content-Type": "application/json"}, timeout=15,
                )
                assert response.status_code == status, response.text
                if status == 200:
                    row = await env.db.fetch_one(
                        "SELECT certificate_id FROM {{tables.agents}} WHERE agent_id=$1",
                        UUID(response.json()["agent_id"]),
                    )
                    assert row["certificate_id"] == cert_id
                return response.json()

            async def revoke(credential):
                await writer.revoke_team_certificate(
                    domain, TEAM_NAME, team_controller_signing_key=env.team_sk,
                    certificate_id=credential[0],
                )

            async def rotate():
                pin = await AdmittedTeamKeys(env.db).pin(TEAM)
                assert pin is not None and pin.change_time_floor is not None
                # SDK controller acts use whole seconds. Sign after the floor
                # recorded by the live team admission.
                earliest = pin.change_time_floor.replace(microsecond=0) + timedelta(seconds=1)
                delay = (earliest - datetime.now(UTC)).total_seconds()
                if delay > 0:
                    await asyncio.sleep(delay)
                next_key = _make_keypair()[2]
                await writer.rotate_team_key(
                    domain, TEAM_NAME, new_team_did_key=next_key,
                    namespace_controller_signing_key=env.namespace_sk,
                )
                assert await pinned_team_key(
                    db=env.db, registry_client=writer, team_id=TEAM, served_key=next_key,
                    txt_resolver=TXTAnswers({"_awid.example.test": env.namespace_did}),
                ) == next_key

            yield member, connect, revoke, rotate, transport, point_window
        finally:
            await cached.aclose()


@pytest.mark.asyncio
async def test_first_connect_for_members_registered_between_list_reads(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, _, _, transport, point_window):
        await connect(await member("first-member"))
        assert transport.reads == 1
        async with point_window():
            second, third = await asyncio.gather(member("second-member"), member("third-member"))
            await connect(second)
            await connect(third)
            await connect(second)
        assert (transport.reads, transport.point_reads) == (1, 2)


@pytest.mark.asyncio
async def test_unregistered_certificate_reuses_exact_refusal(privacy_app, monkeypatch):  # noqa: F811
    # This case checks reuse of the refusal while it is fresh.
    monkeypatch.setattr(registry_module, "_TEAM_CERTIFICATES_NEGATIVE_TTL_SECONDS", 24 * 60 * 60)
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, revoke, _, transport, point_window):
        await connect(await member("first-member"))
        async with point_window():
            absent = await member("not-registered", register=False)
            for _ in range(2):
                assert (await connect(absent, status=401))["detail"] == "unregistered"
            assert (transport.reads, transport.point_reads) == (1, 1)
            revoked = await member("revoked")
            await revoke(revoked)
            assert (await connect(revoked, status=401))["detail"]["code"] == "certificate_revoked"
            assert (transport.reads, transport.point_reads) == (1, 2)


@pytest.mark.asyncio
async def test_point_budget_overflow_shares_the_next_list(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, _, _, transport, point_window):
        completed = 0
        waiting = 0
        readers_changed = asyncio.Event()
        release_overflow = asyncio.Event()

        async def hold_overflow(admission):
            nonlocal waiting
            if admission > 0:
                waiting += 1
                readers_changed.set()
                await release_overflow.wait()

        async def connect_reader(credential):
            nonlocal completed
            await connect(credential)
            completed += 1
            readers_changed.set()

        await connect(await member("first-member"))
        assert (transport.reads, transport.point_reads) == (1, 0)
        async with point_window(after_admission=hold_overflow) as window_key:
            admitted = await asyncio.gather(*(member(f"member-{i}") for i in range(18)))
            async with scheduled_certificate_readers() as readers:
                for credential in admitted:
                    readers.create_task(connect_reader(credential))
                try:
                    while completed + waiting < len(admitted):
                        readers_changed.clear()
                        await readers_changed.wait()
                    assert (completed, waiting) == (16, 2), "point reads and overflow waiters"
                    assert (transport.reads, transport.point_reads) == (1, 16)
                    # Both overflow readers can now share the next list.
                    assert await privacy_app.redis.delete(window_key) == 1
                finally:
                    release_overflow.set()
        assert (transport.reads, transport.point_reads) == (2, 16)


@pytest.mark.asyncio
async def test_point_read_outage_is_unavailable(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, _, _, transport, point_window):
        await connect(await member("first-member"))
        async with point_window():
            second = await member("second-member")
            transport.point_unavailable = True
            error = await connect(second, status=503)
            assert "AWID certificate existence check" in error["detail"]
            assert (transport.reads, transport.point_reads) == (1, 1)
            transport.point_unavailable = False
            transport.point_throttled = True
            error = await connect(second, status=503)
            assert "upstream rate limited" in error["detail"]
            assert (transport.reads, transport.point_reads) == (1, 2)
            transport.point_throttled = False
            await connect(second)
            assert (transport.reads, transport.point_reads) == (1, 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("slot", ["list", "point"])
@pytest.mark.parametrize("path", ["/v1/connect", "/v1/agents"])
async def test_key_rotation_during_certificate_miss_refuses_both_slots(privacy_app, monkeypatch, path, slot):  # noqa: F811
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    env = privacy_app
    async with (
        _local_admissions(env, monkeypatch) as (member, connect, _, rotate, transport, point_window),
        AsyncExitStack() as stack,
    ):
        if slot == "point":
            await connect(await member("initial"))
            await stack.enter_async_context(point_window())
        previous = await member("rotation-pending")
        before = transport.reads, transport.point_reads
        # Move the pin through the signed controller act while the request
        # that already verified the certificate is waiting for standing.
        transport.before_standing_read = rotate
        if path == "/v1/connect":
            error = await connect(previous, status=401)
        else:
            _, seed, did, certificate = previous
            response = await env.client.get(path, headers=_signed_team_headers(seed, did, TEAM, certificate))
            assert response.status_code == 401, response.text
            error = response.json()
        assert error["detail"]["code"] == "team_key_not_current"
        assert (transport.reads - before[0], transport.point_reads - before[1]) == (
            (1, 0) if slot == "list" else (0, 1)
        )
        assert await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.agents}} WHERE team_id = $1 AND did_key = $2", TEAM, previous[2],
        ) == 0


@pytest.mark.asyncio
async def test_newly_admitted_global_human_connects_behind_warm_strict_list(test_db_factory, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    monkeypatch.setenv("AWEB_DASHBOARD_JWT_SECRET", _JWT_SECRET)
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
        # DNS supplies controller authority; AWID_REGISTRY_URL selects the local registry.
        dns_server.records[(f"_awid.{domain}", "TXT")] = [
            f'"{awid_txt_value(ROOT["did_key"])}"',
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
        agent_sk, _, agent_did = _make_keypair()
        agent_alias = "visible-agent"
        agent_cert_id = f"admission-{uuid4()}"
        agent_certificate = _encode_certificate(_make_certificate(
            team_sk, team_did, agent_did, team_id=team_id, alias=agent_alias,
            identity_scope="local", certificate_id=agent_cert_id,
        ))
        await writer.register_team_certificate(
            domain, team_name, team_controller_signing_key=team_sk,
            certificate_id=agent_cert_id, member_did_key=agent_did,
            member_did_aw=None, member_address=None, alias=agent_alias,
            identity_scope="local", certificate=agent_certificate,
        )
        agent_body = b"{}"
        agent_headers = _signed_team_headers(agent_sk, agent_did, team_id, agent_certificate, agent_body)
        agent = await client.post(
            "/v1/connect", content=agent_body, headers={**agent_headers, "Content-Type": "application/json"},
        )
        assert agent.status_code == 200, agent.text

        cached = server.app.state.awid_registry_client
        before = await cached.list_team_certificates(domain, team_name, active_only=False)
        assert certificate_id not in {cert.certificate_id for cert in before}
        reads_before = transport.reads, transport.point_reads
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
        assert (transport.reads, transport.point_reads) == reads_before
        body = json.dumps({"agent_type": "human"}).encode()
        headers = {**_signed_team_headers(bytes.fromhex(ALICE["seed_hex"]), ALICE["did_key"],
            team_id, certificate, body), "Content-Type": "application/json"}
        response = await client.post("/v1/connect", content=body, headers=headers)
        assert response.status_code == 200, response.text
        # The first miss in a fresh budget window refreshes the full list.
        assert (transport.reads, transport.point_reads) == (reads_before[0] + 1, reads_before[1])
        row = await server.db.get_manager("aweb").fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1",
                                     UUID(response.json()["agent_id"]))
        assert row["certificate_id"] == certificate_id
        assert row["agent_type"] == "human"
        assert row["human_verified_key"] == ALICE["did_key"]
        dashboard = await client.get(
            f"/v1/teams/{team_id}/agents",
            headers={"X-Dashboard-Token": _make_jwt([team_id])},
        )
        assert dashboard.status_code == 200, dashboard.text
        assert {agent["alias"] for agent in dashboard.json()["agents"]} == {agent_alias}

        again = await client.post("/v1/connect", content=body, headers=headers)
        assert again.status_code == 200, again.text
        assert (transport.reads, transport.point_reads) == (reads_before[0] + 1, reads_before[1])
        assert dns_server.queries[(f"_awid.{domain}", "TXT")] > 0
