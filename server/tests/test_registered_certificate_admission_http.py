"""A newly admitted verified global human connects behind a warm certificate list.

Real AWID/aweb HTTP apps, signatures, identity tree, PostgreSQL and Redis.
Only DNS selects the disposable registry authority, as in the human-kind tests.
"""
import asyncio
import json
from contextlib import asynccontextmanager
from time import monotonic
from uuid import UUID, uuid4

import httpx
import pytest
from aweb.api import _build_awid_registry_client
from aweb.team_key_pins import pinned_team_key
from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from awid_service.testing import TXTAnswers
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_id_chain_request_auth import ALICE, ROOT, _fixture_signer, _signed_fixture_certificate
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair, _signed_team_headers


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
            return DomainAuthority(env.team_did, origin, "_awid." + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
        cached = _build_awid_registry_client(env.app, redis=env.redis, transport=transport)
        object.__setattr__(cached, "_domain_verifier", exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            await writer.register_namespace(domain, env.team_did, env.team_sk)
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
                next_key = _make_keypair()[2]
                await writer.rotate_team_key(
                    domain, TEAM_NAME, new_team_did_key=next_key,
                    namespace_controller_signing_key=env.team_sk,
                )
                assert await pinned_team_key(
                    db=env.db, registry_client=writer, team_id=TEAM, served_key=next_key,
                    txt_resolver=TXTAnswers({"_awid.example.test": env.team_did}),
                ) == next_key

            yield member, connect, revoke, rotate, transport
        finally:
            await cached.aclose()


@pytest.mark.asyncio
async def test_first_connect_for_members_registered_between_list_reads(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, _, _, transport):
        admitted = monotonic()
        await connect(await member("first-member"))
        assert transport.reads == 1
        second, third = await asyncio.gather(member("second-member"), member("third-member"))
        assert monotonic() - admitted < 1
        await connect(second)
        await connect(third)
        await connect(second)
        assert monotonic() - admitted < 5
        assert (transport.reads, transport.point_reads) == (1, 2)


@pytest.mark.asyncio
async def test_unregistered_certificate_reuses_exact_refusal(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, revoke, _, transport):
        await connect(await member("first-member"))
        absent = await member("not-registered", register=False)
        for _ in range(2):
            assert (await connect(absent, status=401))["detail"] == "unregistered"
        assert (transport.reads, transport.point_reads) == (1, 1)
        revoked = await member("revoked")
        await revoke(revoked)
        assert (await connect(revoked, status=401))["detail"] == "revoked"
        assert (transport.reads, transport.point_reads) == (1, 2)


@pytest.mark.asyncio
async def test_point_budget_overflow_shares_the_next_list(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, _, _, transport):
        await connect(await member("first-member"))
        admitted = await asyncio.gather(*(member(f"member-{i}") for i in range(18)))
        await asyncio.gather(*(connect(credential) for credential in admitted))
        assert (transport.reads, transport.point_reads) == (2, 16)


@pytest.mark.asyncio
async def test_point_read_outage_is_unavailable(privacy_app, monkeypatch):  # noqa: F811
    async with _local_admissions(privacy_app, monkeypatch) as (member, connect, _, _, transport):
        await connect(await member("first-member"))
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
    async with _local_admissions(env, monkeypatch) as (member, connect, _, rotate, transport):
        if slot == "point":
            await connect(await member("initial"))
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
async def test_newly_admitted_global_human_connects_behind_warm_strict_list(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    domain = f"awtest-admission-{uuid4().hex}.test"
    certificate_id = f"admission-{uuid4()}"
    transport = _CountLists()
    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(ROOT["did_key"], origin, "_awid." + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
        cached = _build_awid_registry_client(env.app, redis=env.redis, transport=transport)
        object.__setattr__(cached, "_domain_verifier", exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            await writer.register_did(ALICE["did_key"], bytes.fromhex(ALICE["seed_hex"]))
            await writer.register_namespace(domain, ROOT["did_key"], bytes.fromhex(ROOT["seed_hex"]))
            human = _signed_fixture_certificate("alice", domain=domain, identity=ALICE["did_aw"],
                parent={"kind": "namespace", "id": domain}, issuer="root")
            await writer.register_id_certificate(
                {"v": 1, "type": "aweb.id-chain", "certificates": [human]},
                signer=_fixture_signer("alice"), expected_head=None, invitation_id=None,
            )
            # Namespace authority for the existing fixture team, not the ID-tree domain.
            await env.registry_db.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) "
                "VALUES ('example.test', $1, 'verified')", env.team_did,
            )
            before = await cached.list_team_certificates("example.test", TEAM_NAME, active_only=False)
            assert certificate_id not in {cert.certificate_id for cert in before}
            reads_before = transport.reads
            certificate = _encode_certificate(_make_certificate(
                env.team_sk, env.team_did, ALICE["did_key"], team_id=TEAM, alias="new-human",
                member_did_aw=ALICE["did_aw"], identity_scope="global", certificate_id=certificate_id,
            ))
            await writer.register_team_certificate(
                "example.test", TEAM_NAME, team_controller_signing_key=env.team_sk,
                certificate_id=certificate_id, member_did_key=ALICE["did_key"],
                member_did_aw=ALICE["did_aw"], member_address="", alias="new-human",
                identity_scope="global", certificate=certificate,
            )
            authoritative = await writer.list_team_certificates("example.test", TEAM_NAME, active_only=False)
            admitted = next(cert for cert in authoritative if cert.certificate_id == certificate_id)
            assert admitted.revoked_at is None
            # Independent writer did not invalidate this reader's Redis snapshot.
            still_cached = await cached.list_team_certificates("example.test", TEAM_NAME, active_only=False)
            assert certificate_id not in {cert.certificate_id for cert in still_cached}
            assert transport.reads == reads_before
            body = json.dumps({"agent_type": "human"}).encode()
            headers = {**_signed_team_headers(bytes.fromhex(ALICE["seed_hex"]), ALICE["did_key"],
                TEAM, certificate, body), "Content-Type": "application/json"}
            response = await env.client.post("/v1/connect", content=body, headers=headers)
            assert response.status_code == 200, response.text
            assert transport.reads == reads_before + 1
            row = await env.db.fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1",
                                         UUID(response.json()["agent_id"]))
            assert row["certificate_id"] == certificate_id
            assert row["agent_type"] == "human"
            assert row["human_verified_key"] == ALICE["did_key"]
            again = await env.client.post("/v1/connect", content=body, headers=headers)
            assert again.status_code == 200, again.text
            assert transport.reads == reads_before + 1
        finally:
            await cached.aclose()
