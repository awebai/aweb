"""A newly admitted verified global human connects behind a warm certificate list.

Real AWID/aweb HTTP apps, signatures, identity tree, PostgreSQL and Redis.
Only DNS selects the disposable registry authority, as in the human-kind tests.
"""
import json
from uuid import UUID, uuid4

import httpx
import pytest
from aweb.api import _build_awid_registry_client
from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_id_chain_request_auth import ALICE, ROOT, _fixture_signer, _signed_fixture_certificate
from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers


class _CountLists(httpx.AsyncHTTPTransport):
    def __init__(self):
        super().__init__()
        self.reads = 0

    async def handle_async_request(self, request):
        if request.method == "GET" and request.url.path.endswith("/certificates"):
            self.reads += 1
        return await super().handle_async_request(request)


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
