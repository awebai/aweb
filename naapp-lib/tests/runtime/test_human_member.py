"""Exact certificate, fresh registered identity and own human kind on real AWID."""

import asyncio
import base64
from contextlib import aclosing
from datetime import UTC, datetime
from time import perf_counter_ns

import pytest
from aweb_naapp_testing import Member, did_key
from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.registry import RegistryClient
from awid_service.deps import get_domain_verifier
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import HTTPException
from nacl.signing import SigningKey

from aweb_naapp.runtime.human_member import check_human_member
from aweb_naapp.runtime.team_auth import AWIDTeamCache

TEAM = "people:example.com"
DOMAIN = "example.com"


@pytest.fixture
async def human(registry):
    controller = SigningKey.generate()

    async def authority(domain):
        assert domain == DOMAIN
        return DomainAuthority(
            controller_did=did_key(controller),
            registry_url=REGISTRY_URL,
            dns_name=f"_awid.{domain}",
        )

    registry.app.dependency_overrides[get_domain_verifier] = lambda: authority
    registry.app.state.awid_public_origins = (REGISTRY_URL,)
    member = Member(team_id=TEAM)
    async with aclosing(
        RegistryClient(
            REGISTRY_URL,
            transport=registry.transport,
            service_token=SERVICE_TOKEN,
            domain_verifier=authority,
        )
    ) as client:
        await client.register_namespace(DOMAIN, did_key(controller), bytes(controller))
        identity = (await client.register_did(member.did_key, bytes(member.member_key))).did_aw
        member.extra_cert_fields = {"member_did_aw": identity}
        await registry.add_team(TEAM, member.team_did_key)
        await registry.add_certificate(member.certificate())
        fields = {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": identity,
            "domain": DOMAIN,
            "parent": {"kind": "namespace", "id": DOMAIN},
            "kind": "human",
            "issuer_key": did_key(controller),
            "issued_at": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        signature = (
            base64.urlsafe_b64encode(
                controller.sign(id_certificate_signing_bytes(fields)).signature
            )
            .rstrip(b"=")
            .decode()
        )
        signed = {"certificate": fields, "signature": signature}
        await client.register_id_certificate(
            {"v": 1, "type": "aweb.id-chain", "certificates": [signed]},
            signer=lambda payload: (member.did_key, member.member_key.sign(payload).signature),
            expected_head=None,
            invitation_id=None,
        )
        cache = AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=60,
            service_token=SERVICE_TOKEN,
            transport=registry.transport,
        )
        yield member, identity, client, cache, signed


async def test_current_human_member_is_the_exact_certified_subject(human):
    member, identity, client, cache, _ = human
    started = perf_counter_ns()
    proof = await check_human_member(
        cache, client, team_id=TEAM, principal=identity, certificate=member.certificate()
    )
    print(f"human_member_lab_elapsed_ns={perf_counter_ns() - started}")
    assert proof.principal == identity and proof.did_key == member.did_key
    assert proof.membership.team_id == TEAM
    assert proof.membership.certificate_id == member.certificate_id
    assert proof.membership.team_did_key == member.team_did_key


async def test_another_principal_cannot_borrow_a_current_humans_certificate(human, registry):
    member, _, client, cache, _ = human
    other = Member(team_id=TEAM)
    identity = await registry.register_did(other.member_key)
    with pytest.raises(HTTPException) as refused:
        await check_human_member(
            cache, client, team_id=TEAM, principal=identity, certificate=member.certificate()
        )
    assert (refused.value.status_code, refused.value.detail) == (403, "principal_not_member")


async def test_revoked_team_membership_is_refused_even_for_a_verified_human(human, registry):
    member, identity, client, cache, _ = human
    await registry.revoke(member.certificate_id)
    with pytest.raises(HTTPException) as refused:
        await check_human_member(
            cache, client, team_id=TEAM, principal=identity, certificate=member.certificate()
        )
    assert (refused.value.status_code, refused.value.detail) == (403, "principal_not_member")


async def test_an_agent_with_a_human_parent_is_not_a_human_holder(human, registry):
    member, identity, client, cache, root = human
    agent = Member(
        team_id=TEAM, team_key=member.team_key, certificate_id="cert-agent", alias="worker"
    )
    agent_id = (await client.register_did(agent.did_key, bytes(agent.member_key))).did_aw
    agent.extra_cert_fields = {"member_did_aw": agent_id}
    await registry.add_certificate(agent.certificate())
    fields = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": agent_id,
        "domain": DOMAIN,
        "parent": {"kind": "identity", "id": identity},
        "kind": "agent",
        "issuer_key": member.did_key,
        "issued_at": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed = {
        "certificate": fields,
        "signature": base64.urlsafe_b64encode(
            member.member_key.sign(id_certificate_signing_bytes(fields)).signature
        )
        .rstrip(b"=")
        .decode(),
    }
    await client.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": [root, signed]},
        signer=lambda payload: (agent.did_key, agent.member_key.sign(payload).signature),
        expected_head=None,
        invitation_id=None,
    )
    with pytest.raises(HTTPException) as refused:
        await check_human_member(
            cache, client, team_id=TEAM, principal=agent_id, certificate=agent.certificate()
        )
    assert (refused.value.status_code, refused.value.detail) == (403, "principal_not_human")


async def test_unavailable_public_identity_evidence_never_admits_a_known_human(human):
    member, identity, _, cache, _ = human
    listener = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    listener.close()
    await listener.wait_closed()
    async with aclosing(RegistryClient(f"http://127.0.0.1:{port}")) as client:
        with pytest.raises(HTTPException) as refused:
            await check_human_member(
                cache, client, team_id=TEAM, principal=identity, certificate=member.certificate()
            )
    assert (refused.value.status_code, refused.value.detail) == (
        503,
        "principal_status_unavailable",
    )


async def test_runtime_exposes_the_same_exact_human_member_admission(human, registry, tmp_path):
    from tests.runtime.test_runtime_team_services import _runtime

    member, identity, client, _, _ = human
    runtime = _runtime(tmp_path, registry=registry, database_url=registry.db.config.get_dsn())
    proof = await runtime.check_human_member(
        TEAM, principal=identity, certificate=member.certificate(), identity_client=client
    )
    assert proof.principal == identity and proof.did_key == member.did_key
    assert proof.membership.team_id == TEAM


async def test_an_unreadable_private_team_is_unavailable_not_a_membership_denial(human, registry):
    member, identity, client, _, _ = human
    await registry.db.execute(
        "UPDATE {{tables.teams}} SET visibility='private' WHERE domain=$1 AND name='people'", DOMAIN
    )
    unreadable = AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=60,
        service_token="unrecognized-fixture-service",
        transport=registry.transport,
    )
    with pytest.raises(HTTPException) as refused:
        await check_human_member(
            unreadable, client, team_id=TEAM, principal=identity, certificate=member.certificate()
        )
    assert (refused.value.status_code, refused.value.detail) == (
        503,
        "principal_status_unavailable",
    )
