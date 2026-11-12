"""Exact certificate, fresh registered identity and own human kind on real AWID."""

import asyncio
import base64
import os
from contextlib import aclosing
from datetime import UTC, datetime
from time import monotonic_ns, perf_counter_ns

import pytest
from aweb_naapp_testing import Member, did_key
from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.identity_observation import (
    IdentityKindObservation,
    observe_identity_binding,
    observe_identity_kind,
)
from awid.registry import CachedRegistryClient, RegistryClient
from awid_service.deps import get_domain_verifier
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import HTTPException
from nacl.signing import SigningKey
from redis.asyncio import Redis
from redis.asyncio.client import Pipeline

from aweb_naapp import roles
from aweb_naapp.runtime import human_member
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


class _RedisClock(Redis):
    """Only TIME is controlled; all cache reads/writes use the actual Redis."""

    seconds = 1_000_000

    async def time(self):
        return self.seconds, 0

    def pipeline(self, transaction=True, shard_hint=None):
        seconds = self.seconds

        class ClockedPipeline(Pipeline):
            async def execute(self, *args, **kwargs):
                commands = [command for command, _ in self.command_stack]
                results = await super().execute(*args, **kwargs)
                return [
                    (seconds, 0) if command[0] == "TIME" else result
                    for command, result in zip(commands, results, strict=True)
                ]

        return ClockedPipeline(
            self.connection_pool, self.response_callbacks, transaction, shard_hint
        )


@pytest.fixture
async def aged_human(human, registry):
    member, identity, live, cache, _ = human
    redis = _RedisClock.from_url(os.environ["REDIS_URL"])
    cached = CachedRegistryClient(
        REGISTRY_URL,
        redis,
        transport=registry.transport,
        service_token=SERVICE_TOKEN,
        domain_verifier=live._domain_verifier,
    )
    try:
        binding = await observe_identity_binding(cached, did_key=member.did_key, did_aw=identity)
        first = await observe_identity_kind(cached, binding)
        assert first.is_human
        redis.seconds += 59
        # This reuses actual stored status/authority from the real registry.
        yield member, identity, cached, cache
    finally:
        await cached.aclose()
        await redis.aclose()


async def test_public_observation_keeps_exact_cached_evidence_age(aged_human):
    from dataclasses import replace

    member, identity, cached, _ = aged_human
    binding = await observe_identity_binding(cached, did_key=member.did_key, did_aw=identity)
    observation = await observe_identity_kind(cached, binding)
    assert observation.is_human
    assert observation.evidence_age_seconds == 59
    legacy = IdentityKindObservation(observation.did_key, observation.did_aw, observation.result)
    assert legacy.evidence_age_seconds is None
    assert legacy.is_human and legacy == observation
    assert replace(observation, evidence_age_seconds=12) == observation
    assert "evidence_age_seconds" not in observation.result
    missing = await observe_identity_kind(cached, replace(binding, id_tree=None))
    assert missing.evidence_age_seconds is None and not missing.is_human


@pytest.mark.parametrize("wait_ns,refused", [(500_000_000, False), (2_000_000_000, True)])
async def test_cached_kind_deadline_survives_role_lock_before_effect(
    aged_human,
    test_db_factory,
    monkeypatch,
    wait_ns,
    refused,
):
    member, identity, cached, cache = aged_human
    clock = [None]
    monkeypatch.setattr(
        human_member,
        "monotonic_ns",
        lambda: monotonic_ns() if clock[0] is None else clock[0],
    )
    proof = await check_human_member(
        cache, cached, team_id=TEAM, principal=identity, certificate=member.certificate()
    )
    clock[0] = monotonic_ns()
    assert proof.membership.fresh_until > clock[0] + 10_000_000_000
    db = await test_db_factory.create_db(suffix="human_effect", schema="app")
    await roles.apply_roles_migrations(db)
    principal = roles.PrincipalKey(TEAM, identity)
    async with db.transaction() as tx:
        await roles.assign(tx, principal, "example.owner")
    before = await db.fetch_all("SELECT * FROM {{tables.role_assignments}} ORDER BY role")

    async def effect():
        async with db.transaction() as tx:
            assert await roles.hold_role(tx, principal, "example.owner")
            proof.require_fresh()
            await roles.assign(tx, principal, "example.confirmed")
            proof.require_fresh()  # The final local effect fence keeps the same deadline.

    task = None
    try:
        async with db.transaction() as gate:
            await gate.execute("SELECT * FROM {{tables.role_assignments}} FOR UPDATE")
            blocker = await gate.fetch_value("SELECT pg_backend_pid()")
            task = asyncio.create_task(effect())
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                    "WHERE $1=ANY(pg_blocking_pids(pid)))",
                    blocker,
                ):
                    await asyncio.sleep(0.01)
            assert not task.done(), "the effect must actually wait on the authority row"
            clock[0] += wait_ns
            assert proof.membership.is_fresh_at(clock[0])
        if refused:
            with pytest.raises(HTTPException) as failure:
                await asyncio.wait_for(task, 5)
            assert (failure.value.status_code, failure.value.detail) == (
                503,
                "principal_status_unavailable",
            )
            assert (
                await db.fetch_all("SELECT * FROM {{tables.role_assignments}} ORDER BY role")
                == before
            )
        else:
            await asyncio.wait_for(task, 5)
            assert await roles.has_role(db, principal, "example.confirmed")
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("age", [None, float("nan"), -1, 61, True])
async def test_missing_or_invalid_retained_age_cannot_mint_current_effect_proof(
    human,
    monkeypatch,
    age,
):
    from dataclasses import replace

    member, identity, registry, cache, _ = human
    observer = human_member.observe_identity_kind

    async def lost_metadata(client, binding):
        # The actual registry/verifier establishes human kind. Only its new
        # in-process age metadata is removed/corrupted at the consumer boundary,
        # as with a legacy three-argument construction; no identity is fabricated.
        observed = await observer(client, binding)
        assert observed.is_human
        if age is None:
            return IdentityKindObservation(observed.did_key, observed.did_aw, observed.result)
        return replace(observed, evidence_age_seconds=age)

    monkeypatch.setattr(human_member, "observe_identity_kind", lost_metadata)
    with pytest.raises(HTTPException) as refused:
        await check_human_member(
            cache, registry, team_id=TEAM, principal=identity, certificate=member.certificate()
        )
    assert (refused.value.status_code, refused.value.detail) == (
        503,
        "principal_status_unavailable",
    )
