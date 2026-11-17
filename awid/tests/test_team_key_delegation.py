"""Team acts use the ID tree's real DNS, delegation and bounded status read."""
from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4
from nacl.signing import SigningKey

import dns.asyncresolver
import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.dns_verify import awid_txt_value
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import CachedRegistryClient
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid.team_key_acts import TeamKeyActError, verify_team_key_change
from awid_service.main import create_app
from conftest import controller_keypair




class DNS(asyncio.DatagramProtocol):
    def __init__(self, registry_origin):
        self.records = {}
        self.registry_origin = registry_origin

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, peer):
        query = dns.message.from_wire(wire)
        answer = dns.message.make_response(query)
        name = query.question[0].name.to_text().rstrip('.')
        if name in self.records:
            value = awid_txt_value(self.records[name], registry_url=self.registry_origin)
            answer.answer.append(dns.rrset.from_text(name + '.', 0, 'IN', 'TXT', '"' + value + '"'))
        else:
            answer.set_rcode(dns.rcode.NXDOMAIN)
        self.transport.sendto(answer.to_wire(), peer)


@pytest_asyncio.fixture
async def world(awid_db_infra, monkeypatch):
    domain = f"org-{uuid4().hex}.example.com"
    registry_origin = f"https://registry-{uuid4().hex}.example.com"
    dns_server = DNS(registry_origin)
    channel, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: dns_server, local_addr=('127.0.0.1', 0))
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers, resolver.port = ['127.0.0.1'], channel.get_extra_info('sockname')[1]
    monkeypatch.setattr(dns.asyncresolver, 'default_resolver', resolver)
    parent, child, team = controller_keypair(), controller_keypair(), controller_keypair()
    dns_server.records['_awid.example.com'] = parent[1]
    redis_url = os.environ.get('AWID_REDIS_URL') or os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
    try:
        async with Redis.from_url(redis_url) as redis:
            app = create_app(db_infra=awid_db_infra, redis=redis, rate_limiter=MemoryFixedWindowRateLimiter())
            app.state.awid_public_origins = (registry_origin,)
            async with app.router.lifespan_context(app):
                sdk = CachedRegistryClient(registry_url=registry_origin, redis_client=redis,
                                           transport=httpx.ASGITransport(app=app))
                try:
                    await sdk.register_namespace('example.com', parent[1], parent[0])
                    await sdk.register_namespace(domain, child[1], child[0], parent_signing_key=parent[0])
                    await sdk.register_team(domain=domain, name='base', team_did_key=team[1],
                                            display_name='PRIVATE', visibility='public',
                                            namespace_controller_signing_key=child[0])
                    await sdk.rotate_team_key(domain, 'base', new_team_did_key=team[1], namespace_controller_signing_key=child[0])
                    yield SimpleNamespace(domain=domain, sdk=sdk, dns=dns_server, parent=parent, child=child,
                                          team=team, resolver=SystemTXTOutcomeResolver(),
                                          db=awid_db_infra.get_manager('aweb'))
                finally:
                    await sdk.aclose()
    finally:
        channel.close()


async def verify(world, record=None):
    return await verify_team_key_change(
        record or await world.sdk.get_team_key_act(world.domain, 'base'), domain=world.domain, name='base',
        team_did_key=world.team[1], pinned_at=None, resolver=world.resolver,
        fetch_namespace_evidence=world.sdk.namespace_evidence,
    )


@pytest.mark.asyncio
async def test_inherited_child_controller_act_uses_the_id_tree_evidence_path(world):
    act = await verify(world)
    assert act.signer_did_key == world.child[1]
    evidence = await world.sdk.namespace_evidence(world.domain)
    assert evidence.namespace_authority['controller_key'] == world.parent[1]
    assert evidence.status['namespace']['delegation']['controller_key'] == world.child[1]
    assert 0 <= evidence.age_seconds <= 60


@pytest.mark.asyncio
async def test_exact_dns_overrides_a_previously_valid_inherited_witness(world):
    await verify(world)
    world.dns.records['_awid.' + world.domain] = controller_keypair()[1]
    with pytest.raises(TeamKeyActError):
        await verify(world)


@pytest.mark.asyncio
async def test_missing_delegation_never_authorises_the_child_act(world):
    await world.db.execute('UPDATE {{tables.dns_namespaces}} SET parent_domain=NULL, parent_controller_key=NULL WHERE domain=$1', world.domain)
    with pytest.raises(TeamKeyActError):
        await verify(world)


@pytest.mark.asyncio
@pytest.mark.parametrize('apply', [False, True])
async def test_owner_inventory_backfill_is_explicit_idempotent_and_preserves_team_state(world, apply):
    from awid.controller_signing import ControllerDescriptor
    from awid.team_key_backfill import TeamKeyBackfillTarget, reaffirm_team_keys

    await world.db.execute('DELETE FROM {{tables.team_key_acts}}')
    original = dict(await world.db.fetch_one('SELECT * FROM {{tables.teams}}'))
    controller = ControllerDescriptor('namespace', world.domain, world.child[1], 'local', 0)

    def signer(context):
        return world.child[1], SigningKey(world.child[0]).sign(context.signing_bytes()).signature

    report = await reaffirm_team_keys(world.sdk, [TeamKeyBackfillTarget(world.domain, 'base', world.team[1])],
        controllers={world.domain: controller}, signer=signer, apply=apply, resolver=world.resolver)
    assert report['before'] == {'total': 1, 'ready': 0, 'unready': 1, 'conflicted': 0}
    assert report['after']['ready'] == int(apply)
    assert dict(await world.db.fetch_one('SELECT * FROM {{tables.teams}}')) == original
    assert await world.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}}') == 0
    if apply:
        again = await reaffirm_team_keys(world.sdk, [TeamKeyBackfillTarget(world.domain, 'base', world.team[1])],
            controllers={world.domain: controller}, signer=signer, apply=True, resolver=world.resolver)
        assert again['before']['ready'] == 1
        assert await world.db.fetch_value('SELECT count(*) FROM {{tables.team_key_acts}}') == 1
