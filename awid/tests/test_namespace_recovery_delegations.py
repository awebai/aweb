"""Recovery/rotation through real DNS, signed HTTP, PostgreSQL and Redis."""

from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from httpx import ASGITransport, AsyncClient
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.dns_verify import awid_txt_value
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid_service.main import create_app
from conftest import build_signed_headers
from id_tree_support import (
    ORIGIN,
    Tree,
    at,
    certificate,
    consumes,
    covering_headers,
    did_aw,
    did_key,
    seed,
    sign,
)
from lock_waits import wait_until_blocked_on_lock

PARENT = "example.com"
DOMAIN = "org.example.com"


def child_certificate(name):
    fields = certificate(name)["certificate"]
    fields["domain"] = DOMAIN
    signer = "alice"
    if fields["parent"]["kind"] == "namespace":
        fields["parent"]["id"] = DOMAIN
        signer = "root"
    return sign(fields, signer)


class NamespaceDNS(asyncio.DatagramProtocol):
    """Real authoritative UDP answers; absent child records inherit the parent."""

    def __init__(self):
        self.records = {PARENT: "depth1"}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, peer):
        query = dns.message.from_wire(wire)
        answer = dns.message.make_response(query)
        answer.flags |= dns.flags.AA
        name = query.question[0].name.to_text().rstrip(".").removeprefix("_awid.")
        key = self.records.get(name)
        if key is None:
            answer.set_rcode(dns.rcode.NXDOMAIN)
        else:
            value = awid_txt_value(did_key(key), ORIGIN)
            answer.answer.append(
                dns.rrset.from_text(
                    query.question[0].name, 0, "IN", "TXT", '"' + value + '"'
                )
            )
        self.transport.sendto(answer.to_wire(), peer)


def parent_headers(parent, domain, child, *, recovery=False):
    claims = {
        "child_domain": domain,
        "new_controller_did" if recovery else "controller_did": did_key(child),
    }
    signed = build_signed_headers(
        seed(parent),
        did_key(parent),
        domain=domain,
        operation="authorize_subdomain_rotation"
        if recovery
        else "authorize_subdomain_registration",
        **claims,
    )
    return {
        "X-AWEB-Parent-Authorization": signed["Authorization"],
        "X-AWEB-Parent-Timestamp": signed["X-AWEB-Timestamp"],
    }


async def register_child(world, *, domain=DOMAIN, child="root", parent="depth1"):
    return await world.tree.register_namespace(
        child, domain=domain, headers=parent_headers(parent, domain, child)
    )


async def status(world, domain=DOMAIN):
    return await world.tree.client.post(
        "/v1/id-certificates/status", json={"v": 1, "domain": domain, "ids": []}
    )


async def namespace(world, domain=DOMAIN):
    result = await world.tree.client.get(f"/v1/namespaces/{domain}")
    assert result.status_code == 200, result.text
    return result.json()


async def epochs(world, domain=DOMAIN):
    return await world.db.fetch_all(
        "SELECT * FROM {{tables.id_namespace_epochs}} WHERE domain=$1 ORDER BY seq",
        domain,
    )


async def recover(world, *, domain=PARENT, new="root_rotated", parent=None):
    if parent is None:
        world.dns.records[domain] = new
    return await world.tree.replace_controller(
        new,
        domain=domain,
        headers=parent_headers(parent, domain, new, recovery=True) if parent else None,
    )


async def rotate(world, *, previous="depth1", new="root_rotated"):
    world.dns.records[PARENT] = new
    old = (await epochs(world, PARENT))[-1]
    body = {
        "domain": PARENT,
        "operation": "rotate_namespace_controller",
        "from_seq": old["seq"],
        "previous_did_key": did_key(previous),
        "new_did_key": did_key(new),
    }
    raw = json.dumps(body, separators=(",", ":")).encode()
    path = f"/v1/namespaces/{PARENT}/rotate"
    headers = covering_headers(
        previous,
        method="POST",
        path=path,
        body=raw,
        domain=PARENT,
        operation=body["operation"],
        new_key_signer=new,
        **{key: body[key] for key in ("from_seq", "previous_did_key", "new_did_key")},
    )
    return await world.tree.client.post(path, content=raw, headers=headers)


def ok(response):
    assert response.status_code == 200, response.text


def unavailable(response):
    assert (response.status_code, response.json()["detail"]["code"]) == (
        503,
        "evidence_unavailable",
    ), response.text


@pytest_asyncio.fixture
async def delegation_world(awid_db_infra, manual_clock, monkeypatch):
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY", raising=False)
    authority = NamespaceDNS()
    channel, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: authority, local_addr=("127.0.0.1", 0)
    )
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers, resolver.port = (
        ["127.0.0.1"],
        channel.get_extra_info("sockname")[1],
    )
    resolver.timeout, resolver.lifetime = 0.3, 1
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    try:
        redis_url = os.environ.get("AWID_REDIS_URL") or os.environ.get(
            "REDIS_URL", "redis://127.0.0.1:6379/0"
        )
        async with Redis.from_url(redis_url) as redis:
            app = create_app(
                db_infra=awid_db_infra,
                redis=redis,
                rate_limiter=MemoryFixedWindowRateLimiter(),
            )
            app.state.id_tree_clock = manual_clock
            async with app.router.lifespan_context(app):
                async with AsyncClient(
                    transport=ASGITransport(app), base_url=ORIGIN
                ) as client:
                    client.app = app
                    tree = Tree(client, manual_clock)
                    world = SimpleNamespace(
                        tree=tree, dns=authority, db=awid_db_infra.get_manager("aweb")
                    )
                    # Tree.root/exact_dns install synthetic authority; never use them here.
                    ok(await tree.register_namespace("depth1", domain=PARENT))
                    ok(await register_child(world))
                    await tree.did("alice")
                    ok(
                        await tree.register(
                            [child_certificate("alice")],
                            when=at("2026-10-26T00:01:00Z"),
                        )
                    )
                    tree.clock.now = at("2026-10-26T00:10:00Z")
                    yield world
    finally:
        channel.close()


@consumes("namespace-recovery-withdraws-delegations-and-explicit-restore")
async def test_recovery_withdraws_children_and_explicit_restore_keeps_data(
    case, delegation_world
):
    world = delegation_world
    # Nonempty neighbouring data must survive the withdrawal, not only empty tables.
    for route, operation, claims, body in [
        (
            "teams",
            "create_team",
            {"name": "kept"},
            {"name": "kept", "team_did_key": did_key("bob")},
        ),
        (
            "addresses",
            "register_address",
            {"name": "alice"},
            {
                "name": "alice",
                "did_aw": did_aw("alice"),
                "current_did_key": did_key("alice"),
            },
        ),
    ]:
        headers = build_signed_headers(
            seed("root"), did_key("root"), domain=DOMAIN, operation=operation, **claims
        )
        ok(
            await world.tree.client.post(
                f"/v1/namespaces/{DOMAIN}/{route}", json=body, headers=headers
            )
        )
    before = {
        table: await world.db.fetch_all(
            f"SELECT * FROM {{{{tables.{table}}}}} ORDER BY 1"
        )
        for table in (
            "id_namespace_epochs",
            "id_identities",
            "id_certificates",
            "teams",
            "public_addresses",
        )
    }
    ok(await register_child(world, domain="attacker.example.com", child="bob"))
    ok(await recover(world))
    assert "delegation" not in await namespace(world)
    unavailable(await status(world))
    unavailable(await status(world, "attacker.example.com"))
    # Only the parent epoch changed; child epochs/certificates and ordinary rows stay exact.
    after = {
        table: await world.db.fetch_all(
            f"SELECT * FROM {{{{tables.{table}}}}} ORDER BY 1"
        )
        for table in before
    }
    for table in before.keys() - {"id_namespace_epochs"}:
        assert after[table] == before[table]
    child_before = [
        row for row in before["id_namespace_epochs"] if row["domain"] == DOMAIN
    ]
    assert await epochs(world) == child_before
    ok(await register_child(world, parent="root_rotated"))
    assert (await namespace(world))["delegation"]["parent_controller_key"] == did_key(
        "root_rotated"
    )
    ok(await status(world))
    assert await epochs(world) == child_before
    unavailable(await status(world, "attacker.example.com"))
    # The original registered human can still issue, without re-registration or replacement.
    await world.tree.did("bob")
    ok(
        await world.tree.register(
            [child_certificate("alice"), child_certificate("bob")]
        )
    )
    assert case["expected"]["child_epoch_preserved"] is True


@consumes("namespace-recovery-reused-parent-key-no-revival")
async def test_reusing_the_old_parent_key_never_revives_withdrawn_grants(
    case, delegation_world
):
    world = delegation_world
    ok(await recover(world))
    ok(await recover(world, new="depth1"))
    assert "delegation" not in await namespace(world)
    unavailable(await status(world))
    assert case["expected"]["implicit_revival"] is False


@consumes("namespace-recovery-same-key-retry-preserves-restored-child")
async def test_same_key_recovery_retry_preserves_explicitly_restored_child(
    case, delegation_world
):
    world = delegation_world
    ok(await recover(world))
    ok(await register_child(world, parent="root_rotated"))
    before = await namespace(world), await epochs(world), await epochs(world, PARENT)
    ok(await recover(world))
    assert (
        await namespace(world),
        await epochs(world),
        await epochs(world, PARENT),
    ) == before
    ok(await status(world))
    assert case["expected"]["restored_child_valid"] is True


@consumes("namespace-reverify-before-recovery-withdraws-delegations")
async def test_reverify_moving_the_row_does_not_hide_replacement(
    case, delegation_world
):
    world = delegation_world
    world.dns.records[PARENT] = "root_rotated"
    ok(await world.tree.reverify(domain=PARENT))
    assert (await namespace(world, PARENT))["controller_did"] == did_key("root_rotated")
    assert (await epochs(world, PARENT))[-1]["did_key"] == did_key("depth1")
    ok(await recover(world))
    assert "delegation" not in await namespace(world)
    unavailable(await status(world))
    assert case["expected"]["delegation_withdrawn"] is True


@consumes("namespace-pre-epoch-recovery-withdraws-delegations")
@pytest.mark.parametrize("reverify_first", [False, True])
async def test_pre_epoch_recovery_does_not_carry_stale_witnesses(
    case, delegation_world, reverify_first
):
    world = delegation_world
    # Pre-upgrade fixture state; no authority function is substituted.
    await world.db.execute(
        "DELETE FROM {{tables.id_namespace_epochs}} WHERE domain=$1", PARENT
    )
    world.dns.records[PARENT] = "root_rotated"
    if reverify_first:
        ok(await world.tree.reverify(domain=PARENT))
    ok(await recover(world))
    assert "delegation" not in await namespace(world)
    unavailable(await status(world))
    assert case["expected"]["delegation_withdrawn"] is True


@consumes("namespace-pre-epoch-same-key-enrollment-preserves-delegation")
@pytest.mark.parametrize("method", ["register", "recover"])
async def test_same_key_pre_epoch_enrollment_keeps_valid_child_witness(
    case, delegation_world, method
):
    world = delegation_world
    await world.db.execute(
        "DELETE FROM {{tables.id_namespace_epochs}} WHERE domain=$1", PARENT
    )
    before = await namespace(world), await epochs(world)
    if method == "register":
        ok(await world.tree.register_namespace("depth1", domain=PARENT))
    else:
        ok(await world.tree.replace_controller("depth1", domain=PARENT))
    assert (await namespace(world), await epochs(world)) == before
    ok(await status(world))
    assert case["expected"]["child_epoch_preserved"] is True


@consumes("namespace-parent-authorized-recovery-withdraws-own-children")
async def test_parent_authorized_child_recovery_withdraws_its_outgoing_grants(
    case, delegation_world
):
    world = delegation_world
    world.dns.records[DOMAIN] = "root"
    ok(
        await register_child(
            world, domain="grand.org.example.com", child="bob", parent="root"
        )
    )
    ok(await status(world, "grand.org.example.com"))
    ok(await recover(world, domain=DOMAIN, parent="depth1"))
    world.dns.records[DOMAIN] = "root_rotated"
    assert (await namespace(world))["delegation"]["parent_controller_key"] == did_key(
        "depth1"
    )
    assert "delegation" not in await namespace(world, "grand.org.example.com")
    unavailable(await status(world, "grand.org.example.com"))
    assert case["expected"]["incoming_delegation_preserved"] is True


@consumes("namespace-delete-reregister-withdraws-delegations")
async def test_delete_and_same_key_reregistration_do_not_restore_child_grants(
    case, delegation_world
):
    world = delegation_world
    ok(await world.tree.delete_namespace("depth1", domain=PARENT))
    ok(await world.tree.register_namespace("depth1", domain=PARENT))
    assert "delegation" not in await namespace(world)
    unavailable(await status(world))
    assert case["expected"]["implicit_revival"] is False


@consumes("namespace-two-key-rotation-preserves-only-current-delegations")
@pytest.mark.parametrize("stale_key", ["alice", "root_rotated"])
async def test_two_key_rotation_preserves_only_delegations_bound_to_previous_key(
    case, delegation_world, stale_key
):
    world = delegation_world
    ok(await register_child(world, domain="stale.example.com", child="bob"))
    await world.db.execute(
        "UPDATE {{tables.dns_namespaces}} SET parent_controller_key=$2 WHERE domain=$1",
        "stale.example.com",
        did_key(stale_key),
    )
    before = await epochs(world)
    ok(await rotate(world))
    ok(await status(world))
    assert await epochs(world) == before
    assert (await namespace(world))["delegation"]["parent_controller_key"] == did_key(
        "root_rotated"
    )
    unavailable(await status(world, "stale.example.com"))
    assert case["expected"]["stale_delegation_promoted"] is False


@consumes("namespace-recovery-keeps-own-txt-child-independent")
async def test_own_txt_child_needs_no_delegation_after_parent_recovery(
    case, delegation_world
):
    world = delegation_world
    world.dns.records[DOMAIN] = "root"
    before = await epochs(world)
    ok(await recover(world))
    ok(await status(world))
    assert await epochs(world) == before
    assert case["expected"]["exact_child_valid"] is True


@consumes("namespace-observation-does-not-withdraw-delegations")
async def test_dns_observation_never_permanently_withdraws_a_delegation(
    case, delegation_world
):
    world = delegation_world
    before = await namespace(world)
    world.dns.records[PARENT] = "root_rotated"
    ok(await world.tree.reverify(domain=PARENT))
    assert await namespace(world) == before
    world.dns.records[PARENT] = "depth1"
    ok(await world.tree.reverify(domain=PARENT))
    ok(await status(world))
    assert case["expected"]["delegation_preserved"] is True


@consumes("namespace-recovery-racing-old-parent-registration-refuses")
async def test_old_parent_registration_waiting_behind_recovery_is_refused(
    case, delegation_world
):
    world = delegation_world
    async with world.db.transaction() as holder:
        await holder.fetch_one(
            "SELECT * FROM {{tables.dns_namespaces}} WHERE domain=$1 FOR UPDATE", PARENT
        )
        recovery = asyncio.create_task(recover(world))
        await wait_until_blocked_on_lock(world.db, recovery)
        registration = asyncio.create_task(
            register_child(world, domain="racing.example.com", child="bob")
        )
        await wait_until_blocked_on_lock(world.db, registration, waiters=2)
    ok(await recovery)
    refused = await registration
    assert refused.status_code == case["expected"]["old_parent_status"], refused.text
    missing = await world.tree.client.get("/v1/namespaces/racing.example.com")
    assert missing.status_code == 404


@consumes("namespace-recovery-racing-committed-child-registration-clears")
async def test_recovery_withdraws_child_committed_while_recovery_waited(
    case, delegation_world
):
    world = delegation_world
    async with world.db.transaction() as holder:
        # Registration takes parent SHARE before waiting for the child row.
        # Recovery must wait for that real old-key request to commit.
        await holder.fetch_one(
            "SELECT * FROM {{tables.dns_namespaces}} WHERE domain=$1 FOR UPDATE", DOMAIN
        )
        registration = asyncio.create_task(register_child(world))
        await wait_until_blocked_on_lock(world.db, registration)
        recovery = asyncio.create_task(recover(world))
        await wait_until_blocked_on_lock(world.db, recovery, waiters=2)
    ok(await registration)
    ok(await recovery)
    assert "delegation" not in await namespace(world)
    unavailable(await status(world))
    assert case["expected"]["delegation_withdrawn"] is True
