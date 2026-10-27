"""Identity-tree enrollment in did:aw key resolution (docs/id-certificates.md §5).

An enrolled did:aw that omits its chain must not pass as legacy, so key
resolution carries its enrollment: enrolled with the domain fixed at first
enrollment, or proven not enrolled. A server or cache entry that says
nothing means unknown, never not enrolled.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest
import pytest_asyncio

from awid.registry import CachedRegistryClient, IDTreeEnrollment, RegistryClient

from awid_service.routes import did as did_routes

from id_tree_support import DOMAIN, ORIGIN, Tree, at, certificate, certificate_id, did_aw, did_key
from test_registry_client import FakeRedis


@pytest_asyncio.fixture
async def tree(clocked_client, manual_clock):
    tree = Tree(clocked_client, manual_clock)
    tree.clock.now = at("2026-10-26T00:00:00Z")
    await tree.root()
    for key_name in ("alice", "bob"):
        await tree.vector_did(key_name)
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    return tree


async def _id_tree(tree, key_name: str):
    resp = await tree.client.get(f"/v1/did/{did_aw(key_name)}/key")
    assert resp.status_code == 200, resp.text
    return resp.json()["id_tree"]


@pytest.mark.asyncio
async def test_an_enrolled_id_resolves_with_its_domain(tree):
    assert await _id_tree(tree, "alice") == {"enrolled": True, "domain": DOMAIN}


@pytest.mark.asyncio
async def test_a_never_enrolled_id_resolves_as_proven_not_enrolled(tree):
    assert await _id_tree(tree, "bob") == {"enrolled": False}


@pytest.mark.asyncio
async def test_a_revoked_id_is_still_enrolled(tree):
    resp = await tree.revoke("root", "alice", expected_head=certificate_id("alice"), when=at("2026-10-26T00:10:00Z"))
    assert resp.status_code == 200, resp.text
    assert await _id_tree(tree, "alice") == {"enrolled": True, "domain": DOMAIN}


@pytest.mark.asyncio
async def test_the_cached_client_carries_enrollment_through_its_cache(tree):
    redis = FakeRedis()
    client = CachedRegistryClient(ORIGIN, redis, transport=httpx.ASGITransport(app=tree.client.app))
    try:
        fresh = await client.resolve_key_fresh(did_aw("alice"))
        cached = await client.resolve_key(did_aw("alice"))
        bob = await client.resolve_key(did_aw("bob"))
    finally:
        await client.aclose()
    assert fresh.id_tree == cached.id_tree == IDTreeEnrollment(enrolled=True, domain=DOMAIN)
    assert bob.id_tree == IDTreeEnrollment(enrolled=False, domain=None)
    assert cached.current_did_key == did_key("alice")


def _key_answer(**extra) -> dict:
    return {"did_aw": did_aw("alice"), "current_did_key": did_key("alice"), "log_head": None, **extra}


@pytest.mark.asyncio
async def test_an_old_server_without_the_field_leaves_enrollment_unknown():
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(lambda request: httpx.Response(200, json=_key_answer())))
    try:
        resolution = await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert resolution.id_tree is None
    assert resolution.current_did_key == did_key("alice")


@pytest.mark.asyncio
@pytest.mark.parametrize("id_tree", [
    None,
    {"enrolled": True},
    {"enrolled": True, "domain": ""},
    {"enrolled": True, "domain": 7},
    {"enrolled": False, "domain": DOMAIN},
    {"enrolled": "false"},
    {"enrolled": 0},
    {"enrolled": True, "domain": DOMAIN, "extra": 1},
    [True, DOMAIN],
], ids=["null", "enrolled-without-domain", "empty-domain", "non-text-domain", "not-enrolled-with-domain",
        "text-flag", "integer-flag", "unknown-field", "not-an-object"])
async def test_a_malformed_stated_enrollment_rejects_the_resolution(id_tree):
    answer = _key_answer(id_tree=id_tree)
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(lambda request: httpx.Response(200, json=answer)))
    try:
        with pytest.raises(ValueError):
            await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()


class CountingRegistry:
    def __init__(self, answer: dict) -> None:
        self.answer = answer
        self.requests = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        return httpx.Response(200, json=self.answer)


@pytest.mark.asyncio
async def test_a_resolution_that_does_not_state_enrollment_is_fetched_fresh_each_time(caplog):
    registry = CountingRegistry(_key_answer())
    client = CachedRegistryClient(ORIGIN, FakeRedis(), transport=httpx.MockTransport(registry.handler))
    try:
        with caplog.at_level(logging.WARNING, logger="awid.registry"):
            first = await client.resolve_key(did_aw("alice"))
            second = await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert first.id_tree is None and second.id_tree is None
    assert registry.requests == 2
    assert caplog.records == []


@pytest.mark.asyncio
async def test_a_cached_resolution_without_enrollment_is_refetched_not_served():
    registry = CountingRegistry(_key_answer(id_tree={"enrolled": True, "domain": DOMAIN}))
    redis = FakeRedis()
    client = CachedRegistryClient(ORIGIN, redis, transport=httpx.MockTransport(registry.handler))
    await redis.set(client._did_key_cache_key(did_aw("alice")), json.dumps({
        "fetched_at": 2_000_000_000, "fresh_until": 2_000_000_000 + 300,
        "value": {"did_aw": did_aw("alice"), "current_did_key": did_key("alice"), "log_head": None},
    }), ex=600)
    try:
        resolution = await client.resolve_key(did_aw("alice"))
        again = await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert resolution.id_tree == again.id_tree == IDTreeEnrollment(enrolled=True, domain=DOMAIN)
    assert registry.requests == 1


@pytest.mark.asyncio
async def test_a_stated_enrollment_is_reused_from_the_cache():
    registry = CountingRegistry(_key_answer(id_tree={"enrolled": False}))
    client = CachedRegistryClient(ORIGIN, FakeRedis(), transport=httpx.MockTransport(registry.handler))
    try:
        first = await client.resolve_key(did_aw("alice"))
        second = await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert first.id_tree == second.id_tree == IDTreeEnrollment(enrolled=False, domain=None)
    assert registry.requests == 1


@pytest.mark.asyncio
async def test_key_and_enrollment_come_from_one_snapshot(tree, monkeypatch):
    """An enrollment committed while the key is being read is not reported with that key."""
    real = did_routes._fetch_current_encryption_assertion

    async def enroll_bob_meanwhile(db, **kwargs):
        resp = await tree.register(
            [certificate("alice"), certificate("bob")], when=at("2026-10-26T00:03:00Z"),
        )
        assert resp.status_code == 200, resp.text
        return await real(db, **kwargs)

    monkeypatch.setattr(did_routes, "_fetch_current_encryption_assertion", enroll_bob_meanwhile)
    assert await _id_tree(tree, "bob") == {"enrolled": False}
    monkeypatch.setattr(did_routes, "_fetch_current_encryption_assertion", real)
    assert await _id_tree(tree, "bob") == {"enrolled": True, "domain": DOMAIN}
