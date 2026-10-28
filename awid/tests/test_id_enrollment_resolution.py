"""Identity-tree enrollment in did:aw key resolution (docs/id-certificates.md §5).

An enrolled did:aw that omits its chain must not pass as legacy, so key
resolution carries its enrollment: enrolled with the domain fixed at first
enrollment, or proven not enrolled. A server or cache entry that says
nothing means unknown, never not enrolled.
"""

from __future__ import annotations

import contextlib
import json
import logging

import httpx
import pytest
import pytest_asyncio

from awid.registry import CachedRegistryClient, DIDKeyNotFoundError, IDTreeEnrollment, RegistryClient, RegistryError

from awid_service.routes import did as did_routes

from id_tree_support import DOMAIN, ORIGIN, VECTORS, Tree, at, certificate, certificate_id, did_aw, did_key
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


class _EnrollAfterMappingRead:
    """A transaction that commits bob's enrollment right after the route reads the key mapping."""

    def __init__(self, tx, enroll) -> None:
        self._tx = tx
        self._enroll = enroll

    async def fetch_one(self, query, *args):
        row = await self._tx.fetch_one(query, *args)
        if "did_aw_mappings" in query and self._enroll is not None:
            enroll, self._enroll = self._enroll, None
            await enroll()
        return row

    def __getattr__(self, name):
        return getattr(self._tx, name)


class _ManagerEnrollingDuringKeyRead:
    def __init__(self, manager, enroll) -> None:
        self._manager = manager
        self._enroll = enroll

    @contextlib.asynccontextmanager
    async def transaction(self):
        async with self._manager.transaction() as tx:
            yield _EnrollAfterMappingRead(tx, self._enroll)

    def __getattr__(self, name):
        return getattr(self._manager, name)


@pytest.mark.asyncio
async def test_key_and_enrollment_come_from_one_snapshot(tree, monkeypatch):
    """An enrollment committed between the key mapping and enrollment reads is not reported with that key."""
    real_db = did_routes._db

    async def enroll_bob():
        resp = await tree.register([certificate("alice"), certificate("bob")], when=at("2026-10-26T00:03:00Z"))
        assert resp.status_code == 200, resp.text

    monkeypatch.setattr(did_routes, "_db", lambda request: _ManagerEnrollingDuringKeyRead(real_db(request), enroll_bob))
    assert await _id_tree(tree, "bob") == {"enrolled": False}
    monkeypatch.setattr(did_routes, "_db", real_db)
    assert await _id_tree(tree, "bob") == {"enrolled": True, "domain": DOMAIN}


KEY_RESPONSE_CASES = VECTORS["key_response_id_tree"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", KEY_RESPONSE_CASES, ids=lambda c: c["name"])
async def test_key_response_id_tree_cases(case):
    """The frozen carrier cases, by name, through the client's key resolution."""
    registry = CountingRegistry(_key_answer(**case["key_response"]))
    redis = FakeRedis()
    client = CachedRegistryClient(ORIGIN, redis, transport=httpx.MockTransport(registry.handler))
    if "cached_key_response" in case:
        await redis.set(client._did_key_cache_key(did_aw("alice")), json.dumps({
            "fetched_at": 2_000_000_000, "fresh_until": 2_000_000_000 + 300,
            "value": _key_answer(**case["cached_key_response"]),
        }), ex=600)
    expected = case["expected_parse"]
    try:
        if expected["state"] == "malformed":
            with pytest.raises(ValueError):
                await client.resolve_key(did_aw("alice"))
            return
        resolution = await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert resolution.id_tree == {
        "enrolled": IDTreeEnrollment(enrolled=True, domain=expected["domain"]),
        "not_enrolled": IDTreeEnrollment(enrolled=False, domain=None),
        "unknown": None,
    }[expected["state"]]
    if case.get("expected_key_refetch"):
        assert registry.requests == 1


def test_every_key_response_case_is_consumed_here():
    names = [case["name"] for case in KEY_RESPONSE_CASES]
    assert len(names) == len(set(names)) == 19
    assert {case["expected_parse"]["state"] for case in KEY_RESPONSE_CASES} == {
        "enrolled", "not_enrolled", "malformed", "unknown",
    }


# ---------------------------------------------------------------------------
# A missing key mapping still states enrollment (security N66)
# ---------------------------------------------------------------------------


async def _drop_mapping(awid_db_infra, did_aw_value: str) -> None:
    db = awid_db_infra.get_manager("aweb")
    await db.execute("DELETE FROM {{tables.did_aw_mappings}} WHERE did_aw = $1", did_aw_value)


@pytest.mark.asyncio
async def test_an_enrolled_id_without_a_key_mapping_is_still_enrolled(tree, awid_db_infra):
    await _drop_mapping(awid_db_infra, did_aw("alice"))
    resp = await tree.client.get(f"/v1/did/{did_aw('alice')}/key")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "not found", "id_tree": {"enrolled": True, "domain": DOMAIN}}


@pytest.mark.asyncio
async def test_a_never_registered_id_is_proven_not_enrolled(tree):
    unknown = did_aw("other_human")
    resp = await tree.client.get(f"/v1/did/{unknown}/key")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "not found", "id_tree": {"enrolled": False}}


@pytest.mark.asyncio
async def test_the_client_carries_enrollment_on_a_missing_key(tree, awid_db_infra):
    await _drop_mapping(awid_db_infra, did_aw("alice"))
    client = CachedRegistryClient(ORIGIN, FakeRedis(), transport=httpx.ASGITransport(app=tree.client.app))
    try:
        with pytest.raises(DIDKeyNotFoundError) as enrolled:
            await client.resolve_key_fresh(did_aw("alice"))
        with pytest.raises(DIDKeyNotFoundError) as unknown:
            await client.resolve_key(did_aw("other_human"))
    finally:
        await client.aclose()
    assert enrolled.value.id_tree == IDTreeEnrollment(enrolled=True, domain=DOMAIN)
    assert unknown.value.id_tree == IDTreeEnrollment(enrolled=False, domain=None)
    assert isinstance(enrolled.value, RegistryError) and enrolled.value.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("body, expected", [
    ({"detail": "not found"}, None),
    ({"detail": "not found", "id_tree": {"enrolled": False}}, IDTreeEnrollment(enrolled=False, domain=None)),
    ({"detail": "not found", "id_tree": {"enrolled": True, "domain": DOMAIN}}, IDTreeEnrollment(enrolled=True, domain=DOMAIN)),
], ids=["old-404-is-unknown", "stated-not-enrolled", "stated-enrolled"])
async def test_a_missing_key_states_enrollment_only_when_the_registry_says(body, expected):
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(lambda request: httpx.Response(404, json=body)))
    try:
        with pytest.raises(DIDKeyNotFoundError) as missing:
            await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert missing.value.id_tree == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("id_tree", [None, {"enrolled": True}, {"enrolled": "false"}, {"enrolled": False, "domain": DOMAIN}])
async def test_a_malformed_enrollment_on_a_missing_key_rejects(id_tree):
    body = {"detail": "not found", "id_tree": id_tree}
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(lambda request: httpx.Response(404, json=body)))
    try:
        with pytest.raises(ValueError):
            await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_a_missing_key_with_an_unreadable_body_is_unknown():
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(lambda request: httpx.Response(404, content=b"not found")))
    try:
        with pytest.raises(DIDKeyNotFoundError) as missing:
            await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
    assert missing.value.id_tree is None


KEY_RESOLUTION_OUTCOMES = VECTORS["key_resolution_outcomes"]
# Cases whose usable enrollment comes from S4's binding lifecycle rather than a
# response the SDK parses: last-known-good enrollment after a failed refresh.
OUTCOMES_OWNED_BY_S4_BINDING = {"key-resolution-failed-refresh-age-900", "key-resolution-failed-refresh-age-901"}


def _outcome_answer(case: dict) -> httpx.Response:
    if case["http_status"] == 404:
        return httpx.Response(404, json=case["key_response"])
    return httpx.Response(case["http_status"], json=_key_answer(**case["key_response"]))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", [c for c in KEY_RESOLUTION_OUTCOMES if "expected_parse" in c], ids=lambda c: c["name"],
)
async def test_key_resolution_outcome_cases(case):
    """The frozen HTTP and refresh outcomes the SDK parses, by name."""
    requests = []

    def answer(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _outcome_answer(case)

    redis = FakeRedis()
    client = CachedRegistryClient(ORIGIN, redis, transport=httpx.MockTransport(answer))
    if "cached_key_response" in case:
        await redis.set(client._did_key_cache_key(did_aw("alice")), json.dumps({
            "fetched_at": 2_000_000_000, "fresh_until": 2_000_000_000 + 300,
            "value": _key_answer(**case["cached_key_response"]),
        }), ex=600)
    expected = case["expected_parse"]
    stated = {
        "enrolled": IDTreeEnrollment(enrolled=True, domain=expected["domain"]),
        "not_enrolled": IDTreeEnrollment(enrolled=False, domain=None),
        "unknown": None,
    }
    try:
        if expected["state"] == "malformed":
            with pytest.raises(ValueError):
                await client.resolve_key(did_aw("alice"))
        elif case["http_status"] == 404:
            with pytest.raises(DIDKeyNotFoundError) as missing:
                await client.resolve_key(did_aw("alice"))
            assert missing.value.id_tree == stated[expected["state"]]
        else:
            assert (await client.resolve_key(did_aw("alice"))).id_tree == stated[expected["state"]]
    finally:
        await client.aclose()
    if case.get("expected_key_refetch"):
        assert len(requests) == 1


def test_every_key_resolution_outcome_is_accounted_for():
    names = {case["name"] for case in KEY_RESOLUTION_OUTCOMES}
    parsed_here = {case["name"] for case in KEY_RESOLUTION_OUTCOMES if "expected_parse" in case}
    assert len(names) == len(KEY_RESOLUTION_OUTCOMES) == 10
    assert parsed_here | OUTCOMES_OWNED_BY_S4_BINDING == names
    assert not parsed_here & OUTCOMES_OWNED_BY_S4_BINDING


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body", [b"[]", b'["not found"]', b"null", b'"not found"', b"404"],
    ids=["empty-array", "array", "null", "string", "number"],
)
async def test_a_missing_key_whose_json_body_is_not_an_object_rejects(body):
    """As the shared parser treats a non-object response: malformed, never unknown."""
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(
        lambda request: httpx.Response(404, content=body, headers={"Content-Type": "application/json"}),
    ))
    try:
        with pytest.raises(ValueError):
            await client.resolve_key(did_aw("alice"))
    finally:
        await client.aclose()
