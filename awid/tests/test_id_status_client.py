"""The production cached identity-tree status client (docs/id-certificates.md R-1).

Complete evidence is reused to age 60 seconds inclusive, then refreshed
synchronously through one coalesced, bounded attempt. Only after a failed
attempt is last-known-good evidence reused, to age 900 seconds inclusive.
The status and the namespace authority it is checked against are one entry on
one clock, observed once.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import time
import uuid

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

import awid.registry as registry_module
from awid.dns_verify import DnsVerificationError, DomainAuthority
from awid.id_certificates import IDChainEvidence, verify_id_chain
from awid.registry import CachedRegistryClient, RegistryError
from awid_service.deps import get_domain_verifier

from id_tree_support import VECTORS, Tree, at, did_aw, did_key
from test_registry_client import FakeRedis

STATUS_PATH = "/v1/id-certificates/status"
REGISTRY = "http://registry.test"


def _case(name: str) -> dict:
    return next(case for case in VECTORS["verification_cases"] if case["name"] == name)


def _bundle(chain: list[str]) -> dict:
    return {
        "v": 1, "type": "aweb.id-chain",
        "certificates": [copy.deepcopy(VECTORS["certificates"][name]["signed"]) for name in chain],
    }


def _fixture(name: str) -> dict:
    return copy.deepcopy(VECTORS["status_fixtures"][name])


def _open_epoch_key(status: dict) -> str:
    return next(e for e in reversed(status["namespace"]["epochs"]) if e["retired_at"] is None)["did_key"]


VERIFIED = _case("cached-status-age-60")
SUBJECT = VERIFIED["subject"]
BUNDLE = _bundle(VERIFIED["chain"])
DOMAIN = VECTORS["status_fixtures"][VERIFIED["status"]]["domain"]
OTHER_DOMAIN = "other.example"
# An omitted global chain whose private domain the caller supplies.
GLOBAL_SUBJECT = {"id": did_aw("global_agent"), "did_key": did_key("global_agent")}


class Registry:
    """An AWID status endpoint and DNS whose answers and failures a test sets."""

    def __init__(self, clock: list[int]) -> None:
        self.clock = clock
        self.status = {DOMAIN: _fixture("normal")}
        self.controller = {DOMAIN: _open_epoch_key(self.status[DOMAIN])}
        self.http_status = 200
        self.raw_body: bytes | None = None
        self.error_body: bytes | None = None
        self.error_headers: dict[str, str] = {}
        self.requests: list[dict] = []
        self.dns_lookups: list[str] = []
        self.routings: list[str] = []
        self.dns_failure = False
        self.dns_delay = 0.0
        self.http_delay = 0.0
        self.advance_during_fetch = 0
        self.gate: dict[str, asyncio.Event] = {}

    async def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST" and request.url.path == STATUS_PATH
        body = json.loads(request.content)
        self.requests.append(body)
        if body["domain"] in self.gate:
            await self.gate[body["domain"]].wait()
        await asyncio.sleep(self.http_delay)
        self.clock[0] += self.advance_during_fetch
        if self.http_status != 200:
            if self.error_body is not None:
                # Streamed, as a real transport delivers it, so the body is read raw.
                return httpx.Response(
                    self.http_status, headers=self.error_headers, stream=httpx.ByteStream(self.error_body),
                )
            return httpx.Response(self.http_status, json={"detail": "registry unavailable"})
        if self.raw_body is not None:
            return httpx.Response(200, content=self.raw_body)
        return httpx.Response(200, json=self.status[body["domain"]])

    async def verify_domain(self, domain: str) -> DomainAuthority:
        self.dns_lookups.append(domain)
        await asyncio.sleep(self.dns_delay)
        if self.dns_failure:
            raise DnsVerificationError(f"No TXT records found for _awid.{domain}")
        return DomainAuthority(
            controller_did=self.controller[domain], registry_url=REGISTRY, dns_name=f"_awid.{domain}",
        )

    async def route(self, domain: str) -> str:
        self.routings.append(domain)
        return REGISTRY


class ClockedRedis(FakeRedis):
    """A Redis whose server clock a test sets, answering pipelined commands in order."""

    def __init__(self, clock: list[int]) -> None:
        super().__init__()
        self.clock = clock

    async def time(self) -> tuple[int, int]:
        return self.clock[0], 0

    def pipeline(self, transaction: bool = True) -> "ClockedPipeline":
        return ClockedPipeline(self)


class ClockedPipeline:
    def __init__(self, redis: ClockedRedis) -> None:
        self.redis = redis
        self.commands = []

    async def __aenter__(self) -> "ClockedPipeline":
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    def time(self) -> "ClockedPipeline":
        self.commands.append(self.redis.time())
        return self

    def get(self, key: str) -> "ClockedPipeline":
        self.commands.append(self.redis.get(key))
        return self

    async def execute(self) -> list:
        return [await command for command in self.commands]


@pytest_asyncio.fixture
async def env(monkeypatch):
    # clock is the Redis server's; each process's own clock is offset from it.
    clock = [1_000_000]
    offset = [0]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0] + offset[0])
    registry = Registry(clock)
    registry.offset = offset
    redis = ClockedRedis(clock)
    clients = []

    def client(*, timeout_seconds: float = 5.0) -> CachedRegistryClient:
        made = CachedRegistryClient(
            REGISTRY, redis, timeout_seconds=timeout_seconds,
            transport=httpx.MockTransport(registry.handler),
            domain_registry_resolver=registry.route, domain_verifier=registry.verify_domain,
        )
        clients.append(made)
        return made

    registry.client = client()
    registry.make_client = client
    registry.redis = redis
    try:
        yield registry
    finally:
        for made in clients:
            await made.aclose()


async def _evidence(env, *, client=None, bundle=BUNDLE, subject=SUBJECT, domain=DOMAIN) -> IDChainEvidence:
    return await (client or env.client).id_chain_evidence(bundle, subject, domain=domain)


async def _until(condition) -> None:
    async def wait() -> None:
        while not condition():
            await asyncio.sleep(0)

    await asyncio.wait_for(wait(), timeout=1)


def _verdict(evidence: IDChainEvidence, *, bundle=BUNDLE, subject=SUBJECT) -> dict:
    return verify_id_chain(bundle, subject=subject, evidence=evidence, domain=DOMAIN)


def _authority(domain: str, controller_key: str) -> dict:
    return {"domain": domain, "dns_name": f"_awid.{domain}", "inherited": False, "controller_key": controller_key}


@pytest.mark.asyncio
async def test_a_first_read_observes_status_and_authority_together(env):
    evidence = await _evidence(env)
    assert evidence == IDChainEvidence(
        status=_fixture("normal"), namespace_authority=_authority(DOMAIN, env.controller[DOMAIN]),
        age_seconds=0, refresh_failed=False,
    )
    assert env.requests == [{"v": 1, "domain": DOMAIN, "ids": [did_aw("alice")]}]
    assert _verdict(evidence) == VERIFIED["expected"]


@pytest.mark.asyncio
async def test_evidence_is_reused_through_60_seconds_without_dns_or_http(env):
    await _evidence(env)
    env.clock[0] += 60
    evidence = await _evidence(env)
    assert evidence.age_seconds == 60 and evidence.refresh_failed is False
    assert len(env.requests) == len(env.dns_lookups) == len(env.routings) == 1


@pytest.mark.asyncio
async def test_after_60_seconds_the_caller_awaits_a_refresh(env):
    await _evidence(env)
    env.status[DOMAIN] = _fixture("alice-revoked-now")
    env.clock[0] += 61
    evidence = await _evidence(env)
    assert evidence.status == _fixture("alice-revoked-now")
    assert evidence.age_seconds == 0 and evidence.refresh_failed is False
    assert len(env.requests) == len(env.dns_lookups) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [
    "cached-status-age-61-without-failed-refresh",
    "cached-status-age-901-without-failed-refresh",
])
async def test_stale_evidence_is_never_presented_without_a_failed_refresh(env, name):
    case = _case(name)
    bundle, subject = _bundle(case["chain"]), case["subject"]
    assert case["cache"] == {"age_seconds": case["cache"]["age_seconds"], "refresh": "not_needed"}
    stale = IDChainEvidence(
        _fixture(case["status"]), _authority(DOMAIN, env.controller[DOMAIN]), case["cache"]["age_seconds"], False,
    )
    assert _verdict(stale, bundle=bundle, subject=subject) == case["expected"]

    await _evidence(env, bundle=bundle, subject=subject)
    env.clock[0] += case["cache"]["age_seconds"]
    refreshed = await _evidence(env, bundle=bundle, subject=subject)
    assert (refreshed.age_seconds, refreshed.refresh_failed) == (0, False)
    assert _verdict(refreshed, bundle=bundle, subject=subject)["reason"] == "verified"

    env.clock[0] += case["cache"]["age_seconds"]
    env.http_status = 503
    failed = await _evidence(env, bundle=bundle, subject=subject)
    assert (failed.age_seconds, failed.refresh_failed) == (case["cache"]["age_seconds"], True)
    assert _verdict(failed, bundle=bundle, subject=subject) != case["expected"]


@pytest.mark.asyncio
@pytest.mark.parametrize("age, reason", [(61, "verified"), (900, "verified"), (901, "status_expired")])
@pytest.mark.parametrize("failure", ["http-500", "http-429", "dns", "timeout"])
async def test_a_failed_refresh_reuses_last_known_good_evidence_through_900_seconds(env, age, reason, failure):
    first = await _evidence(env)
    stored = dict(env.redis.values)
    env.clock[0] += age
    if failure == "http-500":
        env.http_status = 500
    elif failure == "http-429":
        env.http_status = 429
    elif failure == "dns":
        env.dns_failure = True
    else:
        env.client = env.make_client(timeout_seconds=0.05)
        env.http_delay = 1
    evidence = await _evidence(env)
    assert evidence == IDChainEvidence(first.status, first.namespace_authority, age, True)
    assert _verdict(evidence)["reason"] == reason
    assert env.redis.values == stored  # a failed attempt never restarts the grace


@pytest.mark.asyncio
async def test_last_known_good_is_aged_through_the_failed_attempt(env):
    await _evidence(env)
    env.clock[0] += 61
    env.http_status = 503
    env.advance_during_fetch = 5
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (66, True)


@pytest.mark.asyncio
async def test_a_failed_first_read_has_no_evidence(env):
    env.http_status = 429
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (None, True)
    assert _verdict(evidence)["reason"] == "evidence_unavailable"


@pytest.mark.asyncio
async def test_a_failed_attempt_suppresses_attempts_for_60_seconds(env):
    env.http_status = 503
    for elapsed in (0, 1, 60):
        env.clock[0] = 1_000_000 + elapsed
        evidence = await _evidence(env)
        assert (evidence.age_seconds, evidence.refresh_failed) == (None, True)
        assert len(env.requests) == len(env.dns_lookups) == 1
    env.clock[0] += 1
    await _evidence(env)
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_during_a_cooldown_last_known_good_evidence_keeps_its_true_age(env):
    first = await _evidence(env)
    env.clock[0] += 61
    env.http_status = 503
    assert (await _evidence(env)).age_seconds == 61
    env.clock[0] += 9
    evidence = await _evidence(env)
    assert evidence == IDChainEvidence(first.status, first.namespace_authority, 70, True)
    assert _verdict(evidence)["reason"] == "verified"
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_a_cooldown_never_extends_the_grace(env):
    await _evidence(env)
    env.clock[0] += 850
    env.http_status = 503
    assert _verdict(await _evidence(env))["reason"] == "verified"
    env.clock[0] += 51
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (901, True)
    assert _verdict(evidence)["reason"] == "status_expired"
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_a_success_ends_the_domains_cooldown(env):
    env.gate[DOMAIN] = asyncio.Event()
    succeeding = asyncio.create_task(_evidence(env))
    await _until(lambda: len(env.requests) == 1)
    env.dns_failure = True
    failed = await _evidence(env, bundle=None, subject=GLOBAL_SUBJECT)
    assert failed.refresh_failed is True
    env.dns_failure = False
    env.gate[DOMAIN].set()
    assert (await succeeding).age_seconds == 0
    del env.gate[DOMAIN]
    retried = await _evidence(env, bundle=None, subject=GLOBAL_SUBJECT)
    assert (retried.age_seconds, retried.refresh_failed) == (0, False)
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_a_cooldown_is_per_domain_and_not_persisted(env):
    env.status[OTHER_DOMAIN] = _fixture("normal") | {"domain": OTHER_DOMAIN}
    env.controller[OTHER_DOMAIN] = env.controller[DOMAIN]
    env.http_status = 503
    await _evidence(env)
    env.http_status = 200
    other = await _evidence(env, bundle=None, subject=GLOBAL_SUBJECT, domain=OTHER_DOMAIN)
    assert other.age_seconds == 0
    assert (await _evidence(env)).refresh_failed is True
    assert len(env.requests) == 2
    restarted = await _evidence(env, client=env.make_client())
    assert (restarted.age_seconds, restarted.refresh_failed) == (0, False)
    assert len(env.requests) == 3


@pytest.mark.asyncio
async def test_concurrent_stale_readers_share_one_refresh(env):
    await _evidence(env)
    env.clock[0] += 61
    env.status[DOMAIN] = _fixture("alice-rotated")
    env.gate[DOMAIN] = asyncio.Event()
    readers = [asyncio.create_task(_evidence(env)) for _ in range(5)]
    await _until(lambda: len(env.requests) == 2)
    await asyncio.sleep(0.01)
    assert not any(reader.done() for reader in readers)
    env.gate[DOMAIN].set()
    results = await asyncio.gather(*readers)
    assert len(env.requests) == len(env.dns_lookups) == 2
    assert all(result.status == _fixture("alice-rotated") and result.age_seconds == 0 for result in results)


@pytest.mark.asyncio
async def test_concurrent_readers_share_one_failed_attempt(env):
    await _evidence(env)
    env.clock[0] += 61
    env.http_status = 500
    env.gate[DOMAIN] = asyncio.Event()
    readers = [asyncio.create_task(_evidence(env)) for _ in range(3)]
    await _until(lambda: len(env.requests) == 2)
    env.gate[DOMAIN].set()
    results = await asyncio.gather(*readers)
    assert len(env.requests) == 2
    assert all((result.age_seconds, result.refresh_failed) == (61, True) for result in results)


@pytest.mark.asyncio
async def test_a_cancelled_reader_does_not_cancel_the_shared_refresh(env):
    await _evidence(env)
    env.clock[0] += 61
    env.status[DOMAIN] = _fixture("alice-rotated")
    env.gate[DOMAIN] = asyncio.Event()
    first = asyncio.create_task(_evidence(env))
    second = asyncio.create_task(_evidence(env))
    await _until(lambda: len(env.requests) == 2)
    first.cancel()
    env.gate[DOMAIN].set()
    assert (await second).status == _fixture("alice-rotated")
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_one_timeout_bounds_dns_and_http_together(env):
    env.client = env.make_client(timeout_seconds=0.3)
    env.dns_delay = env.http_delay = 0.2
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (None, True)
    env.clock[0] += 61
    env.dns_delay = env.http_delay = 0.1
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (0, False)


@pytest.mark.asyncio
async def test_a_stalled_domain_does_not_delay_another_domain(env):
    env.status[OTHER_DOMAIN] = _fixture("normal") | {"domain": OTHER_DOMAIN}
    env.controller[OTHER_DOMAIN] = env.controller[DOMAIN]
    env.gate[DOMAIN] = asyncio.Event()
    stalled = asyncio.create_task(_evidence(env))
    await _until(lambda: len(env.requests) == 1)
    other = await asyncio.wait_for(
        _evidence(env, bundle=None, subject=GLOBAL_SUBJECT, domain=OTHER_DOMAIN), timeout=1,
    )
    assert (other.status["domain"], other.age_seconds) == (OTHER_DOMAIN, 0)
    assert not stalled.done()
    env.gate[DOMAIN].set()
    assert (await stalled).age_seconds == 0


@pytest.mark.asyncio
async def test_a_stalled_domain_does_not_age_another_domains_entry(env):
    env.status[OTHER_DOMAIN] = _fixture("normal") | {"domain": OTHER_DOMAIN}
    env.controller[OTHER_DOMAIN] = env.controller[DOMAIN]
    await _evidence(env)
    env.clock[0] += 30
    await _evidence(env, bundle=None, subject=GLOBAL_SUBJECT, domain=OTHER_DOMAIN)
    env.clock[0] += 31
    env.http_status = 503
    assert (await _evidence(env)).refresh_failed is True
    other = await _evidence(env, bundle=None, subject=GLOBAL_SUBJECT, domain=OTHER_DOMAIN)
    assert (other.age_seconds, other.refresh_failed) == (31, False)


@pytest.mark.asyncio
async def test_the_observation_time_is_when_the_refresh_began(env):
    env.advance_during_fetch = 7
    evidence = await _evidence(env)
    assert evidence.age_seconds == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("writer_skew", [600, -600])
async def test_a_shared_entry_is_aged_on_the_redis_clock_whatever_the_process_clocks(env, writer_skew):
    writer, reader = env.make_client(), env.make_client()
    env.offset[0] = writer_skew
    await _evidence(env, client=writer)
    env.status[DOMAIN] = _fixture("alice-revoked-now")
    env.clock[0] += 620  # the reader's first read, long after its clock passed the writer's stamp
    env.offset[0] = 0
    env.http_status = 503
    stale = await _evidence(env, client=reader)
    assert (stale.status, stale.age_seconds, stale.refresh_failed) == (_fixture("normal"), 620, True)

    env.clock[0] += 61  # past the reader's cooldown
    env.http_status = 200
    refreshed = await _evidence(env, client=reader)
    assert (refreshed.status, refreshed.age_seconds, refreshed.refresh_failed) == (
        _fixture("alice-revoked-now"), 0, False,
    )


@pytest.mark.asyncio
async def test_a_process_clock_far_from_the_redis_clock_still_reuses_fresh_evidence(env):
    await _evidence(env)
    env.clock[0] += 30
    env.offset[0] = 3600
    evidence = await _evidence(env, client=env.make_client())
    assert (evidence.age_seconds, evidence.refresh_failed) == (30, False)
    assert len(env.requests) == 1


@pytest.mark.asyncio
async def test_an_entry_stamped_ahead_of_the_redis_clock_is_refreshed(env):
    await _evidence(env)
    env.status[DOMAIN] = _fixture("alice-revoked-now")
    env.clock[0] -= 1  # the Redis clock stepped back
    evidence = await _evidence(env)
    assert evidence.status == _fixture("alice-revoked-now")
    assert (evidence.age_seconds, evidence.refresh_failed) == (0, False)
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_an_entry_stamped_ahead_of_the_redis_clock_gives_no_grace(env):
    await _evidence(env)
    env.clock[0] -= 1
    env.http_status = 503
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (None, True)
    assert _verdict(evidence)["reason"] == "evidence_unavailable"


class UnavailableRedis(FakeRedis):
    async def get(self, key: str):
        raise OSError("Redis unavailable")

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        raise OSError("Redis unavailable")

    async def time(self):
        raise OSError("Redis unavailable")

    def pipeline(self, transaction: bool = True):
        raise OSError("Redis unavailable")


@pytest.mark.asyncio
async def test_without_redis_each_read_is_fetched_and_none_is_reused(env):
    client = CachedRegistryClient(
        REGISTRY, UnavailableRedis(), transport=httpx.MockTransport(env.handler),
        domain_registry_resolver=env.route, domain_verifier=env.verify_domain,
    )
    try:
        first = await _evidence(env, client=client)
        env.clock[0] += 1
        second = await _evidence(env, client=client)
    finally:
        await client.aclose()
    assert (first.age_seconds, first.refresh_failed, second.age_seconds) == (0, False, 0)
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_a_clock_stepping_back_during_a_refresh_leaves_its_evidence_unavailable(env):
    env.advance_during_fetch = -5
    evidence = await _evidence(env)
    assert evidence.age_seconds == -5
    assert _verdict(evidence)["reason"] == "evidence_unavailable"


@pytest.mark.asyncio
async def test_a_cooldown_recorded_ahead_of_this_clock_does_not_suppress_attempts(env):
    env.http_status = 503
    await _evidence(env)
    env.offset[0] -= 1  # this process's clock stepped back
    env.http_status = 200
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (0, False)
    assert len(env.requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("fetched_at", [1_000_000.5, "1000000", True, None])
async def test_a_corrupt_stored_entry_is_dropped_and_refreshed(env, fetched_at):
    await _evidence(env)
    [key] = env.redis.values
    entry = json.loads(env.redis.values[key])
    env.redis.values[key] = json.dumps(entry | {"fetched_at": fetched_at})
    env.clock[0] += 1
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (0, False)
    assert len(env.requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("body, headers", [
    (b"<html>" + b"x" * (64 * 1024) + b"</html>", {"Content-Type": "text/html"}),
    (b"\x1f\x8b compressed error page", {"Content-Encoding": "gzip"}),
], ids=["oversized-error-page", "encoded-error-page"])
async def test_an_unreadable_refusal_is_a_failed_refresh(env, body, headers):
    first = await _evidence(env)
    env.clock[0] += 61
    env.http_status = 502
    env.error_body, env.error_headers = body, headers
    evidence = await _evidence(env)
    assert evidence == IDChainEvidence(first.status, first.namespace_authority, 61, True)
    env.clock[0] += 1
    assert (await _evidence(env)).refresh_failed is True
    assert len(env.requests) == 2  # the failure opened the cooldown


@pytest.mark.asyncio
async def test_a_restarted_client_keeps_the_original_observation_time(env):
    await _evidence(env)
    env.clock[0] += 61
    env.http_status = 503
    restarted = env.make_client()
    evidence = await _evidence(env, client=restarted)
    assert (evidence.age_seconds, evidence.refresh_failed) == (61, True)


@pytest.mark.asyncio
@pytest.mark.parametrize("fixture", ["human-not-registered", "alice-revoked-now", "root-replaced"])
async def test_a_successful_answer_replaces_prior_evidence_even_through_a_later_outage(env, fixture):
    await _evidence(env)
    env.clock[0] += 61
    env.status[DOMAIN] = _fixture(fixture)
    env.controller[DOMAIN] = _open_epoch_key(env.status[DOMAIN])
    replaced = await _evidence(env)
    assert replaced.status == _fixture(fixture)
    env.clock[0] += 61
    env.http_status = 500
    evidence = await _evidence(env)
    assert (evidence.status, evidence.age_seconds, evidence.refresh_failed) == (_fixture(fixture), 61, True)


@pytest.mark.asyncio
async def test_contradictory_authority_is_kept_as_current_and_never_verifies(env):
    await _evidence(env)
    env.clock[0] += 61
    env.controller[DOMAIN] = did_key("other_human")
    evidence = await _evidence(env)
    assert evidence.namespace_authority["controller_key"] == did_key("other_human")
    assert evidence.age_seconds == 0
    assert _verdict(evidence)["reason"] == "evidence_unavailable"
    env.clock[0] += 61
    env.http_status = 500
    assert _verdict(await _evidence(env))["reason"] == "evidence_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b"not json", b"[]", b'"status"'])
async def test_a_malformed_successful_answer_is_unavailable_and_ends_the_old_tree(env, body):
    await _evidence(env)
    env.clock[0] += 61
    env.raw_body = body
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (None, False)
    assert _verdict(evidence)["reason"] == "evidence_unavailable"
    env.raw_body = None
    env.http_status = 500
    evidence = await _evidence(env)
    assert (evidence.age_seconds, evidence.refresh_failed) == (None, True)


@pytest.mark.asyncio
async def test_a_chainless_local_subject_creates_no_registry_dependency(env):
    local = {"id": did_key("global_agent"), "did_key": did_key("global_agent")}
    evidence = await _evidence(env, bundle=None, subject=local)
    assert evidence.age_seconds is None
    assert env.requests == env.dns_lookups == env.routings == []
    assert verify_id_chain(None, subject=local, evidence=evidence, domain=DOMAIN)["reason"] == "legacy_no_chain"


@pytest.mark.asyncio
async def test_a_bundle_for_another_domain_creates_no_registry_dependency(env):
    evidence = await _evidence(env, domain=OTHER_DOMAIN)
    assert evidence.age_seconds is None
    assert env.requests == env.dns_lookups == []
    assert verify_id_chain(BUNDLE, subject=SUBJECT, evidence=evidence, domain=OTHER_DOMAIN)["reason"] == "domain_mismatch"


@pytest.mark.asyncio
async def test_the_raw_status_fetch_raises_on_a_rate_limited_answer(env):
    env.http_status = 429
    with pytest.raises(RegistryError) as refused:
        await env.client.fetch_id_certificate_status(DOMAIN, {"v": 1, "domain": DOMAIN, "ids": []})
    assert refused.value.status_code == 429


@pytest.mark.asyncio
async def test_the_cached_client_reads_the_real_status_endpoint(clocked_client, manual_clock):
    tree = Tree(clocked_client, manual_clock)
    tree.clock.now = at("2026-10-26T00:00:00Z")
    await tree.root()
    for key_name in ("alice", "global_agent"):
        await tree.vector_did(key_name)
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("alice", "global-agent", when=at("2026-10-26T00:04:00Z"))
    tree.clock.now = at("2026-10-26T00:30:00Z")

    async def service_dns(domain: str) -> DomainAuthority:
        return await clocked_client.app.dependency_overrides[get_domain_verifier]()(domain)

    redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    client = CachedRegistryClient(
        "http://testserver", redis, transport=httpx.ASGITransport(app=clocked_client.app),
        domain_verifier=service_dns,
    )
    subject = {"id": did_aw("global_agent"), "did_key": did_key("global_agent")}
    bundle = _bundle(["alice", "global-agent"])
    key = client._id_status_cache_key({"v": 1, "domain": DOMAIN, "ids": [did_aw("alice"), did_aw("global_agent")]})
    try:
        await redis.delete(key)
        evidence = await client.id_chain_evidence(bundle, subject, domain=DOMAIN)
    finally:
        await redis.delete(key)
        await client.aclose()
        await redis.aclose()
    assert (evidence.age_seconds, evidence.refresh_failed) == (0, False)
    verdict = verify_id_chain(bundle, subject=subject, evidence=evidence, domain=DOMAIN)
    assert verdict == {
        "outcome": "nearest_human", "human_id": did_aw("alice"), "identity_valid": True,
        "kind": "agent", "reason": "verified",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("skew", [600, -600])
async def test_real_redis_ages_shared_evidence_on_its_own_clock(env, monkeypatch, skew):
    """Two processes whose clocks disagree share one entry through a real Redis."""
    domain = f"{uuid.uuid4().hex}.example"
    env.status[domain] = _fixture("normal") | {"domain": domain}
    env.controller[domain] = env.controller[DOMAIN]
    redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    clients = [
        CachedRegistryClient(
            REGISTRY, redis, transport=httpx.MockTransport(env.handler),
            domain_registry_resolver=env.route, domain_verifier=env.verify_domain,
        )
        for _ in range(2)
    ]
    key = clients[0]._id_status_cache_key({"v": 1, "domain": domain, "ids": [did_aw("global_agent")]})
    try:
        monkeypatch.setattr(registry_module, "_cache_now", lambda: int(time.time()) + skew)
        written = await _evidence(env, client=clients[0], bundle=None, subject=GLOBAL_SUBJECT, domain=domain)
        monkeypatch.setattr(registry_module, "_cache_now", lambda: int(time.time()) - skew)
        read = await _evidence(env, client=clients[1], bundle=None, subject=GLOBAL_SUBJECT, domain=domain)
    finally:
        await redis.delete(key)
        for client in clients:
            await client.aclose()
        await redis.aclose()
    assert (written.age_seconds, written.refresh_failed) == (0, False)
    assert read.refresh_failed is False and 0 <= read.age_seconds <= 2
    assert len(env.requests) == 1
