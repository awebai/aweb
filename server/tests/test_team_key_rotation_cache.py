"""Real signed team-auth requests across an external AWID key rotation."""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException

import awid.registry as registry_module
from awid.registry import CachedRegistryClient
from awid.signing import canonical_json_bytes, sign_message
from aweb.team_auth_deps import verify_request_certificate
from test_team_auth_deps import (
    _encode_certificate, _make_certificate, _make_keypair, _request_with_app_state,
)


class _Redis:
    def __init__(self, clock):
        self.clock = clock
        self.values = {}
        self.expires = {}
        self.unavailable = False
        self.deny_admission = False

    async def get(self, key):
        if self.unavailable:
            raise OSError("Redis unavailable")
        if self.expires.get(key, float("inf")) <= self.clock[0]:
            self.values.pop(key, None)
        return self.values.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if self.unavailable or (nx and self.deny_admission):
            raise OSError("Redis unavailable")
        if nx and await self.get(key) is not None:
            return False
        self.values[key] = value
        self.expires[key] = self.clock[0] + ex if ex else float("inf")
        return True

    async def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)


@pytest_asyncio.fixture
async def world(monkeypatch):
    monkeypatch.delenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", raising=False)
    clock = [1_000_000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])
    old, _, old_did = _make_keypair()
    new, _, new_did = _make_keypair()
    member, _, member_did = _make_keypair()
    env = SimpleNamespace(
        clock=clock, old=old, old_did=old_did, new=new, new_did=new_did,
        member=member, member_did=member_did, keys={"backend": old_did, "other": old_did},
        key_reads=0, revocation_reads=0, revoked=[], status=200,
        entered=asyncio.Event(), release=None, clients=[],
    )

    async def handler(request):
        if request.url.path.endswith("/revocations"):
            env.revocation_reads += 1
            return httpx.Response(200, json={
                "revocations": [{"certificate_id": value} for value in env.revoked],
                "has_more": False,
            })
        name = request.url.path.rsplit("/", 1)[-1]
        env.key_reads += 1
        if name not in env.keys:
            return httpx.Response(404, json={"detail": "Unknown team"})
        env.entered.set()
        if env.release is not None:
            await env.release.wait()
        return httpx.Response(env.status, json={
            "team_id": f"{name}:acme.com", "domain": "acme.com", "name": name,
            "team_did_key": env.keys[name], "created_at": "2026-01-01T00:00:00Z",
        })

    env.redis = _Redis(clock)

    def client():
        value = CachedRegistryClient(
            registry_url="http://registry.test", redis_client=env.redis,
            transport=httpx.MockTransport(handler),
        )
        env.clients.append(value)
        return value

    env.client = client
    env.registry = client()
    for name in env.keys:
        await env.registry.get_team_public_key("acme.com", name)
        await env.registry.get_team_revocations("acme.com", name)
    env.key_reads = env.revocation_reads = 0
    env.entered.clear()
    try:
        yield env
    finally:
        for value in env.clients:
            await value.aclose()


async def _verify(env, *, signer="new", name="backend", registry=None, cert_patch=None, headers_patch=None):
    cert = _make_certificate(
        getattr(env, signer), getattr(env, signer + "_did"), env.member_did,
        team_id=f"{name}:acme.com",
    )
    cert.update(cert_patch or {})
    timestamp = datetime.now(timezone.utc).isoformat()
    body_hash = hashlib.sha256(b"").hexdigest()
    payload = canonical_json_bytes({
        "team_id": cert["team_id"], "timestamp": timestamp, "body_sha256": body_hash,
    })
    headers = {
        "Authorization": f"DIDKey {env.member_did} {sign_message(env.member, payload)}",
        "X-AWEB-Timestamp": timestamp, "X-AWID-Team-Certificate": _encode_certificate(cert),
    }
    headers.update(headers_patch or {})
    request = _request_with_app_state(headers)
    request.app.state.awid_registry_client = registry or env.registry
    return await verify_request_certificate(request, db=object())


async def _refused(env, **kwargs):
    with pytest.raises(HTTPException) as caught:
        await _verify(env, **kwargs)
    assert caught.value.status_code == 401
    return caught.value.detail


@pytest.mark.asyncio
async def test_external_rotation_recovers_on_first_request_and_updates_cache(world):
    env = world
    # The controller rotates outside this client; its old-key certificate still
    # follows the existing cache freshness policy until the failure refresh.
    env.keys["backend"] = env.new_did
    assert (await _verify(env, signer="old"))["verified_team_did_key"] == env.old_did
    assert env.key_reads == 0
    assert (await _verify(env))["verified_team_did_key"] == env.new_did
    assert env.key_reads == 1
    assert await env.registry.get_team_public_key("acme.com", "backend") == env.new_did
    assert await _refused(env, signer="old") == "bad_signature"
    assert env.key_reads == 1


@pytest.mark.asyncio
async def test_bad_certificate_flood_is_coalesced_including_slow_attempt(world):
    env = world
    env.release = asyncio.Event()
    calls = [asyncio.create_task(_refused(env)) for _ in range(16)]
    try:
        await asyncio.wait_for(env.entered.wait(), timeout=1)
        # The attempt lasts longer than its cooldown: waiters must still join
        # that attempt rather than starting their own requests.
        env.clock[0] += 6
        more = [asyncio.create_task(_refused(env)) for _ in range(8)]
        calls.extend(more)
        await asyncio.sleep(0)
        assert env.key_reads == 1
    finally:
        env.release.set()
        await asyncio.gather(*calls)
    assert env.key_reads == 1


@pytest.mark.asyncio
async def test_cooldown_is_shared_by_clients_and_independent_per_team(world):
    env = world
    other_client = env.client()
    assert await _refused(env) == "bad_signature"
    assert env.key_reads == 1
    assert await _refused(env, registry=other_client) == "bad_signature"
    assert env.key_reads == 1
    await _refused(env, name="other", registry=other_client)
    assert env.key_reads == 2
    env.clock[0] += 5
    await _refused(env, registry=other_client)
    assert env.key_reads == 3


@pytest.mark.asyncio
async def test_second_rotation_recovers_after_cooldown(world):
    env = world
    env.keys["backend"] = env.new_did
    await _verify(env)
    # Another external rotation within the window cannot force another read.
    env.keys["backend"] = env.old_did
    await _refused(env, signer="old")
    assert env.key_reads == 1
    env.clock[0] += 5
    assert (await _verify(env, signer="old"))["verified_team_did_key"] == env.old_did
    assert env.key_reads == 2


@pytest.mark.asyncio
async def test_new_key_retry_reads_revocations_again(world):
    env = world
    env.keys["backend"] = env.new_did
    env.revoked = ["cert-001"]
    assert await _refused(env) == "revoked"
    assert env.key_reads == 1
    assert env.revocation_reads == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 500, 404])
async def test_unchanged_or_failed_refresh_keeps_401_and_original_fact_age(world, status):
    env = world
    cache_key = env.registry._team_public_key_cache_key("acme.com", "backend")
    before = env.redis.values[cache_key]
    env.clock[0] += 2
    env.status = status
    assert await _refused(env) == "bad_signature"
    assert env.key_reads == 1
    assert env.redis.values[cache_key] == before
    await _refused(env)
    assert env.key_reads == 1


@pytest.mark.asyncio
async def test_member_mismatch_never_refreshes_team_key(world):
    _, _, wrong_member = _make_keypair()
    detail = await _refused(world, cert_patch={"member_did_key": wrong_member})
    assert detail == "member_key_mismatch"
    assert world.key_reads == 0


@pytest.mark.asyncio
async def test_redis_admission_failure_never_falls_back_to_an_unbounded_read(world):
    world.redis.deny_admission = True
    await _refused(world)
    await _refused(world)
    assert world.key_reads == 0


@pytest.mark.asyncio
async def test_bad_signature_under_refreshed_key_never_drives_revocation_read(world):
    world.keys["backend"] = world.new_did
    await _refused(world, cert_patch={"signature": sign_message(world.member, b"wrong certificate")})
    assert world.key_reads == 1
    assert world.revocation_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("headers_patch,cert_patch", [
    ({"X-AWID-Team-Certificate": "not-base64"}, {}),
    ({}, {"version": 99}),
    ({}, {"certificate_id": ""}),
    ({"X-AWEB-Timestamp": "2000-01-01T00:00:00Z"}, {}),
])
async def test_non_signature_refusals_never_refresh(world, headers_patch, cert_patch):
    await _refused(world, headers_patch=headers_patch, cert_patch=cert_patch)
    assert world.key_reads == 0


@pytest.mark.asyncio
async def test_unknown_team_has_only_its_existing_discovery_read(world):
    assert await _refused(world, name="missing") == "unknown_team"
    assert world.key_reads == 1


@pytest.mark.asyncio
async def test_cached_revocation_never_triggers_key_refresh(world):
    key = world.registry._team_revocations_cache_key("acme.com", "backend")
    entry = json.loads(world.redis.values[key])
    entry["value"] = ["cert-001"]
    world.redis.values[key] = json.dumps(entry)
    assert await _refused(world, signer="old") == "revoked"
    assert world.key_reads == 0
