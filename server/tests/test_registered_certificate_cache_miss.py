"""Strict team auth rechecks a signed, unrevoked certificate missing from a warm list."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace

import awid.registry as registry_module
import httpx
import pytest
import pytest_asyncio
from aweb.team_auth_deps import verify_request_certificate
from awid.registry import CachedRegistryClient
from team_facts_fixtures import LegacyTeamFacts
from awid.signing import canonical_json_bytes, sign_message
from fastapi import HTTPException
from test_team_auth_deps import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _request_with_app_state,
)
from test_team_key_rotation_cache import _Redis


class LegacyCacheRegistry(LegacyTeamFacts, CachedRegistryClient):
    """Real cache/transport, with independent explicit-legacy protection facts."""


@pytest_asyncio.fixture
async def world(monkeypatch):
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    clock = [1_000_000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])
    team, _, team_did = _make_keypair()
    member, _, member_did = _make_keypair()
    env = SimpleNamespace(
        clock=clock, team=team, team_did=team_did, member=member, member_did=member_did,
        registered=["cert-earlier"], revoked=[], list_reads=0, list_status=200, clients=[],
        entered=asyncio.Event(), release=None, registry_key=team_did,
    )

    async def handler(request):
        if request.url.path.endswith("/revocations"):
            return httpx.Response(200, json={
                "revocations": [{"certificate_id": value} for value in env.revoked], "has_more": False,
            })
        if request.url.path.endswith("/certificates"):
            env.list_reads += 1
            env.entered.set()
            if env.release is not None:
                await env.release.wait()
            return httpx.Response(env.list_status, json={
                "certificates": [{
                    "certificate_id": value, "member_did_key": member_did, "alias": "member",
                    "identity_scope": "local", "issued_at": "2026-01-01T00:00:00Z", "revoked_at": None,
                } for value in env.registered], "has_more": False,
            })
        return httpx.Response(200, json={
            "team_id": "backend:acme.com", "domain": "acme.com", "name": "backend",
            "team_did_key": env.registry_key, "created_at": "2026-01-01T00:00:00Z",
        })

    env.redis = _Redis(clock)

    def client(**kwargs):
        value = LegacyCacheRegistry(
            registry_url="http://registry.test", redis_client=env.redis,
            transport=httpx.MockTransport(handler), **kwargs,
        )
        env.clients.append(value)
        return value

    env.client = client
    env.registry = client()
    await env.registry.get_team_public_key("acme.com", "backend")
    await env.registry.get_team_revocations("acme.com", "backend")
    await env.registry.list_team_certificates("acme.com", "backend", active_only=False)
    env.list_reads = 0
    env.entered.clear()
    try:
        yield env
    finally:
        for value in env.clients:
            await value.aclose()


async def _verify(env, certificate_id, *, signer=None, registry=None, bad_request=False):
    signer_key, signer_did = signer or (env.team, env.team_did)
    cert = _make_certificate(signer_key, signer_did, env.member_did,
                             certificate_id=certificate_id, identity_scope="local")
    timestamp = datetime.now(UTC).isoformat()
    payload = canonical_json_bytes({
        "team_id": cert["team_id"], "timestamp": timestamp, "body_sha256": hashlib.sha256(b"").hexdigest(),
    })
    signature = sign_message(env.team if bad_request else env.member, payload)
    request = _request_with_app_state({
        "Authorization": f"DIDKey {env.member_did} {signature}",
        "X-AWEB-Timestamp": timestamp, "X-AWID-Team-Certificate": _encode_certificate(cert),
    })
    request.app.state.awid_registry_client = registry or env.registry
    return await verify_request_certificate(request, db=object())


async def _refused(env, certificate_id, **kwargs):
    with pytest.raises(HTTPException) as caught:
        await _verify(env, certificate_id, **kwargs)
    return caught.value


@pytest.mark.asyncio
async def test_new_registration_behind_warm_list_is_accepted_and_cached(world):
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert world.list_reads == 1
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_absent_stays_refused_with_budget_shared_across_clients(world):
    for index, registry in enumerate((world.registry, world.registry, world.client())):
        error = await _refused(world, "cert-never", registry=registry)
        assert error.status_code == (401 if index == 0 else 503)
        if index == 0:
            assert error.detail == "unregistered"
    assert world.list_reads == 1
    world.clock[0] += 5
    await _refused(world, "cert-never")
    assert world.list_reads == 2


@pytest.mark.asyncio
async def test_revoked_stays_refused_without_miss_refresh(world):
    world.revoked.append("cert-revoked")
    # Revocations expire before the ten-minute certificate-list tier.
    world.clock[0] += 121
    await world.registry.get_team_revocations("acme.com", "backend")
    error = await _refused(world, "cert-revoked")
    assert (error.status_code, error.detail) == (401, "revoked")
    assert world.list_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_request", [False, True])
async def test_forged_signature_does_not_spend_list_refresh_budget(world, bad_request):
    forger, _, forger_did = _make_keypair()
    error = await _refused(world, "cert-forged", signer=(forger, forger_did), bad_request=bad_request)
    assert error.status_code == 401
    assert error.detail != "unregistered"
    assert world.list_reads == 0
    assert not any(key.startswith("awid:team_certificates_miss_refresh:") for key in world.redis.values)
    if bad_request:
        assert not any(key.startswith("awid:team_key_signature_refresh:") for key in world.redis.values)
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_registry_failure_fails_closed_and_is_not_retried_within_budget(world):
    world.registered.append("cert-new")
    world.list_status = 503
    assert (await _refused(world, "cert-new")).status_code == 503
    assert world.list_reads == 1
    assert (await _refused(world, "cert-new")).status_code == 503
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_redis_admission_failure_never_fetches_authority(world):
    world.redis.deny_admission = True
    error = await _refused(world, "cert-never")
    assert error.status_code == 503
    assert world.list_reads == 0


@pytest.mark.asyncio
async def test_concurrent_misses_share_inflight_refresh_past_admission_window(world):
    world.release = asyncio.Event()
    calls = [asyncio.create_task(_refused(world, "cert-never")) for _ in range(12)]
    try:
        await asyncio.wait_for(world.entered.wait(), 1)
        world.clock[0] += 6
        calls.extend(asyncio.create_task(_refused(world, "cert-never")) for _ in range(12))
        await asyncio.sleep(0)
        assert world.list_reads == 1
    finally:
        world.release.set()
        await asyncio.gather(*calls)
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_slow_refresh_is_bounded_by_existing_timeout(world):
    world.release = asyncio.Event()
    client = world.client(timeout_seconds=0.05)
    try:
        error = await asyncio.wait_for(_refused(world, "cert-never", registry=client), 0.5)
        assert error.status_code == 503
    finally:
        world.release.set()
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_key_rotation_and_list_miss_cannot_bypass_current_revocation(world):
    new, _, new_did = _make_keypair()
    world.registry_key = new_did
    world.registered.append("cert-new")
    world.revoked.append("cert-new")
    error = await _refused(world, "cert-new", signer=(new, new_did))
    assert (error.status_code, error.detail) == (401, "revoked")


@pytest.mark.asyncio
async def test_caller_cancellation_does_not_extend_deadline_or_cancel_other_waiter(world):
    world.registered.append("cert-new")
    world.release = asyncio.Event()
    first = asyncio.create_task(_verify(world, "cert-new"))
    await asyncio.wait_for(world.entered.wait(), 1)
    second = asyncio.create_task(_verify(world, "cert-new"))
    await asyncio.sleep(0)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(first, 0.1)
    world.release.set()
    assert (await asyncio.wait_for(second, 1))["certificate_id"] == "cert-new"
    assert world.list_reads == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stall", [False, True])
async def test_cache_write_failure_or_stall_is_transient(world, monkeypatch, stall):
    world.registered.append("cert-new")
    original = world.redis.set

    async def write(key, value, ex=None, nx=False):
        if not nx:
            if stall:
                await asyncio.Event().wait()
            raise OSError("Cache write failed")
        return await original(key, value, ex=ex, nx=nx)

    monkeypatch.setattr(world.redis, "set", write)
    client = world.client(timeout_seconds=0.05)
    error = await asyncio.wait_for(_refused(world, "cert-new", registry=client), 0.5)
    assert error.status_code == 503
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_refresh_writes_only_its_reader_authority_partition(world):
    service = world.client(service_token="test-service-capability-at-least-32-bytes")
    await service.list_team_certificates("acme.com", "backend", active_only=False)
    world.list_reads = 0
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new", registry=service))["certificate_id"] == "cert-new"
    assert world.list_reads == 1
    assert "cert-new" not in {cert.certificate_id for cert in await world.registry.list_team_certificates(
        "acme.com", "backend", active_only=False,
    )}
    # The independent reader cannot reuse private facts or bypass the shared budget.
    assert (await _refused(world, "cert-new")).status_code == 503
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_existing_positive_never_acquires_miss_admission(world):
    world.redis.deny_admission = True
    assert (await _verify(world, "cert-earlier"))["certificate_id"] == "cert-earlier"
    assert world.list_reads == 0


@pytest.mark.asyncio
async def test_new_registration_and_rotated_key_can_recover_together(world):
    new, _, new_did = _make_keypair()
    world.registry_key = new_did
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new", signer=(new, new_did)))["certificate_id"] == "cert-new"
    assert world.list_reads == 1
