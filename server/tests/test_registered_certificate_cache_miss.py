"""Strict team auth rechecks a signed, unrevoked certificate missing from a warm list."""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import awid.registry as registry_module
import httpx
import pytest
import pytest_asyncio
from aweb.team_auth_deps import verify_request_certificate
from awid.registry import CachedRegistryClient
from certificate_read_support import scheduled_certificate_readers
from team_facts_fixtures import LegacyTeamFacts
from awid.signing import canonical_json_bytes, sign_message
from fastapi import HTTPException
from redis.asyncio import Redis
from test_team_auth_deps import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _request_with_app_state,
)


class LegacyCacheRegistry(LegacyTeamFacts, CachedRegistryClient):
    """Real cache/transport, with independent explicit-legacy protection facts."""


@pytest_asyncio.fixture
async def world(monkeypatch, aweb_cloud_db):
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    clock = [1_000_000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])
    team, _, team_did = _make_keypair()
    member, _, member_did = _make_keypair()
    env = SimpleNamespace(
        clock=clock,
        team=team,
        team_did=team_did,
        member=member,
        member_did=member_did,
        registered=["cert-earlier"],
        revoked=[],
        list_reads=0,
        point_reads=0,
        list_status=200,
        clients=[],
        entered=asyncio.Event(),
        release=None,
        registry_key=team_did,
        # The real aweb schema: certificate verification reads the team-key pins.
        db=SimpleNamespace(get_manager=lambda _name: aweb_cloud_db.aweb_db),
    )

    async def handler(request):
        if request.url.path.endswith("/revocations"):
            return httpx.Response(
                200,
                json={
                    "revocations": [{"certificate_id": value} for value in env.revoked],
                    "has_more": False,
                },
            )
        if "/certificates/" in request.url.path and request.url.path.endswith(
            "/status"
        ):
            env.point_reads += 1
            cert_id = request.url.path.split("/")[-2]
            if cert_id not in env.registered:
                return httpx.Response(404, json={"detail": "Certificate not found"})
            return httpx.Response(
                200,
                json={
                    "team_id": "backend:acme.com",
                    "team_did_key": env.registry_key,
                    "status": "active",
                    "revoked_at": None,
                },
            )
        if request.url.path.endswith("/certificates"):
            env.list_reads += 1
            env.entered.set()
            if env.release is not None:
                await env.release.wait()
            return httpx.Response(
                env.list_status,
                json={
                    "certificates": [
                        {
                            "certificate_id": value,
                            "member_did_key": member_did,
                            "alias": "member",
                            "identity_scope": "local",
                            "issued_at": "2026-01-01T00:00:00Z",
                            "revoked_at": None,
                        }
                        for value in env.registered
                    ],
                    "has_more": False,
                },
            )
        return httpx.Response(
            200,
            json={
                "team_id": "backend:acme.com",
                "domain": "acme.com",
                "name": "backend",
                "team_did_key": env.registry_key,
                "created_at": "2026-01-01T00:00:00Z",
            },
        )

    env.origin = f"http://{uuid4().hex}.registry.test"
    env.window_key = (
        f"awid:team_certificates_miss_refresh:{env.origin}:acme.com/backend"
    )
    async with Redis.from_url(os.environ["REDIS_URL"], decode_responses=True) as redis:
        env.redis = redis

        def client(**kwargs):
            value = LegacyCacheRegistry(
                registry_url=env.origin,
                redis_client=redis,
                transport=httpx.MockTransport(handler),
                **kwargs,
            )
            env.clients.append(value)
            return value

        env.client = client
        env.registry = client()
        await env.registry.get_team_public_key("acme.com", "backend")
        await env.registry.get_team_revocations("acme.com", "backend")
        await env.registry.list_team_certificates(
            "acme.com", "backend", active_only=False
        )
        env.list_reads = 0
        env.entered.clear()
        try:
            yield env
        finally:
            for value in env.clients:
                await value.aclose()


async def _verify(
    env, certificate_id, *, signer=None, registry=None, bad_request=False
):
    signer_key, signer_did = signer or (env.team, env.team_did)
    cert = _make_certificate(
        signer_key,
        signer_did,
        env.member_did,
        certificate_id=certificate_id,
        identity_scope="local",
    )
    timestamp = datetime.now(UTC).isoformat()
    payload = canonical_json_bytes(
        {
            "team_id": cert["team_id"],
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
        }
    )
    signature = sign_message(env.team if bad_request else env.member, payload)
    request = _request_with_app_state(
        {
            "Authorization": f"DIDKey {env.member_did} {signature}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWID-Team-Certificate": _encode_certificate(cert),
        }
    )
    request.app.state.awid_registry_client = registry or env.registry
    return await verify_request_certificate(request, db=env.db)


async def _refused(env, certificate_id, **kwargs):
    with pytest.raises(HTTPException) as caught:
        await _verify(env, certificate_id, **kwargs)
    return caught.value


def _observation_readers_arrived(registry, monkeypatch, count):
    arrived = asyncio.Event()
    read_observation = registry._read_team_certificate_observation

    async def observe(key):
        state = registry._team_certificate_miss_states.get(key)
        if state is not None and state.readers == count:
            arrived.set()
        return await read_observation(key)

    monkeypatch.setattr(registry, "_read_team_certificate_observation", observe)
    return arrived


@pytest.mark.asyncio
async def test_new_registration_behind_warm_list_is_accepted_and_cached(world):
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert world.list_reads == 1
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_absent_stays_refused_with_cache_shared_across_clients(world):
    for registry in (world.registry, world.registry, world.client()):
        error = await _refused(world, "cert-never", registry=registry)
        assert (error.status_code, error.detail) == (401, "unregistered")
    assert (world.list_reads, world.point_reads) == (1, 1)


@pytest.mark.asyncio
async def test_revoked_stays_refused_without_miss_refresh(world):
    world.revoked.append("cert-revoked")
    # Revocations expire before the ten-minute certificate-list tier.
    world.clock[0] += 121
    await world.registry.get_team_revocations("acme.com", "backend")
    error = await _refused(world, "cert-revoked")
    assert (error.status_code, error.detail["code"]) == (401, "certificate_revoked")
    assert world.list_reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_request", [False, True])
async def test_forged_signature_does_not_spend_list_refresh_budget(world, bad_request):
    forger, _, forger_did = _make_keypair()
    error = await _refused(
        world, "cert-forged", signer=(forger, forger_did), bad_request=bad_request
    )
    assert error.status_code == 401
    assert error.detail != "unregistered"
    assert world.list_reads == 0
    assert await world.redis.get(world.window_key) is None
    if bad_request:
        assert (
            await world.redis.get(
                f"awid:team_key_signature_refresh:{world.origin}:acme.com/backend"
            )
            is None
        )
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert world.list_reads == 1


@pytest.mark.asyncio
async def test_list_failure_fails_closed_and_point_read_can_recover(world):
    world.registered.append("cert-new")
    world.list_status = 503
    assert (await _refused(world, "cert-new")).status_code == 503
    assert world.list_reads == 1
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert (world.list_reads, world.point_reads) == (1, 1)


@pytest.mark.asyncio
async def test_redis_admission_failure_never_fetches_authority(world, monkeypatch):
    async def unavailable(*args, **kwargs):
        raise OSError("Redis admission unavailable")

    monkeypatch.setattr(world.redis, "eval", unavailable)
    error = await _refused(world, "cert-never")
    assert error.status_code == 503
    assert world.list_reads == 0


@pytest.mark.asyncio
async def test_concurrent_misses_share_inflight_refresh_past_admission_window(
    world, monkeypatch
):
    world.release = asyncio.Event()
    world.registered.append("cert-new")
    all_arrived = _observation_readers_arrived(world.registry, monkeypatch, 24)
    async with scheduled_certificate_readers() as callers:
        calls = [callers.create_task(_verify(world, "cert-new")) for _ in range(12)]
        try:
            await world.entered.wait()
            await world.redis.delete(world.window_key)
            calls.extend(
                callers.create_task(_verify(world, "cert-new")) for _ in range(12)
            )
            await all_arrived.wait()
            assert world.list_reads == 1
        finally:
            world.release.set()
    results = [call.result() for call in calls]
    assert all(result["certificate_id"] == "cert-new" for result in results)
    assert (world.list_reads, world.point_reads) == (1, 0)


@pytest.mark.asyncio
async def test_slow_refresh_is_bounded_by_existing_timeout(world):
    world.release = asyncio.Event()
    client = world.client(timeout_seconds=0.05)
    try:
        error = await asyncio.wait_for(
            _refused(world, "cert-never", registry=client), 0.5
        )
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
    assert (error.status_code, error.detail["code"]) == (401, "certificate_revoked")


@pytest.mark.asyncio
async def test_caller_cancellation_does_not_extend_deadline_or_cancel_other_waiter(
    world, monkeypatch
):
    world.registered.append("cert-new")
    world.release = asyncio.Event()
    client = world.client(timeout_seconds=60)
    both_arrived = _observation_readers_arrived(client, monkeypatch, 2)
    async with scheduled_certificate_readers() as callers:
        first = callers.create_task(_verify(world, "cert-new", registry=client))
        try:
            await world.entered.wait()
            second = callers.create_task(_verify(world, "cert-new", registry=client))
            await both_arrived.wait()
            with pytest.raises(asyncio.CancelledError):
                async with asyncio.timeout(10):
                    first.cancel()
                    await first
            assert not world.release.is_set()
            assert not second.done()
        finally:
            world.release.set()
    assert second.result()["certificate_id"] == "cert-new"
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
    assert (await _verify(world, "cert-new", registry=service))[
        "certificate_id"
    ] == "cert-new"
    assert world.list_reads == 1
    assert "cert-new" not in {
        cert.certificate_id
        for cert in await world.registry.list_team_certificates(
            "acme.com",
            "backend",
            active_only=False,
        )
    }
    # The exact standing can be shared without updating the ordinary list or
    # exposing the service reader's member metadata.
    assert (await _verify(world, "cert-new"))["certificate_id"] == "cert-new"
    assert (world.list_reads, world.point_reads) == (1, 0)
    assert "cert-new" not in {
        cert.certificate_id
        for cert in await world.registry.list_team_certificates(
            "acme.com",
            "backend",
            active_only=False,
        )
    }


@pytest.mark.asyncio
async def test_existing_positive_never_acquires_miss_admission(world):
    assert (await _verify(world, "cert-earlier"))["certificate_id"] == "cert-earlier"
    assert await world.redis.get(world.window_key) is None
    assert (world.list_reads, world.point_reads) == (0, 0)


@pytest.mark.asyncio
async def test_new_registration_and_rotated_key_can_recover_together(world):
    new, _, new_did = _make_keypair()
    world.registry_key = new_did
    world.registered.append("cert-new")
    assert (await _verify(world, "cert-new", signer=(new, new_did)))[
        "certificate_id"
    ] == "cert-new"
    assert world.list_reads == 1
