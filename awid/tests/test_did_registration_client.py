"""A did:aw's initial registration: the shared entry builder and the signer path.

The signer is a ``payload -> (did_key, raw signature)`` callable, sync or
awaitable, as for the identity-tree writes. A host that keeps the key behind
it rebuilds the exact payload from ``initial_registration_entry`` before it
signs, and the signer path asks it to sign nothing else.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from awid.did import did_from_public_key, stable_id_from_did_key
from awid.id_certificates import verify_ed25519
from awid.log import initial_registration_entry, log_entry_payload
from awid.registry import (
    AlreadyRegisteredError,
    CachedRegistryClient,
    DIDKeyNotFoundError,
    RegistryClient,
)

from id_tree_support import ORIGIN, did_aw, did_key, did_registration_entry
from test_registry_client import FakeRedis

ENTRY_FIELDS = (
    "did_aw", "seq", "operation", "previous_did_key", "new_did_key",
    "prev_entry_hash", "state_hash", "authorized_by", "timestamp",
)


def _did_key(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


def signer_for(key: SigningKey):
    def signer(payload: bytes) -> tuple[str, bytes]:
        return _did_key(key), key.sign(payload).signature

    return signer


def async_signer_for(key: SigningKey):
    async def signer(payload: bytes) -> tuple[str, bytes]:
        await asyncio.sleep(0)
        return _did_key(key), key.sign(payload).signature

    return signer


def test_the_entry_is_the_frozen_initial_registration_of_a_vector_identity():
    frozen = did_registration_entry("alice")

    entry = initial_registration_entry(did_key("alice"), timestamp=frozen["timestamp"])

    assert entry == {"did_aw": did_aw("alice"), **{field: frozen[field] for field in ENTRY_FIELDS[1:]}}
    verify_ed25519(did_key("alice"), log_entry_payload(**entry), base64.b64decode(frozen["signature"] + "=="))


def test_the_entry_refuses_a_did_key_that_does_not_decode_strictly():
    with pytest.raises(ValueError):
        initial_registration_entry("did:key:z6Mknotakey", timestamp="2026-10-29T00:00:00Z")


class Recording(httpx.ASGITransport):
    """The real AWID app, recording every request the client sends it."""

    def __init__(self, app) -> None:
        super().__init__(app=app)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await super().handle_async_request(request)


@pytest_asyncio.fixture
async def awid(clocked_client):
    transport = Recording(clocked_client.app)
    registry = RegistryClient(ORIGIN, transport=transport)
    try:
        yield SimpleNamespace(registry=registry, requests=transport.requests)
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("make_signer", [signer_for, async_signer_for])
async def test_a_signer_registers_the_did_and_is_asked_for_nothing_else(awid, make_signer):
    key = SigningKey.generate()
    asked: list[bytes] = []
    sign = make_signer(key)

    async def signer(payload: bytes):
        asked.append(payload)
        answer = sign(payload)
        return await answer if asyncio.iscoroutine(answer) else answer

    receipt = await awid.registry.register_did_with_signer(_did_key(key), signer=signer)

    stable_id = stable_id_from_did_key(_did_key(key))
    assert receipt == {"registered": True, "did_aw": stable_id, "current_did_key": _did_key(key)}
    [payload] = asked
    [sent] = awid.requests
    body = httpx.Response(200, content=sent.content).json()
    assert (sent.method, sent.url.path, sent.headers.get("Authorization")) == ("POST", "/v1/did", None)
    assert payload == log_entry_payload(**initial_registration_entry(_did_key(key), timestamp=body["timestamp"]))
    assert (await awid.registry.resolve_key(stable_id)).current_did_key == _did_key(key)


@pytest.mark.asyncio
async def test_the_signer_signs_the_entry_at_the_intended_timestamp(awid):
    key = SigningKey.generate()
    asked: list[bytes] = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def signer(payload: bytes):
        asked.append(payload)
        return signer_for(key)(payload)

    await awid.registry.register_did_with_signer(_did_key(key), signer=signer, timestamp=timestamp)

    assert asked == [log_entry_payload(**initial_registration_entry(_did_key(key), timestamp=timestamp))]


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt", [
    {"registered": False},
    {"registered": "true"},
    {"did_aw": "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj"},
    {"current_did_key": "did:key:z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2"},
])
async def test_a_receipt_that_does_not_register_this_did_and_key_is_refused(receipt):
    key = SigningKey.generate()
    answer = {"registered": True, "did_aw": stable_id_from_did_key(_did_key(key)),
              "current_did_key": _did_key(key), **receipt}
    registry = RegistryClient(ORIGIN, transport=httpx.MockTransport(lambda request: httpx.Response(200, json=answer)))
    try:
        with pytest.raises(ValueError):
            await registry.register_did_with_signer(_did_key(key), signer=signer_for(key))
    finally:
        await registry.aclose()


def _raises(payload: bytes):
    raise PermissionError("custody check refused")


def _other_key(key: SigningKey):
    other = SigningKey.generate()
    return lambda payload: (_did_key(other), other.sign(payload).signature)


def _bad_signature(key: SigningKey):
    return lambda payload: (_did_key(key), key.sign(payload + b"x").signature)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["raises", "other_key", "bad_signature"])
async def test_a_refused_or_wrong_signer_answer_sends_nothing(awid, bad):
    key = SigningKey.generate()
    signer = {"raises": lambda: _raises, "other_key": lambda: _other_key(key),
              "bad_signature": lambda: _bad_signature(key)}[bad]()

    with pytest.raises((PermissionError, ValueError)):
        await awid.registry.register_did_with_signer(_did_key(key), signer=signer)

    assert awid.requests == []
    with pytest.raises(DIDKeyNotFoundError):
        await awid.registry.resolve_key(stable_id_from_did_key(_did_key(key)))


@pytest.mark.asyncio
async def test_registering_the_same_key_again_returns_the_same_receipt(awid):
    key = SigningKey.generate()

    first = await awid.registry.register_did_with_signer(_did_key(key), signer=signer_for(key))
    again = await awid.registry.register_did_with_signer(_did_key(key), signer=signer_for(key))

    assert again == first


@pytest.mark.asyncio
async def test_a_did_whose_key_has_rotated_refuses_its_initial_registration(awid):
    key, rotated = SigningKey.generate(), SigningKey.generate()
    receipt = await awid.registry.register_did_with_signer(_did_key(key), signer=signer_for(key))
    await awid.registry.rotate_key(receipt["did_aw"], _did_key(rotated), bytes(key), bytes(rotated))

    with pytest.raises(AlreadyRegisteredError) as refused:
        await awid.registry.register_did_with_signer(_did_key(key), signer=signer_for(key))

    assert (refused.value.did_aw, refused.value.existing_did_key) == (receipt["did_aw"], _did_key(rotated))


@pytest.mark.asyncio
async def test_the_seed_path_signs_the_same_entry_and_keeps_its_mapping(awid):
    key = SigningKey.generate()

    mapping = await awid.registry.register_did(_did_key(key), bytes(key))

    post = awid.requests[0]
    body = httpx.Response(200, content=post.content).json()
    entry = initial_registration_entry(_did_key(key), timestamp=body["timestamp"])
    assert {field: body[field] for field in ENTRY_FIELDS} == entry
    assert base64.b64decode(body["proof"] + "==") == key.sign(log_entry_payload(**entry)).signature
    assert (mapping.did_aw, mapping.current_did_key) == (entry["did_aw"], _did_key(key))


@pytest.mark.asyncio
async def test_the_seed_path_refuses_a_seed_of_another_key_before_sending(awid):
    key, other = SigningKey.generate(), SigningKey.generate()

    with pytest.raises(ValueError):
        await awid.registry.register_did(_did_key(key), bytes(other))

    assert awid.requests == []


@pytest.mark.asyncio
async def test_the_cached_client_drops_a_cached_key_when_it_registers(clocked_client):
    redis = FakeRedis()
    registry = CachedRegistryClient(ORIGIN, redis, transport=httpx.ASGITransport(app=clocked_client.app))
    key, rotated = SigningKey.generate(), SigningKey.generate()
    try:
        receipt = await registry.register_did_with_signer(_did_key(key), signer=signer_for(key))
        await registry.resolve_key(receipt["did_aw"])
        cache_key = registry._did_key_cache_key(receipt["did_aw"])
        assert cache_key in redis.values

        await registry.register_did_with_signer(_did_key(key), signer=signer_for(key))

        assert cache_key not in redis.values
    finally:
        await registry.aclose()
