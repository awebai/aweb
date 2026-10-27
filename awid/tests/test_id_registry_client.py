"""The public identity-tree registry client: register, revoke and signed rotation.

Each call takes a signer, a ``payload -> (did_key, raw signature)`` callable
whose result may also be awaitable, and owns everything else: the exact body bytes, the covering-v2
payload and its headers, and the checks on what the signer returned, made
before anything is sent.
"""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest
import pytest_asyncio
from nacl.signing import SigningKey

import awid.registry as registry_module
from awid.id_certificates import decode_id_chain_header
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError

from id_tree_support import ORIGIN, VECTORS, Tree, at, certificate, certificate_id, did_aw, did_key, seed
from test_registry_client import FakeRedis

DOMAIN = "example.com"
EXAMPLE = VECTORS["registration_example"]
ROTATION = VECTORS["namespace_rotation_requests"]


def signer_for(key_name: str):
    def signer(payload: bytes) -> tuple[str, bytes]:
        return did_key(key_name), SigningKey(seed(key_name)).sign(payload).signature

    return signer


def async_signer_for(key_name: str):
    """A signer that, like a custodial host's, finishes its own checks before answering."""

    async def signer(payload: bytes) -> tuple[str, bytes]:
        await asyncio.sleep(0)
        return did_key(key_name), SigningKey(seed(key_name)).sign(payload).signature

    return signer


def refusing_signer(payload: bytes):
    raise PermissionError("custody check refused")


async def _refuse_later(payload: bytes):
    await asyncio.sleep(0)
    raise PermissionError("custody check refused")


def _bundle(*names: str) -> dict:
    return {"v": 1, "type": "aweb.id-chain", "certificates": [certificate(name) for name in names]}


class Recorder:
    """A registry that records each request and answers with a set response."""

    def __init__(self, response: httpx.Response | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.response = response or httpx.Response(200, json={})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


@pytest_asyncio.fixture
async def recorded():
    recorder = Recorder()
    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(recorder.handler))
    recorder.client = client
    try:
        yield recorder
    finally:
        await client.aclose()


def _sent_headers(request: httpx.Request, names) -> dict:
    return {name: request.headers.get(name) for name in names}


@pytest.mark.asyncio
@pytest.mark.parametrize("make_signer", [signer_for, async_signer_for], ids=["sync", "async"])
async def test_registration_reproduces_the_frozen_example_byte_for_byte(recorded, monkeypatch, make_signer):
    monkeypatch.setattr(registry_module, "_utc_timestamp", lambda: EXAMPLE["payload"]["timestamp"])
    recorded.response = httpx.Response(200, json=EXAMPLE["response"])
    bundle = decode_id_chain_header(EXAMPLE["headers"]["X-AWID-ID-Chain"])

    receipt = await recorded.client.register_id_certificate(
        bundle, signer=make_signer("bob"),
        expected_head=EXAMPLE["body"]["expected_head"], invitation_id=EXAMPLE["body"]["invitation_id"],
    )

    assert receipt == EXAMPLE["response"]
    [sent] = recorded.requests
    assert (sent.method, sent.url.path) == ("POST", EXAMPLE["payload"]["path"])
    assert sent.content == EXAMPLE["body_utf8"].encode()
    assert _sent_headers(sent, EXAMPLE["headers"]) == EXAMPLE["headers"]


@pytest.mark.asyncio
@pytest.mark.parametrize("make_signer", [signer_for, async_signer_for], ids=["sync", "async"])
async def test_signed_rotation_reproduces_the_frozen_request_byte_for_byte(recorded, monkeypatch, make_signer):
    frozen = ROTATION["valid"]
    monkeypatch.setattr(registry_module, "_utc_timestamp", lambda: frozen["payload"]["timestamp"])
    recorded.response = httpx.Response(200, json={
        "namespace_id": "00000000-0000-4000-8000-000000000009", "domain": DOMAIN,
        "controller_did": frozen["body"]["new_did_key"], "verification_status": "verified",
        "last_verified_at": "2026-10-26T00:10:00Z", "created_at": "2026-10-26T00:00:00Z",
    })

    namespace = await recorded.client.rotate_namespace_with_previous_key(
        DOMAIN, from_seq=frozen["body"]["from_seq"],
        previous_did_key=frozen["body"]["previous_did_key"], new_did_key=frozen["body"]["new_did_key"],
        previous_signer=make_signer("root"), new_signer=make_signer("root_rotated"),
    )

    assert namespace.controller_did == frozen["body"]["new_did_key"]
    [sent] = recorded.requests
    assert (sent.method, sent.url.path) == ("POST", frozen["payload"]["path"])
    assert sent.content == frozen["body_utf8"].encode()
    assert _sent_headers(sent, frozen["headers"]) == frozen["headers"]


def _wrong_key(key_name: str, reported: str):
    sign = signer_for(key_name)
    return lambda payload: (reported, sign(payload)[1])


def _short_signature(key_name: str):
    sign = signer_for(key_name)
    return lambda payload: (did_key(key_name), sign(payload)[1][:63])


def _encoded_signature(key_name: str):
    sign = signer_for(key_name)
    return lambda payload: (did_key(key_name), sign(payload)[1].hex().encode())


def _noncanonical_key(key_name: str):
    sign = signer_for(key_name)
    return lambda payload: (did_key(key_name) + " ", sign(payload)[1])


def _awaitable(signer):
    async def wrapped(payload: bytes):
        return signer(payload)

    return wrapped


@pytest.mark.asyncio
@pytest.mark.parametrize("signer", [refusing_signer, _refuse_later], ids=["sync", "async"])
async def test_a_refusing_signer_sends_nothing(recorded, signer):
    with pytest.raises(PermissionError):
        await recorded.client.register_id_certificate(
            _bundle("alice", "bob"), signer=signer, expected_head=None, invitation_id=None,
        )
    with pytest.raises(PermissionError):
        await recorded.client.revoke_id_certificate(
            DOMAIN, did_aw("bob"), signer=signer, expected_head=certificate_id("bob"),
        )
    with pytest.raises(PermissionError):
        await recorded.client.rotate_namespace_with_previous_key(
            DOMAIN, from_seq=1, previous_did_key=did_key("root"), new_did_key=did_key("root_rotated"),
            previous_signer=signer_for("root"), new_signer=signer,
        )
    assert recorded.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("wrap", [lambda signer: signer, _awaitable], ids=["sync", "async"])
@pytest.mark.parametrize("bad_signer", [
    _short_signature("bob"),
    _encoded_signature("bob"),
    _noncanonical_key("bob"),
    lambda payload: ("did:aw:" + did_aw("bob")[7:], SigningKey(seed("bob")).sign(payload).signature),
    lambda payload: [did_key("bob"), SigningKey(seed("bob")).sign(payload).signature],
    _wrong_key("alice", did_key("bob")),
], ids=["short-signature", "encoded-signature", "noncanonical-key", "not-a-did-key", "not-a-tuple",
        "signed-by-another-key"])
async def test_a_malformed_signer_result_sends_nothing(recorded, bad_signer, wrap):
    with pytest.raises(ValueError):
        await recorded.client.register_id_certificate(
            _bundle("alice", "bob"), signer=wrap(bad_signer), expected_head=None, invitation_id=None,
        )
    with pytest.raises(ValueError):
        await recorded.client.revoke_id_certificate(
            DOMAIN, did_aw("bob"), signer=wrap(bad_signer), expected_head=certificate_id("bob"),
        )
    assert recorded.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("previous_signer, new_signer", [
    (signer_for("root_rotated"), signer_for("root")),
    (signer_for("root"), signer_for("root")),
    (signer_for("root"), _wrong_key("alice", did_key("root_rotated"))),
], ids=["swapped-roles", "one-key-signs-both", "reported-key-is-not-the-signing-key"])
async def test_a_rotation_signer_that_does_not_hold_its_named_key_sends_nothing(recorded, previous_signer, new_signer):
    with pytest.raises(ValueError):
        await recorded.client.rotate_namespace_with_previous_key(
            DOMAIN, from_seq=1, previous_did_key=did_key("root"), new_did_key=did_key("root_rotated"),
            previous_signer=previous_signer, new_signer=new_signer,
        )
    assert recorded.requests == []


@pytest.mark.asyncio
async def test_the_signed_payload_header_is_base64url_of_the_signed_bytes(recorded):
    # Bytes like "?>~" encode to the two characters where base64 and base64url differ.
    domain = "?>~.example"
    await recorded.client.revoke_id_certificate(
        domain, did_aw("bob"), signer=signer_for("root"), expected_head=certificate_id("bob"),
    )
    [sent] = recorded.requests
    header = sent.headers["X-AWEB-Signed-Payload"]
    signed = base64.b64decode(header + "=" * (-len(header) % 4), altchars=b"-_", validate=True)
    assert json.loads(signed)["domain"] == domain
    assert set("-_") & set(header) and not set("+/") & set(header)


@pytest.mark.asyncio
async def test_a_coded_refusal_keeps_its_code(recorded):
    recorded.response = httpx.Response(409, json={"detail": {"code": "head_conflict", "message": "head conflict"}})
    with pytest.raises(RegistryError) as refused:
        await recorded.client.revoke_id_certificate(
            DOMAIN, did_aw("bob"), signer=signer_for("root"), expected_head=certificate_id("bob"),
        )
    assert (refused.value.status_code, refused.value.code) == (409, "head_conflict")


@pytest.mark.asyncio
async def test_an_uncoded_refusal_has_no_code(recorded):
    recorded.response = httpx.Response(429, json={"detail": "rate limit exceeded"})
    with pytest.raises(RegistryError) as refused:
        await recorded.client.revoke_id_certificate(
            DOMAIN, did_aw("bob"), signer=signer_for("root"), expected_head=certificate_id("bob"),
        )
    assert (refused.value.status_code, refused.value.code, refused.value.detail) == (
        429, None, "rate limit exceeded",
    )


# ---------------------------------------------------------------------------
# Through the real AWID routes
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def live(clocked_client, manual_clock):
    tree = Tree(clocked_client, manual_clock)
    tree.clock.now = at("2026-10-26T00:00:00Z")
    await tree.root()
    for key_name in ("alice", "bob"):
        await tree.vector_did(key_name)
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    client = CachedRegistryClient(
        ORIGIN, FakeRedis(), transport=httpx.ASGITransport(app=clocked_client.app),
    )
    tree.registry = client
    try:
        yield tree
    finally:
        await client.aclose()


async def _status(tree, *ids: str) -> dict:
    resp = await tree.client.post("/v1/id-certificates/status", json={"v": 1, "domain": DOMAIN, "ids": list(ids)})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_a_registration_and_its_exact_retry_through_the_real_routes(live):
    invitation = EXAMPLE["body"]["invitation_id"]
    live.clock.now = at("2026-10-26T00:03:00Z")
    receipt = await live.registry.register_id_certificate(
        _bundle("alice", "bob"), signer=signer_for("bob"), expected_head=None, invitation_id=invitation,
    )
    assert receipt == {"certificate_id": certificate_id("bob"), "registered_at": "2026-10-26T00:03:00.000000Z"}

    live.clock.now = at("2026-10-26T00:20:00Z")
    retry = await live.registry.register_id_certificate(
        _bundle("alice", "bob"), signer=signer_for("bob"), expected_head=None, invitation_id=invitation,
    )
    assert retry == receipt


@pytest.mark.asyncio
async def test_the_gate_refuses_a_registration_signed_by_another_key_with_its_code(live):
    with pytest.raises(RegistryError) as refused:
        await live.registry.register_id_certificate(
            _bundle("alice", "bob"), signer=signer_for("alice"), expected_head=None, invitation_id=None,
        )
    assert (refused.value.status_code, refused.value.code) == (403, "subject_mismatch")


@pytest.mark.asyncio
async def test_a_root_revocation_through_the_real_routes(live):
    live.clock.now = at("2026-10-26T00:03:00Z")
    await live.registry.register_id_certificate(
        _bundle("alice", "bob"), signer=signer_for("bob"), expected_head=None, invitation_id=None,
    )
    live.clock.now = at("2026-10-26T00:10:00Z")
    receipt = await live.registry.revoke_id_certificate(
        DOMAIN, did_aw("bob"), signer=signer_for("root"), expected_head=certificate_id("bob"),
    )
    assert receipt == {"revoked_at": "2026-10-26T00:10:00.000000Z", "effective_from": "2026-10-26T00:10:00.000000Z"}
    [bob] = [i for i in (await _status(live, did_aw("bob")))["identities"] if i["id"] == did_aw("bob")]
    assert bob["revocation"] == receipt


@pytest.mark.asyncio
async def test_a_signed_rotation_through_the_real_routes_keeps_the_tree(live):
    live.exact_dns("root_rotated")
    live.clock.now = at("2026-10-26T00:10:00Z")
    namespace = await live.registry.rotate_namespace_with_previous_key(
        DOMAIN, from_seq=1, previous_did_key=did_key("root"), new_did_key=did_key("root_rotated"),
        previous_signer=signer_for("root"), new_signer=signer_for("root_rotated"),
    )
    assert namespace.controller_did == did_key("root_rotated")
    epochs = (await _status(live))["namespace"]["epochs"]
    assert [(e["seq"], e["did_key"], e["continuity"]) for e in epochs] == [
        (1, did_key("root"), "replaced"), (2, did_key("root_rotated"), "rotated"),
    ]

    with pytest.raises(RegistryError) as refused:
        await live.registry.rotate_namespace_with_previous_key(
            DOMAIN, from_seq=1, previous_did_key=did_key("root"), new_did_key=did_key("root_rotated"),
            previous_signer=signer_for("root"), new_signer=signer_for("root_rotated"),
        )
    assert (refused.value.status_code, refused.value.code) == (409, "head_conflict")


@pytest.mark.asyncio
async def test_a_signed_rotation_replaces_the_cached_namespace(live):
    assert (await live.registry.get_namespace(DOMAIN)).controller_did == did_key("root")
    live.exact_dns("root_rotated")
    await live.registry.rotate_namespace_with_previous_key(
        DOMAIN, from_seq=1, previous_did_key=did_key("root"), new_did_key=did_key("root_rotated"),
        previous_signer=signer_for("root"), new_signer=signer_for("root_rotated"),
    )
    assert (await live.registry.get_namespace(DOMAIN)).controller_did == did_key("root_rotated")


class NamespaceRegistry:
    """A registry whose namespace rotates when the signed rotation reaches it."""

    def __init__(self) -> None:
        self.controller = did_key("root")
        self.on_rotate = None

    def namespace(self) -> dict:
        return {
            "namespace_id": "00000000-0000-4000-8000-000000000009", "domain": DOMAIN,
            "controller_did": self.controller, "verification_status": "verified",
            "last_verified_at": "2026-10-26T00:00:00Z", "created_at": "2026-10-26T00:00:00Z",
        }

    async def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=self.namespace())
        if self.on_rotate is not None:
            await self.on_rotate()
        self.controller = did_key("root_rotated")
        return httpx.Response(200, json=self.namespace())


def _rotate(client):
    return client.rotate_namespace_with_previous_key(
        DOMAIN, from_seq=1, previous_did_key=did_key("root"), new_did_key=did_key("root_rotated"),
        previous_signer=signer_for("root"), new_signer=signer_for("root_rotated"),
    )


@pytest.mark.asyncio
async def test_a_namespace_read_during_a_rotation_is_not_served_after_it():
    registry = NamespaceRegistry()
    client = CachedRegistryClient(ORIGIN, FakeRedis(), transport=httpx.MockTransport(registry.handler))

    async def read_before_commit():
        assert (await client.get_namespace(DOMAIN)).controller_did == did_key("root")

    registry.on_rotate = read_before_commit
    try:
        await _rotate(client)
        assert (await client.get_namespace(DOMAIN)).controller_did == did_key("root_rotated")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_a_rotation_whose_answer_is_lost_leaves_no_cached_namespace():
    registry = NamespaceRegistry()
    client = CachedRegistryClient(ORIGIN, FakeRedis(), transport=httpx.MockTransport(registry.handler))

    async def commit_then_lose_the_answer():
        registry.controller = did_key("root_rotated")
        raise httpx.ReadTimeout("answer lost after the registry committed")

    registry.on_rotate = commit_then_lose_the_answer
    try:
        assert (await client.get_namespace(DOMAIN)).controller_did == did_key("root")
        with pytest.raises(httpx.ReadTimeout):
            await _rotate(client)
        assert (await client.get_namespace(DOMAIN)).controller_did == did_key("root_rotated")
    finally:
        await client.aclose()
