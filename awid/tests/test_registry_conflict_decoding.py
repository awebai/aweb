"""Address conflicts cross the public SDK and real registry routes."""

import json
import threading
from contextlib import aclosing
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.registry import (
    AddressAlreadyBoundError,
    DIDCurrentKeyMismatchError,
    DIDRegistrationRequiredError,
    RegistryClient,
    RegistryError,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("conflict", "detail", "error_type"),
    [
        (
            "unregistered",
            "did_aw must be registered before address assignment",
            DIDRegistrationRequiredError,
        ),
        (
            "wrong-key",
            "did_aw current key does not match",
            DIDCurrentKeyMismatchError,
        ),
        (
            "already-bound",
            "address already bound to a different did_aw",
            AddressAlreadyBoundError,
        ),
    ],
)
async def test_real_address_conflict_uses_typed_refusal(
    controller_app, conflict, detail, error_type
):
    env = controller_app
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    _, other_public_key = generate_keypair()
    other_did_key = did_from_public_key(other_public_key)
    name = "conflict"
    origin = str(env.client.base_url).rstrip("/")
    transport = httpx.ASGITransport(app=env.app, client=env.client._transport.client)
    async with aclosing(RegistryClient(origin, transport=transport)) as client:
        if conflict != "unregistered":
            assert (await client.register_did(did_key, seed)).did_aw == did_aw
        if conflict == "already-bound":
            owner_seed, owner_public_key = generate_keypair()
            owner_key = did_from_public_key(owner_public_key)
            owner = await client.register_did(owner_key, owner_seed)
            assert (
                await client.register_address(
                    "local", name, owner.did_aw, env.controller[0], current_did_key=owner_key
                )
            ).did_aw == owner.did_aw

        with pytest.raises(error_type) as caught:
            await client.register_address(
                "local",
                name,
                did_aw,
                env.controller[0],
                current_did_key=other_did_key if conflict == "wrong-key" else did_key,
            )
        assert type(caught.value) is error_type
        assert caught.value.status_code == 409
        assert caught.value.detail == detail

        if conflict == "already-bound":
            observed = await client.resolve_address("local", name)
            assert observed is not None and observed.did_aw == owner.did_aw
        else:
            assert await client.resolve_address("local", name) is None
            if conflict == "unregistered":
                assert (await client.register_did(did_key, seed)).did_aw == did_aw
            assert (
                await client.register_address(
                    "local", name, did_aw, env.controller[0], current_did_key=did_key
                )
            ).did_aw == did_aw


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "content", "body_is_json"),
    [
        (409, b'{"detail":"did_aw current key does not match today"}', True),
        (
            409,
            b'{"detail":{"code":"unknown","message":"did_aw current key does not match"}}',
            True,
        ),
        (503, b'{"detail":"did_aw current key does not match"}', True),
        (409, b"{bad JSON", False),
        (409, b"\xff", False),
    ],
)
async def test_other_registry_failures_remain_failures(status, content, body_is_json):
    async with aclosing(
        RegistryClient(
            "https://registry.example",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(status, content=content)
            ),
        )
    ) as client:
        with pytest.raises(RegistryError) as caught:
            await client._request_json(
                "POST", "/v1/namespaces/example/addresses", json={}
            )
    assert type(caught.value) is RegistryError
    assert caught.value.status_code == status
    assert caught.value.body_is_json is body_is_json


@dataclass
class RegistryErrorPeer:
    origin: str
    payload: bytes = b""
    status: HTTPStatus = HTTPStatus.SERVICE_UNAVAILABLE
    paths: list[str] = field(default_factory=list)


@pytest.fixture(scope="module")
def registry_error_peer():
    """One controlled HTTP peer; the public SDK uses its normal socket transport."""
    peer = RegistryErrorPeer(origin="")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            peer.paths.append(self.path)
            self.send_response(peer.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(peer.payload)))
            self.end_headers()
            self.wfile.write(peer.payload)

        def log_message(self, format, *args):
            # Keep disposable peer access logs out of product-error assertions.
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    peer.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield peer
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "body_is_json", "expected_code"),
    [
        (rb'{"detail":"\ud800"}', True, None),
        (rb'{"detail":"\udfff"}', True, None),
        (rb'{"detail":{"code":"\ud800"}}', True, None),
        (rb'{"detail":{"code":"unavailable\udfff"}}', True, None),
        (b'{"detail":"registry unavailable"}', True, None),
        (b'{"detail":{"code":"unavailable"}}', True, "unavailable"),
        (b"registry unavailable", False, None),
    ],
)
async def test_public_sdk_keeps_malformed_error_metadata_as_http_failure(
    registry_error_peer, payload, body_is_json, expected_code
):
    registry_error_peer.status = HTTPStatus.SERVICE_UNAVAILABLE
    registry_error_peer.payload = payload
    async with aclosing(RegistryClient(registry_error_peer.origin)) as client:
        with pytest.raises(RegistryError) as caught:
            await client.get_namespace("local")
    error = caught.value
    assert type(error) is RegistryError
    assert error.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert error.body_is_json is body_is_json
    assert error.code == expected_code
    assert error.body == (json.loads(payload) if body_is_json else None)
    assert str(error).encode("utf-8")
    assert registry_error_peer.paths[-1] == "/v1/namespaces/local"


@pytest.mark.asyncio
async def test_public_sdk_still_reads_a_complete_namespace(registry_error_peer):
    registry_error_peer.status = HTTPStatus.OK
    registry_error_peer.payload = json.dumps(
        {
            "namespace_id": "namespace-1",
            "domain": "local",
            "controller_did": "did:key:controller",
            "verification_status": "verified",
            "created_at": "2026-11-19T00:00:00Z",
        }
    ).encode()
    async with aclosing(RegistryClient(registry_error_peer.origin)) as client:
        namespace = await client.get_namespace("local")
    assert namespace is not None
    assert namespace.namespace_id == "namespace-1"
    assert namespace.domain == "local"
    assert namespace.controller_did == "did:key:controller"
    assert namespace.verification_status == "verified"
    assert registry_error_peer.paths[-1] == "/v1/namespaces/local"
