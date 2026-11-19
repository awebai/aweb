"""Released and structured address conflicts cross the real SDK decoder."""

import json
import threading
from contextlib import aclosing
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from awid.registry import (
    AddressAlreadyBoundError,
    DIDCurrentKeyMismatchError,
    DIDRegistrationRequiredError,
    RegistryClient,
    RegistryError,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("detail", "code", "error_type"),
    [
        (
            "did_aw must be registered before address assignment",
            "did_registration_required",
            DIDRegistrationRequiredError,
        ),
        (
            "did_aw current key does not match",
            "did_current_key_mismatch",
            DIDCurrentKeyMismatchError,
        ),
        (
            "address already bound to a different did_aw",
            "address_already_bound",
            AddressAlreadyBoundError,
        ),
    ],
)
@pytest.mark.parametrize("format", ["released_detail", "structured_code"])
async def test_address_conflict_uses_typed_refusal(detail, code, error_type, format):
    body = {
        "detail": detail
        if format == "released_detail"
        else {"code": code, "message": "changed prose"}
    }
    async with aclosing(
        RegistryClient(
            "https://registry.example",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(409, json=body)
            ),
        )
    ) as client:
        with pytest.raises(error_type) as caught:
            await client._request_json(
                "POST", "/v1/namespaces/example/addresses", json={}
            )
    assert type(caught.value) is error_type
    assert caught.value.status_code == 409
    assert caught.value.detail == detail


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
