"""Public SDK boundaries over real HTTP; Redis is an explicit unit stand-in.

The peer supplies adversarial wire responses, not registry admission authority.
Native service and Redis qualification remains in the composed caller packet.
"""

from __future__ import annotations

import base64
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.id_tree_requests import covering_payload
from awid.registry import CachedRegistryClient, RegistryError
from awid.signing import canonical_json_bytes, sign_message
from test_registry_client import FakeRedis

DOMAIN, TEAM = "customer.example", "engineering"


@dataclass
class WirePeer:
    origin: str = ""
    response: bytes = b'{"revocations":[],"has_more":false}'
    status: int = 200
    requests: list[tuple[str, str, bytes]] = field(default_factory=list)


@pytest.fixture
def peer():
    state = WirePeer()

    class Endpoint(BaseHTTPRequestHandler):
        def answer(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            state.requests.append((self.command, self.path, body))
            self.send_response(state.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(state.response)))
            self.end_headers()
            self.wfile.write(state.response)

        do_GET = do_POST = answer

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    state.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        assert not thread.is_alive()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wire",
    [
        b"",
        b"{}",
        b'{"revocations":null}',
        b'{"revocations":{}}',
        b'{"revocations":"none"}',
        b'{"revocations":[null]}',
        b'{"revocations":[{}]}',
        b'{"revocations":[{"certificate_id":null}]}',
        b'{"revocations":[{"certificate_id":17}]}',
        b'{"revocations":[{"certificate_id":""}]}',
        b'{"revocations":[],"has_more":true}',
        b'{"revocations":[],"has_more":true,"next_cursor":17}',
        b'{"revocations":[],"has_more":"false"}',
    ],
)
async def test_malformed_revocations_never_become_cached_absence(peer, wire):
    redis = FakeRedis()
    peer.response = wire
    client = CachedRegistryClient(peer.origin, redis)
    try:
        with pytest.raises(RegistryError) as refused:
            await client.get_team_revocations(DOMAIN, TEAM)
        assert refused.value.status_code == 502
        assert str(refused.value) == (
            "AWID revocation response is malformed for engineering:customer.example. "
            "Retry against a registry that returns a complete revocations list."
        )
        assert redis.values == {}
        peer.response = b'{"revocations":[{"certificate_id":"revoked"}],"has_more":false}'
        assert await client.get_team_revocations(DOMAIN, TEAM) == {"revoked"}
        assert len(peer.requests) == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", [b'{"revocations":[]}', b'{"revocations":[],"has_more":false}'])
async def test_explicit_empty_revocations_remain_a_cacheable_complete_answer(peer, wire):
    peer.response = wire
    redis = FakeRedis()
    client = CachedRegistryClient(peer.origin, redis)
    try:
        assert await client.get_team_revocations(DOMAIN, TEAM) == set()
        peer.response = b"{}"
        assert await client.get_team_revocations(DOMAIN, TEAM) == set()
        assert len(peer.requests) == 1
    finally:
        await client.aclose()


class UnavailableInvalidationRedis(FakeRedis):
    async def set(self, key, value, ex=None, nx=False):
        raise OSError("Redis invalidation unavailable")

    async def delete(self, *keys):
        raise OSError("Redis invalidation unavailable")


def prepared_revoke(*, origin: str) -> dict:
    seed, public = generate_keypair()
    certificate_id = str(UUID(int=1))
    signed = covering_payload(
        aud=origin,
        path=f"/v1/namespaces/{DOMAIN}/teams/{TEAM}/certificates/revoke",
        domain=DOMAIN,
        operation="revoke_certificate",
        body=canonical_json_bytes({"certificate_id": certificate_id}),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        claims={"team_name": TEAM, "certificate_id": certificate_id},
    )
    encoded_signature = sign_message(seed, signed)
    return {
        "certificate_id": certificate_id,
        "controller_did": did_from_public_key(public),
        "signing": signed,
        "signature": base64.b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4)),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 403, 503])
async def test_prepared_revoke_reaches_http_once_despite_redis_invalidation_failure(peer, status):
    peer.response = b'{"detail":"registry refused"}'
    peer.status = status
    client = CachedRegistryClient(peer.origin, UnavailableInvalidationRedis())
    selected = prepared_revoke(origin=peer.origin)
    try:
        if status == 200:
            await client.revoke_team_certificate_with_proof(DOMAIN, TEAM, **selected)
        else:
            with pytest.raises(RegistryError) as refused:
                await client.revoke_team_certificate_with_proof(DOMAIN, TEAM, **selected)
            assert refused.value.status_code == status
        assert peer.requests == [
            (
                "POST",
                f"/v1/namespaces/{DOMAIN}/teams/{TEAM}/certificates/revoke",
                canonical_json_bytes({"certificate_id": selected["certificate_id"]}),
            )
        ]
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_invalid_prepared_revoke_does_not_send_through_a_redis_outage(peer):
    client = CachedRegistryClient(peer.origin, UnavailableInvalidationRedis())
    selected = prepared_revoke(origin=peer.origin)
    selected["signature"] = bytes(64)
    try:
        with pytest.raises(ValueError):
            await client.revoke_team_certificate_with_proof(DOMAIN, TEAM, **selected)
        assert peer.requests == []
    finally:
        await client.aclose()
