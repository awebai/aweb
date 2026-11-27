"""Untrusted identity selectors stay in one URL component on real sockets."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.registry import RegistryClient, RegistryError


@pytest.mark.asyncio
@pytest.mark.parametrize("malformed", [False, True])
async def test_identity_path_cannot_supply_path_query_or_fragment(malformed):
    observed = []

    class Endpoint(BaseHTTPRequestHandler):
        def answer(self):
            observed.append(self.path)
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"not_found"}')

        do_GET = do_POST = answer

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    seed, public = generate_keypair()
    person = (
        "did:aw:untrusted/../victim?query=yes#fragment"
        if malformed
        else stable_id_from_did_key(did_from_public_key(public))
    )
    registry = RegistryClient(f"http://127.0.0.1:{server.server_port}")
    try:
        for call in [
            lambda: registry.resolve_key_fresh(person),
            lambda: registry.get_mapping(person, seed),
            lambda: registry.publish_encryption_key(person, {}),
            lambda: registry.list_did_addresses(person),
        ]:
            with pytest.raises(RegistryError):
                await call()
        component = quote(person, safe=":")
        assert observed == [
            f"/v1/did/{component}/{suffix}"
            for suffix in ["key", "full", "encryption-key", "addresses?limit=200"]
        ]
    finally:
        await registry.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
