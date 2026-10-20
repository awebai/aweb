from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aweb.app_manifests import fetch_app_manifest
from aweb.service_errors import ValidationError

MANIFEST = b'{"manifest_version":1}'


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/.well-known/aweb-app.json" and self.server.mode == "ok":
            self.send_response(200)
            self.send_header("Content-Length", str(len(MANIFEST)))
            self.end_headers()
            self.wfile.write(MANIFEST)
        elif self.server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/.well-known/aweb-app.json")
            self.end_headers()
        elif self.server.mode == "large":
            body = b"x" * 64
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def manifest_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.mode = "ok"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _origin(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def test_fetch_app_manifest_returns_the_served_bytes(manifest_server):
    assert fetch_app_manifest(_origin(manifest_server)) == MANIFEST


@pytest.mark.parametrize("mode", ["redirect", "missing"])
def test_fetch_app_manifest_refuses_anything_but_a_direct_200(manifest_server, mode):
    manifest_server.mode = mode

    with pytest.raises(ValidationError):
        fetch_app_manifest(_origin(manifest_server))


def test_fetch_app_manifest_refuses_bytes_over_the_bound(manifest_server):
    manifest_server.mode = "large"

    with pytest.raises(ValidationError):
        fetch_app_manifest(_origin(manifest_server), max_bytes=32)


def _non_loopback_address() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if address.startswith("127.") else address


def test_fetch_app_manifest_refuses_plain_http_outside_loopback():
    address = _non_loopback_address()
    if address is None:
        pytest.skip("no non-loopback interface")
    server = ThreadingHTTPServer((address, 0), _Handler)
    server.mode = "ok"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(ValidationError):
            fetch_app_manifest(f"http://{address}:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()
