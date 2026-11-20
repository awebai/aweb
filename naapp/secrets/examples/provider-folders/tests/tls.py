"""A loopback HTTPS listener with a throwaway CA, for tests that need real TLS.

It answers the two Graph reads a replay of an empty outbox makes (the app
folder and its listing) and records every request it receives.
"""

import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APPROOT = {"id": "TLS-APPROOT", "parentReference": {"driveId": "tls-drive"}}


def make_ca_and_server_cert(directory: Path) -> tuple[Path, Path, Path]:
    """Write a CA and a localhost certificate it signs; return (ca, cert, key)."""
    ca_key, ca = directory / "ca.key", directory / "ca.pem"
    key, request, cert = (
        directory / "server.key",
        directory / "server.csr",
        directory / "server.pem",
    )
    extensions = directory / "server.ext"
    extensions.write_text(
        "subjectAltName=DNS:localhost\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n"
    )
    for command in (
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            ca_key,
            "-out",
            ca,
            "-days",
            "1",
            "-subj",
            "/CN=Fictional Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        [
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key,
            "-out",
            request,
            "-subj",
            "/CN=localhost",
        ],
        [
            "x509",
            "-req",
            "-in",
            request,
            "-CA",
            ca,
            "-CAkey",
            ca_key,
            "-CAcreateserial",
            "-out",
            cert,
            "-days",
            "1",
            "-extfile",
            extensions,
        ],
    ):
        subprocess.run(["openssl", *map(str, command)], check=True, capture_output=True)
    return ca, cert, key


class GraphListener:
    """Serve APPROOT and an empty listing over TLS on 127.0.0.1."""

    def __init__(self, cert: Path, key: Path):
        self.requests: list[tuple[str, str, str | None]] = []
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                listener.requests.append(
                    (self.command, self.path, self.headers.get("Authorization"))
                )
                if self.path == "/v1.0/me/drive/special/approot":
                    body = APPROOT
                elif self.path.startswith("/v1.0/me/drive/special/approot/children"):
                    body = {"value": []}
                else:
                    body = {"error": {"code": "accessDenied"}}
                payload = json.dumps(body).encode()
                self.send_response(200 if "error" not in body else 403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert, key)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "GraphListener":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
