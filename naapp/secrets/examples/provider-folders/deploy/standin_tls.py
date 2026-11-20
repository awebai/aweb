"""The persisted Graph stand-in: tests/standin.py served over real TLS.

The drill runs the pinned replay.py against it, so the publisher's real HTTPS
client (certificate verification against ca_bundle, trust_env=False, the
bearer kept to the Graph origin) is exercised, not an in-memory transport.
Each origin (Graph, upload sessions, downloads) is its own listener on
127.0.0.1, with a leaf certificate from a lab CA made for that one drill.

Not part of the pinned file set. It qualifies the publisher's handling only;
it says nothing about real Graph access, scope or account support.
"""

import os
import ssl
import subprocess
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

from tests.standin import OneDriveStandIn

HOST = "127.0.0.1"
OPENSSL_TIMEOUT_S = 30


@dataclass(frozen=True)
class LabCA:
    directory: Path
    ca_pem: Path
    leaf_pem: Path
    leaf_key: Path


def lab_ca(directory: Path) -> LabCA:
    """A one-drill CA and one leaf for 127.0.0.1, in a new 0700 directory.

    The CA key is removed once the leaf is signed, so nothing else can be
    issued under this CA.
    """
    directory.mkdir(mode=0o700)
    ca_key, ca_pem = directory / "ca.key", directory / "ca.pem"
    leaf_key, leaf_csr, leaf_pem = (
        directory / "leaf.key",
        directory / "leaf.csr",
        directory / "leaf.pem",
    )
    extensions = directory / "leaf.ext"
    extensions.write_text(
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
        # Python 3.13's default strict verification requires both identifiers.
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
    )
    key = ["-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
    _openssl(
        "req", "-x509", "-new", *key, "-keyout", ca_key, "-out", ca_pem, "-days", "1",
        "-subj", "/CN=acwd25 drill lab CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign",
        "-addext", "subjectKeyIdentifier=hash",
    )  # fmt: skip
    _openssl("req", "-new", *key, "-keyout", leaf_key, "-out", leaf_csr, "-subj", "/CN=127.0.0.1")
    _openssl(
        "x509", "-req", "-in", leaf_csr, "-CA", ca_pem, "-CAkey", ca_key, "-set_serial", "1",
        "-out", leaf_pem, "-days", "1", "-extfile", extensions,
    )  # fmt: skip
    for spent in (ca_key, leaf_csr, extensions):
        spent.unlink()
    os.chmod(leaf_key, 0o600)
    return LabCA(directory, ca_pem, leaf_pem, leaf_key)


class TLSStandIn:
    """One OneDriveStandIn behind three local HTTPS origins.

    Use as a context manager. `standin` is the folder itself (its items and
    fault switches); `requests` is every request it was handed, in order.
    A lost answer (the stand-in raising a transport error after commit)
    closes the connection without a response, as a real lost answer does.
    """

    def __init__(self, lab: LabCA):
        self.lab = lab
        self.requests: list[httpx.Request] = []
        self.lock = threading.Lock()
        self.servers: list[ThreadingHTTPServer] = []
        self.threads: list[threading.Thread] = []
        self.standin: OneDriveStandIn | None = None
        self.graph_origin = ""

    def __enter__(self) -> "TLSStandIn":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.lab.leaf_pem, self.lab.leaf_key)
        for _ in range(3):
            server = ThreadingHTTPServer((HOST, 0), _Handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.drill = self
            server.origin = f"https://{HOST}:{server.server_address[1]}"
            self.servers.append(server)
        graph, upload, download = (server.origin for server in self.servers)
        self.graph_origin = graph
        self.standin = OneDriveStandIn(
            graph=f"{graph}/v1.0", upload_origin=upload, download_origin=download
        )
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
        return self

    def __exit__(self, *exc) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=10)

    def answer(self, request: httpx.Request) -> httpx.Response | None:
        """The stand-in's answer, or None for a lost one."""
        with self.lock:
            self.requests.append(request)
            try:
                return self.standin.handle(request)
            except httpx.TransportError:
                return None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        request = httpx.Request(
            self.command,
            f"{self.server.origin}{self.path}",
            headers=list(self.headers.items()),
            content=body,
        )
        response = self.server.drill.answer(request)
        if response is None:
            self.close_connection = True
            return
        content = response.read()
        self.send_response(response.status_code)
        for name, value in response.headers.items():
            if name.lower() not in ("content-length", "transfer-encoding", "connection"):
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    do_GET = do_POST = do_PUT = _serve

    def log_message(self, *args) -> None:
        pass


def _openssl(*arguments) -> None:
    subprocess.run(
        ["openssl", *map(str, arguments)],
        check=True,
        capture_output=True,
        timeout=OPENSSL_TIMEOUT_S,
    )
