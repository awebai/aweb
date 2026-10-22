"""Loopback C4 client probe: real HTTP and the production Python verifier, no member authority."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from aweb_naapp.pages.render import page_shell
from aweb_naapp.runtime.capability_links import LinkRefused
from aweb_naapp.runtime.capability_links.routes import refusal_response
from aweb_naapp.runtime.link_requests import (
    LinkRequestRefused,
    check_session_did_key,
    verify_link_request_bytes,
)

SESSIONS: dict = {}
SECRET = "A" * 43  # The public zeros conformance fixture, never a real capability.


class Handler(BaseHTTPRequestHandler):
    def reply(self, value, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def refuse(self, code, status):
        # The same serializer the real N5 exchange route calls.
        response = refusal_response(LinkRefused(code, status))
        self.send_response(response.status_code)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(response.body)

    def do_GET(self):
        if self.path == "/":
            shell = page_shell(script_path="/host.js", asset_origin="https://assets.invalid")
            self.send_response(200)
            for name, value in shell.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(shell.html.encode())
        elif self.path in {"/host.js", "/page-link-client.js"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.end_headers()
            self.wfile.write(
                b"export {};"
                if self.path == "/host.js"
                else files("aweb_naapp.pages").joinpath("assets/page-link-client.js").read_bytes()
            )
        elif self.path == "/mounted/redirect":
            self.send_response(302)
            self.send_header("Location", "/mounted/must-not-follow")
            self.end_headers()
        else:
            self.signed(b"")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        route = urlsplit(self.path)
        if route.path == "/mounted/v1/links/lnk-test/session":
            refusal = parse_qs(route.query).get("refusal", [""])[0]
            codes = {
                "404": "link_unavailable",
                "429": "safety_rate_limited",
                "503": "authority_unavailable",
                "403": "current_member_required",
            }
            if refusal in codes:
                self.refuse(codes[refusal], int(refusal))
                return
            if refusal in {"malformed", "not-json"}:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    b'{"detail": {"code": 42}}' if refusal == "malformed" else b"Unavailable"
                )
                return
            request = json.loads(body)
            if request["secret"] != SECRET:
                self.refuse("link_unavailable", 404)
                return
            check_session_did_key(request["session_did_key"])
            session_id = "lks-" + secrets.token_hex(8)
            csrf = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
            expires = datetime.now(UTC) + timedelta(minutes=15)
            SESSIONS[session_id] = {
                "key": request["session_did_key"],
                "csrf": csrf,
                "nonces": set(),
                "expires": expires,
            }
            self.reply(
                {
                    "session_id": session_id,
                    "csrf_token": csrf,
                    "expires_at": expires.isoformat().replace("+00:00", "Z"),
                    "link": {"page_id": "records", "mode": "live", "actions": []},
                }
            )
        else:
            self.signed(body)

    def signed(self, body):
        try:
            scheme, session_id, signature = self.headers["Authorization"].split(" ")
            assert scheme == "AWEB-Link-Request"
            session = SESSIONS[session_id]
            assert datetime.now(UTC) < session["expires"]
            payload = verify_link_request_bytes(
                self.headers["X-AWEB-Signed-Payload"],
                signature,
                session_did_key=session["key"],
                expected={
                    "link_id": "lnk-test",
                    "session_id": session_id,
                    "method": self.command,
                    "path": self.path,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                },
                now=datetime.now(UTC),
            )
            assert payload["nonce"] not in session["nonces"]
            session["nonces"].add(payload["nonce"])
            if self.command not in {"GET", "HEAD"}:
                assert self.headers["Origin"] == f"http://127.0.0.1:{self.server.server_port}"
                assert secrets.compare_digest(self.headers["X-AWEB-CSRF"], session["csrf"])
            assert not self.headers.get("Cookie")
            self.reply(
                {
                    "verified": True,
                    "path": self.path,
                    "method": self.command,
                    "body": list(body),
                    "nonce": payload["nonce"],
                    "session_id": session_id,
                    "referrer": self.headers.get("Referer"),
                }
            )
        except (LinkRequestRefused, KeyError, AssertionError, AttributeError, ValueError):
            self.refuse("signature_invalid", 401)

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({"origin": f"http://127.0.0.1:{server.server_port}"}), flush=True)
server.serve_forever()
