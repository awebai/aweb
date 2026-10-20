"""Disposable loopback fixture adapters, never an application's authority layer."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import subprocess
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator

SESSIONS: dict[str, dict] = {}
SESSION_LOCK = threading.Lock()


def additions(page: dict) -> None:
    page["actions"] = [
        {
            "id": "save-note",
            "kind": "edit",
            "label": "Save note",
            "policy_ref": "fixture-edit",
            "input_schema": {
                "type": "object",
                "properties": {
                    "note": {"type": "string", "minLength": 2, "maxLength": 500},
                    "guests": {"type": "integer", "minimum": 1, "maximum": 20},
                    "visit": {"type": "string"},
                    "priority": {"type": "string", "enum": ["normal", "urgent"]},
                    "confirmed": {"type": "boolean"},
                    "attachment": {"type": "string"},
                },
                "required": ["note", "guests"],
                "additionalProperties": False,
            },
        },
        {
            "id": "request-visit",
            "kind": "intent",
            "label": "Ask the agent",
            "policy_ref": "fixture-request",
            "target": "agent-fixture",
            "input_schema": {"type": "object", "additionalProperties": False},
        },
        {
            "id": "upload-document",
            "kind": "edit",
            "label": "Upload document",
            "policy_ref": "fixture-edit",
            "input_schema": {
                "type": "object",
                "properties": {"attachment_id": {"type": "string"}},
                "required": ["attachment_id"],
                "additionalProperties": False,
            },
        },
    ]
    page["layout"].extend(
        [
            {
                "id": "note-form",
                "type": "form",
                "props": {
                    "submit_action": "save-note",
                    "fields": [
                        {
                            "id": "note",
                            "kind": "text",
                            "label": "Note",
                            "required": True,
                            "description": "A short note for the property team.",
                        },
                        {"id": "guests", "kind": "number", "label": "Guests", "required": True},
                        {"id": "visit", "kind": "date", "label": "Visit date"},
                        {
                            "id": "priority",
                            "kind": "select",
                            "label": "Priority",
                            "options": [
                                {"value": "normal", "label": "Normal"},
                                {"value": "urgent", "label": "Urgent"},
                            ],
                        },
                        {"id": "confirmed", "kind": "checkbox", "label": "Confirmed"},
                        {
                            "id": "attachment",
                            "kind": "file",
                            "label": "Attachment",
                            "accept": ["text/plain"],
                            "max_bytes": 1024,
                        },
                    ],
                },
            },
            {
                "id": "request-button",
                "type": "button",
                "props": {
                    "label": "Ask the agent",
                    "action": "request-visit",
                    "confirmation": "Send a visit request to the agent?",
                },
            },
            {
                "id": "document-upload",
                "type": "file_drop",
                "props": {
                    "label": "Upload a document",
                    "action": "upload-document",
                    "accept": ["text/plain"],
                    "max_bytes": 1024,
                },
            },
            {
                "id": "property-image",
                "type": "image",
                "props": {
                    "asset_id": "property-illustration",
                    "alt": "A property courtyard",
                    "caption": "A host-issued asset from the separate asset origin.",
                },
            },
            {
                "id": "property-video",
                "type": "video",
                "props": {
                    "asset_id": "property-tour",
                    "alt": "Property tour fixture",
                    "caption": "Playback starts only when you choose.",
                },
            },
            {"id": "agent-health", "type": "agent_presence", "props": {"subject": "agent-fixture"}},
            {
                "id": "app-console",
                "type": "link_out",
                "props": {"label": "Open app console", "path": "/console"},
            },
        ]
    )


def session(handler: BaseHTTPRequestHandler) -> tuple[str, dict]:
    cookie = SimpleCookie(handler.headers.get("Cookie", ""))
    value = cookie["gallery"].value if "gallery" in cookie else ""
    with SESSION_LOCK:
        if value not in SESSIONS:
            value = secrets.token_urlsafe(24)
            SESSIONS[value] = {
                "csrf": secrets.token_urlsafe(32),
                "rev": 1,
                "state_updated": False,
                "receipts": {},
            }
        return value, SESSIONS[value]


def json_response(
    handler: BaseHTTPRequestHandler, body: dict, status: int = 200, cookie: str | None = None
) -> None:
    data = json.dumps(body).encode()
    handler.send_response(status)
    for name, value in {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Length": str(len(data)),
    }.items():
        handler.send_header(name, value)
    if cookie:
        handler.send_header("Set-Cookie", f"gallery={cookie}; HttpOnly; SameSite=Strict; Path=/")
    handler.end_headers()
    handler.wfile.write(data)


def host_get(handler: BaseHTTPRequestHandler, asset_origin: str, case: str = "") -> None:
    cookie, state = session(handler)
    now = datetime.now(UTC)
    health = {
        "subject": "agent-fixture",
        "reachable": "yes",
        "observed_at": (now - timedelta(seconds=25)).isoformat(),
        "valid_until": (now + timedelta(minutes=5)).isoformat(),
    }
    if case == "health-expiring":
        health["valid_until"] = (now + timedelta(seconds=1)).isoformat()
    configuration = {
        "csrf_token": state["csrf"] if case != "no-csrf" else "",
        "asset_origin": asset_origin,
        "app_origin": "https://app.example",
        "allowed_actions": ["save-note", "request-visit", "upload-document"],
        "health": health,
    }
    json_response(handler, configuration, cookie=cookie)


def post(handler: BaseHTTPRequestHandler, path: str, page: dict) -> None:
    cookie, state = session(handler)
    expected_origin = f"http://127.0.0.1:{cast(ThreadingHTTPServer,handler.server).server_port}"
    if handler.headers.get("Origin") != expected_origin or not secrets.compare_digest(
        handler.headers.get("X-CSRF-Token", ""), state["csrf"]
    ):
        json_response(handler, {"code": "csrf_required"}, 403)
        return
    size = int(handler.headers.get("Content-Length", "0"))
    if size < 1 or size > 2_000_000:
        json_response(handler, {"code": "schema_invalid"}, 422)
        return
    try:
        request = json.loads(handler.rfile.read(size))
    except (UnicodeDecodeError, ValueError):
        json_response(handler, {"code": "schema_invalid"}, 422)
        return
    with SESSION_LOCK:
        if path == "/api/fixture-change":
            state["rev"] += 1
            state["state_updated"] = request.get("mode") == "state"
            json_response(handler, {"page_rev": state["rev"]})
            return
        action = next((a for a in page["actions"] if a["id"] == request.get("action_id")), None)
        if not action or request.get("page_id") != page["page_id"]:
            json_response(handler, {"code": "action_denied"}, 403)
            return
        key = request.get("idempotency_key")
        if not isinstance(key, str) or not key:
            json_response(handler, {"code": "schema_invalid"}, 422)
            return
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
        prior = state["receipts"].get((path, key))
        if prior:
            json_response(
                handler,
                prior[1] if prior[0] == canonical else {"code": "idempotency_conflict"},
                200 if prior[0] == canonical else 409,
            )
            return
        if request.get("expected_page_rev") != state["rev"]:
            json_response(handler, {"code": "revision_conflict", "page_rev": state["rev"]}, 409)
            return
        if path == "/api/upload":
            payload = request.get("file", {})
            try:
                data = base64.b64decode(payload.get("bytes", ""), validate=True)
            except ValueError:
                data = b"x" * 1025
            if (
                payload.get("mime") != "text/plain"
                or len(data) > 1024
                or payload.get("size") != len(data)
                or request.get("input", {}).get("file_sha256")
                != "sha256:" + hashlib.sha256(data).hexdigest()
            ):
                json_response(handler, {"code": "schema_invalid"}, 422)
                return
            receipt = {"attachment_id": f"attachment-{secrets.token_hex(8)}"}
        elif path == "/api/invoke":
            if action["kind"] == "answer" or not Draft202012Validator(
                action["input_schema"]
            ).is_valid(request.get("input")):
                json_response(handler, {"code": "schema_invalid"}, 422)
                return
            state["rev"] += 1
            receipt = (
                {"transaction_id": secrets.token_hex(8), "page_rev": state["rev"]}
                if action["kind"] == "edit"
                else {
                    "action_id": secrets.token_hex(8),
                    "page_rev": state["rev"],
                    "delivery": "pending",
                    "execution": "not_started",
                }
            )
        else:
            json_response(handler, {"code": "resource_not_found"}, 404)
            return
        state["receipts"][(path, key)] = (canonical, receipt)
        json_response(handler, receipt)


class AssetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == "/property-tour":
            data = files("aweb_naapp.pages").joinpath("assets/gallery-video.mp4").read_bytes()
            mime = "video/mp4"
        else:
            data = b'<svg xmlns="http://www.w3.org/2000/svg" width="640" height="320" viewBox="0 0 640 320"><rect width="640" height="320" fill="#f4efe6"/><path d="M100 270V130L210 55l110 75v140zm250 0V100h160v170z" fill="#cf4a26"/><path d="M150 270v-90h110v90m240-130h-45v50h45" fill="#fffdf9"/></svg>'
            mime = "image/svg+xml"
        self.send_response(200)
        for name, value in {
            "Content-Type": mime,
            "Content-Length": str(len(data)),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
        }.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        pass


def asset_server(port: int) -> tuple[ThreadingHTTPServer, tempfile.TemporaryDirectory]:
    temporary = tempfile.TemporaryDirectory(prefix="page-gallery-tls-")
    cert, key = Path(temporary.name) / "cert.pem", Path(temporary.name) / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", port), AssetHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, temporary
