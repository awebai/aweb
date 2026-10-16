"""Request coding is transport: auth and routes consume the original bytes."""

import base64
import gzip
import hashlib
import json
import random
from uuid import UUID

import httpx
import pytest
from fastapi import Request

from aweb.api import create_app
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers, _signed_team_headers

CAP = 1024 * 1024


def _probe_app():
    app = create_app()
    seen = []

    @app.middleware("http")
    async def observe(request, call_next):
        seen.append(request.headers.get("content-encoding"))
        return await call_next(request)

    @app.post("/compression-probe")
    async def probe(request: Request):
        body = await request.body()
        return {
            "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "cached_sha256": request.state.body_sha256,
            "encoding": request.headers.get("content-encoding"),
            "length": request.headers.get("content-length"),
            "transfer": request.headers.get("transfer-encoding"),
        }

    @app.get("/compression-error")
    async def error():
        raise RuntimeError("fixture internal failure")

    return app, seen


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", [None, "identity", "gzip", " GZip "])
async def test_original_bytes_reach_body_cache_and_routes(encoding):
    app, seen = _probe_app()
    body = b'{"body":"curl `https://example.test`", "unicode":"\xc3\xb1"}'
    compressed = encoding is not None and encoding.strip().lower() == "gzip"
    headers = {"Content-Encoding": encoding} if encoding else {}
    if compressed:
        headers["Transfer-Encoding"] = "chunked"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.post(
            "/compression-probe", content=gzip.compress(body) if compressed else body,
            headers=headers,
        )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["size"] == len(body)
    assert result["sha256"] == result["cached_sha256"] == hashlib.sha256(body).hexdigest()
    assert result["length"] == str(len(body))
    assert result["encoding"] == (None if compressed else encoding)
    assert result["transfer"] is None
    assert seen == [None if compressed else encoding]
    assert response.headers["accept-encoding"] == "gzip"


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", [None, "identity"])
async def test_large_plain_writes_remain_accepted(encoding):
    app, _ = _probe_app()
    body = b"x" * (CAP + 1)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.post("/compression-probe", content=body,
                                     headers={"Content-Encoding": encoding} if encoding else {})
    assert response.status_code == 200
    assert response.json()["size"] == len(body)


@pytest.mark.asyncio
@pytest.mark.parametrize("body,encoding,status", [
    (gzip.compress(b"x" * (CAP + 1)), "gzip", 413),
    (gzip.compress(random.Random(42).randbytes(CAP + 1)), "gzip", 413),
    (b"not gzip", "gzip", 400),
    (b"", "gzip", 400),
    (gzip.compress(b"hello")[:-1], "gzip", 400),
    (gzip.compress(b"hello") + b"junk", "gzip", 400),
    (b"plain", "br", 415),
    (gzip.compress(b"hello"), "gzip, identity", 415),
], ids=["decoded-cap", "compressed-cap", "corrupt", "empty", "truncated", "trailing", "br", "stacked"])
async def test_bad_encoding_refused_before_inner_middleware(body, encoding, status):
    app, seen = _probe_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.post("/compression-probe", content=body, headers={"Content-Encoding": encoding})
    assert response.status_code == status, response.text
    assert response.headers["accept-encoding"] == "gzip"
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("path,status", [("/health", 200), ("/absent", 404), ("/compression-error", 500)])
async def test_all_responses_advertise_gzip(path, status):
    app, _ = _probe_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.get(path)
    assert response.status_code == status
    assert response.headers.get_list("accept-encoding") == ["gzip"]


@pytest.mark.asyncio
@pytest.mark.parametrize("auth", ["identity", "team-v2"])
async def test_gzip_signed_mail_uses_decoded_bytes_and_rejects_tampering(privacy_app, auth):
    env = privacy_app
    alice = env.actors["alice"]
    original = json.dumps({"to_did": env.actors["bob"].did, "subject": "compressed signed mail", "body": "hello"}).encode()
    if auth == "identity":
        headers = _signed_identity_headers(alice.sk, alice.did, "", original)
    else:
        headers = _signed_team_headers(alice.sk, alice.did, TEAM, alice.certificate, original)
        env.app.state.public_origin = "http://compression.test"
        signed = canonical_json_bytes({
            "v": 2, "aud": env.app.state.public_origin, "method": "POST", "path": "/v1/messages",
            "body_sha256": hashlib.sha256(original).hexdigest(), "team_id": TEAM,
            "timestamp": headers["X-AWEB-Timestamp"],
        })
        headers["X-AWEB-Signed-Payload"] = base64.urlsafe_b64encode(signed).rstrip(b"=").decode()
        headers["Authorization"] = f"DIDKey {alice.did} {sign_message(alice.sk, signed)}"
    headers.update({"Content-Type": "application/json", "Content-Encoding": "gzip"})
    response = await env.client.post("/v1/messages", content=gzip.compress(original), headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["accept-encoding"] == "gzip"
    row = await env.db.fetch_one("SELECT body FROM {{tables.messages}} WHERE message_id = $1", UUID(response.json()["message_id"]))
    assert row["body"] == "hello"
    count = await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}")
    tampered = original.replace(b"hello", b"forged")
    refused = await env.client.post("/v1/messages", content=gzip.compress(tampered), headers=headers)
    assert refused.status_code == 401, refused.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == count
