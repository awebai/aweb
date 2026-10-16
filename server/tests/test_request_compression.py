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
    (gzip.compress(b"hello")[:-1] + b"\xff", "gzip", 400),
    (gzip.compress(b"hello") + b"junk", "gzip", 400),
    (b"plain", "br", 415),
    (gzip.compress(b"hello"), "gzip, identity", 415),
], ids=["decoded-cap", "compressed-cap", "corrupt", "empty", "truncated", "bad-checksum", "trailing", "br", "stacked"])
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
@pytest.mark.parametrize("encoding", [None, "identity", "gzip"])
async def test_gzip_signed_mail_uses_decoded_bytes_and_rejects_tampering(privacy_app, auth, encoding):
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
    headers["Content-Type"] = "application/json"
    if encoding:
        headers["Content-Encoding"] = encoding
    encode = gzip.compress if encoding == "gzip" else lambda body: body
    response = await env.client.post("/v1/messages", content=encode(original), headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["accept-encoding"] == "gzip"
    row = await env.db.fetch_one("SELECT body FROM {{tables.messages}} WHERE message_id = $1", UUID(response.json()["message_id"]))
    assert row["body"] == "hello"
    count = await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}")
    tampered = original.replace(b"hello", b"forged")
    refused = await env.client.post("/v1/messages", content=encode(tampered), headers=headers)
    assert refused.status_code == 401, refused.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == count


async def _asgi_upload(chunks, *, cap=128, headers=None, nested=False):
    from aweb.request_compression import RequestDecompressionMiddleware

    sent, seen = [], []
    consumed = 0

    async def receive():
        nonlocal consumed
        if consumed >= len(chunks):
            return {"type": "http.disconnect"}
        chunk = chunks[consumed]
        consumed += 1
        return {"type": "http.request", "body": chunk, "more_body": consumed < len(chunks)}

    async def inner(scope, receive, send):
        body = await receive()
        seen.append((scope, body))
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"accept-encoding", b"obsolete"), (b"x-fixture", b"kept")]})
        await send({"type": "http.response.body", "body": b"ok"})

    app = RequestDecompressionMiddleware(inner, max_body_bytes=cap)
    if nested:
        app = RequestDecompressionMiddleware(app, max_body_bytes=cap)
    scope = {"type": "http", "headers": headers or [(b"content-encoding", b"gzip")]}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent, seen, consumed


@pytest.mark.asyncio
@pytest.mark.parametrize("nested", [False, True])
async def test_chunked_concatenated_members_and_nested_decoding(nested):
    body = b"hello" * 20
    packed = gzip.compress(body[:50]) + gzip.compress(body[50:])
    sent, seen, _ = await _asgi_upload([packed[i:i+1] for i in range(len(packed))], nested=nested,
        headers=[(b"content-encoding", b"gzip"), (b"content-length", b"wrong"), (b"transfer-encoding", b"chunked")])
    assert len(seen) == 1
    scope, message = seen[0]
    assert message == {"type": "http.request", "body": body, "more_body": False}
    assert scope["headers"] == [(b"content-length", b"100")]
    assert sent[0]["status"] == 200
    assert sent[0]["headers"] == [(b"x-fixture", b"kept"), (b"accept-encoding", b"gzip")]


@pytest.mark.asyncio
@pytest.mark.parametrize("decoded_size,status", [(128, 200), (129, 413)])
async def test_decoded_cap_boundary_with_bounded_zlib_output(monkeypatch, decoded_size, status):
    from aweb import request_compression

    factory = request_compression.zlib.decompressobj
    limits, sizes = [], []

    class ObservedDecoder:
        def __init__(self, *args, **kwargs):
            self.decoder = factory(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.decoder, name)

        def decompress(self, data, max_length=0):
            # A zero/unbounded request fails before it can allocate the bomb.
            assert 0 < max_length <= 129
            limits.append(max_length)
            result = self.decoder.decompress(data, max_length)
            sizes.append(len(result))
            return result

    monkeypatch.setattr(request_compression.zlib, "decompressobj", ObservedDecoder)
    sent, seen, _ = await _asgi_upload([gzip.compress(b"x" * decoded_size)])
    assert sent[0]["status"] == status
    assert bool(seen) == (status == 200)
    assert limits and max(sizes) <= 129


@pytest.mark.asyncio
async def test_compressed_cap_stops_reading_before_later_chunks():
    # Empty members consume input while producing no output: output-only caps
    # would accept this chain. A third chunk must never be requested.
    member = gzip.compress(b"")
    sent, seen, consumed = await _asgi_upload([member * 6, member, b"must not read"])
    assert sent[0]["status"] == 413
    assert seen == []
    assert consumed == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("extra,status", [(0, 200), (-1, 413)])
async def test_compressed_cap_boundary(extra, status):
    packed = gzip.compress(random.Random(42).randbytes(128))
    sent, seen, _ = await _asgi_upload([packed], cap=len(packed) + extra)
    assert sent[0]["status"] == status
    assert bool(seen) == (status == 200)


@pytest.mark.asyncio
async def test_duplicate_encoding_headers_are_unsupported():
    sent, seen, consumed = await _asgi_upload([gzip.compress(b"hi")],
        headers=[(b"content-encoding", b"gzip"), (b"content-encoding", b"identity")])
    assert sent[0]["status"] == 415
    assert seen == [] and consumed == 0


@pytest.mark.asyncio
async def test_decoder_internal_error_is_a_bounded_advertised_500(monkeypatch, caplog):
    from aweb.request_compression import RequestDecompressionMiddleware

    async def broken(self, receive):
        raise RuntimeError("fixture private internal detail")

    monkeypatch.setattr(RequestDecompressionMiddleware, "_decode", broken)
    sent, seen, _ = await _asgi_upload([gzip.compress(b"hi")])
    assert sent[0]["status"] == 500
    assert sent[0]["headers"].count((b"accept-encoding", b"gzip")) == 1
    assert sent[1]["body"] == b"Internal server error"
    assert seen == []
    assert "fixture private internal detail" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["lifespan", "websocket"])
async def test_non_http_is_untouched(kind):
    from aweb.request_compression import RequestDecompressionMiddleware

    scope = {"type": kind}
    async def receive():
        return {"type": "fixture"}
    async def send(message):
        pass
    async def inner(actual_scope, actual_receive, actual_send):
        assert actual_scope is scope
        assert actual_receive is receive and actual_send is send
    await RequestDecompressionMiddleware(inner)(scope, receive, send)


@pytest.mark.asyncio
async def test_disconnected_upload_never_calls_inner_app():
    sent, seen, _ = await _asgi_upload([])
    assert sent == seen == []


@pytest.mark.asyncio
async def test_inner_failure_after_response_start_never_sends_a_second_response(caplog):
    from aweb.request_compression import RequestDecompressionMiddleware

    sent = []
    error = RuntimeError("fixture crash after response start")

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b"partial", "more_body": True})
        raise error

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await RequestDecompressionMiddleware(inner)({"type": "http", "headers": []}, receive, send)
    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert len(starts) == 1
    assert starts[0]["status"] == 202
    assert starts[0]["headers"] == [(b"accept-encoding", b"gzip")]
    records = [record for record in caplog.records if record.name == "aweb.request_compression"]
    assert len(records) == 1
    assert records[0].exc_info[1] is error
