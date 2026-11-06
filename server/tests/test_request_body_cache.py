"""The request-body cache that signature verification reads, as pure ASGI middleware."""

from __future__ import annotations

import asyncio
import hashlib

import pytest
from fastapi import FastAPI, HTTPException, Request
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from aweb.api import RequestBodyCacheMiddleware, create_app

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class Note(BaseModel):
    text: str


def _app():
    app = FastAPI()
    app.add_middleware(RequestBodyCacheMiddleware)

    @app.post("/notes")
    async def post_note(note: Note, request: Request):
        # The replay has been consumed; a further read must answer at once.
        after = await asyncio.wait_for(request.receive(), timeout=0.5)
        return {
            "text": note.text,
            "cached": request.state.cached_body.decode(),
            "sha256": request.state.body_sha256,
            "after": [after["type"], after["body"].decode(), after["more_body"]],
        }

    @app.get("/notes")
    async def get_notes(request: Request):
        return {"cached": request.state.cached_body.decode(), "sha256": request.state.body_sha256}

    @app.post("/refuse")
    async def refuse(note: Note):
        raise HTTPException(status_code=409, detail=f"refused {note.text}")

    return app


@pytest.mark.asyncio
async def test_a_post_body_is_cached_hashed_and_still_parsed():
    body = b'{"text":"hello"}'
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test") as client:
        response = await client.post("/notes", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "text": "hello",
        "cached": body.decode(),
        "sha256": hashlib.sha256(body).hexdigest(),
        "after": ["http.request", "", False],
    }


@pytest.mark.asyncio
async def test_a_get_sees_an_empty_cached_body():
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test") as client:
        response = await client.get("/notes")
    assert response.status_code == 200, response.text
    assert response.json() == {"cached": "", "sha256": EMPTY_SHA256}


@pytest.mark.asyncio
async def test_a_post_that_errors_still_gets_its_response():
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test") as client:
        response = await asyncio.wait_for(
            client.post("/refuse", json={"text": "x"}), timeout=5,
        )
    assert response.status_code == 409
    assert response.json() == {"detail": "refused x"}


@pytest.mark.asyncio
async def test_a_multi_part_body_is_read_whole_before_the_app_runs():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["state"]["cached_body"])
        message = await receive()
        seen.append(message)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    parts = [
        {"type": "http.request", "body": b'{"text":', "more_body": True},
        {"type": "http.request", "body": b'"split"}', "more_body": False},
    ]

    async def receive():
        return parts.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    await RequestBodyCacheMiddleware(app)({"type": "http", "method": "POST", "headers": []}, receive, send)
    assert seen == [b'{"text":"split"}', {"type": "http.request", "body": b'{"text":"split"}', "more_body": False}]
    assert sent[0]["status"] == 204


@pytest.mark.asyncio
async def test_non_http_scopes_pass_through_untouched():
    calls = []

    async def app(scope, receive, send):
        calls.append((scope, receive, send))

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message):
        return None

    scope = {"type": "lifespan"}
    await RequestBodyCacheMiddleware(app)(scope, receive, send)
    assert calls == [(scope, receive, send)]
    assert "state" not in scope


def test_create_app_keeps_no_base_http_middleware():
    app = create_app()
    assert RequestBodyCacheMiddleware in [entry.cls for entry in app.user_middleware]
    assert not [entry.cls for entry in app.user_middleware if entry.cls is BaseHTTPMiddleware]


async def _run(middleware, scope, chunks):
    """Drive one request through the middleware; report what the app saw and what was read."""
    seen, sent, read = [], [], []

    async def receive():
        message = next(chunks)
        read.append(len(message.get("body", b"")))
        return message

    async def send(message):
        sent.append(message)

    await middleware({"type": "http", "method": "POST", "headers": [], **scope}, receive, send)
    return seen, sent, read


def _recording_app(seen):
    async def app(scope, receive, send):
        seen.append(len(scope["state"]["cached_body"]))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    return app


def _status(sent):
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


@pytest.mark.asyncio
async def test_a_body_at_the_cap_is_cached_and_one_byte_more_is_refused():
    cap = 4096
    seen = []
    middleware = RequestBodyCacheMiddleware(_recording_app(seen), max_body_bytes=cap)

    at_cap = iter([{"type": "http.request", "body": b"x" * cap, "more_body": False}])
    _, sent, _ = await _run(middleware, {}, at_cap)
    assert seen == [cap] and _status(sent) == 204

    over = iter([{"type": "http.request", "body": b"x" * cap, "more_body": True},
                 {"type": "http.request", "body": b"y", "more_body": False}])
    _, sent, _ = await _run(middleware, {}, over)
    assert seen == [cap], "the app must not run for an oversized body"
    assert _status(sent) == 413


@pytest.mark.asyncio
async def test_an_endless_body_is_refused_without_reading_past_the_cap():
    cap, chunk = 64 * 1024, 1024

    def endless():
        while True:
            yield {"type": "http.request", "body": b"z" * chunk, "more_body": True}

    seen = []
    _, sent, read = await _run(RequestBodyCacheMiddleware(_recording_app(seen), max_body_bytes=cap), {}, endless())
    assert _status(sent) == 413 and seen == []
    assert sum(read) <= cap + chunk, sum(read)


@pytest.mark.asyncio
async def test_a_declared_oversized_body_is_refused_before_any_read():
    seen = []
    scope = {"headers": [(b"content-length", b"4097")]}
    _, sent, read = await _run(RequestBodyCacheMiddleware(_recording_app(seen), max_body_bytes=4096), scope, iter([]))
    assert read == [] and seen == [] and _status(sent) == 413


def test_the_default_cap_admits_the_largest_released_client_body():
    # aw sends --body-file bodies up to 10 MiB; encrypted, base64 makes that about 13.4 MiB.
    from aweb.api import DEFAULT_MAX_REQUEST_BODY_BYTES

    assert DEFAULT_MAX_REQUEST_BODY_BYTES == 16 * 1024 * 1024
    assert DEFAULT_MAX_REQUEST_BODY_BYTES > (10 * 1024 * 1024) * 4 // 3


@pytest.mark.asyncio
async def test_create_app_takes_its_cap_from_the_environment(monkeypatch):
    monkeypatch.setenv("AWEB_MAX_REQUEST_BODY_BYTES", "1024")
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/messages", content=b"x" * 2048, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


@pytest.mark.parametrize("value", ["0", "-1", "lots"])
def test_an_invalid_cap_refuses_to_start(monkeypatch, value):
    monkeypatch.setenv("AWEB_MAX_REQUEST_BODY_BYTES", value)
    with pytest.raises(ValueError, match="AWEB_MAX_REQUEST_BODY_BYTES"):
        create_app()
