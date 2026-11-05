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
