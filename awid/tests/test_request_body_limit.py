"""A request body over the limit is refused with 413 before the app uses it.

A body that declares its length is refused before the app runs. One that
does not is counted as the app reads it, and the read that passes the limit
ends the request. Nothing is buffered by the limiter itself.
"""

from __future__ import annotations

import logging

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from httpx import ASGITransport, AsyncClient

from awid.request_body_limit import RequestBodyLimitMiddleware

LIMIT = 16
LOGGER = "awid.request_body_limit"


def _app(seen: list[bytes]) -> RequestBodyLimitMiddleware:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request) -> dict:
        body = await request.body()
        seen.append(body)
        return {"length": len(body)}

    @app.post("/streamed")
    async def streamed(request: Request) -> dict:
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
        seen.append(b"streamed")
        return {"length": total}

    @app.api_route("/unread", methods=["GET", "POST"], response_class=PlainTextResponse)
    async def unread() -> str:
        seen.append(b"unread")
        return "ok"

    return RequestBodyLimitMiddleware(app, max_body_bytes=LIMIT)


async def _chunks(*parts: bytes):
    for part in parts:
        yield part


@pytest.fixture
def seen() -> list[bytes]:
    return []


@pytest_asyncio.fixture
async def http(seen):
    async with AsyncClient(transport=ASGITransport(app=_app(seen)), base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_a_body_at_the_limit_reaches_the_app_whole(http, seen):
    response = await http.post("/echo", content=b"x" * LIMIT)
    assert (response.status_code, response.json()) == (200, {"length": LIMIT})
    assert seen == [b"x" * LIMIT]


@pytest.mark.asyncio
async def test_a_declared_length_over_the_limit_is_refused_before_the_app_runs(http, seen):
    response = await http.post("/unread", content=b"x" * (LIMIT + 1))
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/echo", "/streamed"])
async def test_an_undeclared_body_over_the_limit_is_refused_as_it_is_read(http, seen, path):
    response = await http.post(path, content=_chunks(b"x" * LIMIT, b"x"))
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert seen == []


@pytest.mark.asyncio
async def test_an_undeclared_body_within_the_limit_reaches_the_app(http, seen):
    response = await http.post("/echo", content=_chunks(b"x" * 8, b"x" * 8))
    assert (response.status_code, response.json()) == (200, {"length": LIMIT})


@pytest.mark.asyncio
async def test_a_request_without_a_body_is_untouched(http, seen):
    response = await http.get("/unread")
    assert (response.status_code, response.text) == (200, "ok")


@pytest.mark.asyncio
async def test_a_malformed_declared_length_is_counted_as_it_is_read(seen):
    sent: list[dict] = []
    messages = [{"type": "http.request", "body": b"x" * (LIMIT + 1), "more_body": False}]

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/echo", "raw_path": b"/echo", "query_string": b"",
        "headers": [(b"content-length", b"many")], "http_version": "1.1", "scheme": "http",
        "server": ("testserver", 80), "client": ("127.0.0.1", 1), "root_path": "",
    }
    await _app(seen)(scope, receive, send)
    assert sent[0]["status"] == 413
    assert seen == []


@pytest.mark.asyncio
async def test_a_body_passing_the_limit_after_the_response_began_ends_the_request():
    async def answers_first(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await receive()

    async def receive():
        return {"type": "http.request", "body": b"x" * (LIMIT + 1), "more_body": False}

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    limited = RequestBodyLimitMiddleware(answers_first, max_body_bytes=LIMIT)
    with pytest.raises(Exception) as raised:
        await limited({"type": "http", "method": "POST", "path": "/", "headers": []}, receive, send)
    assert getattr(raised.value, "status_code", None) == 413
    assert [message["status"] for message in sent if message["type"] == "http.response.start"] == [200]


@pytest.mark.asyncio
async def test_other_scopes_pass_through():
    reached: list[str] = []

    async def app(scope, receive, send):
        reached.append(scope["type"])

    await RequestBodyLimitMiddleware(app, max_body_bytes=LIMIT)({"type": "lifespan"}, None, None)
    assert reached == ["lifespan"]


@pytest.mark.parametrize("limit", [0, -1])
def test_a_limit_below_one_byte_is_refused(limit):
    with pytest.raises(ValueError):
        RequestBodyLimitMiddleware(lambda *_: None, max_body_bytes=limit)


def _refusals(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.name == LOGGER]


@pytest.mark.asyncio
async def test_a_declared_refusal_is_logged_without_the_body_or_query(http, seen, caplog):
    body = b"x" * (LIMIT + 1)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        response = await http.post("/echo?token=secret", content=body)
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert seen == []
    assert _refusals(caplog) == [f"Request body too large: POST /echo declared {LIMIT + 1} bytes, limit {LIMIT}"]
    assert "secret" not in caplog.text and "xxxx" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/echo", "/streamed"])
async def test_an_undeclared_refusal_is_logged_without_the_body_or_query(http, seen, caplog, path):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        response = await http.post(f"{path}?token=secret", content=_chunks(b"x" * LIMIT, b"x"))
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert seen == []
    assert _refusals(caplog) == [f"Request body too large: POST {path} received {LIMIT + 1} bytes, limit {LIMIT}"]
    assert "secret" not in caplog.text and "xxxx" not in caplog.text


@pytest.mark.asyncio
async def test_a_logged_path_stops_at_an_encoded_query_or_fragment(http, caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        query = await http.post("/echo%3Ftoken=secret", content=b"x" * (LIMIT + 1))
        fragment = await http.post("/echo%23secret", content=b"x" * (LIMIT + 1))
    assert (query.status_code, fragment.status_code) == (413, 413)
    assert _refusals(caplog) == [
        f"Request body too large: POST /echo declared {LIMIT + 1} bytes, limit {LIMIT}",
        f"Request body too large: POST /echo declared {LIMIT + 1} bytes, limit {LIMIT}",
    ]
    assert "secret" not in caplog.text
