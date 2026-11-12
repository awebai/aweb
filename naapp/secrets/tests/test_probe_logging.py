"""The shipped ASGI boundary logs probes, without starting DB/network services."""

import json
import logging
import secrets
from pathlib import Path

import httpx
import pytest

from aweb_secrets.app import create_app
from tests.test_app import API, CONSOLE, _settings, allow_all, kms_check


@pytest.fixture
def service(tmp_path):
    # No lifespan: /live is live; the actual /ready check reports no database.
    return create_app(
        _settings("postgresql://unused@localhost/unused", tmp_path),
        policy=allow_all,
        kms=kms_check(True),
    )


def probe_lines(caplog):
    return [
        json.loads(record.getMessage().removeprefix("probe_request "))
        for record in caplog.records
        if record.name == "uvicorn.error" and record.getMessage().startswith("probe_request ")
    ]


@pytest.mark.parametrize("origin", [API, CONSOLE])
@pytest.mark.parametrize("path,status", [("/ready", 503), ("/live", 200)])
async def test_probe_request_lines_include_only_method_path_query_and_actual_status(
    service, caplog, origin, path, status
):
    tag = secrets.token_hex(16)
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
            response = await client.get(origin + path + "?probe=" + tag)
    assert response.status_code == status
    assert probe_lines(caplog) == [
        {"method": "GET", "path": path, "query": "probe=" + tag, "status": status}
    ]


@pytest.mark.parametrize("path", ["/v1/secrets", "/manifests/v2.json", "/health", "/ready/other"])
async def test_api_and_other_paths_have_no_probe_request_line(service, caplog, path):
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
            response = await client.get(API + path + "?private=" + secrets.token_hex(16))
    if path == "/manifests/v2.json":
        assert response.status_code == 200
    assert probe_lines(caplog) == []


async def test_probe_logs_neither_headers_nor_body_and_keeps_origin_refusals(service, caplog):
    private = secrets.token_urlsafe(32)
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
            response = await client.post(
                "https://wrong-host.test/live?probe=wrong-host",
                headers={"Authorization": "Bearer " + private, "Cookie": "private=" + private},
                content=private,
            )
    assert response.status_code == 421
    assert probe_lines(caplog) == [
        {"method": "POST", "path": "/live", "query": "probe=wrong-host", "status": 421}
    ]
    if any(private in record.getMessage() for record in caplog.records):
        raise AssertionError("request headers or body reached probe logging")


async def test_probe_query_is_escaped_into_one_log_line(service, caplog):
    raw = b'probe="tag"\nforged\r\t\x1b\xff'
    messages = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        await service(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/live",
                "raw_path": b"/live",
                "query_string": raw,
                "headers": [(b"host", b"api.secrets.test")],
            },
            receive,
            send,
        )
    assert messages[0]["status"] == 200
    assert probe_lines(caplog)[0]["query"] == raw.decode("ascii", errors="backslashreplace")
    line = next(r.getMessage() for r in caplog.records if r.name == "uvicorn.error")
    assert len(line.splitlines()) == 1
    assert "\x1b" not in line


def test_shipped_command_keeps_global_access_logging_off():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    command = next(
        line.removeprefix("CMD ")
        for line in dockerfile.read_text().splitlines()
        if line.startswith("CMD ")
    )
    assert "--no-access-log" in json.loads(command)
