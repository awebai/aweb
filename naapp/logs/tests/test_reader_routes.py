"""The reader tools of logs' agent origin, as the manifest declares them, and
the DNS tracer every test that starts a runtime runs under."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

REMOVE_READER_TOOL: dict[str, Any] = {
    "name": "remove-reader",
    "description": "Remove a reader of the team's log; never the last one.",
    "method": "POST",
    "path": "/v1/reader-removals",
    "input_schema": {
        "type": "object",
        "properties": {"scope": {"type": "string"}},
        "required": ["scope"],
        "additionalProperties": False,
    },
    "params": [{"name": "scope", "in": "body"}],
    "scopes": ["logs.readers"],
    "mutation": True,
    "body": {"mode": "json"},
    "invocation_contexts": ["agent"],
}


@contextmanager
def blocked_dns() -> Iterator[list[str]]:
    """Refuse and record every name lookup but the local database's."""
    original = socket.getaddrinfo
    looked_up: list[str] = []

    def refuse(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in ("localhost", "127.0.0.1", "::1", None):
            return original(host, *args, **kwargs)
        looked_up.append(str(host))
        raise socket.gaierror(f"blocked DNS lookup of {host}")

    socket.getaddrinfo = refuse  # type: ignore[assignment]
    try:
        yield looked_up
    finally:
        socket.getaddrinfo = original  # type: ignore[assignment]


def test_the_dns_tracer_refuses_and_records_a_real_lookup() -> None:
    with blocked_dns() as looked_up:
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("logs.example.test", 443)
    assert looked_up == ["logs.example.test"]
