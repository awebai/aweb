"""One naapp service on two origins: an agent origin and a human origin.

The agent origin serves the app's member-signed tools. Its authority is the
team-auth signature on each request and nothing else, so it carries no ambient
credential: the ``Cookie`` request header is removed before the app sees the
request, and any ``Set-Cookie`` the app sends is removed from the response.

The human origin serves pages for a person in a browser, authenticated by that
origin's own session. It never accepts team-auth: a request carrying an
``Authorization`` header (any scheme) or any ``X-AWEB-*`` or ``X-AWID-*``
header is refused before the app sees it.

Each origin is its own ASGI app, chosen by the request's ``Host``, so a route
exists on exactly one origin. A request for any other host is misdirected. The
lifespan is the agent app's (the runtime's); the human app shares the runtime's
state and must not depend on a lifespan of its own.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_DEFAULT_PORTS = {"http": 80, "https": 443}
_TEAM_AUTH_PREFIXES = (b"x-aweb-", b"x-awid-")


def _origin_hosts(origin: str) -> frozenset[str]:
    """The ``Host`` values that name ``origin``: its host, lowercased, with and
    without the scheme's default port."""
    parts = urlsplit(origin.rstrip("/"))
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ValueError(f"{origin!r} is not an http(s) origin")
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError(f"{origin!r} is not a plain origin")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port or _DEFAULT_PORTS[parts.scheme]
    hosts = {f"{host}:{port}"}
    if port == _DEFAULT_PORTS[parts.scheme]:
        hosts.add(host)
    return frozenset(hosts)


def _host(scope: Scope) -> str:
    for name, value in scope.get("headers", ()):
        if name == b"host":
            return str(value.decode("latin-1").lower())
    return ""


def _carries_team_auth(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    return any(name == b"authorization" or name.startswith(_TEAM_AUTH_PREFIXES) for name, _ in headers)


async def _refuse(send: Send, status: int, code: str, message: str) -> None:
    body = json.dumps({"code": code, "message": message}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"x-content-type-options", b"nosniff"),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def split_origins(
    agent_app: ASGIApp, human_app: ASGIApp, *, agent_origin: str, human_origin: str
) -> ASGIApp:
    """The ASGI app serving ``agent_app`` on ``agent_origin`` and ``human_app``
    on ``human_origin``. The two origins must be distinct."""
    agent_hosts = _origin_hosts(agent_origin)
    human_hosts = _origin_hosts(human_origin)
    if agent_hosts & human_hosts:
        raise ValueError("the agent origin and the human origin must be distinct")

    async def agent(scope: Scope, receive: Receive, send: Send) -> None:
        headers = [(name, value) for name, value in scope["headers"] if name != b"cookie"]

        async def send_without_cookies(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": [
                        (name, value)
                        for name, value in message.get("headers", ())
                        if name.lower() != b"set-cookie"
                    ],
                }
            await send(message)

        await agent_app({**scope, "headers": headers}, receive, send_without_cookies)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await agent_app(scope, receive, send)
            return
        if scope["type"] != "http":
            raise RuntimeError(f"unsupported ASGI scope type {scope['type']!r}")
        host = _host(scope)
        if host in agent_hosts:
            await agent(scope, receive, send)
        elif host in human_hosts:
            if _carries_team_auth(scope["headers"]):
                await _refuse(send, 403, "team_auth_refused", "This origin does not accept team-auth")
                return
            await human_app(scope, receive, send)
        else:
            await _refuse(send, 421, "unknown_origin", "This service does not serve that host")

    return app
