"""Federated delivery connects only to admitted addresses of the delivery origin.

The delivery function and the address policy are the real ones. Names resolve
through a recording resolver, and every listener is on this machine.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.external_authority import OriginContext
from awid.registry import Address, AddressDelivery, KeyResolution
from awid.signing import canonical_json_bytes, sign_message

import aweb.federation.mail as federation_mail
import test_chat_http
import test_messages_http
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.mcp.auth import AuthContext
from aweb.mcp.server import register_tools
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.mcp.tools import chat as chat_tools
from aweb.mcp.tools import mail as mail_tools
from did_key_fixtures import named_did_key
from test_federation_mail import _envelope
from test_mcp_contacts_consumer import ToolCollector
from test_mcp_mail_chat import DBInfra

SOURCE = Path(__file__).resolve().parents[1] / "src" / "aweb"
PRODUCTION = OriginContext()
ISOLATED_DEVELOPMENT = OriginContext(
    app_env="development",
    federation_test_enabled=True,
    listener_origin="http://127.0.0.1:8000",
)
PUBLIC_IPV4 = "93.184.216.34"
PUBLIC_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"
NON_PUBLIC_ADDRESSES = [
    "127.0.0.1",
    "127.8.9.10",
    "10.0.0.5",
    "172.16.0.9",
    "172.31.255.254",
    "192.168.1.1",
    "169.254.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "100.127.255.254",
    "0.0.0.0",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::1",
    "::",
    "fc00::1",
    "fd12:3456:789a::1",
    "fe80::1",
    "ff02::1",
    "::ffff:10.0.0.5",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:192.168.1.1",
]


class Hosts:
    """Answers each name from a table and records every lookup."""

    def __init__(self, answers: dict[str, tuple[str, ...]]) -> None:
        self.answers = answers
        self.queries: list[str] = []

    async def resolve_all(self, hostname: str) -> tuple[str, ...]:
        self.queries.append(hostname)
        return self.answers[hostname]


class Listener:
    """A loopback HTTP listener that records every connection and request."""

    def __init__(self, status: int = 200, body: bytes = b"{}", headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.connections = 0
        self.requests: list[bytes] = []
        self.server: asyncio.Server | None = None
        self.port = 0

    async def __aenter__(self) -> "Listener":
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value)
            self.requests.append(head + await reader.readexactly(length))
            extra = "".join(f"{name}: {value}\r\n" for name, value in self.headers.items())
            writer.write(
                f"HTTP/1.1 {self.status} Answer\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(self.body)}\r\n{extra}Connection: close\r\n\r\n".encode()
                + self.body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    def header(self, name: str, request: int = 0) -> str:
        for line in self.requests[request].split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
            key, _, value = line.partition(b":")
            if key.strip().lower() == name.lower().encode():
                return value.strip().decode()
        raise AssertionError(f"request carries no {name} header")


def _transport(hosts: Hosts, context: OriginContext = PRODUCTION):
    from aweb.federation.transport import AddressCheckedTransport

    return AddressCheckedTransport(host_resolver=hosts, origin_context=context)


@pytest.fixture
def dials(monkeypatch):
    """Every request the transport hands to the network, answered here with an empty document."""
    seen: list[httpx.Request] = []

    async def record(_self, request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", record)
    return seen


@pytest.fixture
def no_system_resolution(monkeypatch):
    """Fail the test if the system resolver is asked for anything but an address literal."""
    real = socket.getaddrinfo

    def numeric_only(host, *args, **kwargs):
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in str(host) else socket.AF_INET, str(host))
        except OSError:
            raise AssertionError(f"system resolver was asked for {host!r}") from None
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", numeric_only)


async def _deliver(origin: str, transport) -> dict:
    return await deliver_federated_message(
        delivery_origin=origin,
        envelope=_envelope(),
        signature="signature",
        transport=transport,
    )


def _assert_refused(error: FederatedMailDeliveryError, origin: str, reason: str = "delivery_origin_refused") -> None:
    assert error.status_code == 502
    assert error.reason == reason
    assert str(error) == f"Federated mail delivery to {origin} failed: {reason}"


def _assert_address_refused(error: FederatedMailDeliveryError, origin: str) -> None:
    _assert_refused(error, origin, "delivery_address_refused")


@pytest.mark.asyncio
async def test_http_delivery_origin_is_refused_before_resolution_or_connection(dials):
    async with Listener() as listener:
        hosts = Hosts({"peer.example": ("127.0.0.1",)})
        origin = f"http://peer.example:{listener.port}"
        with pytest.raises(FederatedMailDeliveryError) as caught:
            await _deliver(origin, _transport(hosts))
        _assert_refused(caught.value, origin)
        assert hosts.queries == []
        assert dials == []
        assert listener.connections == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("address", NON_PUBLIC_ADDRESSES)
async def test_delivery_origin_resolving_to_a_non_public_address_is_refused(address, dials):
    async with Listener() as listener:
        hosts = Hosts({"peer.example": (address,)})
        origin = f"https://peer.example:{listener.port}"
        with pytest.raises(FederatedMailDeliveryError) as caught:
            await _deliver(origin, _transport(hosts))
        _assert_address_refused(caught.value, origin)
        assert hosts.queries == ["peer.example"]
        assert dials == []
        assert listener.connections == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "::ffff:127.0.0.1"])
async def test_refused_loopback_answer_reaches_no_listener(address):
    async with Listener() as listener:
        hosts = Hosts({"peer.example": (address,)})
        origin = f"https://peer.example:{listener.port}"
        with pytest.raises(FederatedMailDeliveryError) as caught:
            await _deliver(origin, _transport(hosts))
        _assert_address_refused(caught.value, origin)
        assert listener.connections == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answers",
    [(PUBLIC_IPV4, "10.0.0.5"), ("169.254.169.254", PUBLIC_IPV4), (PUBLIC_IPV6, "fd00::1"), ()],
)
async def test_every_answer_must_be_public(answers, dials):
    hosts = Hosts({"peer.example": answers})
    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver("https://peer.example", _transport(hosts))
    _assert_address_refused(caught.value, "https://peer.example")
    assert dials == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "origin",
    ["https://10.0.0.5", "https://127.0.0.1", "https://169.254.169.254", "https://[::1]", f"https://{PUBLIC_IPV4}"],
)
async def test_address_literal_delivery_origin_is_refused(origin, dials):
    hosts = Hosts({})
    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver(origin, _transport(hosts))
    _assert_refused(caught.value, origin)
    assert hosts.queries == []
    assert dials == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answers", "connected"),
    [
        ((PUBLIC_IPV4,), PUBLIC_IPV4),
        ((PUBLIC_IPV6,), PUBLIC_IPV6),
        ((PUBLIC_IPV4, "1.1.1.1"), PUBLIC_IPV4),
        ((PUBLIC_IPV6, PUBLIC_IPV4), PUBLIC_IPV6),
    ],
)
async def test_delivery_connects_to_the_address_that_was_checked(answers, connected, dials, no_system_resolution):
    hosts = Hosts({"peer.example": answers})

    assert await _deliver("https://peer.example:8443", _transport(hosts)) == {}

    assert hosts.queries == ["peer.example"]
    assert len(dials) == 1
    request = dials[0]
    assert request.url.scheme == "https"
    assert request.url.host == connected
    assert request.url.port == 8443
    assert request.url.path == "/v1/federation/messages"
    assert request.headers["Host"] == "peer.example:8443"
    assert request.extensions["sni_hostname"] == "peer.example"


@pytest.mark.asyncio
async def test_delivery_tries_the_next_checked_address_when_one_does_not_connect(monkeypatch, no_system_resolution):
    attempts: list[tuple[str, float]] = []

    async def dial(_self, request: httpx.Request) -> httpx.Response:
        attempts.append((request.url.host, request.extensions["timeout"]["connect"]))
        if request.url.host == PUBLIC_IPV6:
            raise httpx.ConnectError("no route to host", request=request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    hosts = Hosts({"peer.example": (PUBLIC_IPV6, PUBLIC_IPV4)})

    assert await _deliver("https://peer.example", _transport(hosts)) == {}

    assert hosts.queries == ["peer.example"]
    assert [host for host, _ in attempts] == [PUBLIC_IPV6, PUBLIC_IPV4]
    # An address that does not answer leaves time for the next one.
    assert attempts[0][1] < attempts[1][1] == 10.0


@pytest.mark.asyncio
async def test_delivery_does_not_resend_after_a_connection_was_made(monkeypatch):
    attempts: list[str] = []

    async def dial(_self, request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.host)
        raise httpx.ReadError("connection closed", request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    hosts = Hosts({"peer.example": (PUBLIC_IPV4, "1.1.1.1")})

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver("https://peer.example", _transport(hosts))

    assert caught.value.reason == "delivery_origin_unreachable"
    assert attempts == [PUBLIC_IPV4]


@pytest.mark.asyncio
async def test_isolated_development_reaches_a_listener_on_the_second_address():
    async with Listener() as listener:
        hosts = Hosts({"peer.test": ("::1", "127.0.0.1")})

        assert await _deliver(
            f"http://peer.test:{listener.port}", _transport(hosts, ISOLATED_DEVELOPMENT),
        ) == {}

        assert hosts.queries == ["peer.test"]
        assert listener.connections == 1


@pytest.mark.asyncio
async def test_each_delivery_resolves_and_checks_again(dials):
    hosts = Hosts({"peer.example": (PUBLIC_IPV4,)})
    transport = _transport(hosts)
    assert await _deliver("https://peer.example", transport) == {}

    hosts.answers["peer.example"] = ("10.0.0.5",)
    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver("https://peer.example", transport)

    _assert_address_refused(caught.value, "https://peer.example")
    assert hosts.queries == ["peer.example", "peer.example"]
    assert len(dials) == 1


@pytest.mark.asyncio
async def test_isolated_development_delivers_over_http_to_the_resolved_address(no_system_resolution):
    async with Listener() as listener:
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        origin = f"http://peer.test:{listener.port}"

        assert await _deliver(origin, _transport(hosts, ISOLATED_DEVELOPMENT)) == {}

        assert hosts.queries == ["peer.test"]
        assert listener.connections == 1
        assert listener.requests[0].startswith(b"POST /v1/federation/messages HTTP/1.1\r\n")
        assert listener.header("Host") == f"peer.test:{listener.port}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("context", "host"),
    [
        (OriginContext(app_env="production", federation_test_enabled=True, listener_origin="http://127.0.0.1:8000"), "peer.test"),
        (OriginContext(app_env="development", federation_test_enabled=False, listener_origin="http://127.0.0.1:8000"), "peer.test"),
        (OriginContext(app_env="development", federation_test_enabled=True, listener_origin="https://aweb.example"), "peer.test"),
        (ISOLATED_DEVELOPMENT, "peer.example"),
    ],
)
async def test_isolated_development_allowance_needs_every_condition(context, host):
    async with Listener() as listener:
        hosts = Hosts({host: ("127.0.0.1",)})
        for scheme, reason in (("http", "delivery_origin_refused"), ("https", "delivery_address_refused")):
            origin = f"{scheme}://{host}:{listener.port}"
            with pytest.raises(FederatedMailDeliveryError) as caught:
                await _deliver(origin, _transport(hosts, context))
            _assert_refused(caught.value, origin, reason)
        assert listener.connections == 0


@pytest.mark.asyncio
async def test_redirect_answer_is_not_followed():
    async with Listener() as target:
        redirect = {"Location": f"http://127.0.0.1:{target.port}/v1/federation/messages"}
        async with Listener(status=307, headers=redirect) as listener:
            hosts = Hosts({"peer.test": ("127.0.0.1",)})
            origin = f"http://peer.test:{listener.port}"
            with pytest.raises(FederatedMailDeliveryError) as caught:
                await _deliver(origin, _transport(hosts, ISOLATED_DEVELOPMENT))
            assert caught.value.status_code == 502
            assert caught.value.reason == "HTTP 307"
            assert listener.connections == 1
            assert target.connections == 0


@pytest.mark.asyncio
async def test_connections_are_not_shared_between_origins_at_one_address():
    async with Listener() as listener:
        hosts = Hosts({"one.test": ("127.0.0.1",), "two.test": ("127.0.0.1",)})
        transport = _transport(hosts, ISOLATED_DEVELOPMENT)
        for name in ("one.test", "two.test", "one.test"):
            assert await _deliver(f"http://{name}:{listener.port}", transport) == {}
        assert listener.connections == 3
        assert [listener.header("Host", index) for index in range(3)] == [
            f"{name}:{listener.port}" for name in ("one.test", "two.test", "one.test")
        ]


@pytest.mark.asyncio
async def test_unresolvable_delivery_origin_is_unreachable(dials):
    from awid.federation_errors import FederationAuthorityError

    class Unresolvable:
        async def resolve_all(self, hostname: str) -> tuple[str, ...]:
            raise FederationAuthorityError("sender_registry_unavailable")

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver("https://peer.example", _transport(Unresolvable()))
    assert caught.value.status_code == 502
    assert caught.value.reason == "delivery_origin_unreachable"
    assert dials == []


@pytest.mark.asyncio
async def test_large_error_answer_reaches_the_caller_as_a_status_only(caplog):
    secret = "AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    body = json.dumps({"detail": secret + " " + "x" * 60_000, "error": secret}).encode()
    async with Listener(status=500, body=body) as listener:
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        origin = f"http://peer.test:{listener.port}"
        with caplog.at_level(logging.WARNING, logger="aweb.federation.mail"):
            with pytest.raises(FederatedMailDeliveryError) as caught:
                await _deliver(origin, _transport(hosts, ISOLATED_DEVELOPMENT))

    error = caught.value
    assert error.status_code == 502
    assert error.reason == "HTTP 500"
    assert str(error) == f"Federated mail delivery to {origin} failed: HTTP 500"
    records = [record.getMessage() for record in caplog.records if record.name == "aweb.federation.mail"]
    assert len(records) == 1
    assert origin in records[0]
    assert "500" in records[0]
    assert len(records[0]) <= 512


def test_delivery_requires_a_transport():
    parameter = inspect.signature(deliver_federated_message).parameters["transport"]
    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert not hasattr(federation_mail, "deliver_federated_mail")


@pytest.mark.asyncio
async def test_delivery_without_a_transport_makes_no_request(dials):
    with pytest.raises(TypeError):
        await deliver_federated_message(
            delivery_origin="https://peer.example", envelope=_envelope(), signature="signature",
        )
    with pytest.raises(TypeError):
        await _deliver("https://peer.example", None)
    assert dials == []


def _calls(tree: ast.AST, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (getattr(node.func, "id", None) == name or getattr(node.func, "attr", None) == name)
    ]


def test_every_server_caller_passes_the_delivery_transport():
    callers = []
    for path in SOURCE.rglob("*.py"):
        for call in _calls(ast.parse(path.read_text()), "deliver_federated_message"):
            callers.append(path.relative_to(SOURCE).as_posix())
            assert "transport" in {keyword.arg for keyword in call.keywords}, path
    assert sorted(callers) == ["routes/chat.py", "routes/messages.py"]


def test_one_module_makes_destination_named_requests():
    """Outside the operator's own CLI and the test harness, the server builds an
    HTTP client in the delivery function alone and dials in the transport module alone."""
    clients, dialers = [], []
    for path in SOURCE.rglob("*.py"):
        relative = path.relative_to(SOURCE).as_posix()
        if relative in {"cli.py", "testing.py"}:
            continue
        tree = ast.parse(path.read_text())
        clients += [relative for _ in _calls(tree, "AsyncClient") + _calls(tree, "Client")]
        dialers += [relative for _ in _calls(tree, "AsyncHTTPTransport") + _calls(tree, "HTTPTransport")]
    assert clients == ["federation/mail.py"]
    assert dialers == ["federation/transport.py"]


def test_id_tree_registry_reads_use_the_same_pinned_transport():
    import aweb.federation.id_tree_registry as id_tree_registry
    import aweb.federation.transport as transport

    assert id_tree_registry.PinnedTransport is transport.PinnedTransport
    assert id_tree_registry.admitted_addresses is transport.admitted_addresses
    assert not hasattr(id_tree_registry, "_PinnedTransport")


def test_federation_authority_carries_the_delivery_transport(monkeypatch):
    from aweb.federation.activation import build_federation_authority_activation
    from aweb.federation.transport import AddressCheckedTransport, delivery_transport

    monkeypatch.delenv("AWEB_FEDERATION_TEST", raising=False)
    monkeypatch.delenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", raising=False)
    database = SimpleNamespace(get_manager=lambda _name: object())
    authority = build_federation_authority_activation(database, public_origin="https://aweb.example")

    transport = authority.delivery_transport
    assert isinstance(transport, AddressCheckedTransport)
    assert authority.delivery_transport is transport
    assert transport.host_resolver is authority.resolver.host_resolver
    assert transport.origin_context is authority.resolver.origin_context
    assert delivery_transport(authority) is transport
    assert delivery_transport(authority, None, None) is transport
    host_set = httpx.MockTransport(lambda _request: httpx.Response(200, json={}))
    assert delivery_transport(authority, None, host_set) is host_set
    assert delivery_transport(None) is None
    assert delivery_transport(SimpleNamespace()) is None


PRIVATE_DELIVERY_ORIGINS = "AWEB_FEDERATION_PRIVATE_DELIVERY_ORIGINS"
PRIVATE_ORIGIN = "https://aweb.acme.internal"


class Rows:
    """Answers every single-row query with one row."""

    def __init__(self, row: dict) -> None:
        self.row = row

    async def fetch_one(self, *_args):
        return self.row


def _authority(monkeypatch, setting: str | None, row: dict | None = None):
    from aweb.federation.activation import build_federation_authority_activation

    for name in ("APP_ENV", "AWEB_FEDERATION_TEST", "AWEB_FEDERATION_TEST_DEFAULT_REGISTRY"):
        monkeypatch.delenv(name, raising=False)
    if setting is None:
        monkeypatch.delenv(PRIVATE_DELIVERY_ORIGINS, raising=False)
    else:
        monkeypatch.setenv(PRIVATE_DELIVERY_ORIGINS, setting)
    database = SimpleNamespace(get_manager=lambda _name: Rows(row or {}))
    return build_federation_authority_activation(database, public_origin="https://aweb.example")


def _private_hosts() -> Hosts:
    return Hosts({
        "aweb.acme.internal": ("10.0.0.5",),
        "mail.aweb.acme.internal": ("10.0.0.5",),
        "acme.internal": ("10.0.0.5",),
    })


@pytest.mark.asyncio
async def test_private_delivery_origin_is_refused_by_default_and_the_log_names_the_setting(
    monkeypatch, dials, caplog,
):
    authority = _authority(monkeypatch, None)
    authority.resolver.host_resolver = hosts = _private_hosts()

    with caplog.at_level(logging.WARNING, logger="aweb.federation.transport"):
        with pytest.raises(FederatedMailDeliveryError) as caught:
            await _deliver(PRIVATE_ORIGIN, authority.delivery_transport)

    _assert_address_refused(caught.value, PRIVATE_ORIGIN)
    assert PRIVATE_DELIVERY_ORIGINS not in str(caught.value)
    assert hosts.queries == ["aweb.acme.internal"]
    assert dials == []
    [record] = [record for record in caplog.records if record.name == "aweb.federation.transport"]
    assert record.levelno == logging.WARNING
    assert PRIVATE_ORIGIN in record.getMessage()
    assert PRIVATE_DELIVERY_ORIGINS in record.getMessage()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setting",
    [PRIVATE_ORIGIN, "https://AWEB.acme.internal.:443/", f" https://other.internal , {PRIVATE_ORIGIN} "],
)
async def test_listed_private_delivery_origin_is_delivered_to_the_checked_address(
    setting, monkeypatch, dials, no_system_resolution,
):
    authority = _authority(monkeypatch, setting)
    authority.resolver.host_resolver = hosts = _private_hosts()

    assert await _deliver(PRIVATE_ORIGIN, authority.delivery_transport) == {}

    assert hosts.queries == ["aweb.acme.internal"]
    [request] = dials
    assert request.url.scheme == "https"
    assert request.url.host == "10.0.0.5"
    assert request.url.port is None
    assert request.url.path == "/v1/federation/messages"
    assert request.headers["Host"] == "aweb.acme.internal"
    assert request.extensions["sni_hostname"] == "aweb.acme.internal"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answers",
    [
        ("10.0.0.5",),
        ("172.16.0.1",),
        ("172.31.255.255",),
        ("192.168.1.1",),
        ("100.64.1.2",),
        ("100.127.255.254",),
        ("fd00::5",),
        ("fc00::1",),
        ("::ffff:10.0.0.5",),
        ("172.32.0.1",),
        ("10.0.0.5", PUBLIC_IPV4),
        ("100.64.1.2", "fd00::5"),
    ],
)
async def test_listed_delivery_origin_admits_private_networks_at_the_checked_address(
    answers, monkeypatch, dials, no_system_resolution,
):
    authority = _authority(monkeypatch, PRIVATE_ORIGIN)
    authority.resolver.host_resolver = hosts = Hosts({"aweb.acme.internal": answers})

    assert await _deliver(PRIVATE_ORIGIN, authority.delivery_transport) == {}

    assert hosts.queries == ["aweb.acme.internal"]
    [request] = dials
    assert request.url.host == str(ipaddress.ip_address(answers[0]))
    assert request.headers["Host"] == "aweb.acme.internal"
    assert request.extensions["sni_hostname"] == "aweb.acme.internal"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answers",
    [
        ("169.254.169.254",),
        ("169.254.1.1",),
        ("127.0.0.1",),
        ("0.0.0.0",),
        ("::1",),
        ("::",),
        ("fe80::1",),
        ("::ffff:169.254.169.254",),
        ("::ffff:127.0.0.1",),
        ("192.0.2.1",),
        ("198.18.0.1",),
        ("240.0.0.1",),
        ("224.0.0.1",),
        ("255.255.255.255",),
        ("ff02::1",),
        ("10.0.0.5", "169.254.169.254"),
        ("fd00::5", "fe80::1"),
        (PUBLIC_IPV4, "127.0.0.1"),
        (),
    ],
)
async def test_listed_delivery_origin_refuses_addresses_outside_the_private_networks(
    answers, monkeypatch, dials, caplog,
):
    authority = _authority(monkeypatch, PRIVATE_ORIGIN)
    authority.resolver.host_resolver = Hosts({"aweb.acme.internal": answers})

    with caplog.at_level(logging.WARNING, logger="aweb.federation.transport"):
        with pytest.raises(FederatedMailDeliveryError) as caught:
            await _deliver(PRIVATE_ORIGIN, authority.delivery_transport)

    _assert_address_refused(caught.value, PRIVATE_ORIGIN)
    assert dials == []
    [record] = [record for record in caplog.records if record.name == "aweb.federation.transport"]
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert PRIVATE_ORIGIN in message
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"):
        assert network in message
    assert f"add {PRIVATE_ORIGIN} to" not in message


@pytest.mark.parametrize("address", ["100.64.1.2", "172.16.0.1", "fd00::5"])
@pytest.mark.asyncio
async def test_private_networks_of_listed_origins_stay_refused_for_unlisted_origins(address, monkeypatch, dials):
    authority = _authority(monkeypatch, PRIVATE_ORIGIN)
    authority.resolver.host_resolver = Hosts({"aweb.partner.internal": (address,)})

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver("https://aweb.partner.internal", authority.delivery_transport)

    _assert_address_refused(caught.value, "https://aweb.partner.internal")
    assert dials == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("origin", "reason"),
    [
        ("https://aweb.acme.internal:8443", "delivery_address_refused"),
        ("http://aweb.acme.internal", "delivery_origin_refused"),
        ("https://mail.aweb.acme.internal", "delivery_address_refused"),
        ("https://acme.internal", "delivery_address_refused"),
    ],
)
async def test_origin_differing_from_the_listed_one_is_refused(origin, reason, monkeypatch, dials):
    authority = _authority(monkeypatch, PRIVATE_ORIGIN)
    authority.resolver.host_resolver = _private_hosts()

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver(origin, authority.delivery_transport)

    _assert_refused(caught.value, origin, reason)
    assert dials == []


@pytest.mark.asyncio
async def test_listed_private_delivery_origin_does_not_widen_id_tree_registry_reads(monkeypatch, dials):
    from awid.federation_errors import FederationAuthorityError

    row = {
        "authority_selection": "dns", "authority_name": "acme.internal", "controller_did": "did:key:controller",
        "inherited": False, "registry_explicit": True, "registry_origin": PRIVATE_ORIGIN,
        "authority_statement_digest": "digest",
    }
    authority = _authority(monkeypatch, PRIVATE_ORIGIN, row)
    authority.resolver.host_resolver = hosts = _private_hosts()
    token = SimpleNamespace(
        canonical_address="acme.internal/bob", did_aw="did:aw:bob", checkpoint_revision=1, cohort_generation=1,
    )

    with pytest.raises(FederationAuthorityError) as caught:
        async with authority.received_registry_client(token, named_did_key("bob"), None):
            pass

    assert caught.value.reason == "sender_registry_origin_forbidden"
    assert hosts.queries == ["aweb.acme.internal"]
    assert dials == []
    assert await _deliver(PRIVATE_ORIGIN, authority.delivery_transport) == {}
    assert len(dials) == 1


def test_only_the_delivery_transport_receives_the_private_delivery_origins():
    """Registry reads admit addresses without the delivery allowlist."""
    callers = []
    for path in SOURCE.rglob("*.py"):
        for call in _calls(ast.parse(path.read_text()), "admitted_addresses"):
            keywords = {keyword.arg for keyword in call.keywords}
            callers.append((path.relative_to(SOURCE).as_posix(), "private_origins" in keywords))
    assert sorted(callers) == [("federation/id_tree_registry.py", False), ("federation/transport.py", True)]


@pytest.mark.parametrize(
    "entry",
    [
        "aweb.acme.internal",
        "https://aweb.acme.internal/v1",
        "https://aweb.acme.internal?x=1",
        "https://aweb.acme.internal#top",
        "https://ops@aweb.acme.internal",
        "10.0.0.0/8",
        "https://10.0.0.0/8",
        "https://10.0.0.5",
        "https://[fd00::1]",
        "https://*.acme.internal",
        "*",
        "http://aweb.acme.internal",
        "ftp://aweb.acme.internal",
    ],
)
def test_invalid_private_delivery_origin_refuses_start_up_naming_the_entry(entry, monkeypatch):
    with pytest.raises(ValueError) as caught:
        _authority(monkeypatch, f"{PRIVATE_ORIGIN},{entry}")
    assert PRIVATE_DELIVERY_ORIGINS in str(caught.value)
    assert repr(entry) in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", [None, "", "  ", " , "])
async def test_unset_or_empty_private_delivery_origins_keep_the_default(setting, monkeypatch, dials):
    authority = _authority(monkeypatch, setting)
    authority.resolver.host_resolver = _private_hosts()

    assert authority.delivery_transport.private_delivery_origins == frozenset()
    with pytest.raises(FederatedMailDeliveryError) as caught:
        await _deliver(PRIVATE_ORIGIN, authority.delivery_transport)
    _assert_address_refused(caught.value, PRIVATE_ORIGIN)
    assert dials == []


def _private_origin_authority():
    hosts = Hosts({"remote.example": ("10.0.0.5",)})
    return SimpleNamespace(delivery_transport=_transport(hosts)), hosts


REFUSED_DETAIL = "Federated mail delivery to https://remote.example failed: delivery_address_refused"


async def _signer_for(signing_key, did):
    async def signer(**kwargs) -> HostedMessageSigningResult:
        signed_payload = canonical_signed_payload(kwargs["payload"])
        return HostedMessageSigningResult(
            from_did=did,
            signature=sign_message(signing_key, signed_payload.encode("utf-8")),
            signed_payload=signed_payload,
            signing_key_id=did,
        )

    return signer


async def _mcp_sender(aweb_db, monkeypatch, tools):
    team_id = "ops:acme.com"
    agent_id, workspace_id = uuid4(), uuid4()
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    await aweb_db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ($1, 'acme.com', 'ops', $2)",
        team_id, named_did_key("z6MkTeam"),
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, status, inbound_mode, did_aw_verified_key)
        VALUES ($1, $2, $3, 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'active', 'open', $3)
        """,
        agent_id, team_id, did,
    )
    monkeypatch.setattr(
        tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id, agent_id=str(agent_id), workspace_id=str(workspace_id), alias="alice",
            did_key=did, did_aw="did:aw:alice", address="acme.com/alice", trusted_proxy=True,
        ),
    )
    return SimpleNamespace(team_id=team_id, agent_id=agent_id, did=did, signer=await _signer_for(signing_key, did))


def _registered_tools(aweb_db, authority, signer) -> ToolCollector:
    collector = ToolCollector()
    register_tools(
        collector,  # type: ignore[arg-type]
        db_infra=DBInfra(aweb_db),
        redis=None,
        registry_client=SimpleNamespace(),
        federation_authority=authority,
        hosted_signer=signer,
        public_origin="https://local.example",
    )
    return collector


@pytest.mark.asyncio
async def test_mcp_federated_mail_to_a_private_address_is_refused(aweb_cloud_db, monkeypatch, dials):
    db = aweb_cloud_db.aweb_db
    sender = await _mcp_sender(db, monkeypatch, mail_tools)
    conversation_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
        VALUES ($1, 'mail', $2, 'did:aw:alice')
        """,
        conversation_id, sender.team_id,
    )
    await db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role
        )
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3, 'sender', 'initiator'),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', $4,
             'federation:https://remote.example', 'participant')
        """,
        conversation_id, sender.agent_id, sender.did, named_did_key("bob"),
    )
    authority, hosts = _private_origin_authority()
    tools = _registered_tools(db, authority, sender.signer)

    result = json.loads(await tools.funcs["send_mail"](
        conversation_id=str(conversation_id), subject="Re", body="federated reply", plaintext=True,
    ))

    assert result == {"error": REFUSED_DETAIL}
    assert hosts.queries == ["remote.example"]
    assert dials == []
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0


@pytest.mark.asyncio
async def test_mcp_federated_chat_to_a_private_address_is_refused(aweb_cloud_db, monkeypatch, dials):
    db = aweb_cloud_db.aweb_db
    sender = await _mcp_sender(db, monkeypatch, chat_tools)
    session_id = uuid4()
    await db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by) VALUES ($1, $2, 'alice')",
        session_id, sender.team_id,
    )
    await db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (
            session_id, did, agent_id, alias, address, delivery_origin, current_did_key
        )
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3),
            ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', 'https://remote.example', $4)
        """,
        session_id, sender.agent_id, sender.did, named_did_key("bob"),
    )
    authority, hosts = _private_origin_authority()
    tools = _registered_tools(db, authority, sender.signer)

    result = json.loads(await tools.funcs["send_chat"](
        conversation_id=str(session_id), message="federated continuation", plaintext=True,
    ))

    assert result == {"error": REFUSED_DETAIL}
    assert hosts.queries == ["remote.example"]
    assert dials == []
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}") == 0


def _remote_bob() -> Address:
    return Address(
        address_id="addr-remote-private",
        domain="otherco.com",
        name="bob",
        did_aw="did:aw:bob",
        current_did_key=named_did_key("bob"),
        reachability="public",
        created_at=datetime.now(timezone.utc).isoformat(),
        delivery=AddressDelivery(origin="https://remote.example"),
    )


def _signed(sender_key, payload: dict) -> tuple[str, str]:
    signed_payload = canonical_json_bytes(payload).decode()
    return signed_payload, sign_message(sender_key, signed_payload.encode())


@pytest.mark.asyncio
async def test_mail_route_delivers_through_the_authority_transport(aweb_cloud_db, dials):
    db = aweb_cloud_db.aweb_db
    alice_key, _, alice_did = test_messages_http._make_keypair()
    await test_messages_http._insert_team(db, "backend:acme.com")
    agent_id = await test_messages_http._insert_agent(
        db, team_id="backend:acme.com", alias="alice", did_key=alice_did,
        did_aw="did:aw:alice", address="acme.com/alice",
    )
    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=_remote_bob())
    app = test_messages_http._build_test_app(db, registry)
    authority, hosts = _private_origin_authority()
    app.state.federation_authority.delivery_transport = authority.delivery_transport
    app.dependency_overrides[get_messaging_auth] = lambda: MessagingAuth(
        did_key=alice_did, did_aw="did:aw:alice", address="acme.com/alice",
        team_id="backend:acme.com", alias="alice", agent_id=agent_id,
    )
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload, signature = _signed(alice_key, {
        "body": "hello", "conversation_id": conversation_id, "from": "acme.com/alice",
        "from_did": alice_did, "from_stable_id": "did:aw:alice", "message_id": message_id,
        "subject": "private origin", "timestamp": timestamp, "to": "otherco.com/bob",
        "to_did": named_did_key("bob"), "to_stable_id": "did:aw:bob", "type": "mail",
    })

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/messages", json={
            "to_address": "otherco.com/bob", "subject": "private origin", "body": "hello",
            "conversation_id": conversation_id, "message_id": message_id, "timestamp": timestamp,
            "from_did": alice_did, "signature": signature, "signed_payload": signed_payload,
        })

    assert response.status_code == 502, response.text
    assert response.json() == {"detail": REFUSED_DETAIL}
    assert hosts.queries == ["remote.example"]
    assert dials == []
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0


@pytest.mark.asyncio
async def test_chat_route_delivers_through_the_authority_transport(aweb_cloud_db, dials):
    db = aweb_cloud_db.aweb_db
    alice_key, _, alice_did = test_chat_http._make_keypair()
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ('backend:acme.com', 'acme.com', 'backend', $1)",
        named_did_key("team-1"),
    )
    agent_id = await db.fetch_value(
        """
        INSERT INTO {{tables.agents}}
            (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', $1)
        RETURNING agent_id
        """,
        alice_did,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=named_did_key("bob"))
    )
    registry.resolve_address = AsyncMock(return_value=_remote_bob())
    app = test_chat_http._build_test_app(db, registry)
    app.state.public_origin = "https://local.example"
    authority, hosts = _private_origin_authority()
    app.state.federation_authority.delivery_transport = authority.delivery_transport
    app.dependency_overrides[get_messaging_auth] = lambda: MessagingAuth(
        did_key=alice_did, did_aw="did:aw:alice", address="acme.com/alice",
        team_id="backend:acme.com", alias="alice", agent_id=agent_id,
    )
    session_id, message_id = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload, signature = _signed(alice_key, {
        "body": "private origin chat", "conversation_id": session_id, "from": "acme.com/alice",
        "from_did": alice_did, "from_stable_id": "did:aw:alice", "message_id": message_id,
        "timestamp": timestamp, "to": "otherco.com/bob", "to_did": named_did_key("bob"),
        "to_stable_id": "did:aw:bob", "type": "chat",
    })

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/v1/chat/sessions", json={
            "session_id": session_id, "to_addresses": ["otherco.com/bob"], "message": "private origin chat",
            "from_did": alice_did, "message_id": message_id, "timestamp": timestamp,
            "signature": signature, "signed_payload": signed_payload,
        })

    assert response.status_code == 502, response.text
    assert response.json() == {"detail": REFUSED_DETAIL}
    assert hosts.queries == ["remote.example"]
    assert dials == []
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}") == 0
