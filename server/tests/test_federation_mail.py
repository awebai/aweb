from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
from httpx import MockTransport, Response

import aweb.federation.mail as federation_mail_module
from aweb.federation.envelope import FederationEnvelope
from aweb.federation.mail import (
    MAX_FEDERATION_ERROR_BYTES,
    MAX_FEDERATION_RESPONSE_BYTES,
    FederatedMailDeliveryError,
    deliver_federated_message,
)


def _envelope() -> FederationEnvelope:
    return FederationEnvelope(
        type="mail",
        sender_did_aw="did:aw:sender",
        sender_current_did_key="did:key:sender",
        target_address="example.com/bob",
        target_did_aw="did:aw:target",
        target_current_did_key="did:key:target",
        target_delivery_origin="https://target.example",
        body="hello",
        message_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        signed_payload="{}",
    )


def test_federation_http_bound_values_are_pinned():
    assert MAX_FEDERATION_RESPONSE_BYTES == 10 * 1024 * 1024
    assert MAX_FEDERATION_ERROR_BYTES == 64 * 1024


class UnreadEncodedStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.iterations = 0
        self.closed = 0

    async def __aiter__(self):
        self.iterations += 1
        raise AssertionError("encoded response was read before rejection")
        yield b""  # pragma: no cover

    async def aclose(self) -> None:
        self.closed += 1


@pytest.mark.asyncio
async def test_federation_rejects_encoding_before_stream_iteration():
    stream = UnreadEncodedStream()
    accept_encoding: list[str] = []

    def handler(request):
        accept_encoding.append(request.headers.get("accept-encoding", ""))
        return Response(200, stream=stream, headers={"Content-Encoding": "gzip"})

    with pytest.raises(FederatedMailDeliveryError, match="(?i)content.encoding"):
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=MockTransport(handler),
        )
    assert accept_encoding == ["identity"]
    assert stream.iterations == 0
    assert stream.closed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("content_encoding", ["identity", " Identity "])
async def test_federation_accepts_identity_encoded_response(content_encoding: str):
    assert await deliver_federated_message(
        delivery_origin="https://target.example",
        envelope=_envelope(),
        signature="signature",
        transport=MockTransport(
            lambda _request: Response(
                200,
                json={},
                headers={"Content-Encoding": content_encoding},
            )
        ),
    ) == {}


@pytest.mark.asyncio
async def test_federation_redirect_target_receives_no_request():
    target_hits = 0

    def handler(request):
        nonlocal target_hits
        if request.url.host == "target.test":
            target_hits += 1
            return Response(200, json={})
        return Response(307, headers={"Location": "https://target.test/final"})

    with pytest.raises(Exception):
        await deliver_federated_message(
            delivery_origin="https://source.test",
            envelope=_envelope(),
            signature="signature",
            transport=MockTransport(handler),
        )
    assert target_hits == 0


class SlowResponseStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        while True:
            await asyncio.sleep(0.02)
            yield b" "


class ClosingErrorStream(httpx.AsyncByteStream):
    def __init__(self, closed: list[bool]) -> None:
        self.closed = closed

    async def __aiter__(self):
        yield b"{"
        raise httpx.ReadError("malicious response failed mid-stream")

    async def aclose(self) -> None:
        self.closed.append(True)


@pytest.mark.asyncio
async def test_federation_delivery_closes_every_repeated_failed_response():
    closed: list[bool] = []
    transport = MockTransport(
        lambda _request: Response(200, stream=ClosingErrorStream(closed))
    )

    for _attempt in range(16):
        with pytest.raises(FederatedMailDeliveryError, match="failed"):
            await deliver_federated_message(
                delivery_origin="https://target.example",
                envelope=_envelope(),
                signature="signature",
                transport=transport,
            )
    assert len(closed) == 16


@pytest.mark.asyncio
async def test_federation_delivery_enforces_overall_deadline_on_slow_body():
    with pytest.raises(Exception, match="failed"):
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=MockTransport(lambda _request: Response(200, stream=SlowResponseStream())),
            timeout=0.01,
        )


@pytest.mark.asyncio
async def test_federation_delivery_explicitly_disables_redirects(monkeypatch):
    real_client = httpx.AsyncClient
    configured: list[bool] = []

    def client_factory(**kwargs):
        configured.append(kwargs.get("follow_redirects", True))
        kwargs.setdefault("follow_redirects", True)
        return real_client(**kwargs)

    monkeypatch.setattr(federation_mail_module.httpx, "AsyncClient", client_factory)
    await deliver_federated_message(
        delivery_origin="https://target.example",
        envelope=_envelope(),
        signature="signature",
        transport=MockTransport(lambda _request: Response(200, json={})),
    )
    assert configured == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("extra_bytes", "should_succeed"),
    [(0, True), (1, False)],
)
async def test_federation_delivery_enforces_response_limit(extra_bytes: int, should_succeed: bool):
    content = b"{}" + b" " * (MAX_FEDERATION_RESPONSE_BYTES - 2 + extra_bytes)
    transport = MockTransport(lambda _request: Response(200, content=content))

    if should_succeed:
        assert await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        ) == {}
    else:
        with pytest.raises(Exception, match="maximum|size|large|limit"):
            await deliver_federated_message(
                delivery_origin="https://target.example",
                envelope=_envelope(),
                signature="signature",
                transport=transport,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("suffix", "should_succeed"),
    [(b" \r\n\t", True), (b"\n{}", False)],
)
async def test_federation_delivery_requires_one_json_document(
    suffix: bytes,
    should_succeed: bool,
):
    transport = MockTransport(lambda _request: Response(200, content=b"{}" + suffix))

    if should_succeed:
        assert await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        ) == {}
    else:
        with pytest.raises(FederatedMailDeliveryError, match="invalid JSON"):
            await deliver_federated_message(
                delivery_origin="https://target.example",
                envelope=_envelope(),
                signature="signature",
                transport=transport,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body_size", "should_reach_remote_error"),
    [(64 * 1024, True), (64 * 1024 + 1, False)],
)
async def test_federation_delivery_enforces_error_limit(
    body_size: int,
    should_reach_remote_error: bool,
):
    transport = MockTransport(lambda _request: Response(500, content=b"x" * body_size))

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        )
    if should_reach_remote_error:
        assert str(caught.value).endswith("x" * (64 * 1024))
    else:
        assert "maximum size of 65536 bytes" in str(caught.value)


@pytest.mark.asyncio
async def test_federation_delivery_sanitizes_error_controls():
    transport = MockTransport(
        lambda _request: Response(500, content=b"bad\x1b[31m\nnext\x00line")
    )

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        )
    message = str(caught.value)
    assert "\x1b" not in message
    assert "\n" not in message
    assert "\x00" not in message
    assert message.endswith("bad [31m next line")
