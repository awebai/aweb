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
from did_key_fixtures import named_did_key


def _envelope() -> FederationEnvelope:
    return FederationEnvelope(
        type="mail",
        sender_did_aw="did:aw:sender",
        sender_current_did_key=named_did_key("sender"),
        target_address="example.com/bob",
        target_did_aw="did:aw:target",
        target_current_did_key=named_did_key("target"),
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
async def test_federation_does_not_echo_control_bearing_content_encoding():
    stream = UnreadEncodedStream()
    transport = MockTransport(
        lambda _request: Response(
            200,
            stream=stream,
            headers={"Content-Encoding": "\x1b[31m"},
        )
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
    assert message.endswith("unsupported HTTP Content-Encoding")
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


class ChunkedStream(httpx.AsyncByteStream):
    """A response body delivered chunk by chunk, so httpx never pre-reads it.

    A transport handed a ready-made body marks the response stream consumed,
    which sends _read_bounded_response down its already-read path and leaves the
    accumulating loop unexercised. Handing httpx a stream is what puts a
    size-boundary test on the path production takes against a real server.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.chunks_yielded = 0

    async def __aiter__(self):
        for chunk in self._chunks:
            self.chunks_yielded += 1
            yield chunk


def _json_padding_chunks(total_bytes: int, chunk_size: int = 64 * 1024) -> list[bytes]:
    """An empty JSON document padded to exactly total_bytes, split into chunks."""
    body = b"{}" + b" " * (total_bytes - 2)
    return [body[offset : offset + chunk_size] for offset in range(0, len(body), chunk_size)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("extra_bytes", "should_succeed"),
    [(0, True), (1, False)],
)
async def test_federation_delivery_bounds_a_streamed_response(extra_bytes: int, should_succeed: bool):
    chunks = _json_padding_chunks(MAX_FEDERATION_RESPONSE_BYTES + extra_bytes)
    stream = ChunkedStream(chunks)
    transport = MockTransport(lambda _request: Response(200, stream=stream))

    if should_succeed:
        assert await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        ) == {}
        assert stream.chunks_yielded == len(chunks)
    else:
        with pytest.raises(FederatedMailDeliveryError, match="maximum size of 10485760 bytes"):
            await deliver_federated_message(
                delivery_origin="https://target.example",
                envelope=_envelope(),
                signature="signature",
                transport=transport,
            )


@pytest.mark.asyncio
async def test_federation_delivery_abandons_a_streamed_response_at_the_bound():
    chunk_size = 64 * 1024
    chunks = [b" " * chunk_size] * (2 * MAX_FEDERATION_RESPONSE_BYTES // chunk_size)
    stream = ChunkedStream(chunks)

    with pytest.raises(FederatedMailDeliveryError, match="maximum size of 10485760 bytes"):
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=MockTransport(lambda _request: Response(200, stream=stream)),
        )

    # Leaving the body part-read is only reachable from inside the accumulating
    # loop; the already-read path holds the whole response before it can measure
    # it. This is what proves the fixture enters the branch under test.
    assert 0 < stream.chunks_yielded < len(chunks)


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
    assert "xx" not in str(caught.value)
    if should_reach_remote_error:
        assert str(caught.value) == "Federated mail delivery to https://target.example failed: HTTP 500"
        assert caught.value.reason == "HTTP 500"
    else:
        assert "maximum size of 65536 bytes" in str(caught.value)
    assert caught.value.status_code == 502


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        b"bad\x1b[31m\nnext\x00line",
        b'{"detail": "bad\\u001b[31m next line", "error": "internal"}',
        b'{"detail": {"code": "internal", "message": "free text"}}',
        b'{"reason": "not_a_federation_reason", "detail": "free text"}',
        b'{"reason": ["recipient_policy_rejected"]}',
        b'["recipient_policy_rejected"]',
        b"[" * 60_000,
        b"",
    ],
)
async def test_federation_delivery_does_not_relay_an_untyped_error_answer(content: bytes):
    transport = MockTransport(lambda _request: Response(500, content=content))

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        )
    assert str(caught.value) == "Federated mail delivery to https://target.example failed: HTTP 500"
    assert caught.value.reason == "HTTP 500"
    assert caught.value.status_code == 502


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "reason", "relayed_status"),
    [
        (403, "recipient_policy_rejected", 403),
        (422, "local_sender_route_mismatch", 422),
        (404, "recipient_identity_not_found", 404),
        (421, "target_route_mismatch", 421),
        (503, "sender_registry_unavailable", 502),
    ],
)
async def test_federation_delivery_relays_only_the_typed_refusal_reason(
    status: int, reason: str, relayed_status: int,
):
    body = {
        "detail": "The recipient is not set up for messaging; internal note 8f3a",
        "reason": reason,
        "retryable": False,
        "correlation_id": "c0ffee",
        "peer_body": "internal note 8f3a",
    }
    transport = MockTransport(lambda _request: Response(status, json=body))

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=transport,
        )
    assert str(caught.value) == f"Federated mail delivery to https://target.example failed: {reason}"
    assert caught.value.reason == reason
    assert caught.value.status_code == relayed_status


@pytest.mark.asyncio
async def test_federation_delivery_logs_a_bounded_sanitized_error_answer(caplog):
    content = b"bad\x1b[31m\nnext\x00line " + b"y" * 60_000
    transport = MockTransport(lambda _request: Response(500, content=content))

    with caplog.at_level("WARNING", logger="aweb.federation.mail"):
        with pytest.raises(FederatedMailDeliveryError):
            await deliver_federated_message(
                delivery_origin="https://target.example",
                envelope=_envelope(),
                signature="signature",
                transport=transport,
            )
    [message] = [record.getMessage() for record in caplog.records if record.name == "aweb.federation.mail"]
    assert "https://target.example" in message
    assert "bad [31m next line" in message
    assert "\x1b" not in message
    assert "\n" not in message
    assert "\x00" not in message
    assert len(message) <= 512


@pytest.mark.asyncio
async def test_federation_delivery_reports_a_transport_failure_by_kind():
    def handler(_request):
        raise httpx.ConnectError("peer said: internal note 8f3a")

    with pytest.raises(FederatedMailDeliveryError) as caught:
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=MockTransport(handler),
        )
    assert str(caught.value) == (
        "Federated mail delivery to https://target.example failed: delivery_origin_unreachable"
    )
    assert caught.value.status_code == 502


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("recipients", "relayed"),
    [
        (["beta.test/bob"], ["beta.test/bob"]),
        (["beta.test/bob", "x" * 400], []),
        (["beta.test/bob\x1b[31m"], []),
        (["beta.test/bob"] * 40, []),
        ("beta.test/bob", []),
    ],
)
async def test_federation_delivery_bounds_human_chat_refusal_recipients(recipients, relayed):
    from aweb.messaging.chat_policy import HumanChatRefused

    body = {"reason": "recipient_human_mail_only", "retryable": False, "recipients": recipients,
            "detail": "free text"}
    envelope = _envelope().model_copy(update={"type": "chat"})

    with pytest.raises(HumanChatRefused) as caught:
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=envelope,
            signature="signature",
            transport=MockTransport(lambda _request: Response(422, json=body)),
        )
    assert caught.value.recipients == sorted(set(relayed))
