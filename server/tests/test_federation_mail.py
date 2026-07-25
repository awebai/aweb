from __future__ import annotations

import asyncio
import gzip
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


@pytest.mark.asyncio
async def test_federation_rejects_decompressed_response_over_limit():
    content = gzip.compress(b"{}" + b" " * (MAX_FEDERATION_RESPONSE_BYTES - 1))
    with pytest.raises(Exception, match="maximum|size|large|limit"):
        await deliver_federated_message(
            delivery_origin="https://target.example",
            envelope=_envelope(),
            signature="signature",
            transport=MockTransport(
                lambda _request: Response(200, content=content, headers={"Content-Encoding": "gzip"})
            ),
        )


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
