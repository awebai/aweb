"""Bounded 429 read recovery through the real SDK request boundary; no sockets."""

import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

import awid.registry as registry_module
from awid.registry import RegistryClient
from awid.registry_types import RegistryError


class Clock:
    def __init__(self):
        self.now = 0.0
        self.delays = []

    async def sleep(self, delay):
        self.delays.append(delay)
        self.now += delay
        await asyncio.sleep(0)


@pytest.fixture
def clock(monkeypatch):
    value = Clock()
    monkeypatch.setattr(
        registry_module, "_read_retry_now", lambda: value.now, raising=False
    )
    monkeypatch.setattr(
        registry_module, "_read_retry_sleep", value.sleep, raising=False
    )
    return value


@pytest.mark.asyncio
async def test_rate_limited_read_honors_retry_after_then_succeeds(clock):
    requests = []

    def transport(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                429, headers={"Retry-After": "1"}, json={"detail": "private identity"}
            )
        return httpx.Response(200, json={"ok": True})

    client = RegistryClient(
        "https://registry.example", transport=httpx.MockTransport(transport)
    )
    try:
        assert await client._request_json("GET", "/v1/did/example/key") == {"ok": True}
    finally:
        await client.aclose()
    assert len(requests) == 2
    assert clock.delays == [1.0]
    assert all(request.headers["accept-encoding"] == "identity" for request in requests)


@pytest.mark.asyncio
async def test_repeated_throttle_is_finite_and_error_is_sanitized(clock):
    attempts = []
    client = RegistryClient(
        "https://registry.example",
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(
                    429,
                    headers={"Retry-After": "0"},
                    json={"detail": "SECRET did:aw:private"},
                )
            )
        ),
    )
    try:
        with pytest.raises(RegistryError) as caught:
            await client._request_json("GET", "/key")
    finally:
        await client.aclose()
    error = caught.value
    assert type(error).__name__ == "RegistryThrottled"
    assert error.code == "rate_limited" and error.status_code == 429
    assert error.reason == "attempt_budget"
    assert error.attempts == len(attempts) == 3
    assert len(clock.delays) == 2 and all(delay > 0 for delay in clock.delays)
    assert "SECRET" not in str(error) + str(error.detail) + str(error.body)


@pytest.mark.asyncio
@pytest.mark.parametrize("hint", ["6", "999999999999", "9999999999999"])
async def test_retry_after_past_total_budget_is_not_shortened_or_slept(clock, hint):
    attempts = []
    client = RegistryClient(
        "https://registry.example",
        timeout_seconds=5,
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(429, headers={"Retry-After": hint})
            )
        ),
    )
    try:
        with pytest.raises(RegistryError) as caught:
            await client._request_json("GET", "/key")
    finally:
        await client.aclose()
    assert caught.value.code == "rate_limited"
    assert caught.value.reason == "elapsed_budget"
    assert caught.value.retry_after_seconds == float(hint)
    assert len(attempts) == 1 and clock.delays == []


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_registry_mutations_are_never_replayed(clock, method):
    attempts = []
    client = RegistryClient(
        "https://registry.example",
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(429, headers={"Retry-After": "0"})
            )
        ),
    )
    try:
        with pytest.raises(RegistryError):
            await client._request_json(method, "/write", json={"change": True})
    finally:
        await client.aclose()
    assert len(attempts) == 1 and clock.delays == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "headers": {
                "Authorization": "DIDKey external proof",
                "X-AWEB-Timestamp": "old",
            }
        },
        {"headers": {"X-AWEB-Signed-Payload": "external-proof"}},
        {"content": b"nonempty GET body"},
        {"json": {}},
    ],
)
async def test_unrefreshable_proof_or_nonempty_get_is_not_replayed(clock, kwargs):
    attempts = []
    client = RegistryClient(
        "https://registry.example",
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(429, headers={"Retry-After": "0"})
            )
        ),
    )
    try:
        with pytest.raises(RegistryError) as caught:
            await client._request_json("GET", "/key", **kwargs)
    finally:
        await client.aclose()
    assert caught.value.code == ("rate_limited" if "headers" in kwargs else None)
    assert len(attempts) == 1 and clock.delays == []


@pytest.mark.asyncio
async def test_cancellation_during_backoff_propagates_without_another_attempt():
    started = asyncio.Event()
    attempts = []

    def transport(request):
        attempts.append(request)
        started.set()
        return httpx.Response(429, headers={"Retry-After": "1"})

    client = RegistryClient(
        "https://registry.example", transport=httpx.MockTransport(transport)
    )
    task = asyncio.create_task(client._request_json("GET", "/key"))
    try:
        await started.wait()
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        await client.aclose()
    assert len(attempts) == 1


@pytest.mark.asyncio
async def test_callers_original_deadline_cancels_backoff():
    attempts = []
    client = RegistryClient(
        "https://registry.example",
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(429, headers={"Retry-After": "1"})
            )
        ),
    )
    try:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.02):
                await client._request_json("GET", "/key")
    finally:
        await client.aclose()
    assert len(attempts) == 1


def test_retry_after_http_date_and_invalid_values():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    parse = registry_module._retry_after_seconds
    assert parse(format_datetime(now + timedelta(seconds=2), usegmt=True), now=now) == 2
    assert parse(format_datetime(now - timedelta(seconds=2), usegmt=True), now=now) == 0
    for value in (None, "", "-1", "NaN", "inf", "0.1", "nonsense"):
        assert parse(value, now=now) is None


@pytest.mark.asyncio
async def test_sdk_member_signature_is_rebuilt_and_verifies_on_each_attempt(
    clock, monkeypatch
):
    import awid.registry_auth as auth_module
    from awid.signing import verify_did_key_signature

    base = datetime(2026, 11, 12, tzinfo=timezone.utc)

    class WallClock:
        @classmethod
        def now(cls, _zone):
            return base + timedelta(seconds=clock.now)

    monkeypatch.setattr(auth_module, "datetime", WallClock)
    requests = []

    def transport(request):
        requests.append(request)
        stamp = request.headers["X-AWEB-Timestamp"]
        scheme, key, signature = request.headers["Authorization"].split()
        assert scheme == "DIDKey"
        verify_did_key_signature(
            did_key=key,
            payload=f"{stamp}\nGET\n{request.url.path}".encode(),
            signature_b64=signature,
        )
        return (
            httpx.Response(429, headers={"Retry-After": "1"})
            if len(requests) == 1
            else httpx.Response(200, json={"ok": True})
        )

    client = RegistryClient(
        "https://registry.example",
        member_signing_keys={"demo:example.org": bytes(range(32))},
        transport=httpx.MockTransport(transport),
    )
    try:
        assert await client._request_json(
            "GET", "/v1/namespaces/example.org/teams/demo"
        ) == {"ok": True}
    finally:
        await client.aclose()
    assert len(requests) == 2
    assert (
        requests[0].headers["X-AWEB-Timestamp"]
        != requests[1].headers["X-AWEB-Timestamp"]
    )
    assert requests[0].headers["Authorization"] != requests[1].headers["Authorization"]


@pytest.mark.asyncio
async def test_response_is_closed_and_its_private_throttle_body_is_not_read(
    clock, monkeypatch
):
    class ErrorStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            raise AssertionError("throttle bodies must not be read")
            yield b""

        async def aclose(self):
            self.closed = True

    stream = ErrorStream()
    attempts = []

    async def sleep(delay):
        assert stream.closed
        await clock.sleep(delay)

    monkeypatch.setattr(registry_module, "_read_retry_sleep", sleep)

    def transport(request):
        attempts.append(request)
        return (
            httpx.Response(429, stream=stream, headers={"Retry-After": "0"})
            if len(attempts) == 1
            else httpx.Response(200, json={})
        )

    client = RegistryClient(
        "https://registry.example", transport=httpx.MockTransport(transport)
    )
    try:
        assert await client._request_json("GET", "/key") == {}
    finally:
        await client.aclose()
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_original_sdk_budget_exhaustion_during_backoff_retains_throttle(
    monkeypatch,
):
    attempts = []

    async def oversleep(_delay):
        await asyncio.sleep(1)

    monkeypatch.setattr(registry_module, "_read_retry_sleep", oversleep)
    client = RegistryClient(
        "https://registry.example",
        timeout_seconds=0.08,
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(429, headers={"Retry-After": "0"})
            )
        ),
    )
    try:
        with pytest.raises(RegistryError) as caught:
            await client._request_json("GET", "/key")
    finally:
        await client.aclose()
    assert type(caught.value).__name__ == "RegistryThrottled"
    assert caught.value.reason == "elapsed_budget"
    assert len(attempts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("hint", [None, "-1", "malformed"])
async def test_missing_or_invalid_hint_uses_bounded_backoff(clock, hint):
    attempts = []

    def transport(request):
        attempts.append(request)
        headers = {"Retry-After": hint} if hint is not None else {}
        return (
            httpx.Response(429, headers=headers)
            if len(attempts) == 1
            else httpx.Response(200, json={})
        )

    client = RegistryClient(
        "https://registry.example", transport=httpx.MockTransport(transport)
    )
    try:
        assert await client._request_json("GET", "/key") == {}
    finally:
        await client.aclose()
    assert clock.delays == [0.25]
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_late_success_cannot_outlive_original_read_budget(clock):
    def transport(_request):
        clock.now = 6
        return httpx.Response(200, json={"late": True})

    client = RegistryClient(
        "https://registry.example",
        timeout_seconds=5,
        transport=httpx.MockTransport(transport),
    )
    try:
        with pytest.raises(RegistryError) as caught:
            await client._request_json("GET", "/key")
    finally:
        await client.aclose()
    assert caught.value.code == "unavailable"
