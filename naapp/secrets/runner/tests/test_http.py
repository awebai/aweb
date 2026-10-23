"""Outbound signed requests exercise real verified TLS and exact raw bytes."""

import asyncio
import hashlib
import json
import os
import time
from dataclasses import replace
from threading import Event

import pytest
from test_registration import invoke, service  # noqa: F401

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.http import RunnerHTTP
from aweb_secrets_runner.protocol import decode64

DISPATCH = "dsp_" + "a" * 22


def ready(service):  # noqa: F811
    identity = invoke(service)
    service["requests"].clear()
    service["raw_requests"].clear()
    service.update(
        status=204,
        raw=b"",
        headers={"Cache-Control": "no-store", "Content-Type": "application/json"},
    )
    return identity


def test_real_tls_requests_bind_exact_report_bytes_and_fresh_nonce(service):  # noqa: F811
    identity = ready(service)
    body = (
        b' { "exit_code":0,"stdout":"","stderr":"","truncated":false,'
        b'"result_withheld":false,"redaction_count":0 } '
    )

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert await client.claim() is None
            await client.started(DISPATCH)
            await client.result(DISPATCH, body)
            await client.result(DISPATCH, body)

    asyncio.run(scenario())
    nonces = []
    for index, (path, raw, headers) in enumerate(service["raw_requests"]):
        encoded, signature = headers["X-AWEB-Secrets-Runner-Request"].split(".")
        payload = decode64(encoded)
        identity.signing_key.public_key().verify(
            decode64(signature), b"aweb.secrets.runner-request/1\n" + payload
        )
        doc = json.loads(payload)
        assert doc["method"] == "POST"
        assert doc["path"] == path
        assert doc["origin"] == identity.origin
        assert doc["runner_id"] == identity.runner_id
        assert doc["body_sha256"] == hashlib.sha256(raw).hexdigest()
        assert raw == (b"{}" if index < 2 else body)
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept-Encoding"] == "identity"
        nonces.append(doc["nonce"])
    assert len(set(nonces)) == 4


def test_claim_returns_bounded_bytes_for_verifier_without_decoding(service):  # noqa: F811
    identity = ready(service)
    service.update(status=200, raw=b'{"opaque":"signed assignment"}')

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert await client.claim() == service["raw"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "defect", ["large", "large_no_length", "encoding", "cache", "type", "ack_body", "redirect"]
)
def test_invalid_response_is_value_free_and_never_followed(service, defect):  # noqa: F811
    identity = ready(service)
    canary = os.urandom(24).hex()
    service.update(status=200, raw=json.dumps({"canary": canary}).encode())
    if defect in {"large", "large_no_length"}:
        service["raw"] = b"x" * (1024 * 1024 + 1)
        service["omit_length"] = defect == "large_no_length"
    elif defect == "encoding":
        service["headers"]["Content-Encoding"] = "gzip"
    elif defect == "cache":
        del service["headers"]["Cache-Control"]
    elif defect == "type":
        service["headers"]["Content-Type"] = "text/html"
    elif defect == "ack_body":
        service["status"] = 204
    else:
        service["status"] = 302
        service["headers"]["Location"] = service["origin"] + "/redirect"

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused) as error:
                await client.claim()
            assert error.value.code == "runner_response_invalid"
            assert canary not in str(error.value)

    asyncio.run(scenario())
    assert len(service["requests"]) == 1


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "runner_unknown"),
        (404, "runner_dispatch_unknown"),
        (409, "runner_reconciliation_required"),
        (409, "runner_dispatch_state_conflict"),
        (409, "runner_result_conflict"),
        (503, "runner_unavailable"),
    ],
)
def test_only_exact_public_refusals_are_surfaced(service, status, code):  # noqa: F811
    identity = ready(service)
    service.update(status=status, raw=json.dumps({"detail": {"code": code}}).encode())

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused) as error:
                await client.result(DISPATCH, b"{}")
            assert error.value.code == code

    asyncio.run(scenario())


def test_unknown_error_or_extra_private_fields_are_not_reflected(service):  # noqa: F811
    identity = ready(service)
    canary = os.urandom(24).hex()

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            for document in (
                {"detail": {"code": canary}},
                {"detail": {"code": "runner_unknown", "message": canary}},
            ):
                service.update(status=401, raw=json.dumps(document).encode())
                with pytest.raises(Refused) as error:
                    await client.claim()
                assert error.value.code == "runner_response_invalid"
                assert canary not in str(error.value)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"detail":{"code":"runner_unknown","code":"runner_unknown"}}',
        b'{"detail":{"code":false}}',
        b'{"detail":{"code":1.0}}',
        b'{"detail":{"code":"runner_result_conflict"}}',
        b" " * 4097,
    ],
)
def test_malformed_and_status_mismatched_errors_refuse(service, raw):  # noqa: F811
    identity = ready(service)
    service.update(status=401, raw=raw)

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused, match="runner_response_invalid"):
                await client.claim()

    asyncio.run(scenario())


def test_tls_verification_and_ambient_proxy_and_cookie_isolation(service, monkeypatch):  # noqa: F811
    identity = ready(service)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ambient/ca")
    service["headers"]["Set-Cookie"] = "ambient=value; Path=/"

    async def scenario():
        async with RunnerHTTP(identity) as client:
            with pytest.raises(Refused, match="runner_unavailable"):
                await client.claim()
        assert service["requests"] == []
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            await client.claim()
            await client.claim()

    asyncio.run(scenario())
    assert len(service["requests"]) == 2
    assert all("Cookie" not in headers for _, _, headers in service["raw_requests"])


def test_total_deadline_and_cancellation_close_in_flight_request(service):  # noqa: F811
    identity = ready(service)
    service.update(received=Event(), resume=Event())

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"], deadline_s=0.5) as client:
            started = time.monotonic()
            try:
                with pytest.raises(Refused, match="runner_unavailable"):
                    await client.claim()
                assert service["received"].is_set()
                assert time.monotonic() - started < 2
            finally:
                service["resume"].set()
        service["received"].clear()
        service["resume"].clear()
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            task = asyncio.create_task(client.claim())
            assert await asyncio.to_thread(service["received"].wait, 2)
            task.cancel()
            try:
                with pytest.raises(asyncio.CancelledError):
                    await task
            finally:
                service["resume"].set()

    asyncio.run(scenario())


def test_unregistered_identity_and_invalid_dispatch_refuse_without_network(service):  # noqa: F811
    identity = ready(service)
    with pytest.raises(Refused, match="runner_unregistered"):
        RunnerHTTP(replace(identity, runner_id=None))

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused, match="runner_request_invalid"):
                await client.started(DISPATCH + "/../result")

    asyncio.run(scenario())
    assert service["requests"] == []
