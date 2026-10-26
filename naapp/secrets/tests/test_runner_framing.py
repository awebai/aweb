"""Transport framing on real Starlette requests, without a stand-in S13 service."""

import hashlib
import secrets
from datetime import UTC, datetime

import pytest
from aweb_naapp.hooks.strictjson import encode_base64url
from awid.did import did_from_public_key
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from aweb_secrets.runner_protocol import RunnerRefused, canonical, format_time
from aweb_secrets.runner_routes import (
    _read_body,
    _request_head,
    _runner_refusal,
    _runner_reply,
)
from aweb_secrets.runner_types import RunnerReply


def signed_header(body=b"{}", path="/runner/v1/claim"):
    key = SigningKey.generate()
    raw = canonical(
        {
            "v": 1,
            "type": "aweb.secrets.runner-request",
            "origin": "https://secrets.example",
            "runner_id": "rnr_" + secrets.token_urlsafe(16),
            "kid": did_from_public_key(bytes(key.verify_key)),
            "method": "POST",
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": format_time(datetime.now(UTC)),
            "nonce": encode_base64url(secrets.token_bytes(16)),
        }
    )
    signature = key.sign(b"aweb.secrets.runner-request/1\n" + raw).signature
    return encode_base64url(raw) + "." + encode_base64url(signature)


def request(chunks=(), *, headers=(), root_path="", raw_path=b"/runner/v1/claim", query=b""):
    pending = list(chunks)
    reads = []

    async def receive():
        reads.append(1)
        chunk = pending.pop(0) if pending else b""
        return {"type": "http.request", "body": chunk, "more_body": bool(pending)}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/runner/v1/claim",
        "raw_path": raw_path,
        "root_path": root_path,
        "query_string": query,
        "headers": list(headers),
    }
    return Request(scope, receive), reads


def headers(header=None, media=b"application/json"):
    return [
        (b"x-aweb-secrets-runner-request", (header or signed_header()).encode()),
        (b"content-type", media),
    ]


@pytest.mark.parametrize("raw_path", [b"/runner/v1/claim", b"/secrets/runner/v1/claim"])
def test_signed_external_target_retains_mount_and_header_without_reading_body(raw_path):
    header = signed_header(path="/secrets/runner/v1/claim")
    incoming, reads = request(headers=headers(header), raw_path=raw_path, root_path="/secrets")
    assert _request_head(incoming) == (header, "/secrets/runner/v1/claim")
    assert reads == []


@pytest.mark.parametrize("media", [b"application/json", b"Application/JSON; charset=UTF-8"])
def test_supported_media_leaves_exact_body_for_final_service_verification(media):
    incoming, reads = request(headers=headers(media=media))
    _request_head(incoming)
    assert reads == []


@pytest.mark.parametrize(
    "extra,media,status",
    [
        ([], b"text/plain", 415),
        ([], b"application/json; charset=latin-1", 415),
        ([], b"application/json; other=x", 415),
        ([(b"content-encoding", b"gzip")], b"application/json", 415),
        ([(b"content-type", b"application/json")], b"application/json", 415),
        ([(b"x-aweb-secrets-runner-request", b"duplicate")], b"application/json", 400),
    ],
)
def test_unsupported_or_ambiguous_headers_refuse_before_read(extra, media, status):
    incoming, reads = request(headers=headers(media=media) + extra)
    with pytest.raises(HTTPException) as refused:
        _request_head(incoming)
    assert refused.value.status_code == status
    assert refused.value.detail == {"code": "runner_request_invalid"}
    assert reads == []


@pytest.mark.parametrize("bad", [b"not-signed", b"x" * 4097, b""])
def test_invalid_runner_header_has_constant_refusal_before_read(bad):
    incoming, reads = request(
        headers=[(b"x-aweb-secrets-runner-request", bad), (b"content-type", b"application/json")]
    )
    with pytest.raises(RunnerRefused) as refused:
        _request_head(incoming)
    assert refused.value.code == "runner_request_invalid"
    assert reads == []


def test_query_or_non_ascii_target_is_not_reinterpreted():
    for changes in ({"query": b"unexpected=1"}, {"raw_path": b"/runner/\xff"}):
        incoming, reads = request(headers=headers(), **changes)
        with pytest.raises(HTTPException) as refused:
            _request_head(incoming)
        assert refused.value.status_code == 400
        assert refused.value.detail == {"code": "runner_request_invalid"}
        assert reads == []


async def test_chunked_body_preserves_original_bytes_and_accepts_exact_limit():
    chunks = [b' {"stdout":', '"é"'.encode(), b"} \n"]
    expected = b"".join(chunks)
    incoming, reads = request(chunks)
    assert await _read_body(incoming, limit=len(expected)) == expected
    assert len(reads) == len(chunks)


async def test_stream_limit_aborts_at_first_oversized_chunk():
    incoming, reads = request([b"12", b"345", b"never read"])
    with pytest.raises(HTTPException) as refused:
        await _read_body(incoming, limit=4)
    assert refused.value.status_code == 413
    assert refused.value.detail == {"code": "runner_request_too_large"}
    assert len(reads) == 2


@pytest.mark.parametrize("length", [b"-1", b"+2", b"two", b"", b"2, 2"])
async def test_invalid_declared_length_does_not_read_stream(length):
    incoming, reads = request([b"{}"], headers=[(b"content-length", length)])
    with pytest.raises(HTTPException) as refused:
        await _read_body(incoming, limit=4096)
    assert refused.value.status_code == 400
    assert reads == []


async def test_declared_length_obeys_pinned_limit_before_read_and_cannot_hide_overflow():
    incoming, reads = request([b"12345"], headers=[(b"content-length", b"5")])
    with pytest.raises(HTTPException) as refused:
        await _read_body(incoming, limit=4)
    assert refused.value.status_code == 413 and reads == []
    incoming, reads = request([b"12345"], headers=[(b"content-length", b"2")])
    with pytest.raises(HTTPException) as refused:
        await _read_body(incoming, limit=4)
    assert refused.value.status_code == 413


async def test_duplicate_or_incorrect_length_refuses_and_correct_length_passes():
    for lengths in ([b"2", b"2"], [b"3"]):
        incoming, _ = request([b"{}"], headers=[(b"content-length", n) for n in lengths])
        with pytest.raises(HTTPException) as refused:
            await _read_body(incoming, limit=4096)
        assert refused.value.status_code == 400
    incoming, _ = request([b"{}"], headers=[(b"content-length", b"2")])
    assert await _read_body(incoming, limit=4096) == b"{}"


def test_stored_assignment_bytes_and_empty_ack_are_returned_without_reencoding():
    raw = b' {"opaque": "signed bytes"}\n'
    response = _runner_reply(RunnerReply(200, raw), operation="claim")
    assert response.body == raw and response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    for operation in ("claim", "started", "result"):
        response = _runner_reply(RunnerReply(204), operation=operation)
        assert response.status_code == 204 and response.body == b""
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "operation,reply",
    [
        ("result", RunnerReply(200, b"{}")),
        ("claim", RunnerReply(204, b"unexpected")),
        ("claim", RunnerReply(200)),
        ("claim", RunnerReply(200, b"x" * (1024 * 1024 + 1))),
    ],
)
def test_invalid_service_reply_is_not_published(operation, reply):
    with pytest.raises(ValueError):
        _runner_reply(reply, operation=operation)


@pytest.mark.parametrize(
    "code,status",
    [
        ("runner_request_invalid", 400),
        ("runner_result_invalid", 400),
        ("runner_request_binding_mismatch", 400),
        ("runner_unknown", 401),
        ("runner_dispatch_unknown", 404),
        ("runner_request_stale", 409),
        ("runner_request_replayed", 409),
        ("runner_result_conflict", 409),
        ("runner_dispatch_state_conflict", 409),
        ("runner_reconciliation_required", 409),
        ("runner_unavailable", 503),
    ],
)
def test_service_refusals_use_only_protocol_status_and_code(code, status):
    response = _runner_refusal(RunnerRefused(code))
    assert response.status_code == status
    assert response.body == b'{"detail":{"code":"' + code.encode() + b'"}}'
    assert response.headers["cache-control"] == "no-store"


def test_unknown_refusal_text_is_not_returned():
    response = _runner_refusal(RunnerRefused("unexpected private error"))
    assert response.status_code == 503
    assert response.body == b'{"detail":{"code":"runner_unavailable"}}'
