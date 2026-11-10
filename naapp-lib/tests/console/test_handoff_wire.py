"""Real signed HTTP requests through the human/agent origin split."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aweb_naapp.console.handoff_wire import (
    HandoffWireRefused,
    loopback_redirect,
    verify_console_request,
)
from aweb_naapp.runtime.origins import split_origins

ORIGIN = "https://console.example"
AGENT = "https://api.example"
SUBJECT = "00000000-0000-4000-8000-000000000001"
NOW = datetime.now(UTC).replace(microsecond=0)


@pytest.mark.parametrize(
    "uri",
    [
        "https://remote.example/callback",
        "http://localhost:1234/callback",
        "http://127.1:1234/callback",
        "http://127.0.0.1.evil:1234/callback",
        "http://127.0.0.1:0/callback",
        "http://127.0.0.1:65536/callback",
        "http://127.0.0.1:0123/callback",
        "http://user@127.0.0.1:1234/callback",
        "http://127.0.0.1:1234/callback?next=remote",
        "http://127.0.0.1:1234/callback#x",
        "http://127.0.0.1:1234/%2fremote",
        "http://127.0.0.1:1234/\\remote",
    ],
)
def test_only_literal_loopback_redirects_are_admitted(uri):
    with pytest.raises(HandoffWireRefused):
        loopback_redirect(uri)


@pytest.mark.parametrize("uri", ["http://127.0.0.1:1/callback", "http://[::1]:65535/a/b_-."])
def test_literal_loopback_redirect_is_retained_exactly(uri):
    assert loopback_redirect(uri) == uri


def signed_headers(secret, key, **changes):
    payload = {
        "v": 2,
        "auth": "handoff-session",
        "aud": ORIGIN,
        "method": "POST",
        "path": "/signed?x=a%20b",
        "session_id": SUBJECT,
        "body_sha256": hashlib.sha256(b"{}").hexdigest(),
        "timestamp": NOW.isoformat().replace("+00:00", "Z"),
        "nonce": "a" * 32,
    }
    payload.update(changes)
    raw = canonical_json_bytes(payload)
    return {
        "X-Console-Key": key,
        "X-Console-Signature": sign_message(secret, raw),
        "X-Console-Timestamp": payload["timestamp"],
        "X-Console-Signed-Payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
    }


def app(key):
    human = FastAPI()

    @human.post("/signed")
    async def signed(request: Request):
        try:
            nonce = await verify_console_request(
                request,
                origin=ORIGIN,
                client_key=key,
                domain="handoff-session",
                subject_field="session_id",
                subject=SUBJECT,
                now=NOW,
            )
        except HandoffWireRefused:
            return JSONResponse({"detail": "console_session_required"}, status_code=401)
        return {"nonce": nonce}

    return split_origins(FastAPI(), human, agent_origin=AGENT, human_origin=ORIGIN)


async def test_console_signature_reaches_the_real_human_origin_boundary():
    secret, public = generate_keypair()
    key = did_from_public_key(public)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(key)), base_url=ORIGIN
    ) as client:
        response = await client.post(
            "/signed?x=a%20b", content=b"{}", headers=signed_headers(secret, key)
        )
        assert response.status_code == 200
        assert response.json() == {"nonce": "a" * 32}
        headers = signed_headers(secret, key)
        headers["Authorization"] = "DIDKey refused"
        assert (
            await client.post("/signed?x=a%20b", content=b"{}", headers=headers)
        ).status_code == 403


@pytest.mark.parametrize(
    "change",
    [
        {"auth": "handoff-result"},
        {"aud": AGENT},
        {"path": "/signed?x=a+b"},
        {"method": "GET"},
        {"session_id": "another"},
        {"team_id": "extra"},
        {"nonce": "a" * 31},
        {"timestamp": (NOW - timedelta(seconds=301)).isoformat().replace("+00:00", "Z")},
        {"body_sha256": hashlib.sha256(b"different").hexdigest()},
    ],
)
async def test_signature_is_bound_to_the_actual_request_and_protocol(change):
    secret, public = generate_keypair()
    key = did_from_public_key(public)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(key)), base_url=ORIGIN
    ) as client:
        response = await client.post(
            "/signed?x=a%20b", content=b"{}", headers=signed_headers(secret, key, **change)
        )
    assert response.status_code == 401


async def test_a_different_ephemeral_key_cannot_answer_for_the_bound_key():
    _, public = generate_keypair()
    other_secret, other_public = generate_keypair()
    key = did_from_public_key(public)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(key)), base_url=ORIGIN
    ) as client:
        response = await client.post(
            "/signed?x=a%20b",
            content=b"{}",
            headers=signed_headers(other_secret, did_from_public_key(other_public)),
        )
    assert response.status_code == 401
