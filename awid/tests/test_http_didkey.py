"""Tests for awid.http_didkey — the HTTP request envelope DIDKey verifier."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from awid import dns_auth
from awid.did import did_from_public_key, generate_keypair
from awid.http_didkey import build_http_didkey_payload, verify_http_didkey_request
from awid.signing import canonical_json_bytes, sign_message


FIXED_NOW = datetime(2026, 4, 8, 12, 0, 0, tzinfo=timezone.utc)


def _json_body_bytes(body: dict[str, object]) -> bytes:
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _auth_headers(
    *,
    body_bytes: bytes,
    signing_seed: bytes,
    did_key: str,
    method: str = "POST",
    path: str = "/verify",
    auth_did_key: str | None = None,
    timestamp: str | None = None,
) -> dict[str, str]:
    timestamp = timestamp or FIXED_NOW.isoformat().replace("+00:00", "Z")
    header_did_key = auth_did_key or did_key
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "method": method,
            "path": path,
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"DIDKey {header_did_key} {sign_message(signing_seed, payload)}",
        "Content-Type": "application/json",
        "X-AWEB-Timestamp": timestamp,
    }


@pytest_asyncio.fixture
async def verifier_client(monkeypatch) -> AsyncClient:
    monkeypatch.setattr(dns_auth, "_utc_now", lambda: FIXED_NOW)

    app = FastAPI()

    @app.post("/verify")
    async def verify_route(request: Request) -> dict[str, object]:
        did_key = await verify_http_didkey_request(request)
        body = await request.json()
        return {"did_key": did_key, "body": body}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.asyncio
async def test_verify_http_didkey_request_happy_path(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key, "token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(body_bytes=body_bytes, signing_seed=seed, did_key=did_key),
        content=body_bytes,
    )

    assert response.status_code == 200, response.text
    assert response.json()["did_key"] == did_key
    assert response.json()["body"]["did_key"] == did_key


@pytest.mark.asyncio
async def test_tampered_body_byte_returns_401(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    signed_body = _json_body_bytes({"did_key": did_key, "token": "signed-token"})
    sent_body = _json_body_bytes({"did_key": did_key, "token": "sent-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(body_bytes=signed_body, signing_seed=seed, did_key=did_key),
        content=sent_body,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"


@pytest.mark.asyncio
async def test_tampered_method_returns_401(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key, "token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(
            body_bytes=body_bytes, signing_seed=seed, did_key=did_key, method="GET"
        ),
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"


@pytest.mark.asyncio
async def test_tampered_path_returns_401(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key, "token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(
            body_bytes=body_bytes, signing_seed=seed, did_key=did_key, path="/wrong-path"
        ),
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"


@pytest.mark.asyncio
async def test_timestamp_outside_allowed_skew_returns_401(
    verifier_client: AsyncClient,
) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key, "token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(
            body_bytes=body_bytes,
            signing_seed=seed,
            did_key=did_key,
            timestamp=(FIXED_NOW - timedelta(seconds=301)).isoformat().replace("+00:00", "Z"),
        ),
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Timestamp outside allowed skew window"


@pytest.mark.asyncio
async def test_wrong_did_key_returns_401(verifier_client: AsyncClient) -> None:
    signing_seed, _ = generate_keypair()
    _, wrong_public_key = generate_keypair()
    wrong_did_key = did_from_public_key(wrong_public_key)
    body_bytes = _json_body_bytes({"did_key": wrong_did_key, "token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(
            body_bytes=body_bytes,
            signing_seed=signing_seed,
            did_key=wrong_did_key,
        ),
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"


@pytest.mark.asyncio
async def test_replay_is_statelessly_accepted(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key, "token": "bootstrap-token"})
    headers = _auth_headers(body_bytes=body_bytes, signing_seed=seed, did_key=did_key)

    first = await verifier_client.post("/verify", headers=headers, content=body_bytes)
    second = await verifier_client.post("/verify", headers=headers, content=body_bytes)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text


@pytest.mark.asyncio
async def test_json_reserialization_drift_returns_401(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    sent_body = b'{\n  "token": "bootstrap-token",\n  "did_key": "%b"\n}' % did_key.encode("utf-8")
    reserialized_body = _json_body_bytes({"did_key": did_key, "token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers=_auth_headers(
            body_bytes=reserialized_body, signing_seed=seed, did_key=did_key
        ),
        content=sent_body,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"


@pytest.mark.asyncio
async def test_missing_authorization_header_returns_401(
    verifier_client: AsyncClient,
) -> None:
    body_bytes = _json_body_bytes({"token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers={
            "Content-Type": "application/json",
            "X-AWEB-Timestamp": FIXED_NOW.isoformat().replace("+00:00", "Z"),
        },
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing Authorization header"


@pytest.mark.asyncio
async def test_malformed_authorization_header_returns_401(
    verifier_client: AsyncClient,
) -> None:
    body_bytes = _json_body_bytes({"token": "bootstrap-token"})

    response = await verifier_client.post(
        "/verify",
        headers={
            "Authorization": "Bearer some-token",
            "Content-Type": "application/json",
            "X-AWEB-Timestamp": FIXED_NOW.isoformat().replace("+00:00", "Z"),
        },
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authorization must be: DIDKey <did:key> <signature>"


@pytest.mark.asyncio
async def test_missing_timestamp_header_returns_401(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key})
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "method": "POST",
            "path": "/verify",
            "timestamp": FIXED_NOW.isoformat().replace("+00:00", "Z"),
        }
    )

    response = await verifier_client.post(
        "/verify",
        headers={
            "Authorization": f"DIDKey {did_key} {sign_message(seed, payload)}",
            "Content-Type": "application/json",
        },
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing X-AWEB-Timestamp header"


@pytest.mark.asyncio
async def test_malformed_timestamp_returns_401(verifier_client: AsyncClient) -> None:
    seed, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    body_bytes = _json_body_bytes({"did_key": did_key})
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "method": "POST",
            "path": "/verify",
            "timestamp": "not-a-real-timestamp",
        }
    )

    response = await verifier_client.post(
        "/verify",
        headers={
            "Authorization": f"DIDKey {did_key} {sign_message(seed, payload)}",
            "Content-Type": "application/json",
            "X-AWEB-Timestamp": "not-a-real-timestamp",
        },
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Malformed timestamp"


def test_build_http_didkey_payload_matches_sot_shape() -> None:
    body_bytes = b'{"token":"bootstrap-token"}'

    payload = build_http_didkey_payload(
        body_bytes=body_bytes,
        method="post",
        path="/verify",
        timestamp="2026-04-08T12:00:00Z",
    )

    assert payload == canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "method": "POST",
            "path": "/verify",
            "timestamp": "2026-04-08T12:00:00Z",
        }
    )


def test_build_http_didkey_payload_normalizes_method_to_uppercase() -> None:
    body_bytes = b"{}"

    lower = build_http_didkey_payload(
        body_bytes=body_bytes, method="post", path="/x", timestamp="2026-04-08T12:00:00Z"
    )
    upper = build_http_didkey_payload(
        body_bytes=body_bytes, method="POST", path="/x", timestamp="2026-04-08T12:00:00Z"
    )
    mixed = build_http_didkey_payload(
        body_bytes=body_bytes, method="Post", path="/x", timestamp="2026-04-08T12:00:00Z"
    )

    assert lower == upper == mixed
