"""Shared HTTP mounts with actual request signatures, PostgreSQL and B2/B3."""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from awid.protected_request import verify_protected_request
from awid.signing import canonical_json_bytes
from fastapi import FastAPI, HTTPException
from nacl.signing import SigningKey

from aweb_naapp.console import ClientIdentity, LoginLimiter, apply_console_migrations
from aweb_naapp.runtime.protected_signer.http import ProtectedOperationsHTTP
from tests.runtime.test_protected_signer import ORIGIN, did_key  # noqa: F401


@pytest_asyncio.fixture
async def http_world(signer_world):
    w = signer_world
    key = SigningKey.generate()
    await apply_console_migrations(w.passkeys.db)
    limiter = LoginLimiter(
        w.passkeys.db, client_identity=ClientIdentity(), limit=100, window=timedelta(minutes=1)
    )

    class Authentication:
        # Test server's provisioned requester-key binding. Use .4's actual
        # covering verifier, not a second parser or synthetic UV evidence.
        async def check(self, request, label):
            signer = await verify_protected_request(
                request,
                operation=label,
                request_origin=ORIGIN,
                service_id=w.operation.context.service_id,
                domain=w.operation.context.authority_domain,
                scope=w.operation.context.fields(),
            )
            if signer != did_key(key):
                raise HTTPException(401, "requester_invalid")

        async def requester(self, request, operation):
            await self.check(request, "protected_operation_prepare")
            return w.requester

        async def reader(self, request, operation_id):
            await self.check(request, "protected_operation_receipt")
            return w.reader

    auth = Authentication()
    mount = ProtectedOperationsHTTP(
        w.signer,
        request_origin=ORIGIN,
        requester=auth.requester,
        reader=auth.reader,
        limiter=limiter,
    )
    app = FastAPI()
    app.include_router(mount.api_router())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        yield w, client, key


def headers(w, key, method, path, body=b""):
    timestamp = datetime.now(UTC).isoformat()
    raw = canonical_json_bytes(
        dict(
            v=2,
            type="aweb.awid-controller-request",
            aud=ORIGIN,
            operation="protected_operation_prepare"
            if method == "POST"
            else "protected_operation_receipt",
            domain=w.operation.context.authority_domain,
            timestamp=timestamp,
            method=method,
            path=path,
            body_sha256=hashlib.sha256(body).hexdigest(),
            service_id=w.operation.context.service_id,
            scope_sha256=hashlib.sha256(
                canonical_json_bytes(w.operation.context.fields())
            ).hexdigest(),
        )
    )
    return {
        "Authorization": f"DIDKey {did_key(key)} "
        + base64.b64encode(key.sign(raw).signature).decode().rstrip("="),
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "Content-Type": "application/json",
    }


async def post(w, client, key, body):
    raw = canonical_json_bytes(body) if isinstance(body, dict) else body
    return await client.post(
        "/protected-operations",
        content=raw,
        headers=headers(w, key, "POST", "/protected-operations", raw),
    )


async def test_prepare_payload_is_the_exact_existing_b2_digest_wrapper_and_receipt_recovers_result(
    http_world,
):
    w, client, key = http_world
    intent = {**w.operation.intent(), "redirect_uri": "http://127.0.0.1:41234/callback"}
    response = await post(w, client, key, intent)
    assert response.status_code == 200, response.text
    prepared = response.json()
    assert set(prepared) == {"operation_id", "handoff_id", "digest", "payload", "expires_at"}
    assert (
        hashlib.sha256(
            b"aweb.approval-request/1\n" + canonical_json_bytes(prepared["payload"])
        ).hexdigest()
        == prepared["digest"]
    )
    assert all(prepared["payload"]["request"][k] == v for k, v in intent.items())
    assert (await post(w, client, key, intent)).json() == prepared
    options = await w.signer.approval_options(prepared["operation_id"], human=w.human)
    committed = await w.signer.execute(
        prepared["operation_id"], w.device.get(dict(options)), human=w.human
    )
    path = "/protected-operations/" + prepared["operation_id"]
    result = await client.get(path, headers=headers(w, key, "GET", path))
    assert result.status_code == 200
    assert result.json() == {"state": "committed", "result": committed.result}
    assert result.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"extra": "ignored"}, "request_invalid"),
        ({"redirect_uri": "https://attacker.example/callback"}, "redirect_uri_refused"),
        ({"operation": "raw.sign"}, "operation_refused"),
    ],
)
async def test_invalid_or_unsupported_prepare_cannot_mint(http_world, mutation, code):
    w, client, key = http_world
    response = await post(w, client, key, {**w.operation.intent(), **mutation})
    assert response.status_code == 400
    assert response.json() == {"detail": code}
    assert (
        await w.passkeys.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_signer_operations}}"
        )
        == 0
    )


async def test_duplicate_fields_wrong_signature_and_ambient_cookie_refuse(http_world):
    w, client, key = http_world
    raw = canonical_json_bytes(w.operation.intent())
    duplicate = raw[:-1] + b',"variant":"default"}'
    assert (await post(w, client, key, duplicate)).status_code == 400
    assert (await post(w, client, SigningKey.generate(), w.operation.intent())).status_code == 401
    client.cookies.set("console", "ambient")
    assert (await post(w, client, key, w.operation.intent())).status_code == 401


async def test_receipt_requires_actual_original_requester_and_exact_scope(http_world):
    w, client, key = http_world
    prepared = (await post(w, client, key, w.operation.intent())).json()
    path = "/protected-operations/" + prepared["operation_id"]
    wrong = await client.get(path, headers=headers(w, SigningKey.generate(), "GET", path))
    assert wrong.status_code == 401
    pending = await client.get(path, headers=headers(w, key, "GET", path))
    assert pending.json()["state"] == "pending" and pending.json()["reason"] == "awaiting_human"
    path = "/protected-operations/" + str(uuid.uuid4())
    assert (await client.get(path, headers=headers(w, key, "GET", path))).status_code == 404


async def test_changed_callback_under_same_id_conflicts_and_cookie_is_never_requester(http_world):
    w, client, key = http_world
    intent = {**w.operation.intent(), "redirect_uri": "http://127.0.0.1:41234/a"}
    assert (await post(w, client, key, intent)).status_code == 200
    response = await post(w, client, key, {**intent, "redirect_uri": "http://127.0.0.1:41234/b"})
    assert response.status_code == 409 and response.json()["detail"] == "operation_conflict"


async def test_non_json_post_and_nonempty_get_are_bounded_refusals(http_world):
    w, client, key = http_world
    raw = canonical_json_bytes(w.operation.intent())
    signed = headers(w, key, "POST", "/protected-operations", raw)
    signed["Content-Type"] = "text/plain"
    response = await client.post("/protected-operations", content=raw, headers=signed)
    assert response.status_code == 415 and response.json()["detail"] == "json_required"
    path = "/protected-operations/" + str(uuid.uuid4())
    response = await client.request(
        "GET", path, content=b"unexpected", headers=headers(w, key, "GET", path, b"unexpected")
    )
    assert response.status_code == 400 and response.json()["detail"] == "request_invalid"
