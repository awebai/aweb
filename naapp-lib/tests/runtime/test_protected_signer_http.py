"""Shared HTTP mounts with actual request signatures, PostgreSQL and B2/B3."""

from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from asyncpg import PostgresError
from awid.did import stable_id_from_did_key
from awid.protected_request import verify_protected_request
from awid.signing import canonical_json_bytes
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
)
from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.http import ProtectedOperationsHTTP
from tests.runtime.protected_signer_support import ORIGIN, SCOPE, did_key


@pytest_asyncio.fixture
async def http_world(world):
    w = world
    key = SigningKey.generate()
    await apply_console_migrations(w.passkeys.db)
    limiter = LoginLimiter(
        w.passkeys.db,
        client_identity=ClientIdentity(),
        limit=10,
        window=timedelta(minutes=1),
        clock=w.clock,
    )

    await w.passkeys.db.execute("CREATE TABLE {{tables.http_requesters}} (key TEXT PRIMARY KEY)")
    await w.passkeys.db.execute("INSERT INTO {{tables.http_requesters}} VALUES($1)", did_key(key))

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
            try:
                current = await w.passkeys.db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM {{tables.http_requesters}} WHERE key=$1)", signer
                )
            except PostgresError:
                raise SignerRefused("evidence_unavailable") from None
            if not current:
                raise SignerRefused("requester_invalid")

        async def requester(self, request, operation):
            await self.check(request, "protected_operation_prepare")
            return w.requester

        async def reader(self, request, operation_id):
            await self.check(request, "protected_operation_receipt")
            return w.reader

    auth = Authentication()

    async def admitted_scope(scope):
        return scope in {SCOPE, "other-console-scope"}

    sessions = ConsoleSessions(w.passkeys.db, passkeys=w.passkeys, scopes=admitted_scope)

    mount = ProtectedOperationsHTTP(
        w.signer,
        request_origin=ORIGIN,
        requester=auth.requester,
        reader=auth.reader,
        limiter=limiter,
        human_sessions=sessions,
        human_csrf_key="protected-human-csrf",
    )
    app = FastAPI()
    app.include_router(mount.api_router())
    app.include_router(mount.human_router())
    app.state.protected_operations = mount

    app.include_router(console_login_router(sessions=sessions, limiter=limiter, prefix="/human"))
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
        ({"operation": "raw.sign"}, "operation_not_served"),
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


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize(
    "fault,status,code",
    [("key", 401, "requester_invalid"), ("storage", 503, "receipt_unavailable")],
)
async def test_actual_callback_refusals_keep_auth_and_availability_distinct(
    http_world, method, fault, status, code
):
    w, client, key = http_world
    path = "/protected-operations"
    if method == "GET":
        prepared = (await post(w, client, key, w.operation.intent())).json()
        path += "/" + prepared["operation_id"]
    before = await w.passkeys.db.fetch_value(
        "SELECT count(*) FROM {{tables.protected_signer_operations}}"
    )
    if fault == "storage":
        await w.passkeys.db.execute("DROP TABLE {{tables.http_requesters}}")
    else:
        key = SigningKey.generate()
    if method == "POST":
        response = await post(w, client, key, w.operation.intent())
    else:
        response = await client.get(path, headers=headers(w, key, "GET", path))
    assert response.status_code == status and response.json() == {"detail": code}
    assert (
        await w.passkeys.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_signer_operations}}"
        )
        == before
    )


async def test_receipt_polling_cannot_spend_the_humans_login_budget(http_world):
    w, client, key = http_world
    prepared = (await post(w, client, key, w.operation.intent())).json()
    path = "/protected-operations/" + prepared["operation_id"]
    for _ in range(9):
        assert (await client.get(path, headers=headers(w, key, "GET", path))).status_code == 200
    assert (await client.get(path, headers=headers(w, key, "GET", path))).status_code == 429
    options = await client.post("/human/login/options", json={"scope": SCOPE})
    assert options.status_code == 200, options.text
    login = await client.post(
        "/human/login", json={"scope": SCOPE, "assertion": w.device.get(options.json())}
    )
    assert login.status_code == 200 and login.json()["csrf_token"]


async def test_wrong_public_host_refuses_without_minting(http_world):
    w, client, key = http_world
    raw = canonical_json_bytes(w.operation.intent())
    signed = headers(w, key, "POST", "/protected-operations", raw)
    signed["Host"] = "attacker.example"
    response = await client.post("/protected-operations", content=raw, headers=signed)
    assert response.status_code == 403 and response.json() == {"detail": "scope_refused"}
    assert (
        await w.passkeys.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_signer_operations}}"
        )
        == 0
    )


async def test_retained_context_is_exact_routing_metadata_not_receipt_authority(http_world):
    w, client, key = http_world
    prepared = await w.signer.prepare(w.operation, requester=w.requester)
    other_context = replace(
        w.operation.context,
        authority_id="other-team:oatspec.io",
        human_id=stable_id_from_did_key(did_key(SigningKey.generate())),
    )
    other = replace(w.operation, operation_id=str(uuid.uuid4()), context=other_context)
    request = {**prepared.payload, **other.intent()}
    request["artifact"]["template"]["team_id"] = other_context.authority_id
    covered = {
        "policy": {"ref": request["policy_ref"], "version": request["policy_version"]},
        "request": request,
    }
    digest = hashlib.sha256(
        b"aweb.approval-request/1\n" + canonical_json_bytes(covered)
    ).hexdigest()
    # A retained metadata fixture for another configured authority. It grants
    # no B2 approval and never purports to be a signed or executable effect.
    await w.passkeys.db.execute(
        "INSERT INTO {{tables.protected_signer_operations}} "
        "(operation_id,handoff_id,requester,intent,request,digest,approval_id,candidate_links,expires_at) "
        "SELECT $1,$2,'other-requester',$3,$4,$7,$5,'{}'::jsonb,expires_at "
        "FROM {{tables.protected_signer_operations}} WHERE operation_id=$6",
        other.operation_id,
        str(uuid.uuid4()),
        canonical_json_bytes(other.intent()),
        canonical_json_bytes(request),
        str(uuid.uuid4()),
        prepared.operation_id,
        digest,
    )
    assert await w.signer.lookup_context(prepared.operation_id) == w.operation.context
    assert await w.signer.lookup_context(other.operation_id) == other_context
    assert await w.signer.lookup_context(str(uuid.uuid4())) is None
    with pytest.raises(SignerRefused, match="scope_refused"):
        await w.signer.receipt(other.operation_id, reader=w.reader)
    assert "protected_operation_signed" not in await w.audit.kinds()


async def test_valid_json_above_64_kib_is_refused_before_mint(http_world):
    w, client, key = http_world
    raw = canonical_json_bytes(w.operation.intent()) + b" " * (64 * 1024)
    response = await post(w, client, key, raw)
    assert response.status_code == 400 and response.json() == {"detail": "request_invalid"}
    assert (
        await w.passkeys.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_signer_operations}}"
        )
        == 0
    )
