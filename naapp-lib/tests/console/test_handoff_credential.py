"""Public credential handoffs verify real WebAuthn and grant no role or session."""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI

from aweb_naapp.console import ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_credential import credential_handoff_router
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.runtime.passkeys import RelyingParty
from tests.console.test_handoff_store import ORIGIN, handoff_db, start_body

__all__ = ["handoff_db"]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def headers(secret, key, handoff, body):
    stamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes(
        {
            "v": 2,
            "auth": "handoff-result",
            "aud": ORIGIN,
            "method": "POST",
            "path": f"/handoffs/{handoff}/result",
            "handoff_id": handoff,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": stamp,
            "nonce": "1" * 32,
        }
    )
    return {
        "X-Console-Key": key,
        "X-Console-Timestamp": stamp,
        "X-Console-Signature": sign_message(secret, payload),
        "X-Console-Signed-Payload": b64(payload),
        "Content-Type": "application/json",
    }


def app(db):
    human = FastAPI()

    async def admitted(scope):
        return (
            scope["installation_id"] == "00000000-0000-4000-8000-000000000001"
            and scope["role"] == "example.owner"
        )

    human.include_router(
        credential_handoff_router(
            store=HandoffStore(db),
            rp=RelyingParty(ORIGIN, "Example"),
            admits=admitted,
            limiter=LoginLimiter(
                db, client_identity=ClientIdentity(), limit=30, window=timedelta(minutes=1)
            ),
        )
    )
    return human


async def test_credential_result_is_verified_one_shot_and_authorizes_nothing(handoff_db):
    secret, public = generate_keypair()
    key = did_from_public_key(public)
    verifier = b64(hashlib.sha256(b"a fresh local invocation").digest())
    store = HandoffStore(handoff_db)
    from aweb_naapp.console.handoff_store import parse_start

    created = await store.create(
        parse_start(
            start_body(
                purpose="credential",
                client_key=key,
                verifier_sha256=hashlib.sha256(verifier.encode()).hexdigest(),
            )
        )
    )
    handoff = created["handoff_id"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(handoff_db)), base_url=ORIGIN
    ) as browser:
        state = await browser.get(f"/handoff/{handoff}/credential")
        assert state.status_code == 200
        csrf = {"X-CSRF-Token": state.json()["csrf_token"], "Origin": ORIGIN}
        options = await browser.post(
            f"/handoff/{handoff}/credential/options", json={}, headers=csrf
        )
        assert options.status_code == 200
        device = SoftAuthenticator(ORIGIN)
        response = await browser.post(
            f"/handoff/{handoff}/credential/complete",
            json={"credential": device.create(options.json())},
            headers=csrf,
        )
        assert response.status_code == 200
        callback = urlsplit(response.json()["redirect_uri"])
        query = parse_qs(callback.query)
        assert query["handoff_id"] == [handoff]
        body = json.dumps({"v": 1, "code": query["code"][0], "verifier": verifier}).encode()
        signed = headers(secret, key, handoff, body)
        for changed in ({"code": b64(bytes(32))}, {"verifier": b64(bytes(32))}):
            wrong_body = json.dumps(
                {"v": 1, "code": query["code"][0], "verifier": verifier, **changed}
            ).encode()
            refused = await browser.post(
                f"/handoffs/{handoff}/result",
                content=wrong_body,
                headers=headers(secret, key, handoff, wrong_body),
            )
            assert (refused.status_code, refused.json()) == (403, {"detail": "handoff_refused"})
        other_secret, other_public = generate_keypair()
        wrong_key = await browser.post(
            f"/handoffs/{handoff}/result",
            content=body,
            headers=headers(other_secret, did_from_public_key(other_public), handoff, body),
        )
        assert wrong_key.status_code == 403
        staged = await handoff_db.fetch_one(
            "SELECT code_sha256,released_at FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid",
            handoff,
        )
        assert staged["released_at"] is None
        assert bytes(staged["code_sha256"]) == hashlib.sha256(query["code"][0].encode()).digest()
        released = await browser.post(f"/handoffs/{handoff}/result", content=body, headers=signed)
        assert released.status_code == 200
        assert released.json()["purpose"] == "credential"
        credential = released.json()["credential"]
        assert set(credential) == {"credential_id", "public_key", "rp_id"}
        assert credential["rp_id"] == "console.example"
        assert (
            await browser.post(f"/handoffs/{handoff}/result", content=body, headers=signed)
        ).status_code == 403
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_sessions}}") == 0
    row = await handoff_db.fetch_one(
        "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid", handoff
    )
    assert row is None  # Post-commit cleanup removes the released handoff.


@pytest.mark.parametrize("fault", ["other_handoff", "foreign_origin", "no_uv"])
async def test_registration_is_bound_and_a_failed_challenge_cannot_be_reused(handoff_db, fault):
    from aweb_naapp.console.handoff_store import parse_start

    store = HandoffStore(handoff_db)
    ids = [
        (await store.create(parse_start(start_body(purpose="credential"))))["handoff_id"]
        for _ in range(2)
    ]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(handoff_db)), base_url=ORIGIN
    ) as browser:
        challenges = []
        for handoff in ids:
            state = await browser.get(f"/handoff/{handoff}/credential")
            csrf = {"X-CSRF-Token": state.json()["csrf_token"], "Origin": ORIGIN}
            options = await browser.post(
                f"/handoff/{handoff}/credential/options", json={}, headers=csrf
            )
            assert options.status_code == 200
            challenges.append((options.json(), csrf))
        device = SoftAuthenticator(ORIGIN)
        options, csrf = challenges[1]
        credential = device.create(
            challenges[0][0] if fault == "other_handoff" else options,
            origin="https://foreign.example" if fault == "foreign_origin" else None,
            user_verified=fault != "no_uv",
        )
        path = f"/handoff/{ids[1]}/credential/complete"
        assert (
            await browser.post(path, json={"credential": credential}, headers=csrf)
        ).status_code == 403
        # Verification failure consumed this challenge, even a genuine assertion
        # for that old challenge cannot subsequently complete the handoff.
        assert (
            await browser.post(path, json={"credential": device.create(options)}, headers=csrf)
        ).status_code == 403
        fresh = await browser.post(f"/handoff/{ids[1]}/credential/options", json={}, headers=csrf)
        completed = await browser.post(
            path, json={"credential": device.create(fresh.json())}, headers=csrf
        )
        assert completed.status_code == 200


async def test_credential_browser_writes_require_the_bound_browser_and_same_origin(handoff_db):
    from aweb_naapp.console.handoff_store import parse_start

    handoff = (
        await HandoffStore(handoff_db).create(parse_start(start_body(purpose="credential")))
    )["handoff_id"]
    service = app(handoff_db)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service), base_url=ORIGIN
    ) as browser:
        state = await browser.get(f"/handoff/{handoff}/credential")
        path = f"/handoff/{handoff}/credential/options"
        csrf = {"X-CSRF-Token": state.json()["csrf_token"], "Origin": ORIGIN}
        for changed in (
            {"Origin": "https://foreign.example"},
            {"X-CSRF-Token": "wrong"},
            {"Origin": ""},
        ):
            assert (
                await browser.post(path, json={}, headers={**csrf, **changed})
            ).status_code == 403
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=service), base_url=ORIGIN
        ) as stranger:
            assert (await stranger.post(path, json={}, headers=csrf)).status_code == 403
            assert (await stranger.get(f"/handoff/{handoff}/credential")).status_code == 403
        assert (await browser.post(path, json={}, headers=csrf)).status_code == 200
