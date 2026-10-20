"""Purpose-bound app credentials against the real verifier and database."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from awid.signing import canonical_json_bytes, sign_message
from aweb.app_credentials import APP_EVENT, APP_GRANT_READ, HOOK_RESOLVE, PURPOSES, verify_app_credential
from tests.test_app_events_http import (
    DIGEST,
    OTHER_TEAM_ID,
    TEAM_ID,
    _build_events_app,
    _install_folio,
    _make_app_keypair,
    _seed_team_and_agent,
)

READ_PURPOSES = (APP_GRANT_READ, HOOK_RESOLVE)
EMIT_BODY = b'{"type":"folio/doc.changed","resource_ref":"pitch","payload":{}}'


def _app(aweb_db) -> FastAPI:
    app = _build_events_app(aweb_db)

    @app.post("/probe/{purpose}")
    async def probe(purpose: str, request: Request):
        credential = await verify_app_credential(request, aweb_db, purpose)
        return {"purpose": credential.purpose, "team_id": credential.team_id, "kid": credential.kid}

    return app


def _headers(*, signing_key: bytes, did_key: str, kid: str, path: str, body: bytes, prefix: str, auth: str, team_id: str = TEAM_ID):
    timestamp = datetime.now(timezone.utc).isoformat()
    canonical = canonical_json_bytes(
        {
            "v": 1,
            "auth": auth,
            "aud": "http://test",
            "method": "POST",
            "path": path,
            "team_id": team_id,
            "app_id": "folio",
            "kid": kid,
            "did_key": did_key,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"{prefix}{did_key} {sign_message(signing_key, canonical)}",
        "X-AWEB-App-ID": "folio",
        "X-AWEB-App-Key-ID": kid,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("="),
        "Content-Type": "application/json",
    }


def _signed_for(purpose: str, **kwargs):
    spec = PURPOSES[purpose]
    return _headers(prefix=spec.prefix, auth=spec.auth, **kwargs)


async def _register_app_key(db, *, did_key: str, kid: str, purposes: list[str], team_id: str = TEAM_ID) -> None:
    # Nothing writes team_app_keys in production until keys are derived from
    # pinned manifest bytes; the test seeds the row the way that writer will.
    await db.execute(
        """
        INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)
        VALUES ($1, 'folio', 'https://folio.aweb.ai', $2, $3, $4, $5::TEXT[])
        """,
        team_id,
        DIGEST,
        kid,
        did_key,
        purposes,
    )


async def _post(app, path: str, body: bytes, headers: dict):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post(path, content=body, headers=headers)


@pytest_asyncio.fixture
async def installed(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    emit_key, emit_did = _make_app_keypair()
    await _install_folio(db, did_key=emit_did, kid="emit-1")
    read_key, read_did = _make_app_keypair()
    await _register_app_key(db, did_key=read_did, kid="read-1", purposes=[APP_GRANT_READ, HOOK_RESOLVE])
    return {
        "db": db,
        "app": _app(db),
        "emit": {"signing_key": emit_key, "did_key": emit_did, "kid": "emit-1"},
        "read": {"signing_key": read_key, "did_key": read_did, "kid": "read-1"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", READ_PURPOSES)
async def test_a_key_registered_for_a_read_purpose_verifies_for_it(installed, purpose):
    path = f"/probe/{purpose}"
    response = await _post(installed["app"], path, b"{}", _signed_for(purpose, path=path, body=b"{}", **installed["read"]))

    assert response.status_code == 200, response.text
    assert response.json()["purpose"] == purpose


@pytest.mark.asyncio
async def test_a_key_is_refused_for_a_purpose_it_does_not_declare(installed):
    key, did = _make_app_keypair()
    await _register_app_key(installed["db"], did_key=did, kid="grant-only", purposes=[APP_GRANT_READ])
    path = f"/probe/{HOOK_RESOLVE}"

    response = await _post(
        installed["app"], path, b"{}",
        _signed_for(HOOK_RESOLVE, signing_key=key, did_key=did, kid="grant-only", path=path, body=b"{}"),
    )

    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_an_emit_key_never_signs_a_read_purpose(installed):
    path = f"/probe/{APP_GRANT_READ}"

    response = await _post(installed["app"], path, b"{}", _signed_for(APP_GRANT_READ, path=path, body=b"{}", **installed["emit"]))

    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_a_read_purpose_credential_is_refused_at_the_emit_endpoint(installed):
    for purpose in READ_PURPOSES:
        response = await _post(
            installed["app"], "/v1/events/app", EMIT_BODY,
            _signed_for(purpose, path="/v1/events/app", body=EMIT_BODY, **installed["read"]),
        )
        assert response.status_code == 401, (purpose, response.text)


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", READ_PURPOSES)
async def test_an_app_event_credential_is_refused_at_a_read_purpose(installed, purpose):
    path = f"/probe/{purpose}"

    response = await _post(installed["app"], path, b"{}", _signed_for(APP_EVENT, path=path, body=b"{}", **installed["emit"]))

    assert response.status_code == 401, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", READ_PURPOSES)
async def test_prefix_and_signed_auth_must_both_name_the_purpose(installed, purpose):
    path = f"/probe/{purpose}"
    spec = PURPOSES[purpose]
    other = PURPOSES[APP_EVENT]

    right_prefix_wrong_auth = await _post(
        installed["app"], path, b"{}",
        _headers(prefix=spec.prefix, auth=other.auth, path=path, body=b"{}", **installed["read"]),
    )
    wrong_prefix_right_auth = await _post(
        installed["app"], path, b"{}",
        _headers(prefix=other.prefix, auth=spec.auth, path=path, body=b"{}", **installed["read"]),
    )

    assert right_prefix_wrong_auth.status_code == 401, right_prefix_wrong_auth.text
    assert wrong_prefix_right_auth.status_code == 401, wrong_prefix_right_auth.text


@pytest.mark.asyncio
async def test_emit_endpoint_refuses_wrong_prefix_or_wrong_auth(installed):
    read_spec = PURPOSES[APP_GRANT_READ]
    emit_spec = PURPOSES[APP_EVENT]
    path = "/v1/events/app"

    right_prefix_wrong_auth = await _post(
        installed["app"], path, EMIT_BODY,
        _headers(prefix=emit_spec.prefix, auth=read_spec.auth, path=path, body=EMIT_BODY, **installed["emit"]),
    )
    wrong_prefix_right_auth = await _post(
        installed["app"], path, EMIT_BODY,
        _headers(prefix=read_spec.prefix, auth=emit_spec.auth, path=path, body=EMIT_BODY, **installed["emit"]),
    )
    valid = await _post(installed["app"], path, EMIT_BODY, _signed_for(APP_EVENT, path=path, body=EMIT_BODY, **installed["emit"]))

    assert right_prefix_wrong_auth.status_code == 401, right_prefix_wrong_auth.text
    assert wrong_prefix_right_auth.status_code == 401, wrong_prefix_right_auth.text
    assert valid.status_code == 200, valid.text


@pytest.mark.asyncio
async def test_revoked_or_other_team_app_keys_are_refused(installed):
    db = installed["db"]
    await _seed_team_and_agent(db, team_id=OTHER_TEAM_ID)
    other_key, other_did = _make_app_keypair()
    await _install_folio(db, team_id=OTHER_TEAM_ID, did_key=_make_app_keypair()[1], kid="emit-9")
    await _register_app_key(db, did_key=other_did, kid="other-read", purposes=[APP_GRANT_READ], team_id=OTHER_TEAM_ID)
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET revoked_at = NOW() WHERE team_id = $1 AND key_id = 'read-1'", TEAM_ID
    )
    path = f"/probe/{APP_GRANT_READ}"

    revoked = await _post(installed["app"], path, b"{}", _signed_for(APP_GRANT_READ, path=path, body=b"{}", **installed["read"]))
    other_team = await _post(
        installed["app"], path, b"{}",
        _signed_for(APP_GRANT_READ, signing_key=other_key, did_key=other_did, kid="other-read", path=path, body=b"{}"),
    )

    assert revoked.status_code == 403, revoked.text
    assert other_team.status_code == 403, other_team.text
