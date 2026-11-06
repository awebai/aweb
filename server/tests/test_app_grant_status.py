"""GET /v1/apps/self/grant against the real verifier, routes and database."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from awid.signing import canonical_json_bytes, sign_message
from httpx import ASGITransport, AsyncClient

from aweb import app_credentials
from aweb.app_credentials import APP_GRANT_READ, HOOK_RESOLVE, PURPOSES
from aweb.config import get_app_grant_max_age_seconds
from aweb.hook_bindings import PRODUCTION, HookBindingDeclaration, write_pending_bindings
from aweb.routes.app_hooks import router as app_hooks_router
from aweb.routes.apps import router as apps_router
from tests.installation_fixtures import install_fixture_app as install_app
from tests.test_app_credentials import _register_app_key
from tests.test_app_events_http import (
    AGENT_ID,
    OTHER_TEAM_ID,
    TEAM_ID,
    _build_events_app,
    _install_folio,
    _make_app_keypair,
    _seed_team_and_agent,
)

GRANT_PATH = "/v1/apps/self/grant"
NEW_DIGEST = "sha256:" + "d" * 64
VECTOR = json.loads(
    (Path(__file__).resolve().parents[2] / "test-vectors" / "app-read-credential-v1.json").read_text(encoding="utf-8")
)


def _app(db, *, public_origin: str = "http://test"):
    app = _build_events_app(db, public_origin=public_origin)
    app.include_router(apps_router)
    return app


def _grant_read_headers(*, signing_key: bytes, did_key: str, kid: str, team_id: str = TEAM_ID, path: str = GRANT_PATH):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical = canonical_json_bytes(
        {
            "v": 1,
            "auth": APP_GRANT_READ,
            "aud": "http://test",
            "method": "GET",
            "path": path,
            "team_id": team_id,
            "app_id": "folio",
            "kid": kid,
            "did_key": did_key,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"{PURPOSES[APP_GRANT_READ].prefix}{did_key} {sign_message(signing_key, canonical)}",
        "X-AWEB-App-ID": "folio",
        "X-AWEB-App-Key-ID": kid,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("="),
    }


async def _get(app, headers: dict, path: str = GRANT_PATH):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path, headers=headers)


async def _reinstall_folio(db, *, team_id: str, digest: str, scopes: list[str], app_version: str):
    return await install_app(
        db,
        team_id=team_id,
        app_id="folio",
        origin="https://folio.aweb.ai",
        app_version=app_version,
        manifest_version=1,
        digest=digest,
        granted_scopes=scopes,
        installed_by_agent_id=str(AGENT_ID),
        event_types=[],
        emit_keys=[],
    )


@pytest_asyncio.fixture
async def installed(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    await _install_folio(db, did_key=_make_app_keypair()[1], kid="emit-1")
    read_key, read_did = _make_app_keypair()
    await _register_app_key(db, did_key=read_did, kid="read-1", purposes=[APP_GRANT_READ])
    return {"db": db, "app": _app(db), "read": {"signing_key": read_key, "did_key": read_did, "kid": "read-1"}}


@pytest.mark.asyncio
async def test_grant_read_returns_the_installed_grant_of_the_credentials_team_and_app(installed):
    before = datetime.now(timezone.utc).replace(microsecond=0)

    response = await _get(installed["app"], _grant_read_headers(**installed["read"]))

    assert response.status_code == 200, response.text
    body = response.json()
    as_of = datetime.strptime(body.pop("as_of"), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert before <= as_of <= datetime.now(timezone.utc)
    installed_at = datetime.fromisoformat(body.pop("installed_at"))
    assert installed_at == await installed["db"].fetch_value("SELECT installed_at FROM {{tables.team_app_installs}}")
    current = await installed["db"].fetch_one("SELECT installation_id,generation,digest FROM {{tables.team_app_installs}} WHERE team_id=$1", TEAM_ID)
    assert body == {
        "team_id": TEAM_ID,
        "app_id": "folio",
        "state": "active",
        "origin": "https://folio.aweb.ai",
        "app_version": "1.x",
        "manifest_version": 1,
        "digest": current["digest"],
        "granted_scopes": ["folio:read"],
        "installation_id": current["installation_id"],
        "generation": current["generation"],
        "origin_verified": True,
        "max_age_seconds": 60,
    }


@pytest.mark.asyncio
async def test_max_age_seconds_follows_configuration(installed, monkeypatch):
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", "30")

    response = await _get(installed["app"], _grant_read_headers(**installed["read"]))

    assert response.status_code == 200, response.text
    assert response.json()["max_age_seconds"] == 30


@pytest.mark.parametrize("value", ["0", "-1", "61", "3600", "30s", "", " 30", "３０"])
def test_max_age_configuration_outside_one_to_sixty_seconds_is_refused(monkeypatch, value):
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", value)

    with pytest.raises(ValueError):
        get_app_grant_max_age_seconds()


@pytest.mark.parametrize("value", ["1", "60"])
def test_max_age_configuration_bounds_are_accepted(monkeypatch, value):
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", value)

    assert get_app_grant_max_age_seconds() == int(value)


@pytest.mark.asyncio
async def test_no_key_registered_for_grant_read_is_app_key_not_registered(installed):
    key, did = _make_app_keypair()
    await _register_app_key(installed["db"], did_key=did, kid="hooks-only", purposes=[HOOK_RESOLVE])

    unregistered_key, unregistered_did = _make_app_keypair()
    hooks_only = await _get(installed["app"], _grant_read_headers(signing_key=key, did_key=did, kid="hooks-only"))
    unknown = await _get(
        installed["app"], _grant_read_headers(signing_key=unregistered_key, did_key=unregistered_did, kid="nobody")
    )

    for response in (hooks_only, unknown):
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "app_key_not_registered"


@pytest.mark.asyncio
async def test_a_digest_change_is_visible_on_the_next_read(installed):
    db = installed["db"]
    changed = await _reinstall_folio(db, team_id=TEAM_ID, digest=NEW_DIGEST, scopes=["folio:read", "folio:write"], app_version="2.0")
    new_key, new_did = _make_app_keypair()
    await db.execute(
        """
        INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)
        VALUES ($1, 'folio', 'https://folio.aweb.ai', $2, 'read-2', $3, $4::TEXT[])
        """,
        TEAM_ID,
        changed.digest,
        new_did,
        [APP_GRANT_READ],
    )

    old_digest_key = await _get(installed["app"], _grant_read_headers(**installed["read"]))
    new_digest_key = await _get(installed["app"], _grant_read_headers(signing_key=new_key, did_key=new_did, kid="read-2"))

    assert old_digest_key.status_code == 403, old_digest_key.text
    assert old_digest_key.json()["detail"] == "app_key_not_registered"
    assert new_digest_key.status_code == 200, new_digest_key.text
    body = new_digest_key.json()
    assert (body["digest"], body["granted_scopes"], body["app_version"]) == (changed.digest, ["folio:read", "folio:write"], "2.0")


@pytest.mark.asyncio
async def test_the_answer_never_includes_another_team_or_app(installed):
    db = installed["db"]
    await _seed_team_and_agent(db, team_id=OTHER_TEAM_ID)
    await _reinstall_folio(db, team_id=OTHER_TEAM_ID, digest=NEW_DIGEST, scopes=["folio:admin"], app_version="9.0")
    other_key, other_did = _make_app_keypair()
    await _register_app_key(db, did_key=other_did, kid="other-read", purposes=[APP_GRANT_READ], team_id=OTHER_TEAM_ID)
    await install_app(
        db,
        team_id=TEAM_ID,
        app_id="notes",
        origin="https://notes.example",
        app_version="1.0",
        manifest_version=1,
        digest="sha256:" + "e" * 64,
        granted_scopes=["notes:read"],
        installed_by_agent_id=str(AGENT_ID),
        event_types=[],
        emit_keys=[],
    )

    own = await _get(installed["app"], _grant_read_headers(**installed["read"]))
    other_team_key_claiming_this_team = await _get(
        installed["app"], _grant_read_headers(signing_key=other_key, did_key=other_did, kid="other-read")
    )
    with_query = await _get(
        installed["app"],
        _grant_read_headers(**installed["read"], path=f"{GRANT_PATH}?team_id={OTHER_TEAM_ID}&app_id=notes"),
        path=f"{GRANT_PATH}?team_id={OTHER_TEAM_ID}&app_id=notes",
    )

    assert own.status_code == 200, own.text
    assert (own.json()["team_id"], own.json()["app_id"], own.json()["granted_scopes"]) == (TEAM_ID, "folio", ["folio:read"])
    assert other_team_key_claiming_this_team.status_code == 403, other_team_key_claiming_this_team.text
    assert with_query.status_code == 200, with_query.text
    assert (with_query.json()["team_id"], with_query.json()["app_id"]) == (TEAM_ID, "folio")


@pytest.mark.asyncio
async def test_an_app_without_an_installation_gets_app_key_not_registered(installed):
    db = installed["db"]
    await db.execute("DELETE FROM {{tables.team_app_installs}} WHERE team_id = $1 AND app_id = 'folio'", TEAM_ID)

    response = await _get(installed["app"], _grant_read_headers(**installed["read"]))

    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "app_key_not_registered"


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["pending_origin_verification", "uninstalled"])
async def test_non_active_installation_is_reported_with_its_real_identity(installed, state):
    await installed["db"].execute("UPDATE {{tables.team_app_installs}} SET state=$1,origin_verified=FALSE", state)
    response = await _get(installed["app"], _grant_read_headers(**installed["read"]))
    assert response.status_code == 200, response.text
    assert response.json()["state"] == state
    assert response.json()["installation_id"]
    assert response.json()["generation"] == 1
    assert response.json()["origin_verified"] is False


# --- app-read-credential-v1 ---


def test_the_servers_purpose_table_equals_the_vectors():
    # The vector is the one list of app credential purposes; the server and the
    # naapp signer each assert equality with it, so neither can add one alone.
    assert {
        purpose: {"prefix": spec.prefix, "auth": spec.auth} for purpose, spec in PURPOSES.items()
    } == VECTOR["purposes"]


def test_vector_bytes_are_reproduced_from_its_seed():
    for case in VECTOR["cases"] + VECTOR["negative_cases"]:
        canonical = canonical_json_bytes(case["payload"])
        assert canonical.decode() == case["canonical_payload"], case["name"]
        assert base64.urlsafe_b64encode(canonical).decode().rstrip("=") == case["signed_payload_b64url"], case["name"]
        assert sign_message(bytes.fromhex(VECTOR["seed_hex"]), canonical) == case["signature_b64"], case["name"]
        assert hashlib.sha256(case["body"].encode()).hexdigest() == case["payload"]["body_sha256"], case["name"]


@pytest_asyncio.fixture
async def vector_installed(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    await _install_folio(db, did_key=_make_app_keypair()[1], kid="emit-1")
    case = VECTOR["cases"][0]
    await _register_app_key(
        db, did_key=VECTOR["did_key"], kid=case["payload"]["kid"], purposes=[APP_GRANT_READ, HOOK_RESOLVE]
    )
    # Seed a production under the actual installation pin for the hook-resolve
    # case. Owner-act activation is covered separately.
    current = await db.fetch_one(
        "SELECT digest, installation_id, generation FROM {{tables.team_app_installs}} "
        "WHERE team_id = $1 AND app_id = 'folio'", TEAM_ID,
    )
    assert current is not None
    async with db.transaction() as tx:
        [production] = await write_pending_bindings(
            tx, team_id=TEAM_ID, app_id="folio", origin="https://folio.aweb.ai", digest=current["digest"],
            installation_id=current["installation_id"], generation=current["generation"],
            declarations=[
                HookBindingDeclaration(
                    kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook="post-secret-use-hook"
                )
            ],
        )
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'active', activated_at = date_trunc('milliseconds', NOW()),
            active_from = date_trunc('milliseconds', NOW()) + INTERVAL '60 seconds',
            activation_act_sha256 = $2
        WHERE binding_id = $1
        """,
        production.binding_id, "ab" * 32,
    )
    # The vector's timestamp is fixed for byte parity. Skew is covered by the
    # verifier's own tests; here every other check runs on the frozen bytes.
    monkeypatch.setattr(app_credentials, "enforce_timestamp_skew", lambda _timestamp: None)
    app = _app(db, public_origin=case["payload"]["aud"])
    app.include_router(app_hooks_router)
    return app


async def _send_case(app, case: dict):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(case["method"], case["path"], content=case["body"].encode(), headers=case["headers"])


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
async def test_vector_positive_cases_verify_at_their_routes(vector_installed, case):
    response = await _send_case(vector_installed, case)

    assert response.status_code == 200, response.text
    assert response.json()["team_id"] == case["payload"]["team_id"]
    if case["purpose"] == APP_GRANT_READ:
        assert response.json()["app_id"] == case["payload"]["app_id"]
    else:
        assert case["purpose"] == HOOK_RESOLVE
        assert response.json()["bindings"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda case: case["name"])
async def test_vector_negative_cases_are_refused(vector_installed, case):
    response = await _send_case(vector_installed, case)

    assert response.status_code == case["expected_status"], response.text


def test_vector_timestamp_is_outside_the_replay_window_of_today():
    timestamp = datetime.strptime(VECTOR["cases"][0]["payload"]["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert abs(datetime.now(timezone.utc) - timestamp) > timedelta(seconds=VECTOR["replay_window_seconds"])
