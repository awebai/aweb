"""v2 app keys registered from the pinned manifest bytes, through the one manifest reader.

Installs, reseeds and credentials run against the real registry, verifier,
routes and database. The manifests are C3's own v2 base manifest with keys
these tests can sign with, C3's interpreter vector cases, and the committed
manifests of the live apps.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

import aweb.routes.apps as apps_routes
from awid.signing import canonical_json_bytes, sign_message
from aweb_naapp.manifest import ManifestError, load_manifest, read_manifest_bytes

from aweb.app_credentials import APP_EVENT, APP_GRANT_READ, HOOK_RESOLVE, PURPOSES
from aweb.app_registry import (
    get_active_app_emit_key,
    get_active_app_key,
    install_app,
    manifest_registration,
    reseed_app_registrations,
    reserved_app_ids,
)
from aweb.service_errors import ConflictError, ValidationError
from tests.test_app_credentials import _app as _probe_app
from tests.test_app_credentials import _post
from tests.test_app_events_http import AGENT_ID, OTHER_TEAM_ID, TEAM_ID, _make_app_keypair, _seed_team_and_agent
from tests.test_app_install_bytes import _install as _install_over_http
from tests.test_app_registry_http import _build_apps_app, _fake_team_identity

ROOT = Path(__file__).resolve().parents[2]
VECTOR = json.loads((ROOT / "test-vectors" / "app-manifests" / "app-manifest-v2-v1.json").read_text(encoding="utf-8"))
V2_BASE = VECTOR["base_manifests"]["v2"]
APP_ID = V2_BASE["app"]["id"]
ORIGIN = V2_BASE["app"]["origin"]
EMIT_BODY = b'{"type":"fixture/workspace.changed","resource_ref":"w1","payload":{}}'


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _v2_manifest(keys: list[dict[str, Any]], *, version: str = "0.0.0") -> bytes:
    document = copy.deepcopy(V2_BASE)
    document["app_keys"] = keys
    document["app"]["version"] = version
    return _canonical(document)


def _key(kid: str, purposes: list[str]) -> tuple[bytes, dict[str, Any]]:
    signing_key, did_key = _make_app_keypair()
    return signing_key, {"kid": kid, "did_key": did_key, "purposes": purposes}


async def _install_v2(db, manifest: bytes, *, team_id: str = TEAM_ID, version: str = "0.0.0"):
    return await install_app(
        db,
        team_id=team_id,
        app_id=APP_ID,
        origin=ORIGIN,
        app_version=version,
        manifest_version=2,
        digest=_digest(manifest),
        granted_scopes=["fixture:read"],
        installed_by_agent_id=str(AGENT_ID),
        manifest=manifest,
    )


async def _team_keys(db, team_id: str = TEAM_ID) -> list[tuple[str, str, list[str], bool]]:
    rows = await db.fetch_all(
        """
        SELECT key_id, did_key, purposes, revoked_at IS NOT NULL AS revoked
        FROM {{tables.team_app_keys}} WHERE team_id = $1 AND app_id = $2 ORDER BY key_id, digest
        """,
        team_id,
        APP_ID,
    )
    return [(row["key_id"], row["did_key"], list(row["purposes"]), row["revoked"]) for row in rows]


def _signed_for_app(purpose: str, signing_key: bytes, entry: dict[str, Any], *, path: str, body: bytes, team_id: str = TEAM_ID):
    spec = PURPOSES[purpose]
    timestamp = datetime.now(timezone.utc).isoformat()
    canonical = canonical_json_bytes(
        {
            "v": 1, "auth": spec.auth, "aud": "http://test", "method": "POST", "path": path,
            "team_id": team_id, "app_id": APP_ID, "kid": entry["kid"], "did_key": entry["did_key"],
            "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"{spec.prefix}{entry['did_key']} {sign_message(signing_key, canonical)}",
        "X-AWEB-App-ID": APP_ID,
        "X-AWEB-App-Key-ID": entry["kid"],
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("="),
        "Content-Type": "application/json",
    }


@pytest_asyncio.fixture
async def db(aweb_cloud_db):
    database = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(database)
    await _seed_team_and_agent(database, team_id=OTHER_TEAM_ID)
    return database


# --- registration -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_v2_install_registers_exactly_the_bytes_app_keys(db):
    _, read = _key("read-1", [APP_GRANT_READ, HOOK_RESOLVE])
    _, emit = _key("emit-1", [APP_EVENT])
    manifest = _v2_manifest([read, emit])

    await _install_v2(db, manifest)

    assert await _team_keys(db) == sorted(
        [
            (read["kid"], read["did_key"], [APP_GRANT_READ, HOOK_RESOLVE], False),
            (emit["kid"], emit["did_key"], [APP_EVENT], False),
        ]
    )
    emit_rows = await db.fetch_all("SELECT 1 FROM {{tables.team_app_emit_keys}} WHERE team_id = $1", TEAM_ID)
    assert emit_rows == []


@pytest.mark.asyncio
async def test_registered_keys_verify_for_their_declared_purposes_only(db):
    read_signer, read = _key("read-1", [APP_GRANT_READ])
    await _install_v2(db, _v2_manifest([read]))
    app = _probe_app(db)

    declared = await _post(
        app, f"/probe/{APP_GRANT_READ}", b"{}",
        _signed_for_app(APP_GRANT_READ, read_signer, read, path=f"/probe/{APP_GRANT_READ}", body=b"{}"),
    )
    undeclared = await _post(
        app, f"/probe/{HOOK_RESOLVE}", b"{}",
        _signed_for_app(HOOK_RESOLVE, read_signer, read, path=f"/probe/{HOOK_RESOLVE}", body=b"{}"),
    )

    assert declared.status_code == 200, declared.text
    assert undeclared.status_code == 403, undeclared.text


@pytest.mark.asyncio
async def test_an_unknown_purpose_label_is_stored_and_grants_nothing(db):
    signer, entry = _key("custom-1", ["x-custom"])
    await _install_v2(db, _v2_manifest([entry]))
    app = _probe_app(db)

    assert await _team_keys(db) == [(entry["kid"], entry["did_key"], ["x-custom"], False)]
    for purpose in (APP_GRANT_READ, HOOK_RESOLVE):
        response = await _post(
            app, f"/probe/{purpose}", b"{}",
            _signed_for_app(purpose, signer, entry, path=f"/probe/{purpose}", body=b"{}"),
        )
        assert response.status_code == 403, (purpose, response.text)


@pytest.mark.asyncio
async def test_a_v2_app_emits_with_an_app_keys_key_declaring_app_event(db):
    emit_signer, emit = _key("emit-1", [APP_EVENT])
    read_signer, read = _key("read-1", [APP_GRANT_READ])
    await _install_v2(db, _v2_manifest([emit, read]))
    app = _probe_app(db)

    emitted = await _post(
        app, f"/probe/{APP_EVENT}", EMIT_BODY,
        _signed_for_app(APP_EVENT, emit_signer, emit, path=f"/probe/{APP_EVENT}", body=EMIT_BODY),
    )
    read_key_emits = await _post(
        app, f"/probe/{APP_EVENT}", EMIT_BODY,
        _signed_for_app(APP_EVENT, read_signer, read, path=f"/probe/{APP_EVENT}", body=EMIT_BODY),
    )

    assert emitted.status_code == 200, emitted.text
    assert read_key_emits.status_code == 403, read_key_emits.text


@pytest.mark.asyncio
async def test_a_kid_keeps_its_first_did_key_and_a_conflicting_install_writes_nothing(db):
    _, first = _key("read-1", [APP_GRANT_READ])
    await _install_v2(db, _v2_manifest([first]))
    _, other = _key("read-1", [APP_GRANT_READ])
    conflicting = _v2_manifest([other], version="0.0.1")

    with pytest.raises(ConflictError):
        await _install_v2(db, conflicting, version="0.0.1")

    assert await _team_keys(db) == [(first["kid"], first["did_key"], [APP_GRANT_READ], False)]
    install = await db.fetch_one(
        "SELECT digest FROM {{tables.team_app_installs}} WHERE team_id = $1 AND app_id = $2", TEAM_ID, APP_ID
    )
    assert install["digest"] != _digest(conflicting)


@pytest.mark.asyncio
async def test_a_revoked_key_stays_revoked_when_the_same_bytes_are_installed_again(db):
    _, entry = _key("read-1", [APP_GRANT_READ])
    manifest = _v2_manifest([entry])
    await _install_v2(db, manifest)
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET revoked_at = NOW() WHERE team_id = $1 AND key_id = 'read-1'", TEAM_ID
    )

    await _install_v2(db, manifest)

    assert await _team_keys(db) == [(entry["kid"], entry["did_key"], [APP_GRANT_READ], True)]


@pytest.mark.asyncio
async def test_a_revoked_key_stays_revoked_when_new_bytes_list_it_again(db):
    signer, entry = _key("read-1", [APP_GRANT_READ, HOOK_RESOLVE])
    await _install_v2(db, _v2_manifest([entry]))
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET revoked_at = NOW() WHERE team_id = $1 AND key_id = 'read-1'", TEAM_ID
    )

    await _install_v2(db, _v2_manifest([entry], version="0.0.1"), version="0.0.1")

    app = _probe_app(db)
    for purpose in (APP_GRANT_READ, HOOK_RESOLVE):
        assert await get_active_app_key(
            db, team_id=TEAM_ID, app_id=APP_ID, kid=entry["kid"], did_key=entry["did_key"], purpose=purpose
        ) is None, purpose
        response = await _post(
            app, f"/probe/{purpose}", b"{}",
            _signed_for_app(purpose, signer, entry, path=f"/probe/{purpose}", body=b"{}"),
        )
        assert response.status_code == 403, (purpose, response.text)


@pytest.mark.asyncio
async def test_another_teams_keys_are_never_active_for_this_team(db):
    signer, entry = _key("read-1", [APP_GRANT_READ])
    manifest = _v2_manifest([entry])
    await _install_v2(db, manifest, team_id=OTHER_TEAM_ID)
    app = _probe_app(db)

    response = await _post(
        app, f"/probe/{APP_GRANT_READ}", b"{}",
        _signed_for_app(APP_GRANT_READ, signer, entry, path=f"/probe/{APP_GRANT_READ}", body=b"{}"),
    )

    assert response.status_code == 403, response.text
    assert await get_active_app_key(
        db, team_id=TEAM_ID, app_id=APP_ID, kid=entry["kid"], did_key=entry["did_key"], purpose=APP_GRANT_READ
    ) is None


@pytest.mark.asyncio
async def test_reseed_recreates_app_key_rows_from_the_bytes(db):
    _, entry = _key("read-1", [APP_GRANT_READ, HOOK_RESOLVE])
    manifest = _v2_manifest([entry])
    await _install_v2(db, manifest)
    await db.execute("DELETE FROM {{tables.team_app_keys}} WHERE team_id = $1", TEAM_ID)

    report = await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)

    assert report.reseeded == [TEAM_ID]
    assert await _team_keys(db) == [(entry["kid"], entry["did_key"], [APP_GRANT_READ, HOOK_RESOLVE], False)]


@pytest.mark.asyncio
async def test_reseed_reports_a_team_whose_app_key_id_holds_another_key(db):
    _, entry = _key("read-1", [APP_GRANT_READ])
    manifest = _v2_manifest([entry])
    await _install_v2(db, manifest)
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET did_key = $2 WHERE team_id = $1", TEAM_ID, _make_app_keypair()[1]
    )

    report = await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)

    assert report.key_conflict == [TEAM_ID]


# --- one reader -------------------------------------------------------------------


def _apply(node: Any, tokens: list[str], op: str, value: Any) -> Any:
    """RFC 6901 set/remove, as the vector's mutation_semantics define them."""
    key = tokens[0].replace("~1", "/").replace("~0", "~")
    if len(tokens) == 1:
        if isinstance(node, list):
            if op == "remove":
                del node[int(key)]
            elif key == "-":
                node.append(value)
            else:
                node[int(key)] = value
        elif op == "remove":
            del node[key]
        else:
            node[key] = value
        return node
    child = node[int(key)] if isinstance(node, list) else node[key]
    _apply(child, tokens[1:], op, value)
    return node


def _case_bytes(case: dict[str, Any]) -> bytes:
    document = copy.deepcopy(VECTOR["base_manifests"][case["base"]])
    for mutation in case.get("mutations", []):
        _apply(document, mutation["path"].split("/")[1:], mutation["op"], mutation.get("value"))
    return _canonical(document)


def _identity(data: bytes) -> tuple[str, str] | None:
    try:
        app = json.loads(data)["app"]
        return str(app["id"]), str(app["origin"])
    except (ValueError, KeyError, TypeError):
        return None


def _registered_keys(registration) -> list[tuple[str, str, tuple[str, ...]]]:
    keys = [(key.kid, key.did_key, (APP_EVENT,)) for key in registration.emit_keys]
    keys += [(key.kid, key.did_key, key.purposes) for key in registration.app_keys]
    return sorted(keys)


VECTOR_INPUTS = [(case["name"], _case_bytes(case), case["expected"]) for case in VECTOR["cases"]] + [
    (case["name"], case["bytes"].encode(), case["expected"]) for case in VECTOR["raw_cases"]
]


@pytest.mark.asyncio
async def test_a_refused_manifest_is_a_422_whose_detail_carries_the_readers_code(db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    _, entry = _key("bad", [APP_GRANT_READ])
    entry["did_key"] = "did:key:zNotAKey"
    manifest = _v2_manifest([entry])
    body = {
        "app_id": APP_ID, "origin": ORIGIN, "app_version": "0.0.0", "manifest_version": 2,
        "digest": _digest(manifest), "granted_scopes": [], "events": [], "event_emitters": [],
        "manifest": base64.b64encode(manifest).decode(),
    }

    response = await _install_over_http(_build_apps_app(db), body)

    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "app_keys_invalid"
    assert await _team_keys(db) == []


def test_the_server_reserves_the_names_the_vector_reserves():
    assert set(VECTOR["reserved_names"]) <= set(reserved_app_ids())


@pytest.mark.parametrize(("name", "data", "expected"), VECTOR_INPUTS, ids=[item[0] for item in VECTOR_INPUTS])
def test_install_reads_bytes_exactly_as_the_shared_reader_does(name, data, expected):
    identity = _identity(data)
    if identity is None:
        assert not expected["accepted"], name
        return
    app_id, origin = identity
    try:
        registration = manifest_registration(data, app_id=app_id, origin=origin, digest=_digest(data))
    except ValidationError as refused:
        assert not expected["accepted"], (name, refused)
        cause = refused.__cause__
        if isinstance(cause, ManifestError):
            assert cause.code == expected["error"], name
        return
    assert expected["accepted"], name
    resolved = load_manifest(data, reserved_names=reserved_app_ids())
    assert _registered_keys(registration) == sorted((kid, did, tuple(p)) for kid, did, p in resolved.app_keys)
    assert registration.manifest_version == resolved.manifest_version
    assert sorted(registration.requested_scopes) == sorted(set(resolved.install_scopes))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("app_id", "origin"),
    [("folio", "https://folio.aweb.ai"), ("library", "https://library.aweb.ai")],
)
async def test_every_live_apps_committed_manifest_installs_through_the_reader(db, app_id, origin):
    manifest = read_manifest_bytes(ROOT / "naapp" / app_id / "src" / app_id / "aweb-app.json", origin)
    document = json.loads(manifest)

    installed = await install_app(
        db,
        team_id=TEAM_ID,
        app_id=app_id,
        origin=origin,
        app_version=document["app"]["version"],
        manifest_version=document["manifest_version"],
        digest=_digest(manifest),
        granted_scopes=[],
        installed_by_agent_id=str(AGENT_ID),
        manifest=manifest,
    )

    assert installed.digest == _digest(manifest)
    for emitter in document.get("event_emitters", []):
        assert await get_active_app_emit_key(
            db, team_id=TEAM_ID, app_id=app_id, kid=emitter["kid"], did_key=emitter["did_key"]
        ) is not None
