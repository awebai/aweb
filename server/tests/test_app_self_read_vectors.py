"""The server's answers to an app's self-reads against the frozen vectors.

Each scenario is seeded through the real install path and each request is
signed as the app signs it; the route's status and body must be the vector's
answer, with only the values the vector names as server-generated substituted,
and those first checked for the spelling the app accepts. The app side of the
same vectors is naapp-lib/tests/runtime/test_app_self_read_vectors.py.
"""

from __future__ import annotations

import json
import re
from uuid import UUID
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.app_credentials import APP_GRANT_READ, HOOK_RESOLVE
from aweb.hook_bindings import HookBindingDeclaration, write_pending_bindings
from aweb.routes.app_hooks import router as app_hooks_router
from aweb.routes.apps import router as apps_router
from awid.did import did_from_public_key
from tests.app_credential_signing import app_credential_headers
from tests.installation_fixtures import install_fixture_app, seed_hook_installation
from tests.test_app_credentials import _register_app_key
from tests.test_app_events_http import AGENT_ID, _build_events_app, _seed_team_and_agent

ROOT = Path(__file__).resolve().parents[2]
GRANT = json.loads((ROOT / "docs" / "vectors" / "app-grant-status-v1.json").read_text())
HOOKS = json.loads((ROOT / "docs" / "vectors" / "hook-resolution-v1.json").read_text())
GRANT_PATH = "/v1/apps/self/grant"
# The spellings an app's grant source accepts (aweb_naapp.runtime.team_grants).
APP_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)")
AS_OF = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# The one spelling an app's hook resolver accepts for a binding id.
CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@pytest_asyncio.fixture
async def grant_db(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(GRANT["scenario"]["max_age_seconds"]))
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db, team_id=GRANT["scenario"]["team_id"])
    return db


async def _seed_grant(db, seed: dict | None) -> None:
    scenario = GRANT["scenario"]
    manifest = scenario["manifest"].encode()
    document = json.loads(manifest)
    install = await install_fixture_app(
        db,
        team_id=scenario["team_id"],
        app_id=scenario["app_id"],
        origin=scenario["origin"],
        app_version=document["app"]["version"],
        manifest_version=document["manifest_version"],
        granted_scopes=(seed or {"granted_scopes": []})["granted_scopes"],
        manifest=manifest,
        installed_by_agent_id=str(AGENT_ID),
    )
    assert install.digest == scenario["digest"]
    signing_key = SigningKey(bytes.fromhex(scenario["grant_read_key"]["seed_hex"]))
    await _register_app_key(
        db,
        did_key=did_from_public_key(bytes(signing_key.verify_key)),
        kid=scenario["grant_read_key"]["kid"],
        purposes=[APP_GRANT_READ],
        team_id=scenario["team_id"],
    )
    if seed is None:
        await db.execute(
            "DELETE FROM {{tables.team_app_installs}} WHERE team_id = $1 AND app_id = $2",
            scenario["team_id"],
            scenario["app_id"],
        )
    elif seed["state"] != "active":
        await db.execute(
            "UPDATE {{tables.team_app_installs}} SET state = $1, origin_verified = $2",
            seed["state"],
            seed["origin_verified"],
        )


async def _read_grant(db):
    scenario = GRANT["scenario"]
    app = _build_events_app(db, public_origin="http://test")
    app.include_router(apps_router)
    headers = app_credential_headers(
        purpose=APP_GRANT_READ,
        seed=bytes.fromhex(scenario["grant_read_key"]["seed_hex"]),
        method="GET",
        aud="http://test",
        path=GRANT_PATH,
        team_id=scenario["team_id"],
        app_id=scenario["app_id"],
        kid=scenario["grant_read_key"]["kid"],
        body=b"",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(GRANT_PATH, headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", GRANT["answers"], ids=lambda answer: answer["name"])
async def test_the_server_gives_each_grant_answer(grant_db, answer):
    await _seed_grant(grant_db, answer["seed"])

    response = await _read_grant(grant_db)

    assert response.status_code == answer["status"], response.text
    body = response.json()
    expected = json.loads(answer["body"])
    if response.status_code == 200:
        assert isinstance(body["installation_id"], str) and body["installation_id"]
        assert APP_TIME.fullmatch(body["installed_at"]), body["installed_at"]
        assert AS_OF.fullmatch(body["as_of"]), body["as_of"]
        for generated in ("installation_id", "installed_at", "as_of"):
            body[generated] = expected[generated]
    assert body == expected


# --- hook resolution ---


def _moment(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


@pytest_asyncio.fixture
async def hook_db(aweb_cloud_db, monkeypatch):
    """The vector's scenario; returns each binding label's server-generated id."""
    scenario = HOOKS["scenario"]
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(scenario["max_age_seconds"]))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps(scenario["producer_keys"]))
    db = aweb_cloud_db.aweb_db
    team_id = scenario["team_id"]
    await _seed_team_and_agent(db, team_id=team_id)
    for app_id, app in scenario["apps"].items():
        pin = {"app_id": app_id, "origin": app["origin"], "digest": app["description"]}
        await seed_hook_installation(db, pin, team_id=team_id, installation_id=app["installation_id"])
        assert pin["digest"] == app["digest"]
        for key in [{**app["resolve_key"], "purposes": [HOOK_RESOLVE]}, *app["hook_keys"]]:
            signing_key = SigningKey(bytes.fromhex(key["seed_hex"]))
            await db.execute(
                """
                INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)
                VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[])
                """,
                team_id, app_id, app["origin"], app["digest"], key["kid"],
                did_from_public_key(bytes(signing_key.verify_key)), key["purposes"],
            )
    ids: dict[str, UUID] = {}
    # The install path writes each app's live generation; a later write would supersede it.
    for binding in scenario["bindings"]:
        if binding["state"] != "active":
            continue
        app = scenario["apps"][binding["app"]]
        async with db.transaction() as tx:
            (written,) = await write_pending_bindings(
                tx, team_id=team_id, app_id=binding["app"], origin=app["origin"], digest=app["digest"],
                installation_id=app["installation_id"], generation=app["generation"],
                declarations=[HookBindingDeclaration(
                    kind=binding["kind"], catalog_id=binding["hook"][0], catalog_version=binding["hook"][1],
                    hook=binding["hook"][2], tool=binding["tool"], method=binding["method"],
                    path=binding["path"], scopes=tuple(binding["scopes"]),
                )],
            )
        await db.execute(
            """
            UPDATE {{tables.app_hook_bindings}}
            SET state = 'active', activated_at = $2, active_from = $3, activation_act_sha256 = $4
            WHERE binding_id = $1
            """,
            written.binding_id, _moment(binding["activated_at"]), _moment(binding["active_from"]), "ab" * 32,
        )
        ids[binding["label"]] = written.binding_id
    # Ended and identity-less bindings are history the install path no longer writes.
    for binding in scenario["bindings"]:
        if binding["state"] == "active":
            continue
        app = scenario["apps"][binding["app"]]
        identity = binding["identity"]
        await db.execute(
            """
            INSERT INTO {{tables.app_hook_bindings}} (
                binding_id, kind, team_id, installation_id, generation, app_id, origin, digest,
                catalog_id, catalog_version, hook, tool, method, path, scopes, state, ended_by,
                activated_at, active_from, revoked_at, activation_act_sha256, revocation_act_sha256
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::TEXT[], $16, $17,
                $18, $19, $20, $21, $22
            )
            """,
            UUID(binding["binding_id"]), binding["kind"], team_id,
            app["installation_id"] if identity else None, app["generation"] if identity else None,
            binding["app"], app["origin"], app["digest"], *binding["hook"],
            binding["tool"], binding["method"], binding["path"], binding["scopes"],
            binding["state"], binding["ended_by"],
            _moment(binding["activated_at"]), _moment(binding["active_from"]), _moment(binding["revoked_at"]),
            "ab" * 32 if binding["activated_at"] else None,
            "cd" * 32 if binding["ended_by"] == "owner_act" else None,
        )
        ids[binding["label"]] = UUID(binding["binding_id"])
    return db, ids


async def _resolve(db, answer: dict, ids: dict[str, UUID]):
    scenario = HOOKS["scenario"]
    path = answer["path"].format(**{label: str(binding_id) for label, binding_id in ids.items()})
    headers = {}
    if answer["caller"] is not None:
        key = scenario["apps"][answer["caller"]]["resolve_key"]
        headers = app_credential_headers(
            purpose=HOOK_RESOLVE,
            seed=bytes.fromhex(key["seed_hex"]),
            method="GET",
            aud="http://test",
            path=path,
            team_id=scenario["team_id"],
            app_id=answer["caller"],
            kid=key["kid"],
            body=b"",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    app = _build_events_app(db, public_origin="http://test")
    app.include_router(app_hooks_router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path, headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", HOOKS["answers"], ids=lambda answer: answer["name"])
async def test_the_server_gives_each_hook_resolution_answer(hook_db, answer):
    db, ids = hook_db
    vector_ids = {
        str(ids[binding["label"]]): binding["binding_id"] for binding in HOOKS["scenario"]["bindings"]
    }

    response = await _resolve(db, answer, ids)

    assert response.status_code == answer["status"], response.text
    body = response.json()
    expected = json.loads(answer["body"])
    if response.status_code == 200:
        assert AS_OF.fullmatch(body["as_of"]), body["as_of"]
        body["as_of"] = expected["as_of"]
        for binding in body.get("bindings", []):
            assert CANONICAL_UUID.fullmatch(binding["binding_id"]), binding["binding_id"]
            binding["binding_id"] = vector_ids[binding["binding_id"]]
    assert body == expected
