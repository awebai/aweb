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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.app_credentials import APP_GRANT_READ, HOOK_RESOLVE
from aweb.hook_bindings import ACTIVATE, REVOKE, activate_binding, list_app_bindings, revoke_binding
from aweb.installations import uninstall_installation_on
from aweb.routes.app_hooks import router as app_hooks_router
from aweb.routes.apps import router as apps_router
from awid.did import did_from_public_key
from tests.app_credential_signing import app_credential_headers
from tests.installation_fixtures import install_fixture_app, seed_pending_installation
from tests.test_app_credentials import _register_app_key
from tests.test_app_events_http import AGENT_ID, _build_events_app, _seed_team_and_agent
from tests.test_hook_binding_activation import env  # noqa: F401

# The owner-act environment: a registry holding the team key, its verifier and owner.
__all__ = ["env"]

ROOT = Path(__file__).resolve().parents[2]
GRANT = json.loads((ROOT / "naapp-contracts" / "src" / "aweb_naapp_contracts" / "vectors" / "app-grant-status-v1.json").read_text())
HOOKS = json.loads((ROOT / "naapp-contracts" / "src" / "aweb_naapp_contracts" / "vectors" / "hook-resolution-v1.json").read_text())
GRANT_PATH = "/v1/apps/self/grant"
# The spellings an app's grant source accepts (aweb_naapp.runtime.team_grants).
APP_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)")
AS_OF = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# The binding time spelling an app's hook resolver accepts.
BINDING_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
# The one spelling an app's hook resolver accepts for a binding id.
CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@pytest_asyncio.fixture
async def grant_db(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(GRANT["scenario"]["max_age_seconds"]))
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db, team_id=GRANT["scenario"]["team_id"])
    return db


async def _seed_grant(db, seed: dict | None) -> None:
    """Reach the answer's state through the product; with no seed nothing is registered."""
    if seed is None:
        return
    scenario = GRANT["scenario"]
    manifest = scenario["manifest"].encode()
    document = json.loads(manifest)
    common = dict(
        team_id=scenario["team_id"],
        app_id=scenario["app_id"],
        origin=scenario["origin"],
        app_version=document["app"]["version"],
        manifest_version=document["manifest_version"],
        granted_scopes=seed["granted_scopes"],
    )
    if seed["path"] == "legacy_pending_installation":
        await seed_pending_installation(db, digest=scenario["digest"], **common)
    else:
        install = await install_fixture_app(
            db, manifest=manifest, installed_by_agent_id=str(AGENT_ID), **common
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
    if seed["path"] == "install_then_uninstall":
        async with db.transaction() as tx:
            await uninstall_installation_on(
                tx,
                team_id=scenario["team_id"],
                app_id=scenario["app_id"],
                expected_generation=install.generation,
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


@pytest_asyncio.fixture
async def hook_db(env, monkeypatch):
    """The vector's scenario through the install path and real owner acts.

    Returns the database and each binding label's and each app's server-generated ids."""
    scenario = HOOKS["scenario"]
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(scenario["max_age_seconds"]))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps(scenario["producer_keys"]))
    team_id = scenario["team_id"]
    installations: dict[str, str] = {}
    bindings = {}
    for app_id, app in scenario["apps"].items():
        manifest = app["manifest"].encode()
        install = await install_fixture_app(
            env.db,
            team_id=team_id,
            app_id=app_id,
            origin=app["origin"],
            app_version=json.loads(manifest)["app"]["version"],
            manifest_version=json.loads(manifest)["manifest_version"],
            manifest=manifest,
            installed_by_agent_id=str(AGENT_ID),
        )
        assert (install.digest, install.generation) == (app["digest"], app["generation"])
        installations[app_id] = install.installation_id
        written = {binding.hook: binding for binding in await list_app_bindings(env.db, team_id=team_id, app_id=app_id)}
        for binding in scenario["bindings"]:
            if binding["app"] == app_id:
                bindings[binding["label"]] = written[binding["hook"][2]]
    for binding in scenario["bindings"]:
        written = bindings[binding["label"]]
        for act, apply, wanted in ((ACTIVATE, activate_binding, binding["activated_at"]), (REVOKE, revoke_binding, binding["revoked_at"])):
            if wanted is None:
                continue
            signing, signature = env.owner.sign(act, written)
            await apply(env.db, env.verifier, team_id=team_id, binding_id=written.binding_id, signing=signing, signature=signature)
    return env.db, {label: binding.binding_id for label, binding in bindings.items()}, installations


def _moment(value: str) -> datetime:
    return datetime.fromisoformat(value)


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


# Answers about bindings from before installations carried an identity; the
# migration test writes those rows (test_hook_resolution_identity_migration.py).
PRE_IDENTITY = {binding["label"] for binding in HOOKS["scenario"]["bindings"] if not binding["identity"]}


async def check_hook_answer(hook_db, answer: dict) -> None:
    db, ids, installations = hook_db
    apps = HOOKS["scenario"]["apps"]
    vector_ids = {
        str(ids[binding["label"]]): binding["binding_id"] for binding in HOOKS["scenario"]["bindings"]
    }
    vector_installations = {installations[app_id]: app["installation_id"] for app_id, app in apps.items()}

    response = await _resolve(db, answer, ids)

    assert response.status_code == answer["status"], response.text
    body = response.json()
    expected = json.loads(answer["body"])
    if response.status_code == 200:
        assert AS_OF.fullmatch(body["as_of"]), body["as_of"]
        body["as_of"] = expected["as_of"]
        for binding, wanted in zip(body.get("bindings", []), expected.get("bindings", []), strict=True):
            assert CANONICAL_UUID.fullmatch(binding["binding_id"]), binding["binding_id"]
            binding["binding_id"] = vector_ids[binding["binding_id"]]
            for field in ("activated_at", "active_from", "revoked_at"):
                if binding.get(field) is not None:
                    assert BINDING_TIME.fullmatch(binding[field]), binding[field]
            if binding.get("activated_at") is not None:
                assert _moment(binding["active_from"]) - _moment(binding["activated_at"]) == timedelta(seconds=60)
            # A time is substituted only where both the server and the vector have
            # one; a null on either side alone is a disagreement.
            for field in ("activated_at", "active_from", "revoked_at"):
                if field in binding:
                    assert (binding[field] is None) == (wanted[field] is None), (field, binding[field])
                    binding[field] = wanted[field]
            if binding["installation_id"] is not None:
                assert isinstance(binding["installation_id"], str) and binding["installation_id"]
                binding["installation_id"] = vector_installations[binding["installation_id"]]
    assert body == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [answer for answer in HOOKS["answers"] if not PRE_IDENTITY & set(answer["labels"])],
    ids=lambda answer: answer["name"],
)
async def test_the_server_gives_each_hook_resolution_answer(hook_db, answer):
    await check_hook_answer(hook_db, answer)
