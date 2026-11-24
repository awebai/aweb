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
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.app_credentials import APP_GRANT_READ
from aweb.routes.apps import router as apps_router
from awid.did import did_from_public_key
from tests.app_credential_signing import app_credential_headers
from tests.installation_fixtures import install_fixture_app
from tests.test_app_credentials import _register_app_key
from tests.test_app_events_http import AGENT_ID, _build_events_app, _seed_team_and_agent

ROOT = Path(__file__).resolve().parents[2]
GRANT = json.loads((ROOT / "docs" / "vectors" / "app-grant-status-v1.json").read_text())
GRANT_PATH = "/v1/apps/self/grant"
# The spellings an app's grant source accepts (aweb_naapp.runtime.team_grants).
APP_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)")
AS_OF = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


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
