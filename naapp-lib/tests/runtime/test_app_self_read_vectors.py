"""The app's self-read clients against the frozen server answers.

Each answer's status and body bytes are served through an httpx.MockTransport
to the public client, behind a fixed team-server discovery, so the client's
status handling, JSON decoding and identity checks all run. The server side of
the same vectors is server/tests/test_app_self_read_vectors.py.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.runtime.authorization import GrantUnavailable
from aweb_naapp.runtime.team_grants import AppIdentity, TeamGrantSource
from aweb_naapp.runtime.team_server import TeamServer

AWEB_ROOT = Path(__file__).resolve().parents[3]
GRANT = json.loads((AWEB_ROOT / "docs" / "vectors" / "app-grant-status-v1.json").read_text())
SERVER_URL = "https://aweb.example"


class FixedDirectory:
    """Discovery that always names the same verified server."""

    async def resolve(self, team_id: str, certificate_id: str | None = None) -> TeamServer:
        return TeamServer(
            team_id=team_id,
            server_url=SERVER_URL,
            audience=SERVER_URL,
            team_did_key="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            expires_at=2**62,
        )


def _apply(document: Any, op: str, path: str, value: Any = None) -> Any:
    """One JSON-pointer change: set or remove the member ``path`` names."""
    changed = copy.deepcopy(document)
    *parents, last = [token.replace("~1", "/").replace("~0", "~") for token in path.split("/")[1:]]
    node = changed
    for token in parents:
        node = node[int(token)] if isinstance(node, list) else node[token]
    if op == "remove":
        del node[last]
    else:
        node[last] = value
    return changed


def _answer(name: str) -> dict:
    return next(answer for answer in GRANT["answers"] if answer["name"] == name)


def _grant_source(client: str, status: int, body: bytes) -> TeamGrantSource:
    scenario = GRANT["scenario"]
    config = GRANT["clients"][client]
    signing_key = SigningKey(bytes.fromhex(scenario["grant_read_key"]["seed_hex"]))
    key = AppKey(
        kid=scenario["grant_read_key"]["kid"],
        did_key=did_from_public_key(bytes(signing_key.verify_key)),
        signing_key=signing_key,
    )
    identity = AppIdentity(
        app_id=config["app_id"],
        origin=config["origin"],
        digest=config["digest"],
        manifest_digests=tuple(tuple(pair) for pair in config.get("manifest_digests", ())),
    )

    def serve(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(SERVER_URL + "/v1/apps/self/grant")
        return httpx.Response(status, content=body, headers={"content-type": "application/json"})

    return TeamGrantSource(
        identity=identity,
        signer=AppCredentialSigner(app_id=config["app_id"], key=key, purpose=APP_GRANT_READ),
        discovery=FixedDirectory(),  # type: ignore[arg-type]
        transport=httpx.MockTransport(serve),
    )


def _status_fields(status) -> dict:
    return {
        "team_id": status.team_id,
        "app_id": status.app_id,
        "origin": status.origin,
        "digest": status.digest,
        "state": status.state,
        "app_version": status.app_version,
        "manifest_version": status.manifest_version,
        "granted_scopes": sorted(status.granted_scopes),
        "installation_id": status.installation_id,
        "generation": status.generation,
        "origin_verified": status.origin_verified,
        "installed_at": status.installed_at,
        "as_of": status.as_of,
        "max_age_seconds": status.max_age_seconds,
    }


def _expected_status(expected: dict) -> dict:
    return expected | {
        "installed_at": datetime.fromisoformat(expected["installed_at"]),
        "as_of": datetime.fromisoformat(expected["as_of"]),
    }


GRANT_OUTCOMES = [
    (answer["name"], client, outcome)
    for answer in GRANT["answers"]
    for client, outcome in answer["outcomes"].items()
]


@pytest.mark.parametrize(("name", "client", "outcome"), GRANT_OUTCOMES)
async def test_the_grant_source_reads_each_server_answer(name, client, outcome):
    answer = _answer(name)
    body = answer["body"].encode()
    team_id = GRANT["scenario"]["team_id"]
    if "unavailable" in outcome:
        with pytest.raises(GrantUnavailable) as refused:
            await _grant_source(client, answer["status"], body).status_for(team_id)
        assert refused.value.args == (outcome["unavailable"],)
        return
    status = await _grant_source(client, answer["status"], body).status_for(team_id)
    grant = await _grant_source(client, answer["status"], body).grant_for(team_id)
    if outcome["status"] is None:
        assert status is None
    else:
        assert _status_fields(status) == _expected_status(outcome["status"])
    if outcome["grant"] is None:
        assert grant is None
    else:
        assert grant is not None
        assert (sorted(grant.scopes), grant.installation_id, grant.generation) == (
            sorted(outcome["grant"]["scopes"]),
            outcome["grant"]["installation_id"],
            outcome["grant"]["generation"],
        )
        assert grant.team_id == team_id


REFUSED = [
    (GRANT["refused_answers"]["client"], case) for case in GRANT["refused_answers"]["cases"]
] + [
    ("by_manifest_version", case) for case in GRANT["refused_answers"]["by_manifest_version_cases"]
]


@pytest.mark.parametrize(
    ("client", "case"),
    REFUSED,
    ids=lambda value: value["name"] if isinstance(value, dict) else value,
)
async def test_a_refused_answer_is_unavailable_and_its_base_is_read(client, case):
    refused = GRANT["refused_answers"]
    base = _answer(refused["base"])
    team_id = GRANT["scenario"]["team_id"]
    changed = _apply(json.loads(base["body"]), case["op"], case["path"], case.get("value"))
    with pytest.raises(GrantUnavailable) as unavailable:
        await _grant_source(client, base["status"], json.dumps(changed).encode()).status_for(
            team_id
        )
    assert unavailable.value.args == (refused["outcome"]["unavailable"],)
    # The case's one change is its only fault: the base it changed is read.
    assert await _grant_source(client, base["status"], base["body"].encode()).status_for(team_id)
