"""A member whose certificate the team's key change superseded continues.

The real aw binary against real HTTP aweb and AWID: the server refuses the
superseded certificate as team_key_not_current, aw fetches the certificate the
registry now records for it, verifies it against the team's current key,
installs it and continues. The key change goes through AWID's rotate route with
the namespace controller's act; DNS, the controller's root, is the one external
answer the test supplies.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from awid.signing import canonical_json_bytes, sign_message
from test_cli_human_reply import _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_messages_http import _make_certificate, _make_keypair
from test_team_key_pinning import pinning, register_namespace_controller  # noqa: F401

__all__ = ["pinning"]


def _certificate(team_sk, team_did, member_did, certificate_id):
    cert = _make_certificate(team_sk, team_did, member_did, team_id=TEAM, alias="bob", identity_scope="local",
                             certificate_id=certificate_id)
    for field in ("signature", "member_did_aw", "member_address"):
        cert.pop(field)
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    return cert


def _encoded(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _controller_headers(sk, did, payload):
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = sign_message(sk, canonical_json_bytes({**payload, "timestamp": timestamp}))
    return {"Authorization": f"DIDKey {did} {signature}", "X-AWEB-Timestamp": timestamp}


async def _change_key_with_member(registry_origin, env, old_id, new_cert, new_did):
    body = {"new_team_did_key": new_did,
            "member_certificates": [{"old_certificate_id": old_id, "certificate": _encoded(new_cert)}]}
    async with httpx.AsyncClient(base_url=registry_origin) as registry_http:
        rotated = await registry_http.post(
            f"/v1/namespaces/example.test/teams/{TEAM_NAME}/rotate", json=body,
            headers=_controller_headers(env.namespace_sk, env.namespace_did, {
                "domain": "example.test", "operation": "rotate_team_key",
                "name": TEAM_NAME, "new_team_did_key": new_did,
            }),
        )
    assert rotated.status_code == 200, rotated.text


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_a_member_refused_for_a_superseded_certificate_installs_its_new_one_and_continues(pinning, tmp_path):
    env = pinning
    binary = Path(os.environ["AW_TEST_CLI_BINARY"])
    actor = env.actors["bob"]
    await register_namespace_controller(env, env.namespace_did)
    cert = _certificate(env.team_sk, env.team_did, actor.did, "bob-before")
    home = tmp_path / "member" / ".aw"
    home.mkdir(parents=True, mode=0o700)
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    (home / "identity.yaml").write_text(json.dumps(dict(did=actor.did, custody="self", identity_scope="local")))
    (home / "certificate.json").write_text(json.dumps(cert))
    membership = dict(team_id=TEAM, alias="bob", cert_path="certificate.json")
    (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (home / "workspace.yaml").write_text(json.dumps(dict(
        aweb_url=str(env.client.base_url), memberships=[dict(membership, workspace_id=str(actor.workspace))],
    )))
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
    child_env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"), AW_NO_UPDATE_CHECK="1")

    async def inbox():
        # A file, not a pipe: the output is readable even when aw has to be stopped.
        output = tmp_path / "aw.log"
        with output.open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                str(binary), "--identity-home", str(home), "mail", "inbox", "--json",
                cwd=tmp_path, env=child_env, stdout=log, stderr=asyncio.subprocess.STDOUT,
            )
            try:
                await asyncio.wait_for(process.wait(), 60)
            except TimeoutError:
                process.kill()
                await process.wait()
                pytest.fail("aw mail inbox did not finish: " + output.read_text()[-4000:])
        return process.returncode, output.read_text()

    async with registry_listener(env) as (registry, registry_origin):
        child_env["AWID_REGISTRY_URL"] = registry_origin
        await registry.register_team_certificate(
            "example.test", TEAM_NAME, team_controller_signing_key=env.team_sk,
            certificate_id=cert["certificate_id"], member_did_key=actor.did,
            member_did_aw=None, member_address=None, alias="bob", identity_scope="local",
            certificate=_encoded(cert),
        )
        assert (await inbox())[0] == 0
        next_sk, _, next_did = _make_keypair()
        new_cert = _certificate(next_sk, next_did, actor.did, "bob-after")
        await _change_key_with_member(registry_origin, env, cert["certificate_id"], new_cert, next_did)

        code, output = await inbox()
        assert code == 0, output
        # The next run presents the installed certificate from the start.
        code, output = await inbox()
        assert code == 0, output

    for state in ("teams.yaml", "workspace.yaml"):
        cert_path = yaml.safe_load((home / state).read_text())["memberships"][0]["cert_path"]
        held = json.loads((home / cert_path).read_text())
        assert (held["certificate_id"], held["team_did_key"]) == ("bob-after", next_did), state
