"""Current Go SDK through real OSS HTTP/AWID/PostgreSQL/Redis; no auth mocks.

Run from server with PYTHONPATH=tests and its locked environment.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import subprocess

import pytest

from conftest import aw_cli_binary, shared_test_pool  # noqa: F401
from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401

pytest_plugins = ("pgdbm.fixtures.conftest",)
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def request_auth_driver(tmp_path_factory):
    binary = tmp_path_factory.mktemp("v2-driver") / ("driver.exe" if os.name == "nt" else "driver")
    build = subprocess.run(
        ["go", "build", "-o", str(binary), str(Path(__file__).with_name("request_auth_v2_driver.go"))],
        cwd=ROOT / "cli/go", text=True, capture_output=True, timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    return binary


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["certificate", "identity-local", "identity-global"])
async def test_sdk_json_and_streaming_v2_against_real_stack(privacy_app, request_auth_driver, tmp_path, family):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    actor = env.actors["alice"]
    stable_id = ""
    if family == "identity-global":
        await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        stable_id = stable_id_from_did_key(actor.did)
    session = await _request(env, "alice", "POST", "/v1/chat/sessions", {"to_aliases": ["bob"], "message": "real session"})
    assert session.status_code == 200, session.text
    certificate = ""
    if family == "certificate":
        cert = json.loads(base64.b64decode(actor.certificate))
        for field in ("member_did_aw", "member_address", "signature"):
            cert.pop(field, None)
        cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
        certificate = base64.b64encode(json.dumps(cert).encode()).decode()
    authority = tmp_path / "authority.json"
    authority.write_text(json.dumps(dict(
        URL=str(env.client.base_url).rstrip("/"), DID=actor.did, StableID=stable_id,
        Key=base64.b64encode(actor.sk).decode(), Certificate=certificate,
        SessionID=session.json()["session_id"], Recipient=env.actors["bob"].did,
    )))
    authority.chmod(0o600)
    try:
        process = await asyncio.create_subprocess_exec(
            str(request_auth_driver), str(authority), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
        assert process.returncode == 0, stderr.decode()
        assert json.loads(stdout) == {"v2_requests": 5, "retargeted_status": 401}
    finally:
        authority.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_production_cli_connect_and_event_stream_use_v2(privacy_app, aw_cli_binary, tmp_path, monkeypatch):
    from aweb.auth_metrics import LEGACY_REQUEST_AUTH_ACCEPTED
    from aweb.presence import clear_workspace_presence

    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    actor = env.actors["alice"]
    home = tmp_path / ".aw"
    (home / "team-certs").mkdir(parents=True)
    cert = json.loads(base64.b64decode(actor.certificate))
    for field in ("member_did_aw", "member_address", "signature"):
        cert.pop(field, None)
    cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / cert_path).write_text(json.dumps(cert))
    membership = dict(team_id=TEAM, alias="alice", cert_path=cert_path)
    monkeypatch.setenv("AWEB_DATABASE_URL", env.db.config.get_dsn())
    monkeypatch.setenv("AWEB_DISCOVERY_ORIGIN", str(env.client.base_url).rstrip("/"))
    (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (home / "workspace.yaml").write_text(json.dumps(dict(aweb_url=str(env.client.base_url), memberships=[membership])))
    (home / "signing.key").write_text("-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(actor.sk).decode() + "\n-----END ED25519 PRIVATE KEY-----\n")
    (home / "signing.key").chmod(0o600)
    child = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    child.update(HOME=str(tmp_path), AW_NO_UPDATE_CHECK="1")
    counters = [LEGACY_REQUEST_AUTH_ACCEPTED.labels("certificate", "POST", "/v1/connect", "dev"),
                LEGACY_REQUEST_AUTH_ACCEPTED.labels("certificate", "GET", "/v1/events/stream", "dev")]
    before = [counter._value.get() for counter in counters]
    try:
        for args in (("workspace", "connect", "--service", str(env.client.base_url), "--team", TEAM, "--json"),
                     ("events", "stream", "--timeout", "1", "--json")):
            process = await asyncio.create_subprocess_exec(str(aw_cli_binary), *args, cwd=tmp_path, env=child,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
            assert process.returncode == 0, stderr.decode()
            assert stdout
        assert [counter._value.get() for counter in counters] == before
    finally:
        rows = await env.db.fetch_all("SELECT workspace_id FROM {{tables.workspaces}} WHERE agent_id=$1", actor.id)
        await clear_workspace_presence(env.redis, [str(row["workspace_id"]) for row in rows])
