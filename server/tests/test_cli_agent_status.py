"""Production aw -> team-auth v2 -> real status routes, PostgreSQL and Redis."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path

import pytest

from awid.did import stable_id_from_did_key
from test_agent_status_publish_http import _document, _open_rate_window
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_certificate


@pytest.mark.asyncio
@pytest.mark.parametrize("global_root", [False, True])
async def test_cli_status_designation_publish_and_refusals(privacy_app, tmp_path, global_root):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    repo = Path(__file__).resolve().parents[2]
    binary = Path(os.environ.get("AW_TEST_CLI_BINARY", str(tmp_path / "aw")))
    if "AW_TEST_CLI_BINARY" not in os.environ:
        build = await asyncio.create_subprocess_exec("go", "build", "-o", str(binary), "./cmd/aw",
                                                    cwd=repo / "cli/go", stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)
        output, _ = await build.communicate()
        assert build.returncode == 0, output.decode()
    homes = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        home = (tmp_path / name / ".aw").resolve()
        home.mkdir(parents=True, mode=0o700)
        stable = stable_id_from_did_key(actor.did) if global_root else ""
        address = f"example.test/{name}" if global_root else ""
        cert = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM, alias=name,
                                 identity_scope="global" if global_root else "local",
                                 member_did_aw=stable, member_address=address)
        cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
        (home / "team-certs").mkdir()
        (home / cert_path).write_text(json.dumps(cert))
        membership = {"team_id": TEAM, "alias": name, "cert_path": cert_path}
        (home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [membership]}))
        (home / "workspace.yaml").write_text(json.dumps({"aweb_url": str(env.client.base_url), "memberships": [membership]}))
        (home / "signing.key").write_text("-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(actor.sk).decode() + "\n-----END ED25519 PRIVATE KEY-----\n")
        (home / "signing.key").chmod(0o600)
        if global_root:
            (home / "identity.yaml").write_text(json.dumps({"did": actor.did, "stable_id": stable,
                "address": address, "custody": "self", "identity_scope": "global"}))
            await env.db.execute("UPDATE {{tables.agents}} SET identity_scope = 'global', did_aw = $1, address = $2 WHERE agent_id = $3", stable, address, actor.id)
        homes[name] = home

    # The cwd contains no identity; every command must use the selected root.
    instance = tmp_path / "instance"
    instance.mkdir()
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_", "AW_AGENT_STATUS_"))}
    child_env.update(HOME=str(tmp_path), AW_NO_UPDATE_CHECK="1")

    async def cli(actor, *args, document=None, exit_code=0):
        process = await asyncio.create_subprocess_exec(str(binary), "--identity-home", str(homes[actor]),
            *args, "--json", cwd=instance, env=child_env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(document).encode() if document else None), 30)
        assert process.returncode == exit_code, (stdout.decode(), stderr.decode())
        value = json.loads(stdout)
        assert value["ok"] == (exit_code == 0)
        return value

    set_host = await cli("alice", "status-host", "set", "--host-did", env.actors["bob"].did)
    assert set_host["status"] == 200 and set_host["host_did"] == env.actors["bob"].did
    shown = await cli("alice", "status-host", "show")
    assert shown["host_active"] is True
    document = _document(env, "alice", "bob", agent=stable_id_from_did_key(env.actors["alice"].did) if global_root else env.actors["alice"].did)
    sent = await cli("bob", "status", "publish", "--alias", "alice", "--document", "-", document=document)
    assert sent["status"] == 200 and sent["seq"] == document["seq"]
    row = await env.db.fetch_one("SELECT publisher_did, signed_payload FROM {{tables.agent_status}} WHERE agent_id = $1", env.actors["alice"].id)
    assert row["publisher_did"] == env.actors["bob"].did
    assert json.loads(base64.urlsafe_b64decode(row["signed_payload"] + "=" * (-len(row["signed_payload"]) % 4))) == document
    limited = await cli("bob", "status", "publish", "--alias", "alice", "--document", "-", document={**document, "seq": document["seq"] + 1}, exit_code=3)
    assert limited["status"] == 429 and limited["code"] == "rate_limited" and limited["retry_after"] == 5
    await _open_rate_window(env, "alice")
    stale = await cli("bob", "status", "publish", "--alias", "alice", "--document", "-", document=document, exit_code=3)
    assert stale["status"] == 409 and stale["code"] == "stale_seq" and stale["retry_after"] is None
    refused = await cli("alice", "status", "publish", "--alias", "alice", "--document", "-", document={**document, "publisher_did": env.actors["alice"].did}, exit_code=3)
    assert refused["status"] == 403 and refused["code"] == "not_status_host"
    cleared = await cli("alice", "status-host", "clear")
    assert cleared["host_did"] is None
    assert not (instance / ".aw").exists()
