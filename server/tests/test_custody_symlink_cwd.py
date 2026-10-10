"""Real local resident custody startup through a logical working-directory path."""
import asyncio
import json
import os
from pathlib import Path

import pytest
from awid.signing import canonical_json_bytes, sign_message

from test_cli_human_reply import _cli, _pem
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _make_certificate


@pytest.mark.asyncio
async def test_local_custody_from_symlink_cwd(privacy_app, tmp_path):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    physical = (tmp_path / "resident").resolve()
    physical.mkdir()
    logical = tmp_path / "logical-resident"
    logical.symlink_to(physical, target_is_directory=True)
    home = physical / ".aw"
    home.mkdir(mode=0o700)
    actor = env.actors["bob"]
    team_sk, _, team_did = _make_keypair()
    await env.db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE team_id=$2", team_did, TEAM)
    await env.registry_db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE name=$2", team_did, TEAM.split(":", 1)[0])
    cert = _make_certificate(team_sk, team_did, actor.did, team_id=TEAM, alias="bob", identity_scope="local")
    # Match the public CLI certificate encoding: omit absent local fields.
    for field in ("signature", "member_did_aw", "member_address"):
        cert.pop(field)
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / "team-certs").mkdir(mode=0o700)
    (home / cert_path).write_text(json.dumps(cert))
    (home / cert_path).chmod(0o600)
    member = {"team_id": TEAM, "alias": "bob", "cert_path": cert_path}
    (home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [member]}))
    (home / "workspace.yaml").write_text(json.dumps({"aweb_url": str(env.client.base_url),
        "memberships": [{**member, "workspace_id": str(actor.workspace)}]}))
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    assert not (home / "identity.yaml").exists()

    binary = (tmp_path / "aw").resolve()
    build = await asyncio.create_subprocess_exec("go", "build", "-o", str(binary), "./cmd/aw",
        cwd=Path(__file__).resolve().parents[2] / "cli/go", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    output, _ = await build.communicate()
    assert build.returncode == 0, output.decode()
    child = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    child.update(HOME=str(physical), PWD=str(logical), XDG_CONFIG_HOME=str(physical / ".config"),
        AW_CONFIG_PATH=str(physical / ".config/aw/config.yaml"), AW_NO_UPDATE_CHECK="1",
        AWEB_URL=str(env.client.base_url), AWID_REGISTRY_URL=str(env.client.base_url))
    # PWD is a genuine alternate spelling of cwd, so Go's os.Getwd preserves it.
    log_path = tmp_path / "custody.log"
    with log_path.open("wb") as log:
        process = await asyncio.create_subprocess_exec(str(binary), "custody", "serve", cwd=logical,
            env=child, stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.returncode is None, log_path.read_text()
                status = await _cli(binary, logical, child, "custody", "status", "--json")
                if status["status"] == "running":
                    assert status["resident"]["did_key"] == actor.did
                    assert status["resident"]["alias"] == "bob"
                    assert status["keys"]["signing_ready"], status
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail(log_path.read_text())
        finally:
            if process.returncode is None:
                process.terminate()
                await asyncio.wait_for(process.wait(), 5)
    assert not (home / "identity.yaml").exists()

    # The same resident selected externally through a symlink remains refused.
    other = tmp_path / "other"
    other.mkdir()
    external = dict(child, PWD=str(other), AWEB_IDENTITY_HOME=str(logical / ".aw"))
    refused = await asyncio.create_subprocess_exec(str(binary), "custody", "serve", cwd=other,
        env=external, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    output, _ = await asyncio.wait_for(refused.communicate(), 10)
    assert refused.returncode != 0, output.decode()
    assert b"symlink" in output, output.decode()
