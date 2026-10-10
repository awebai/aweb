"""Preserve explicit server sender addresses for signed alias-form plaintext."""
import asyncio
import json
import os
from pathlib import Path
from uuid import UUID

import pytest
from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from test_cli_human_reply import _cli, _pem
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _make_certificate


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("sender_address", ["example.test/alice", ""])
async def test_cli_preserves_explicit_address_with_signed_alias(privacy_app, tmp_path, kind, sender_address):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    team_sk, _, team_did = _make_keypair()
    await env.db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE team_id=$2", team_did, TEAM)
    await env.registry_db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE name=$2", team_did, TEAM.split(":", 1)[0])
    homes = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        stable = stable_id_from_did_key(actor.did) if name == "alice" else ""
        address = sender_address if stable else ""
        scope = "global" if stable else "local"
        await env.db.execute("UPDATE {{tables.agents}} SET did_aw=$1,address=$2,identity_scope=$3 WHERE agent_id=$4",
                             stable or None, address or None, scope, actor.id)
        if stable:
            await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        cert = _make_certificate(team_sk, team_did, actor.did, team_id=TEAM, alias=name,
                                 identity_scope=scope, member_did_aw=stable, member_address=address)
        cert.pop("signature")
        if not stable:
            cert.pop("member_did_aw")
        if not address:
            cert.pop("member_address")
        cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
        root = (tmp_path / name).resolve()
        home = root / ".aw"
        home.mkdir(parents=True, mode=0o700)
        (home / "team-certs").mkdir(mode=0o700)
        cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
        (home / cert_path).write_text(json.dumps(cert))
        (home / cert_path).chmod(0o600)
        member = {"team_id": TEAM, "alias": name, "cert_path": cert_path}
        (home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [member]}))
        (home / "workspace.yaml").write_text(json.dumps({"aweb_url": str(env.client.base_url),
            "memberships": [{**member, "workspace_id": str(actor.workspace)}]}))
        _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
        if stable:
            (home / "identity.yaml").write_text(json.dumps({"did": actor.did, "stable_id": stable,
                "address": address, "custody": "self", "identity_scope": scope}))
        child = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
        child.update(HOME=str(root), PWD=str(root), XDG_CONFIG_HOME=str(root / ".config"),
            AW_NO_UPDATE_CHECK="1", AWEB_URL=str(env.client.base_url), AWID_REGISTRY_URL=str(env.client.base_url))
        homes[name] = (root, child)
    binary = tmp_path / "aw"
    build = await asyncio.create_subprocess_exec("go", "build", "-o", str(binary), "./cmd/aw",
        cwd=Path(__file__).resolve().parents[2] / "cli/go", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    output, _ = await build.communicate()
    assert build.returncode == 0, output.decode()
    if kind == "mail":
        sent = await _cli(binary, *homes["alice"], "mail", "send", "--plaintext", "--to", "bob",
                          "--subject", "Explicit sender", "--body", "alias-form control", "--json")
        path = f"/v1/messages/{sent['message_id']}"
        read_args = ("mail", "show", "--message-id", sent["message_id"])
        table = "messages"
    else:
        sent = await _cli(binary, *homes["alice"], "chat", "send-and-leave", "--plaintext", "bob",
                          "alias-form control", "--json")
        path = f"/v1/chat/sessions/{sent['session_id']}/messages"
        read_args = ("chat", "history", "--session-id", sent["session_id"])
        table = "chat_messages"
    raw = await _request(env, "bob", "GET", path)
    assert raw.status_code == 200, raw.text
    data = raw.json()
    message = data["messages"][0] if "messages" in data else data
    stored = await env.db.fetch_one("SELECT from_address, signed_payload FROM {{tables." + table + "}} WHERE message_id=$1", UUID(message["message_id"]))
    assert (stored["from_address"] or "") == sender_address
    assert (message.get("from_address") or "") == sender_address
    signed = json.loads(stored["signed_payload"])
    assert signed["from"] == "alice"
    assert signed["from_stable_id"] == stable_id_from_did_key(env.actors["alice"].did)
    reader = await asyncio.create_subprocess_exec(str(binary), *read_args, "--json",
        cwd=homes["bob"][0], env=homes["bob"][1], stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    output, error = await asyncio.wait_for(reader.communicate(), 30)
    assert reader.returncode == 0, error.decode()
    shown = json.loads(output)
    assert (shown["messages"][0].get("from_address") or "") == sender_address, {
        "stored_address": stored["from_address"], "http_address": message.get("from_address"),
        "signed_from": signed["from"], "cli_address": shown["messages"][0].get("from_address"),
    }
