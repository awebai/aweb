"""Mail starts by recipient and continues only by an explicit conversation ID."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import UUID

import pytest
from awid.signing import canonical_json_bytes, sign_message
from aweb.messaging.conversations import create_conversation
from identity_binding_support import register_global_identity
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _pem
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_certificate


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_cli_can_start_mail_beside_an_empty_human_binding_conversation(privacy_app, tmp_path):
    env = privacy_app
    stable = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        address = f"example.test/{name}"
        stable[name] = await register_global_identity(env, actor, address)
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1,address=$2,identity_scope='global' WHERE agent_id=$3",
            stable[name], address, actor.id,
        )
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", env.actors["bob"].id)
    # A channel binding creates this empty pair before either participant sends.
    # Its routing DIDs and actor IDs are valid; both participant addresses are NULL.
    empty = await create_conversation(
        env.infra, conversation_type="mail", team_id=TEAM, created_by_did=stable["bob"],
        initiator={"did": stable["bob"], "agent_id": env.actors["bob"].id, "alias": "bob",
                   "current_did_key": env.actors["bob"].did, "transport_hint": "local"},
        recipients=[{"did": stable["alice"], "agent_id": env.actors["alice"].id, "alias": "alice",
                     "current_did_key": env.actors["alice"].did, "transport_hint": "local"}],
    )
    old_id = UUID(empty["conversation_id"])
    participants = await env.db.fetch_all(
        "SELECT agent_id,address,role FROM {{tables.conversation_participants}} WHERE conversation_id=$1", old_id,
    )
    assert {row["agent_id"] for row in participants} == {env.actors[name].id for name in ("alice", "bob")}
    assert all(row["address"] is None for row in participants)
    assert next(row["role"] for row in participants if row["agent_id"] == env.actors["bob"].id) == "initiator"
    for name in ("alice", "bob"):
        listed = await _request(env, name, "GET", "/v1/conversations?conversation_type=mail")
        assert listed.status_code == 200, listed.text
        assert listed.json()["conversations"] == []
        inbox = await _request(env, name, "GET", "/v1/messages/inbox?unread_only=false")
        assert inbox.status_code == 200, inbox.text
        assert inbox.json()["messages"] == []

    actor = env.actors["alice"]
    root = tmp_path / "alice"
    home = root / ".aw"
    home.mkdir(parents=True, mode=0o700)
    (home / "team-certs").mkdir(mode=0o700)
    cert = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM, alias="alice",
                             identity_scope="global", member_did_aw=stable["alice"],
                             member_address="example.test/alice")
    cert.pop("signature")
    cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / cert_path).write_text(json.dumps(cert))
    (home / cert_path).chmod(0o600)
    member = {"team_id": TEAM, "alias": "alice", "cert_path": cert_path}
    (home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [member]}))
    (home / "workspace.yaml").write_text(json.dumps({"aweb_url": str(env.client.base_url),
        "memberships": [{**member, "workspace_id": str(actor.workspace)}]}))
    (home / "identity.yaml").write_text(json.dumps({"did": actor.did, "stable_id": stable["alice"],
        "address": "example.test/alice", "custody": "self", "identity_scope": "global"}))
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    child = {key: value for key, value in os.environ.items() if not key.startswith(("AW", "XDG_"))}
    async with _registry_http(env.registry_app) as (registry_url, _):
        child.update(HOME=str(root), PWD=str(root), XDG_CONFIG_HOME=str(root / ".config"),
                     AW_NO_UPDATE_CHECK="1", AWEB_URL=str(env.client.base_url), AWID_REGISTRY_URL=registry_url)
        proc = await asyncio.create_subprocess_exec(
            str(Path(os.environ["AW_TEST_CLI_BINARY"])), "mail", "send", "--to", "bob",
            "--subject", "New thread", "--body", "An independent message", "--plaintext", "--json",
            cwd=root, env=child, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        output, error = await asyncio.wait_for(proc.communicate(), 30)
    assert proc.returncode == 0, {"stdout": output.decode(), "stderr": error.decode(), "empty_conversation": str(old_id)}
    sent = json.loads(output)
    row = await env.db.fetch_one(
        "SELECT conversation_id,to_did,signed_payload FROM {{tables.messages}} WHERE message_id=$1", UUID(sent["message_id"]),
    )
    assert row["conversation_id"] != old_id
    assert row["to_did"] == stable["bob"]
    assert json.loads(row["signed_payload"])["conversation_id"] == str(row["conversation_id"])
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}} WHERE conversation_id=$1", old_id) == 0
