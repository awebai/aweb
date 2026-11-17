"""A chat to a teammate's alias reaches that teammate.

An outside identity chooses its own address name. When other.org/bob has a
chat session with me, `aw chat send-and-leave bob` must still reach my
teammate bob, and never post into the outsider's session.

Real CLI, HTTP, signatures, AWID, PG, Redis and federation/DNS.
"""
import asyncio
import json
import os
from pathlib import Path

import pytest

from chat_pair_support import route_pair, _actor, _send, _signed_team_headers  # noqa: F401
from test_cli_human_reply import _cli, _pem


def _cli_home(tmp_path, actor):
    """The actor's identity home, written as the CLI writes it."""
    node = actor.node
    root = (tmp_path / actor.alias).resolve()
    home = root / ".aw"
    home.mkdir(parents=True, mode=0o700)
    (home / "team-certs").mkdir(mode=0o700)
    cert_path = "team-certs/" + node.team_id.replace("__", "____").replace(":", "__") + ".pem"
    (home / cert_path).write_text(json.dumps(actor.certificate))
    (home / cert_path).chmod(0o600)
    member = {"team_id": node.team_id, "alias": actor.alias, "cert_path": cert_path}
    (home / "teams.yaml").write_text(json.dumps({"active_team": node.team_id, "memberships": [member]}))
    (home / "workspace.yaml").write_text(json.dumps({
        "aweb_url": node.origin, "memberships": [{**member, "workspace_id": str(actor.workspace)}],
    }))
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    if actor.stable:
        (home / "identity.yaml").write_text(json.dumps({
            "did": actor.did, "stable_id": actor.stable, "address": actor.address,
            "custody": "self", "identity_scope": "global",
        }))
    child = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    child.update(HOME=str(root), PWD=str(root), XDG_CONFIG_HOME=str(root / ".config"),
                 AW_NO_UPDATE_CHECK="1", AWEB_URL=node.origin, AWID_REGISTRY_URL=node.registry_origin)
    return root, child


async def _session_of(node, message_id):
    return await node.db.fetch_value(
        "SELECT session_id FROM {{tables.chat_messages}} WHERE message_id=$1", message_id,
    )


async def _participants(node, session_id):
    rows = await node.db.fetch_all(
        "SELECT did, address FROM {{tables.chat_participants}} WHERE session_id=$1", session_id,
    )
    return {row["did"] for row in rows}, {row["address"] for row in rows if row["address"]}


async def _read_as(actor, session_id):
    response = await actor.node.client.get(
        f"/v1/chat/sessions/{session_id}/messages",
        headers=_signed_team_headers(actor.sk, actor.did, actor.node.team_id, actor.encoded_certificate, b""),
    )
    assert response.status_code == 200, response.text
    return [message["body"] for message in response.json()["messages"]]


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("earlier_teammate_session", [False, True], ids=["first-contact", "continuing"])
async def test_chat_to_a_teammate_alias_never_reaches_an_outsider_with_that_name(
    route_pair, tmp_path, earlier_teammate_session,
):
    pair = route_pair
    me = pair.target.global_actor
    teammate = await _actor(pair.target, "bob", global_identity=False)
    outsider = await _actor(pair.source, "bob", global_identity=True)
    root, env = _cli_home(tmp_path, me)
    binary = Path(os.environ["AW_TEST_CLI_BINARY"])

    teammate_session = None
    if earlier_teammate_session:
        earlier = await _cli(binary, root, env, "chat", "send-and-leave", "--plaintext", "--start-conversation",
                             "bob", "earlier, to my teammate", "--json")
        teammate_session = earlier["session_id"]

    # The outsider, whose address name is bob, opens a chat with me.
    opened, first_contact = await _send(outsider, me, "chat")
    assert opened.status_code == 200, opened.text
    outsider_session = await _session_of(pair.target, first_contact.mid)
    assert outsider_session is not None
    federated_before = pair.source.calls.count(("POST", "/v1/federation/messages"))

    sent = await _cli(binary, root, env, "chat", "send-and-leave", "--plaintext",
                      "bob", "for my teammate", "--json")

    session = await _session_of(pair.target, sent["message_id"])
    assert str(session) != str(outsider_session), "the send went into the outsider's session"
    dids, addresses = await _participants(pair.target, session)
    assert teammate.did in dids, (dids, addresses)
    assert outsider.did not in dids and outsider.stable not in dids, (dids, addresses)
    assert outsider.address not in addresses, (dids, addresses)
    assert "for my teammate" in await _read_as(teammate, session)
    if teammate_session is not None:
        assert str(session) == teammate_session, "the send did not continue the session with my teammate"
    assert pair.source.calls.count(("POST", "/v1/federation/messages")) == federated_before, (
        "the send reached the outsider's server"
    )


async def _cli_result(binary, cwd, env, *args):
    process = await asyncio.create_subprocess_exec(
        str(binary), *args, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await asyncio.wait_for(process.communicate(), 30)
    return process.returncode, output.decode()


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("earlier_teammate_session", [False, True], ids=["no-teammate-session", "teammate-session"])
async def test_extend_wait_to_a_teammate_alias_never_posts_into_an_outsiders_session(
    route_pair, tmp_path, earlier_teammate_session,
):
    pair = route_pair
    me = pair.target.global_actor
    await _actor(pair.target, "bob", global_identity=False)
    outsider = await _actor(pair.source, "bob", global_identity=True)
    root, env = _cli_home(tmp_path, me)
    binary = Path(os.environ["AW_TEST_CLI_BINARY"])

    teammate_session = None
    if earlier_teammate_session:
        earlier = await _cli(binary, root, env, "chat", "send-and-leave", "--plaintext", "--start-conversation",
                             "bob", "earlier, to my teammate", "--json")
        teammate_session = earlier["session_id"]
    opened, first_contact = await _send(outsider, me, "chat")
    assert opened.status_code == 200, opened.text
    outsider_session = await _session_of(pair.target, first_contact.mid)
    federated_before = pair.source.calls.count(("POST", "/v1/federation/messages"))
    messages_before = await pair.target.db.fetch_value(
        "SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1", outsider_session,
    )

    code, output = await _cli_result(binary, root, env, "chat", "extend-wait", "--plaintext", "bob", "one more minute", "--json")

    assert await pair.target.db.fetch_value(
        "SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1", outsider_session,
    ) == messages_before, "extend-wait posted into the outsider's session"
    assert pair.source.calls.count(("POST", "/v1/federation/messages")) == federated_before
    if earlier_teammate_session:
        assert code == 0, output
        assert json.loads(output)["session_id"] == teammate_session
    else:
        assert code != 0, output
        assert "no conversation found" in output, output
