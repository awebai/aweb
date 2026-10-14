"""Encrypted mail and chat from the aw CLI to a team-local peer, through the real binary and server.

A local (did:key) peer publishes its encryption key on the team roster; AWID
does not know it.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from aweb.e2ee_messages import decrypt_e2ee_message
from test_addressless_sender_cli import _registry_http
from test_cli_chat_mode import ENCRYPTED_NOTICE, _cli_identities, _cli_output, _publish_encryption_key
from test_cli_human_reply import _cli, _cli_identity_home, _reply_context
from test_dashboard_privacy import _request, privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, True)])
async def test_cli_encrypts_to_a_local_peer_by_its_roster_key(privacy_app, tmp_path, global_resident, grant):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = await _cli_identities(env, global_resident, now)
    agent, peer = identities["bob"], identities["carol"]
    await _publish_encryption_key(env, "carol", peer["encryption_key"])

    def carol_reads(envelope):
        return decrypt_e2ee_message(envelope, {
            **peer, "encryption_key_id": peer["encryption_key"]["encryption_key_id"],
        })

    binary, child_env = await _cli_identity_home(env, tmp_path, agent, global_resident, now)
    body_file = tmp_path / "body.txt"
    async with _registry_http(env.registry_app) as (registry_url, _):
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            # No key for carol has been learned or pinned before these sends.
            plain_in = await _request(env, "carol", "POST", "/v1/messages", {
                "to_did": agent["did"], "subject": "Plain question", "body": "Plain question body",
            })
            assert plain_in.status_code == 200, plain_in.text
            body_file.write_text("Encrypted mail reply")
            code, output = await _cli_output(binary, command_dir, command_env, "mail", "reply",
                                             plain_in.json()["message_id"], "--e2ee", "--body-file", str(body_file))
            assert code == 0, output
            assert ENCRYPTED_NOTICE in output, output
            conversation = await _request(env, "carol", "GET",
                                          f"/v1/messages/conversations/{plain_in.json()['conversation_id']}")
            assert conversation.status_code == 200, conversation.text
            latest = conversation.json()["messages"][-1]
            assert latest["content_mode"] == "encrypted_v2"
            assert carol_reads(latest["encrypted_envelope"])["body"] == "Encrypted mail reply"

            opened = await _request(env, "carol", "POST", "/v1/chat/sessions", {
                "to_dids": [agent["did"]], "message": "Plain chat opening",
            })
            assert opened.status_code == 200, opened.text
            session_id = opened.json()["session_id"]
            sent = await _cli(binary, command_dir, command_env, "chat", "send", "--session-id", session_id,
                              "--e2ee", "--body", "Encrypted chat reply", "--json")
            assert sent["content_mode"] == "encrypted_v2"
            history = await _request(env, "carol", "GET", f"/v1/chat/sessions/{session_id}/messages")
            assert history.status_code == 200, history.text
            latest = history.json()["messages"][-1]
            assert latest["content_mode"] == "encrypted_v2"
            assert carol_reads(latest["encrypted_envelope"])["body"] == "Encrypted chat reply"


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, True)])
async def test_cli_mail_reply_reaches_the_peer_in_a_conversation_it_began(privacy_app, tmp_path, global_resident, grant):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = await _cli_identities(env, global_resident, now)
    agent = identities["bob"]
    binary, child_env = await _cli_identity_home(env, tmp_path, agent, global_resident, now)
    body_file = tmp_path / "body.txt"
    async with _registry_http(env.registry_app) as (registry_url, _):
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            body_file.write_text("Opening from bob")
            opening = await _cli(binary, command_dir, command_env, "mail", "send", "--to", "carol", "--plaintext",
                                 "--new-conversation", "--body-file", str(body_file), "--json")
            answer = await _request(env, "carol", "POST", "/v1/messages", {
                "to_did": agent["stable_id"] or agent["did"], "subject": "Answer", "body": "Answer from carol",
                "conversation_id": opening["conversation_id"],
            })
            assert answer.status_code == 200, answer.text
            assert answer.json()["conversation_id"] == opening["conversation_id"]
            body_file.write_text("Reply from bob")
            replied = await _cli(binary, command_dir, command_env, "mail", "reply", answer.json()["message_id"],
                                 "--plaintext", "--body-file", str(body_file), "--json")
            delivered = await _request(env, "carol", "GET", f"/v1/messages/{replied['message_id']}")
            assert delivered.status_code == 200, delivered.text
            assert delivered.json()["body"] == "Reply from bob"


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, True)])
async def test_cli_encrypted_reply_reaches_the_peer_in_a_conversation_it_began(privacy_app, tmp_path, global_resident, grant):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = await _cli_identities(env, global_resident, now)
    agent, peer = identities["bob"], identities["carol"]
    await _publish_encryption_key(env, "carol", peer["encryption_key"])
    binary, child_env = await _cli_identity_home(env, tmp_path, agent, global_resident, now)
    body_file = tmp_path / "body.txt"
    async with _registry_http(env.registry_app) as (registry_url, _):
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            # bob begins the conversation in plaintext, addressing carol by alias.
            body_file.write_text("Opening from bob")
            opening = await _cli(binary, command_dir, command_env, "mail", "send", "--to", "carol", "--plaintext",
                                 "--new-conversation", "--body-file", str(body_file), "--json")
            answer = await _request(env, "carol", "POST", "/v1/messages", {
                "to_did": agent["stable_id"] or agent["did"], "subject": "Answer", "body": "Answer from carol",
                "conversation_id": opening["conversation_id"],
            })
            assert answer.status_code == 200, answer.text
            body_file.write_text("Encrypted reply from bob")
            replied = await _cli(binary, command_dir, command_env, "mail", "reply", answer.json()["message_id"],
                                 "--e2ee", "--body-file", str(body_file), "--json")
            assert replied["content_mode"] == "encrypted_v2"
            delivered = await _request(env, "carol", "GET", f"/v1/messages/{replied['message_id']}")
            assert delivered.status_code == 200, delivered.text
            plain = decrypt_e2ee_message(delivered.json()["encrypted_envelope"], {
                **peer, "encryption_key_id": peer["encryption_key"]["encryption_key_id"],
            })
            assert plain["body"] == "Encrypted reply from bob"
