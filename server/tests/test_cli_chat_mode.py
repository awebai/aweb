"""The aw CLI's chat and mail content mode, through the real binary and server.

A reply into an encrypted chat stays encrypted without a mode flag and fails
closed when it cannot encrypt; every send reports the mode it used.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest
from awid.did import stable_id_from_did_key
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import decrypt_e2ee_message, encrypt_e2ee_chat, generate_x25519_keypair
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli, _cli_identity_home, _reply_context
from test_messages_http import _signed_team_headers
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401

PLAINTEXT_NOTICE = "Sent as server-readable plaintext"
ENCRYPTED_NOTICE = "Sent encrypted (encrypted_v2)"


async def _cli_output(binary, cwd, env, *args):
    proc = await asyncio.create_subprocess_exec(str(binary), *args, cwd=cwd, env=env,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    output, _ = await asyncio.wait_for(proc.communicate(), 30)
    return proc.returncode, output.decode()


async def _publish_encryption_key(env, name, assertion):
    actor = env.actors[name]
    body = json.dumps(assertion).encode()
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
    headers["Content-Type"] = "application/json"
    published = await env.client.put("/v1/agents/me/encryption-key", content=body, headers=headers)
    assert published.status_code == 200, published.text


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, True)])
async def test_cli_chat_reply_follows_session_mode(privacy_app, tmp_path, global_resident, grant):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = {}
    for name, custody in (("alice", "hosted_custodial"), ("bob", "self"), ("carol", "self")):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        address = "example.test/bob" if global_resident and name == "bob" else ""
        stable_id = stable_id_from_did_key(actor.did) if address else ""
        if address:
            await env.db.execute("UPDATE {{tables.agents}} SET identity_scope = 'global', did_aw = $1, address = $2 WHERE agent_id = $3",
                                 stable_id, address, actor.id)
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk, identity_did=actor.did, identity_stable_id=stable_id,
            encryption_public_key=public, custody=custody, now=now,
        )
        identities[name] = dict(address=address, did=actor.did, stable_id=stable_id, team_id=TEAM,
                                signing_key=actor.sk, private_key=private, encryption_key=assertion)
    hosted, agent, peer = identities["alice"], identities["bob"], identities["carol"]
    await _publish_encryption_key(env, "alice", hosted["encryption_key"])
    await _publish_encryption_key(env, "carol", peer["encryption_key"])
    await env.app.state.awid_registry_client.register_did(hosted["did"], hosted["signing_key"])

    # The hosted agent opens the chat encrypted, as hosted custodial sends do.
    chat_id, opening_id = str(uuid4()), str(uuid4())
    opening = encrypt_e2ee_chat(sender=hosted, recipients=[agent], body="Hosted opening",
                                message_id=opening_id, conversation_id=chat_id, created_at=now)
    opened = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_dids": [agent["did"]], "session_id": chat_id, "message": "",
        "message_id": opening_id, "timestamp": opening["created_at"],
        "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": opening,
    })
    assert opened.status_code == 200, opened.text

    async def stored_messages():
        response = await _request(env, "alice", "GET", f"/v1/chat/sessions/{chat_id}/messages")
        assert response.status_code == 200, response.text
        return response.json()["messages"]

    async def assert_latest_encrypted_to_hosted(text):
        latest = (await stored_messages())[-1]
        assert latest["content_mode"] == "encrypted_v2", latest
        assert text not in json.dumps(latest)
        plain = decrypt_e2ee_message(latest["encrypted_envelope"], {
            **hosted, "encryption_key_id": hosted["encryption_key"]["encryption_key_id"],
        })
        assert plain["body"] == text

    binary, child_env = await _cli_identity_home(env, tmp_path, agent, global_resident, now)
    body_file = tmp_path / "chat.txt"
    async with _registry_http(env.registry_app) as (registry_url, _):
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            # Control: the seat can encrypt to the hosted agent when asked.
            body_file.write_text("Explicit encrypted reply")
            explicit = await _cli(binary, command_dir, command_env, "chat", "send-and-leave", "alice",
                                  "--e2ee", "--body-file", str(body_file), "--json")
            assert explicit["session_id"] == chat_id
            await assert_latest_encrypted_to_hosted("Explicit encrypted reply")
            assert explicit["content_mode"] == "encrypted_v2"

            # No mode flag: every chat reply path follows the encrypted session.
            body_file.write_text("Default reply and leave")
            left = await _cli(binary, command_dir, command_env, "chat", "send-and-leave", "alice",
                              "--body-file", str(body_file), "--json")
            assert left["session_id"] == chat_id
            await assert_latest_encrypted_to_hosted("Default reply and leave")
            assert left["content_mode"] == "encrypted_v2"

            body_file.write_text("Default reply and wait")
            code, output = await _cli_output(binary, command_dir, command_env, "chat", "send-and-wait", "alice",
                                             "--wait", "0", "--body-file", str(body_file))
            assert code == 0, output
            await assert_latest_encrypted_to_hosted("Default reply and wait")
            assert ENCRYPTED_NOTICE in output, output

            body_file.write_text("Default extend wait")
            extended = await _cli(binary, command_dir, command_env, "chat", "extend-wait", "alice",
                                  "--body-file", str(body_file), "--json")
            await assert_latest_encrypted_to_hosted("Default extend wait")
            assert extended["content_mode"] == "encrypted_v2"

            code, output = await _cli_output(binary, command_dir, command_env, "chat", "send", "--session-id", chat_id,
                                             "--body", "Default exact session send")
            assert code == 0, output
            await assert_latest_encrypted_to_hosted("Default exact session send")
            assert ENCRYPTED_NOTICE in output, output

            count_chat = "SELECT count(*) FROM {{tables.chat_messages}}"
            if grant:
                # Fail closed: a grant seat with no custody socket cannot encrypt,
                # so its default reply into the encrypted session errors instead of
                # falling back to plaintext there or in a new chat.
                keyless = tmp_path / "keyless"
                keyless.mkdir()
                await _cli(binary, tmp_path, child_env, "id", "grant", "mint", "--bundle", "normal-agent",
                           "--ttl", "5m", "--out", str(keyless / ".aw"), "--json")
                keyless_env = dict(child_env, AWEB_IDENTITY_HOME=str(keyless / ".aw"))
                before = await env.db.fetch_value(count_chat)
                body_file.write_text("Must not be sent")
                code, output = await _cli_output(binary, keyless, keyless_env, "chat", "send-and-leave", "alice",
                                                 "--body-file", str(body_file))
                assert code != 0, output
                assert "the latest message in this chat is encrypted" in output, output
                assert await env.db.fetch_value(count_chat) == before

            # A failed chat lookup must not turn the encrypted chat into a new
            # plaintext one. Hiding the read-receipt table fails /v1/chat/pending
            # while starting a chat still works.
            reads = await env.db.fetch_value("SELECT to_regclass('{{tables.chat_message_reads}}')::text")
            schema = reads.rsplit(".", 1)[0]
            before = await env.db.fetch_value(count_chat)
            await env.db.execute(f"ALTER TABLE {reads} RENAME TO chat_message_reads_hidden")
            try:
                body_file.write_text("Must not be sent either")
                code, output = await _cli_output(binary, command_dir, command_env, "chat", "send-and-leave", "alice",
                                                 "--body-file", str(body_file))
            finally:
                await env.db.execute(f"ALTER TABLE {schema}.chat_message_reads_hidden RENAME TO chat_message_reads")
            assert code != 0, output
            assert "pending" in output, output
            assert await env.db.fetch_value(count_chat) == before

            # An explicit --plaintext still wins, and says so.
            code, output = await _cli_output(binary, command_dir, command_env, "chat", "send", "--session-id", chat_id,
                                             "--plaintext", "--body", "Explicit plaintext")
            assert code == 0, output
            assert PLAINTEXT_NOTICE in output, output
            latest = (await stored_messages())[-1]
            assert latest["content_mode"] == "legacy_plaintext_v1"
            assert latest["body"] == "Explicit plaintext"

            # A plaintext session stays plaintext without a flag, and says so.
            body_file.write_text("Plain opening")
            plain_first = await _cli(binary, command_dir, command_env, "chat", "send-and-leave", "carol",
                                     "--body-file", str(body_file), "--json")
            assert plain_first["content_mode"] == "legacy_plaintext_v1"
            body_file.write_text("Plain follow-up")
            code, output = await _cli_output(binary, command_dir, command_env, "chat", "send-and-leave", "carol",
                                             "--body-file", str(body_file))
            assert code == 0, output
            assert PLAINTEXT_NOTICE in output, output
            carol_read = await _request(env, "carol", "GET", f"/v1/chat/sessions/{plain_first['session_id']}/messages")
            assert carol_read.status_code == 200, carol_read.text
            assert [m["content_mode"] for m in carol_read.json()["messages"]] == ["legacy_plaintext_v1"] * 2

            # Mail sends report their mode too.
            body_file.write_text("Mail body")
            code, output = await _cli_output(binary, command_dir, command_env, "mail", "send", "--to", "carol",
                                             "--body-file", str(body_file))
            assert code == 0, output
            assert PLAINTEXT_NOTICE in output, output
            encrypted_mail = await _cli(binary, command_dir, command_env, "mail", "send", "--to", "carol", "--e2ee",
                                        "--new-conversation", "--body-file", str(body_file), "--json")
            assert encrypted_mail["content_mode"] == "encrypted_v2"
