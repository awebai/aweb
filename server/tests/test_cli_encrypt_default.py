"""The aw setting that encrypts mail and chat by default, through the real binary and server.

Order of choice: a mode flag, then an encrypted source, then the setting when
the recipient has a published key, then plaintext.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from aweb.e2ee_messages import decrypt_e2ee_message
from test_addressless_sender_cli import _registry_http
from test_cli_chat_mode import ENCRYPTED_NOTICE, PLAINTEXT_NOTICE, _cli_identities, _cli_output, _publish_encryption_key
from test_cli_human_reply import _cli, _cli_identity_home, _reply_context
from test_dashboard_privacy import _request, privacy_app  # noqa: F401

SETTING = "messaging.encrypt_by_default"
NO_KEY_NOTICE = "the recipient has no published encryption key"


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, True)])
async def test_cli_encrypt_by_default_setting(privacy_app, tmp_path, global_resident, grant):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = await _cli_identities(env, global_resident, now)
    agent, peer = identities["bob"], identities["carol"]
    # carol has a published key; alice has none.
    await _publish_encryption_key(env, "carol", peer["encryption_key"])

    def carol_reads(envelope):
        return decrypt_e2ee_message(envelope, {
            **peer, "encryption_key_id": peer["encryption_key"]["encryption_key_id"],
        })

    async def carol_mail(message_id):
        read = await _request(env, "carol", "GET", f"/v1/messages/{message_id}")
        assert read.status_code == 200, read.text
        return read.json()

    async def latest_chat(reader, session_id):
        read = await _request(env, reader, "GET", f"/v1/chat/sessions/{session_id}/messages")
        assert read.status_code == 200, read.text
        return read.json()["messages"][-1]

    count_mail = "SELECT count(*) FROM {{tables.messages}}"
    binary, child_env = await _cli_identity_home(env, tmp_path, agent, global_resident, now)
    body_file = tmp_path / "body.txt"
    body_file.write_text("Body")
    async with _registry_http(env.registry_app) as (registry_url, _):
        child_env["AWID_REGISTRY_URL"] = registry_url

        # Off by default: today's behaviour.
        unset = await _cli(binary, tmp_path, child_env, "settings", "get", SETTING, "--json")
        assert unset == {"key": SETTING, "value": False, "source": "default"}
        sent = await _cli(binary, tmp_path, child_env, "mail", "send", "--to", "carol",
                          "--new-conversation", "--body-file", str(body_file), "--json")
        assert sent["content_mode"] == "legacy_plaintext_v1"

        # The identity turns it on; a grant minted afterwards carries it.
        code, output = await _cli_output(binary, tmp_path, child_env, "settings", "set", SETTING, "true")
        assert code == 0, output
        assert (tmp_path / ".aw" / "settings.yaml").exists()
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            shown = await _cli(binary, command_dir, command_env, "settings", "get", SETTING, "--json")
            assert shown == {"key": SETTING, "value": True, "source": "grant" if grant else "settings"}
            doctor = await _cli(binary, command_dir, command_env, "doctor", "--offline", "--json")
            [check] = [c for c in doctor["checks"] if c["id"] == "messaging.local.encrypt_by_default"]
            assert check["detail"]["value"] is True, check
            if grant:
                # A seat takes the setting at mint; changing it means a new grant.
                code, output = await _cli_output(binary, command_dir, command_env, "settings", "set", SETTING, "false")
                assert code != 0, output
                assert "mint a new grant" in output, output

            # New mail to a recipient with a key: encrypted.
            body_file.write_text("Default mail to carol")
            sent = await _cli(binary, command_dir, command_env, "mail", "send", "--to", "carol",
                              "--new-conversation", "--body-file", str(body_file), "--json")
            assert sent["content_mode"] == "encrypted_v2"
            delivered = await carol_mail(sent["message_id"])
            assert delivered["content_mode"] == "encrypted_v2"
            assert carol_reads(delivered["encrypted_envelope"])["body"] == "Default mail to carol"

            # Reply to a plaintext mail, recipient with a key: upgraded.
            plain_in = await _request(env, "carol", "POST", "/v1/messages", {
                "to_did": agent["did"], "subject": "Plain question", "body": "Plain question body",
            })
            assert plain_in.status_code == 200, plain_in.text
            body_file.write_text("Upgraded mail reply")
            code, output = await _cli_output(binary, command_dir, command_env, "mail", "reply",
                                             plain_in.json()["message_id"], "--body-file", str(body_file))
            assert code == 0, output
            assert ENCRYPTED_NOTICE in output, output

            # New mail to a recipient without a key: plaintext, and says why.
            body_file.write_text("Default mail to alice")
            code, output = await _cli_output(binary, command_dir, command_env, "mail", "send", "--to", "alice",
                                             "--new-conversation", "--body-file", str(body_file))
            assert code == 0, output
            assert PLAINTEXT_NOTICE in output and NO_KEY_NOTICE in output, output

            # An explicit --plaintext wins over the setting.
            explicit = await _cli(binary, command_dir, command_env, "mail", "send", "--to", "carol", "--plaintext",
                                  "--new-conversation", "--body-file", str(body_file), "--json")
            assert explicit["content_mode"] == "legacy_plaintext_v1"

            # Reply into a plaintext chat, recipient with a key: upgraded.
            opened = await _request(env, "carol", "POST", "/v1/chat/sessions", {
                "to_dids": [agent["did"]], "message": "Plain chat opening",
            })
            assert opened.status_code == 200, opened.text
            body_file.write_text("Explicit encrypted chat reply")
            explicit_chat = await _cli(binary, command_dir, command_env, "chat", "send", "--session-id",
                                       opened.json()["session_id"], "--e2ee", "--body", "Explicit encrypted chat reply", "--json")
            assert explicit_chat["content_mode"] == "encrypted_v2"
            # carol answers in plaintext, so the chat's latest message is plaintext again.
            again = await _request(env, "carol", "POST", f"/v1/chat/sessions/{opened.json()['session_id']}/messages",
                                   {"body": "Plain chat follow-up"})
            assert again.status_code == 200, again.text
            body_file.write_text("Upgraded chat reply")
            replied = await _cli(binary, command_dir, command_env, "chat", "send-and-leave", "carol",
                                 "--body-file", str(body_file), "--json")
            assert replied["session_id"] == opened.json()["session_id"]
            assert replied["content_mode"] == "encrypted_v2"
            latest = await latest_chat("carol", replied["session_id"])
            assert latest["content_mode"] == "encrypted_v2"
            assert carol_reads(latest["encrypted_envelope"])["body"] == "Upgraded chat reply"

            # New chat to a recipient without a key: plaintext, and says why.
            body_file.write_text("Default chat to alice")
            code, output = await _cli_output(binary, command_dir, command_env, "chat", "send-and-leave", "alice",
                                             "--body-file", str(body_file))
            assert code == 0, output
            assert PLAINTEXT_NOTICE in output and NO_KEY_NOTICE in output, output

            # A published key that fails verification fails closed: nothing is sent.
            before = await env.db.fetch_value(count_mail)
            original = await env.db.fetch_value(
                "SELECT assertion_signature FROM {{tables.agent_encryption_keys}} WHERE agent_id = $1",
                env.actors["carol"].id,
            )
            await env.db.execute("UPDATE {{tables.agent_encryption_keys}} SET assertion_signature = $1 WHERE agent_id = $2",
                                 "A" * len(original), env.actors["carol"].id)
            body_file.write_text("Must not be sent")
            code, output = await _cli_output(binary, command_dir, command_env, "mail", "send", "--to", "carol",
                                             "--new-conversation", "--body-file", str(body_file))
            await env.db.execute("UPDATE {{tables.agent_encryption_keys}} SET assertion_signature = $1 WHERE agent_id = $2",
                                 original, env.actors["carol"].id)
            assert code != 0, output
            assert await env.db.fetch_value(count_mail) == before
