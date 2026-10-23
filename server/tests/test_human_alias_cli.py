"""Real selected-team CLI first contact to an addressless human; no saved route."""

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from aweb.e2ee_messages import decrypt_e2ee_message, generate_x25519_keypair
from awid.e2ee_keys import build_encryption_key_assertion
from test_cli_human_reply import _cli
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_e2ee_local_sender_read_trust import _local_sender_mail
from test_messages_http import _insert_agent_encryption_assertion


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("global_human", [True, False])
async def test_cli_first_contact_human_alias_with_signed_key(
    privacy_app, tmp_path, global_human  # noqa: F811
):
    env = privacy_app
    async with _local_sender_mail(
        env, tmp_path, False, False, False, human=global_human
    ) as (
        _,
        _,
        binary,
        cwd,
        child_env,
        _,
    ):
        # The shared lifecycle fixture provisioned real services/identities.
        # Remove its initial message/thread: this journey must discover the human
        # by the selected team's alias, with no stored continuation or address.
        await env.db.execute("DELETE FROM {{tables.conversations}}")
        await env.db.execute("DELETE FROM {{tables.messages}}")
        actor = env.actors["alice"]
        await env.db.execute(
            "UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1",
            actor.id,
        )
        private, public = generate_x25519_keypair()
        row = await env.db.fetch_one(
            "SELECT did_aw FROM {{tables.agents}} WHERE agent_id=$1", actor.id
        )
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk,
            identity_did=actor.did,
            identity_stable_id=row["did_aw"] or "",
            encryption_public_key=public,
            custody="hosted_custodial",
            now=datetime.now(UTC),
        )
        body_file = tmp_path / "first-contact.txt"
        body_file.write_text("First encrypted contact through team alias")
        # A stored roster identity alone is not an encryption assertion.
        refused = await asyncio.create_subprocess_exec(
            str(binary),
            "--team",
            TEAM,
            "mail",
            "send",
            "--to",
            "alice",
            "--e2ee",
            "--body-file",
            str(body_file),
            cwd=cwd,
            env=child_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(refused.communicate(), 30)
        assert refused.returncode != 0
        refused_chat = await asyncio.create_subprocess_exec(
            str(binary), "--team", TEAM, "chat", "send-and-leave", "alice",
            "--start-conversation", "--e2ee", "--body-file", str(body_file),
            cwd=cwd, env=child_env, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(refused_chat.communicate(), 30)
        assert refused_chat.returncode != 0
        assert (
            await env.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}")
        )["n"] == 0
        assert (
            await env.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}")
        )["n"] == 0
        assert (await env.db.fetch_one("SELECT count(*) AS n FROM {{tables.chat_messages}}"))["n"] == 0
        assert (await env.db.fetch_one("SELECT count(*) AS n FROM {{tables.chat_sessions}}"))["n"] == 0
        await _insert_agent_encryption_assertion(
            env.db, agent_id=actor.id, team_id=TEAM, assertion=assertion
        )
        sent = await _cli(
            binary,
            cwd,
            child_env,
            "--team",
            TEAM,
            "--json",
            "mail",
            "send",
            "--to",
            "alice",
            "--e2ee",
            "--body-file",
            str(body_file),
        )
        stored = await env.db.fetch_one(
            "SELECT * FROM {{tables.messages}} WHERE message_id=$1",
            UUID(sent["message_id"]),
        )
        assert stored["to_did"] == (row["did_aw"] or actor.did)
        assert stored["content_mode"] == "encrypted_v2"
        encrypted = (
            json.loads(stored["encrypted_envelope"])
            if isinstance(stored["encrypted_envelope"], str)
            else stored["encrypted_envelope"]
        )
        decrypted = decrypt_e2ee_message(
            encrypted,
            identity={
                "did": actor.did,
                "stable_id": row["did_aw"],
                "private_key": private,
                "encryption_key_id": assertion["encryption_key_id"],
            },
        )
        assert decrypted["body"] == body_file.read_text()

        chat_sent = await _cli(
            binary, cwd, child_env, "--team", TEAM, "--json", "chat",
            "send-and-leave", "alice", "--start-conversation", "--e2ee",
            "--body-file", str(body_file),
        )
        chat_stored = await env.db.fetch_one(
            "SELECT content_mode,encrypted_envelope FROM {{tables.chat_messages}} WHERE message_id=$1",
            UUID(chat_sent["message_id"]),
        )
        assert chat_stored["content_mode"] == "encrypted_v2"
        participants = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            UUID(chat_sent["session_id"]),
        )
        assert (row["did_aw"] or actor.did) in {p["did"] for p in participants}
        chat_envelope = chat_stored["encrypted_envelope"]
        if isinstance(chat_envelope, str):
            chat_envelope = json.loads(chat_envelope)
        assert decrypt_e2ee_message(chat_envelope, identity={
            "did": actor.did, "stable_id": row["did_aw"], "private_key": private,
            "encryption_key_id": assertion["encryption_key_id"],
        })["body"] == body_file.read_text()

        # The same actual TCP server now accepts the protected native envelope
        # through the public stable-ID headers and survives loss of preparations.
        from uuid import uuid4

        from aweb.e2ee_messages import encrypt_e2ee_mail
        from aweb.human_channels.contract import decode_record
        from aweb.human_channels.native import NativeMessagingService
        from awid.signing import canonical_json_bytes
        from test_human_channels_native_send import HostAuthority
        from test_messages_http import _signed_identity_headers

        await env.db.execute(
            "CREATE TABLE public.host_authority (actor_id UUID PRIMARY KEY,principal TEXT,signing_key TEXT,custody TEXT,active BOOLEAN,revision INTEGER,encryption_assertion JSONB)"
        )
        sender = env.actors["bob"]
        sender_private, sender_public = generate_x25519_keypair()
        sender_assertion = build_encryption_key_assertion(
            signing_key=sender.sk,
            identity_did=sender.did,
            identity_stable_id="",
            encryption_public_key=sender_public,
            custody="self",
            now=datetime.now(UTC),
        )
        for participant, principal, key, custody, proof in (
            (sender, sender.did, sender.did, "self_custodial", sender_assertion),
            (
                actor,
                row["did_aw"] or actor.did,
                actor.did,
                "hosted_custodial",
                assertion,
            ),
        ):
            await env.db.execute(
                "INSERT INTO public.host_authority VALUES ($1,$2,$3,$4,true,1,$5::jsonb)",
                participant.id,
                principal,
                key,
                custody,
                json.dumps(proof),
            )
        binding = decode_record(
            "ServiceBinding",
            canonical_json_bytes(
                {
                    "service": sender.did,
                    "signing_key_id": sender.did,
                    "audience": str(env.client.base_url).rstrip("/"),
                }
            ),
        )
        provider = HostAuthority(env.db, binding)
        service = NativeMessagingService(env.infra, authority=provider, service=binding)
        env.app.state.human_channels_service = service
        mid, cid = str(uuid4()), str(uuid4())
        envelope = encrypt_e2ee_mail(
            sender={
                "did": sender.did,
                "signing_key": sender.sk,
                "private_key": sender_private,
                "encryption_key": sender_assertion,
            },
            recipients=[
                {
                    "did": actor.did,
                    "stable_id": row["did_aw"],
                    "encryption_key": assertion,
                }
            ],
            subject="transaction",
            body="recover exactly once",
            message_id=mid,
            conversation_id=cid,
            created_at=datetime.now(UTC),
        )
        payload = {
            "to_alias": "alice",
            "conversation_id": cid,
            "message_id": mid,
            "content_mode": "encrypted_v2",
            "message_version": 2,
            "encrypted_envelope": envelope,
        }
        raw = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "X-AWEB-Ingress-Namespace": "journey",
            "X-AWEB-Ingress-Key": "input1",
            "X-AWEB-Ingress-Input-Hash": "sha256:" + "55" * 32,
            **_signed_identity_headers(sender.sk, sender.did, "", raw),
        }
        first = await env.client.post("/v1/messages", content=raw, headers=headers)
        assert first.status_code == 200, first.text
        env.app.state.human_channels_service = NativeMessagingService(
            env.infra, authority=provider, service=binding
        )
        again = await env.client.post("/v1/messages", content=raw, headers=headers)
        assert again.status_code == 200, again.text
        assert again.json() == first.json()
        assert (
            await env.db.fetch_one(
                "SELECT count(*) AS n FROM {{tables.messages}} WHERE message_id=$1",
                UUID(mid),
            )
        )["n"] == 1
        assert (
            await env.db.fetch_one(
                "SELECT count(*) AS n FROM {{tables.human_channel_mutations}}"
            )
        )["n"] == 1

        if global_human:
            # A current registry rotation defeats the stale local key projection.
            from test_messages_http import _make_keypair

            new_sk, _, new_did = _make_keypair()
            await env.app.state.awid_registry_client.rotate_key(
                row["did_aw"], new_did, actor.sk, new_sk
            )
            stale = await env.client.get(
                "/v1/messaging/participants/alice",
                headers=_signed_identity_headers(sender.sk, sender.did, "", b""),
            )
            assert stale.status_code == 409, stale.text
            assert stale.json()["detail"]["code"] == "stale"
