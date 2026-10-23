"""Strict contact policy through real HTTP aweb/AWID, Postgres, Redis and CLI.

Only fixture provisioning uses SQL; authentication, policy, delivery, reads and
contact removal execute the real application. No identity or transport mocks.
"""
from __future__ import annotations

import asyncio
import json
import os
from uuid import UUID

import pytest

from identity_binding_support import register_global_identity
from test_cli_human_reply import _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_certificate, _encode_certificate, _signed_team_headers


@pytest.mark.asyncio
@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.parametrize("mode,outside,multiple", [
    ("contacts_only", False, ""), ("contacts_only", True, ""),
    ("contacts_only", False, "initial"), ("contacts_only", True, "initial"),
    ("team_and_contacts", True, "initial"),
    ("contacts_only", True, "after_removal"), ("team_and_contacts", True, "after_removal"),
])
async def test_contacts_only_real_delivery(privacy_app, tmp_path, mode, outside, multiple):
    env = privacy_app
    sender, recipient = env.actors["alice"], env.actors["bob"]
    sender_team = "outside:example.test" if outside else TEAM
    if outside:
        await env.db.execute("""
            INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
            VALUES ($1, 'example.test', 'outside', $2)
        """, sender_team, env.team_did)
        await env.registry_db.execute("""
            INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility)
            VALUES ('example.test', 'outside', $1, 'public')
        """, env.team_did)
        await env.db.execute("UPDATE {{tables.agents}} SET team_id=$1 WHERE agent_id=$2", sender_team, sender.id)
        await env.db.execute("UPDATE {{tables.workspaces}} SET team_id=$1 WHERE workspace_id=$2", sender_team, sender.workspace)

    async with registry_listener(env) as (_registry, registry_origin):
        identities = {}
        for name, actor, team in (("alice", sender, sender_team), ("bob", recipient, TEAM)):
            address = f"example.test/{name}"
            stable_id = await register_global_identity(env, actor, address)
            identities[name] = stable_id
            await env.db.execute("""
                UPDATE {{tables.agents}} SET identity_scope='global', did_aw=$1, address=$2
                WHERE agent_id=$3
            """, stable_id, address, actor.id)
            certificate = _make_certificate(
                env.team_sk, env.team_did, actor.did, team_id=team, alias=name,
                identity_scope="global", member_did_aw=stable_id, member_address=address,
                certificate_id=f"strict-{name}",
            )
            actor.certificate = _encode_certificate(certificate)
            if name == "bob":
                home = tmp_path / ".aw"
                home.mkdir(mode=0o700)
                _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
                (home / "identity.yaml").write_text(json.dumps(dict(
                    did=actor.did, stable_id=stable_id, address=address, custody="self", identity_scope="global",
                )))
                (home / "certificate.json").write_text(json.dumps(certificate))
                membership = dict(team_id=TEAM, alias=name, cert_path="certificate.json")
                (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
                (home / "workspace.yaml").write_text(json.dumps(dict(
                    aweb_url=str(env.client.base_url), memberships=[dict(membership, workspace_id=str(actor.workspace))],
                )))

        child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
        child_env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"),
                         AWID_REGISTRY_URL=registry_origin, AW_NO_UPDATE_CHECK="1")
        command = await asyncio.create_subprocess_exec(
            os.environ["AW_TEST_CLI_BINARY"], "--identity-home", str(home),
            "inbound-mode", mode.replace("_", "-"), "--json", cwd=tmp_path, env=child_env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        output, error = await asyncio.wait_for(command.communicate(), 30)
        assert command.returncode == 0, error.decode()
        assert json.loads(output)["inbound_mode"] == mode
        assert json.loads(output)["label"] == {"contacts_only": "Contacts only", "team_and_contacts": "Team and contacts"}[mode]

        async def add_membership(name):
            team = f"{name}:example.test"
            await env.db.execute("""
                INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
                VALUES ($1, 'example.test', $2, $3)
            """, team, name, env.team_did)
            await env.db.execute("""
                INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, address, identity_scope, inbound_mode, did_aw_verified_key)
                VALUES ($1, $2, $3, $4, 'example.test/bob', 'global', 'open', $3)
            """, team, name, recipient.did, identities["bob"])

        if multiple == "initial":
            await add_membership("second")

        async def request(actor, team, method, path, payload=None):
            body = json.dumps(payload).encode() if payload is not None else b""
            headers = _signed_team_headers(actor.sk, actor.did, team, actor.certificate, body)
            return await env.client.request(method, path, content=body, headers={**headers, "Content-Type": "application/json"})

        async def send_both(expected):
            mail = await request(sender, sender_team, "POST", "/v1/messages", {
                "to_did": recipient.did, "subject": "Strict policy", "body": "contact test",
            })
            chat = await request(sender, sender_team, "POST", "/v1/chat/sessions", {
                "to_dids": [recipient.did], "message": "contact test",
            })
            assert (mail.status_code, chat.status_code) == (expected, expected), (mail.text, chat.text)
            for response in (mail, chat):
                if expected == 403:
                    assert "exact active contacts" in response.text
            return mail, chat

        await send_both(403)
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_sessions}}") == 0
        # An active identity-bound contact is fixture authority, not a domain,
        # address-only legacy binding, pending row, or team membership.
        row = await env.db.fetch_one("""
            INSERT INTO {{tables.contacts}} (
                owner_did, contact_address, contact_did_aw, binding_controller_did, binding_accepted_at, status
            ) VALUES ($1, 'example.test/alice', $2, $3, clock_timestamp(), 'pending')
            RETURNING contact_id
        """, identities["bob"], identities["alice"], env.team_did)
        await send_both(403)
        await env.db.execute("UPDATE {{tables.contacts}} SET status='active' WHERE contact_id=$1", row["contact_id"])
        mail, chat = await send_both(200)
        mail_id, session_id = mail.json()["message_id"], chat.json()["session_id"]
        delivered = await request(recipient, TEAM, "GET", f"/v1/messages/{mail_id}")
        assert delivered.status_code == 200, delivered.text
        assert delivered.json()["body"] == "contact test"
        # Removal through the recipient's real signed API revokes future sends,
        # including already established chat routes.
        removed = await request(recipient, TEAM, "DELETE", f"/v1/contacts/{row['contact_id']}")
        assert removed.status_code in (200, 204), removed.text
        await send_both(403)
        if multiple:
            await add_membership("third")
        continuation = await request(sender, sender_team, "POST", f"/v1/chat/sessions/{session_id}/messages", {"body": "after removal"})
        mail_continuation = await request(sender, sender_team, "POST", "/v1/messages", {
            "conversation_id": mail.json()["conversation_id"], "subject": "after removal", "body": "after removal",
        })
        assert (continuation.status_code, mail_continuation.status_code) == (403, 403), (continuation.text, mail_continuation.text)
        assert "exact active contacts" in continuation.text
        assert "exact active contacts" in mail_continuation.text
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id=$1", UUID(mail_id)) == 1
        if not outside:
            neighbor = await request(recipient, TEAM, "PATCH", "/v1/agents/me/inbound-mode", {"inbound_mode": "team_and_contacts"})
            assert neighbor.status_code == 200, neighbor.text
            await send_both(200)

        if multiple:
            unified = await request(recipient, TEAM, "PATCH", "/v1/agents/me/inbound-mode", {"inbound_mode": mode})
            assert unified.status_code == 200, unified.text
            modes = await env.db.fetch_all("SELECT inbound_mode FROM {{tables.agents}} WHERE did_aw=$1 AND deleted_at IS NULL", identities["bob"])
            assert len(modes) == (3 if multiple == "initial" else 2)
            assert all(row["inbound_mode"] == mode for row in modes)
            # A fresh signed connect joins another team AFTER the mode is set.
            # The production membership INSERT must inherit policy, not open it.
            joined_team = "newjoin:example.test"
            await env.registry_db.execute("""
                INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility)
                VALUES ('example.test', 'newjoin', $1, 'public')
            """, env.team_did)
            from types import SimpleNamespace
            joined = SimpleNamespace(sk=recipient.sk, did=recipient.did, certificate=_encode_certificate(_make_certificate(
                env.team_sk, env.team_did, recipient.did, team_id=joined_team, alias="bob",
                identity_scope="global", member_did_aw=identities["bob"], member_address="example.test/bob",
                certificate_id="newjoin-bob",
            )))
            connected = await request(joined, joined_team, "POST", "/v1/connect", {"hostname": "policy-test", "workspace_path": str(tmp_path / "joined")})
            assert connected.status_code == 200, connected.text
            assert await env.db.fetch_value("SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id=$1", UUID(connected.json()["agent_id"])) == mode


@pytest.mark.asyncio
async def test_unmarked_global_recipient_keeps_strict_policy(privacy_app):
    from aweb.messaging.messages import resolve_agent_by_did

    env = privacy_app
    sender, recipient = env.actors["alice"], env.actors["bob"]
    sender_id = await register_global_identity(env, sender, "example.test/alice")
    recipient_id = await register_global_identity(env, recipient, "example.test/bob")
    sender.certificate = _encode_certificate(_make_certificate(
        env.team_sk, env.team_did, sender.did, team_id=TEAM, alias="alice",
        identity_scope="global", member_did_aw=sender_id, member_address="example.test/alice",
    ))
    await env.db.execute("""
        UPDATE {{tables.agents}} SET identity_scope='global', did_aw=$1,
            address='example.test/bob', inbound_mode='contacts_only', did_aw_verified_key=NULL
        WHERE agent_id=$2
    """, recipient_id, recipient.id)
    projected = await resolve_agent_by_did(env.infra, recipient.did)
    assert projected["did_aw"] is None
    assert projected["policy_did_aw"] == recipient_id

    async def send_both(expected):
        for path, payload in (
            ("/v1/messages", {"to_did": recipient.did, "subject": "raw policy", "body": "policy check"}),
            ("/v1/chat/sessions", {"to_dids": [recipient.did], "message": "policy check"}),
        ):
            body = json.dumps(payload).encode()
            headers = _signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate, body)
            response = await env.client.post(path, content=body, headers={**headers, "Content-Type": "application/json"})
            assert response.status_code == expected, response.text
            assert "migration required" not in response.text
            if expected == 403:
                assert "exact active contacts" in response.text

    await send_both(403)
    # Key-owned contacts remain valid without attributing an unverified global
    # claim to this recipient. Raw policy facts never grant identity authority.
    await env.db.execute("""
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw, binding_controller_did, binding_accepted_at, status
        ) VALUES ($1, 'example.test/alice', $2, $3, clock_timestamp(), 'active')
    """, recipient.did, sender_id, env.team_did)
    await send_both(200)
    assert await env.db.fetch_value("SELECT did_aw_verified_key FROM {{tables.agents}} WHERE agent_id=$1", recipient.id) is None


@pytest.mark.asyncio
async def test_unverified_caller_cannot_change_another_identity_policy(privacy_app):
    from test_messages_http import _make_keypair

    env = privacy_app
    attacker, recipient, sender = env.actors["carol"], env.actors["bob"], env.actors["alice"]
    victim_id = await register_global_identity(env, recipient)
    await env.db.execute("""
        UPDATE {{tables.agents}} SET identity_scope='global', did_aw=$1,
            inbound_mode='contacts_only', did_aw_verified_key=did_key WHERE agent_id=$2
    """, victim_id, recipient.id)
    controller_sk, _, controller_did = _make_keypair()
    evil_team = "foreign:example.test"
    await env.registry_db.execute("""
        INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility)
        VALUES ('example.test', 'foreign', $1, 'public')
    """, controller_did)
    forged = _encode_certificate(_make_certificate(
        controller_sk, controller_did, attacker.did, team_id=evil_team, alias="mallory",
        identity_scope="global", member_did_aw=victim_id, certificate_id="foreign-global-claim",
    ))

    async def request(actor, team, certificate, method, path, payload):
        body = json.dumps(payload).encode()
        headers = _signed_team_headers(actor.sk, actor.did, team, certificate, body)
        return await env.client.request(method, path, content=body, headers={**headers, "Content-Type": "application/json"})

    refused = await request(attacker, evil_team, forged, "POST", "/v1/connect", {})
    assert refused.status_code == 403, refused.text
    assert "identity_binding_mismatch" in refused.text
    assert not await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.agents}} WHERE team_id=$1", evil_team)
    # Reproduce a pre-existing unverified projection as well: blocking new
    # connect alone must not let an old forged row authorize an all-row PATCH.
    await env.db.execute("""
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'example.test', 'foreign', $2)
    """, evil_team, controller_did)
    await env.db.execute("""
        INSERT INTO {{tables.agents}} (team_id, alias, did_key, did_aw, identity_scope, inbound_mode)
        VALUES ($1, 'mallory', $2, $3, 'global', 'open')
    """, evil_team, attacker.did, victim_id)
    refused = await request(attacker, evil_team, forged, "PATCH", "/v1/agents/me/inbound-mode", {"inbound_mode": "open"})
    assert refused.status_code == 403, refused.text
    assert "identity_binding_mismatch" in refused.text
    assert await env.db.fetch_value("SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id=$1", recipient.id) == "contacts_only"
    for path, payload in (
        ("/v1/messages", {"to_did": recipient.did, "subject": "still strict", "body": "denied"}),
        ("/v1/chat/sessions", {"to_dids": [recipient.did], "message": "denied"}),
    ):
        refused = await request(sender, TEAM, sender.certificate, "POST", path, payload)
        assert refused.status_code == 403, refused.text
        assert "exact active contacts" in refused.text
