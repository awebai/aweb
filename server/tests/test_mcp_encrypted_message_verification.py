"""Hosted MCP views verify encrypted messages by their envelope signature.

An encrypted_v2 message keeps its sender signature inside the envelope, so the
row's legacy signature columns are empty. Every view must still show a
correctly signed message as verified, under the sender's address, and a
tampered one as failed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import decrypt_e2ee_message, encrypt_e2ee_message, generate_x25519_keypair
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import chat as chat_tools
from aweb.mcp.tools import contacts as contacts_tools
from aweb.mcp.tools import mail as mail_tools

from test_mcp_mail_chat import DBInfra

TEAM_ID = "ops:acme.com"


def _identity(alias: str) -> dict:
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    stable_id = stable_id_from_public_key(public_key)
    private_key, public_encryption_key = generate_x25519_keypair()
    return {
        "agent_id": uuid4(),
        "workspace_id": uuid4(),
        "alias": alias,
        "address": f"acme.com/{alias}",
        "did": did,
        "stable_id": stable_id,
        "team_id": TEAM_ID,
        "signing_key": signing_key,
        "private_key": private_key,
        "encryption_key": build_encryption_key_assertion(
            signing_key=signing_key,
            identity_did=did,
            identity_stable_id=stable_id,
            encryption_public_key=public_encryption_key,
            custody="hosted_custodial",
            now=datetime.now(timezone.utc),
        ),
    }


def _auth(identity: dict) -> AuthContext:
    return AuthContext(
        team_id=TEAM_ID,
        agent_id=str(identity["agent_id"]),
        workspace_id=str(identity["workspace_id"]),
        alias=identity["alias"],
        did_key=identity["did"],
        did_aw=identity["stable_id"],
        address=identity["address"],
        trusted_proxy=True,
    )


async def _insert_agents(aweb_db, *identities: dict) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'ops', 'did:key:z6MkTeam')
        """,
        TEAM_ID,
    )
    for identity in identities:
        await aweb_db.execute(
            """
            INSERT INTO {{tables.agents}}
                (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, status, inbound_mode)
            VALUES ($1, $2, $3, $4, $5, $6, 'global', 'active', 'open')
            """,
            identity["agent_id"],
            TEAM_ID,
            identity["did"],
            identity["stable_id"],
            identity["address"],
            identity["alias"],
        )


def _recipient_ref(identity: dict) -> dict:
    return {key: identity[key] for key in ("address", "did", "stable_id", "team_id", "encryption_key")}


def _custody(sender: dict, recipient: dict):
    """The hosted custody seam: seal and open with the identities' real keys."""

    async def encryptor(*, message_type, payload, **_kwargs) -> dict:
        envelope = encrypt_e2ee_message(
            kind=message_type,
            sender=sender,
            recipients=[_recipient_ref(recipient)],
            body=str(payload["body"]),
            subject=str(payload.get("subject") or ""),
            message_id=str(payload["message_id"]),
            conversation_id=str(payload["conversation_id"]),
            created_at=datetime.fromisoformat(str(payload["timestamp"]).replace("Z", "+00:00")),
        )
        return {"content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": envelope}

    async def decryptor(*, agent_id, row, **_kwargs) -> dict:
        reader = sender if agent_id == str(sender["agent_id"]) else recipient
        envelope = row["encrypted_envelope"]
        envelope = json.loads(envelope) if isinstance(envelope, str) else envelope
        plain = decrypt_e2ee_message(
            envelope,
            {
                "address": reader["address"],
                "did": reader["did"],
                "stable_id": reader["stable_id"],
                "encryption_key_id": reader["encryption_key"]["encryption_key_id"],
                "private_key": reader["private_key"],
            },
        )
        return {"subject": plain.get("subject") or "", "body": plain["body"], "decryptable": True}

    return encryptor, decryptor


@pytest.mark.asyncio
async def test_hosted_encrypted_chat_reads_verified_under_the_senders_address(aweb_cloud_db, monkeypatch):
    m = _identity("m")
    bond = _identity("bond")
    await _insert_agents(aweb_cloud_db.aweb_db, m, bond)
    encryptor, decryptor = _custody(m, bond)
    db = DBInfra(aweb_cloud_db.aweb_db)

    monkeypatch.setattr(chat_tools, "get_auth", lambda: _auth(m))
    sent = json.loads(
        await chat_tools.chat_send(
            db, None, registry_client=None, hosted_encryptor=encryptor, to_alias="bond", message="Signed by m"
        )
    )
    assert "error" not in sent, sent
    conversation_id = sent.get("conversation_id") or sent.get("session_id")

    for reader in (m, bond):
        monkeypatch.setattr(chat_tools, "get_auth", lambda reader=reader: _auth(reader))
        history = json.loads(
            await chat_tools.chat_history(db, session_id=conversation_id, hosted_decryptor=decryptor)
        )
        [message] = history["messages"]
        assert message["body"] == "Signed by m", (reader["alias"], message)
        assert message["verification_status"] == "verified", (reader["alias"], message)
        assert message["from_address"] == m["address"], (reader["alias"], message)

    # The same row with its ciphertext swapped no longer verifies.
    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT message_id, encrypted_envelope FROM {{tables.chat_messages}}")
    envelope = row["encrypted_envelope"]
    envelope = json.loads(envelope) if isinstance(envelope, str) else envelope
    envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.chat_messages}} SET encrypted_envelope = $1::jsonb WHERE message_id = $2",
        json.dumps(envelope),
        row["message_id"],
    )
    monkeypatch.setattr(chat_tools, "get_auth", lambda: _auth(bond))
    history = json.loads(await chat_tools.chat_history(db, session_id=conversation_id, hosted_decryptor=None))
    assert history["messages"][0]["verification_status"] == "failed"


@pytest.mark.asyncio
async def test_hosted_encrypted_chat_wait_reply_names_the_senders_address(aweb_cloud_db, monkeypatch):
    m = _identity("m")
    bond = _identity("bond")
    await _insert_agents(aweb_cloud_db.aweb_db, m, bond)
    db = DBInfra(aweb_cloud_db.aweb_db)

    m_encryptor, _ = _custody(m, bond)
    monkeypatch.setattr(chat_tools, "get_auth", lambda: _auth(m))
    sent = json.loads(
        await chat_tools.chat_send(db, None, registry_client=None, hosted_encryptor=m_encryptor, to_alias="bond", message="ping")
    )
    conversation_id = sent.get("conversation_id") or sent.get("session_id")

    _, bond_decryptor = _custody(m, bond)
    first = await aweb_cloud_db.aweb_db.fetch_val("SELECT MIN(created_at) FROM {{tables.chat_messages}}")
    replies, _timed_out = await chat_tools._wait_for_replies(
        aweb_cloud_db.aweb_db,
        None,
        auth=_auth(bond),
        hosted_decryptor=bond_decryptor,
        session_id=UUID(conversation_id),
        participant_did=bond["did"],
        after=first - timedelta(seconds=1),
        wait_seconds=1,
    )
    [reply] = replies
    assert reply["from_address"] == m["address"], reply
    assert reply["verification_status"] == "verified", reply


@pytest.mark.asyncio
async def test_hosted_encrypted_mail_reads_verified_and_a_tampered_one_fails(aweb_cloud_db, monkeypatch):
    m = _identity("m")
    bond = _identity("bond")
    await _insert_agents(aweb_cloud_db.aweb_db, m, bond)
    encryptor, decryptor = _custody(m, bond)
    db = DBInfra(aweb_cloud_db.aweb_db)

    monkeypatch.setattr(mail_tools, "get_auth", lambda: _auth(m))
    sent = json.loads(
        await mail_tools.send_mail(
            db, registry_client=None, hosted_encryptor=encryptor, to="bond", subject="Doc", body="Signed by m"
        )
    )
    assert "error" not in sent, sent

    monkeypatch.setattr(mail_tools, "get_auth", lambda: _auth(bond))
    inbox = json.loads(await mail_tools.check_inbox(db, hosted_decryptor=decryptor))
    [message] = inbox["messages"]
    assert message["body"] == "Signed by m", message
    assert message["verification_status"] == "verified", message
    assert message["from_address"] == m["address"], message

    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT message_id, encrypted_envelope FROM {{tables.messages}}")
    envelope = row["encrypted_envelope"]
    envelope = json.loads(envelope) if isinstance(envelope, str) else envelope
    envelope["signature"] = envelope["signature"][:-4] + "AAAA"
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.messages}} SET encrypted_envelope = $1::jsonb WHERE message_id = $2",
        json.dumps(envelope),
        row["message_id"],
    )
    inbox = json.loads(await mail_tools.check_inbox(db, hosted_decryptor=None, unread_only=False))
    assert inbox["messages"][0]["verification_status"] == "failed"


@pytest.mark.asyncio
async def test_hosted_encrypted_mail_reads_verified_from_a_contact(aweb_cloud_db, monkeypatch):
    m = _identity("m")
    bond = _identity("bond")
    await _insert_agents(aweb_cloud_db.aweb_db, m, bond)
    encryptor, _ = _custody(m, bond)
    db = DBInfra(aweb_cloud_db.aweb_db)

    monkeypatch.setattr(mail_tools, "get_auth", lambda: _auth(m))
    sent = json.loads(
        await mail_tools.send_mail(db, registry_client=None, hosted_encryptor=encryptor, to="bond", body="Signed by m")
    )
    assert "error" not in sent, sent
    contact_id = await aweb_cloud_db.aweb_db.fetch_val(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, $2, 'm')
        RETURNING contact_id
        """,
        bond["stable_id"],
        m["address"],
    )

    monkeypatch.setattr(contacts_tools, "get_auth", lambda: _auth(bond))
    result = json.loads(
        await contacts_tools.read_messages_from_contact(
            db, registry_client=None, contact_id=str(contact_id), channel="mail"
        )
    )
    [message] = result["messages"]
    assert message["verification_status"] == "verified", message
    assert message["from_address"] == m["address"], message
