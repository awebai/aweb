"""An inbox page reads its senders' agent rows with the page, not in a query of their own."""

import asyncpg.connection
import pytest

from test_dashboard_privacy import _request, _seed_mail, privacy_app  # noqa: F401


@pytest.mark.asyncio
async def test_an_inbox_page_reads_sender_membership_rows_with_its_messages(privacy_app, monkeypatch):
    env = privacy_app
    await _seed_mail(env)
    statements: list[str] = []
    execute = asyncpg.connection.Connection._execute

    async def observed_execute(connection, query, *args, **kwargs):
        statements.append(" ".join(query.split()))
        return await execute(connection, query, *args, **kwargs)

    monkeypatch.setattr(asyncpg.connection.Connection, "_execute", observed_execute)
    inbox = await _request(env, "bob", "GET", "/v1/messages/inbox?limit=50")

    assert inbox.status_code == 200, inbox.text
    message = inbox.json()["messages"][0]
    assert message["sender_membership"]["team_id"]
    assert not [q for q in statements if "WHERE agent_id = ANY($1::uuid[])" in q]


async def _encrypted_mail(env, conversation_id):
    from uuid import uuid4

    message_id = uuid4()
    await env.db.execute(
        """INSERT INTO {{tables.messages}}
        (message_id, team_id, conversation_id, from_did, to_did, from_alias, to_alias,
         from_agent_id, to_agent_id, subject, body, content_mode, message_version,
         encrypted_envelope, encrypted_ciphertext, encrypted_key_wraps,
         encrypted_ciphertext_hash, encrypted_ciphertext_size, encrypted_key_wraps_hash,
         encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id, signed_envelope_hash)
        VALUES ($1, $2, $3, $4, $5, 'alice', 'bob', $6, $7, '', '', 'encrypted_v2', 2,
                '{"ciphertext":"opaque"}', 'opaque', '[]', 'sha256:test', 6,
                'sha256:test', 'sha256:test', 'test', 'test', 'sha256:test')""",
        message_id, TEAM, conversation_id, env.actors["alice"].did, env.actors["bob"].did,
        env.actors["alice"].id, env.actors["bob"].id,
    )
    return message_id


async def _attach(env, message_id, conversation_id, ordinal):
    from uuid import uuid4

    attachment_id = uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.message_attachments}} "
        "(attachment_id, message_kind, message_id, conversation_id, size, descriptor_sha256, envelope_sha256, ordinal) "
        "VALUES ($1, 'mail', $2, $3, 10, $4, $4, $5)",
        attachment_id, message_id, conversation_id, f"{ordinal:064x}", ordinal,
    )
    return str(attachment_id)


@pytest.mark.asyncio
async def test_an_inbox_page_reads_its_attachment_references_once(privacy_app, monkeypatch):
    env = privacy_app
    seeded = await _seed_mail(env)
    conversation_id = await env.db.fetch_value(
        "SELECT conversation_id FROM {{tables.messages}} WHERE message_id = $1", seeded,
    )
    with_two, without, with_one = [await _encrypted_mail(env, conversation_id) for _ in range(3)]
    second = await _attach(env, with_two, conversation_id, 1)
    first = await _attach(env, with_two, conversation_id, 0)
    only = await _attach(env, with_one, conversation_id, 0)
    statements: list[str] = []
    execute = asyncpg.connection.Connection._execute

    async def observed_execute(connection, query, *args, **kwargs):
        statements.append(" ".join(query.split()))
        return await execute(connection, query, *args, **kwargs)

    monkeypatch.setattr(asyncpg.connection.Connection, "_execute", observed_execute)
    inbox = await _request(env, "bob", "GET", "/v1/messages/inbox?limit=50")

    assert inbox.status_code == 200, inbox.text
    refs = {m["message_id"]: [ref["id"] for ref in m["attachment_refs"]] for m in inbox.json()["messages"]}
    assert refs[str(with_two)] == [first, second]
    assert refs[str(without)] == []
    assert refs[str(with_one)] == [only]
    assert refs[seeded] == []
    assert len([q for q in statements if "message_attachments" in q]) == 1
