"""An inbox page reads what it renders in a fixed number of statements, not one per message."""

import asyncpg.connection
import pytest

from test_dashboard_privacy import TEAM, _request, _seed_mail, privacy_app  # noqa: F401


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


async def _attach(env, message_id, conversation_id, ordinal, kind="mail"):
    from uuid import uuid4

    attachment_id = uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.message_attachments}} "
        "(attachment_id, message_kind, message_id, conversation_id, size, descriptor_sha256, envelope_sha256, ordinal) "
        "VALUES ($1, $6, $2, $3, 10, $4, $4, $5)",
        attachment_id, message_id, conversation_id, f"{ordinal:064x}", ordinal, kind,
    )
    return str(attachment_id)


def _observe_statements(monkeypatch) -> list[str]:
    statements: list[str] = []
    execute = asyncpg.connection.Connection._execute

    async def observed_execute(connection, query, *args, **kwargs):
        statements.append(" ".join(query.split()))
        return await execute(connection, query, *args, **kwargs)

    monkeypatch.setattr(asyncpg.connection.Connection, "_execute", observed_execute)
    return statements


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
    # A chat attachment under the same message id, and a mail attachment of a
    # message that is not on bob's page, are not this page's references.
    await _attach(env, with_one, conversation_id, 1, kind="chat")
    from uuid import uuid4
    await _attach(env, uuid4(), conversation_id, 0)
    statements = _observe_statements(monkeypatch)
    inbox = await _request(env, "bob", "GET", "/v1/messages/inbox?limit=50")

    assert inbox.status_code == 200, inbox.text
    refs = {m["message_id"]: [ref["id"] for ref in m["attachment_refs"]] for m in inbox.json()["messages"]}
    assert refs[str(with_two)] == [first, second]
    assert refs[str(without)] == []
    assert refs[str(with_one)] == [only]
    assert refs[seeded] == []
    assert len([q for q in statements if "message_attachments" in q]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("page", [1, 50])
async def test_a_page_of_text_only_encrypted_mail_reads_attachments_once(privacy_app, monkeypatch, page):
    env = privacy_app
    seeded = await _seed_mail(env)
    conversation_id = await env.db.fetch_value(
        "SELECT conversation_id FROM {{tables.messages}} WHERE message_id = $1", seeded,
    )
    for _ in range(page):
        await _encrypted_mail(env, conversation_id)
    statements = _observe_statements(monkeypatch)
    inbox = await _request(env, "bob", "GET", f"/v1/messages/inbox?limit={page}")

    assert inbox.status_code == 200, inbox.text
    messages = inbox.json()["messages"]
    assert len(messages) == page
    assert all(m["attachment_refs"] == [] for m in messages)
    assert len([q for q in statements if "message_attachments" in q]) == 1


@pytest.mark.asyncio
async def test_a_chat_history_page_reads_its_attachment_references_once(privacy_app, monkeypatch):
    from uuid import UUID, uuid4

    env = privacy_app
    opened = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_dids": [env.actors["bob"].did], "message": "first",
    })
    assert opened.status_code == 200, opened.text
    session_id = UUID(opened.json()["session_id"])
    opening = await env.db.fetch_value(
        "SELECT message_id FROM {{tables.chat_messages}} WHERE session_id = $1", session_id,
    )
    later = []
    for body in ("second", "third"):
        later.append(await env.db.fetch_value(
            "INSERT INTO {{tables.chat_messages}} (session_id, from_agent_id, from_did, from_alias, body) "
            "VALUES ($1, $2, $3, 'alice', $4) RETURNING message_id",
            session_id, env.actors["alice"].id, env.actors["alice"].did, body,
        ))
    with_two, with_one = later
    second = await _attach(env, with_two, session_id, 1, kind="chat")
    first = await _attach(env, with_two, session_id, 0, kind="chat")
    only = await _attach(env, with_one, session_id, 0, kind="chat")
    await _attach(env, with_one, session_id, 1, kind="mail")
    await _attach(env, uuid4(), session_id, 0, kind="chat")
    statements = _observe_statements(monkeypatch)
    history = await _request(env, "bob", "GET", f"/v1/chat/sessions/{session_id}/messages")

    assert history.status_code == 200, history.text
    refs = {m["message_id"]: [ref["id"] for ref in m["attachment_refs"]] for m in history.json()["messages"]}
    assert refs[str(with_two)] == [first, second]
    assert refs[str(with_one)] == [only]
    assert refs[str(opening)] == []
    assert len([q for q in statements if "message_attachments" in q]) == 1
