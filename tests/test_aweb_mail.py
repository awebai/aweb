from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_aweb_mail_send_inbox_ack_roundtrip(aweb_db_infra):
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")

    namespace_id = uuid.uuid4()
    project_id = uuid.uuid4()
    agent_1_id = uuid.uuid4()
    agent_2_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_id,
        "test-ns",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        "test-project",
        "Test Project",
        namespace_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, namespace_id) VALUES ($1, $2, $3, $4, $5, $6)",
        agent_1_id,
        project_id,
        "agent-1",
        "Agent One",
        "agent",
        namespace_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, namespace_id) VALUES ($1, $2, $3, $4, $5, $6)",
        agent_2_id,
        project_id,
        "agent-2",
        "Agent Two",
        "agent",
        namespace_id,
    )

    api_key_1 = f"aw_sk_{uuid.uuid4().hex}"
    api_key_2 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_1_id,
        api_key_1[:12],
        hash_api_key(api_key_1),
        True,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_2_id,
        api_key_2[:12],
        hash_api_key(api_key_2),
        True,
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            subject = "hello"
            body = "world"

            send = await client.post(
                "/v1/messages",
                headers=_auth_headers(api_key_1),
                json={
                    "to_agent_id": str(agent_2_id),
                    "subject": subject,
                    "body": body,
                    "priority": "normal",
                    "thread_id": None,
                },
            )
            assert send.status_code == 200, send.text
            message_id = send.json()["message_id"]

            inbox = await client.get(
                "/v1/messages/inbox",
                headers=_auth_headers(api_key_2),
                params={"unread_only": True, "limit": 200},
            )
            assert inbox.status_code == 200, inbox.text
            found = next(
                (m for m in inbox.json().get("messages", []) if m.get("message_id") == message_id),
                None,
            )
            assert found is not None
            assert found["from_alias"] == "agent-1"
            assert found["subject"] == subject
            assert found["body"] == body

            ack = await client.post(
                f"/v1/messages/{message_id}/ack",
                headers=_auth_headers(api_key_2),
            )
            assert ack.status_code == 200, ack.text

            inbox_after = await client.get(
                "/v1/messages/inbox",
                headers=_auth_headers(api_key_2),
                params={"unread_only": True, "limit": 200},
            )
            assert inbox_after.status_code == 200, inbox_after.text
            assert all(
                m.get("message_id") != message_id for m in inbox_after.json().get("messages", [])
            )


@pytest.mark.asyncio
async def test_aweb_mail_rejects_to_alias_with_slash(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init_1 = await client.post(
                "/v1/init",
                json={"project_slug": "test/aweb-mail-alias-slash", "alias": "agent-1"},
            )
            assert init_1.status_code == 200, init_1.text
            api_key_1 = init_1.json()["api_key"]

            init_2 = await client.post(
                "/v1/init",
                json={"project_slug": "test/aweb-mail-alias-slash", "alias": "agent-2"},
            )
            assert init_2.status_code == 200, init_2.text

            send = await client.post(
                "/v1/messages",
                headers=_auth_headers(api_key_1),
                json={"to_alias": "acme/agent-2", "body": "hello"},
            )
            assert send.status_code == 422, send.text
            assert "Invalid alias format" in send.text


@pytest.mark.asyncio
async def test_inbox_from_address_no_double_prefix_for_network_messages(aweb_db_infra):
    """Network messages store from_alias as 'org/alias'; inbox must not double-prefix."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")

    namespace_id = uuid.uuid4()
    project_id = uuid.uuid4()
    sender_id = uuid.uuid4()
    receiver_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_id,
        "test-ns",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        "target-project",
        "Target Project",
        namespace_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, namespace_id) VALUES ($1, $2, $3, $4, $5, $6)",
        sender_id,
        project_id,
        "placeholder",
        "Placeholder Sender",
        "agent",
        namespace_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, namespace_id) VALUES ($1, $2, $3, $4, $5, $6)",
        receiver_id,
        project_id,
        "local-receiver",
        "Local Receiver",
        "agent",
        namespace_id,
    )

    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        receiver_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    # Insert a message with network-style from_alias (org/alias, as claweb stores it)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (project_id, from_agent_id, to_agent_id, from_alias, subject, body, priority)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        project_id,
        sender_id,
        receiver_id,
        "sender-org/researcher",  # full network address
        "Test",
        "Body",
        "normal",
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            inbox = await client.get(
                "/v1/messages/inbox",
                headers=_auth_headers(api_key),
                params={"unread_only": False, "limit": 200},
            )
            assert inbox.status_code == 200, inbox.text
            messages = inbox.json()["messages"]
            assert len(messages) == 1
            msg = messages[0]
            assert msg["from_alias"] == "sender-org/researcher"
            # from_address must be the network address as-is, NOT double-prefixed
            assert msg["from_address"] == "sender-org/researcher"
