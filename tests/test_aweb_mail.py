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

    project_id = uuid.uuid4()
    agent_1_id = uuid.uuid4()
    agent_2_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "test-project",
        "Test Project",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_1_id,
        project_id,
        "agent-1",
        "Agent One",
        "agent",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_2_id,
        project_id,
        "agent-2",
        "Agent Two",
        "agent",
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
