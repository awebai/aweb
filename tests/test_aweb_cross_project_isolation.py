from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_two_projects(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_1_id = uuid.uuid4()
    project_2_id = uuid.uuid4()
    agent_1_id = uuid.uuid4()
    agent_2_id = uuid.uuid4()
    agent_3_id = uuid.uuid4()
    agent_4_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_1_id,
        "project-1",
        "Project 1",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_2_id,
        "project-2",
        "Project 2",
    )

    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_1_id,
        project_1_id,
        "agent-1",
        "Agent One",
        "agent",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_2_id,
        project_1_id,
        "agent-2",
        "Agent Two",
        "agent",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_3_id,
        project_2_id,
        "agent-3",
        "Agent Three",
        "agent",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_4_id,
        project_2_id,
        "agent-4",
        "Agent Four",
        "agent",
    )

    api_key_1 = f"aw_sk_{uuid.uuid4().hex}"
    api_key_2 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        """
        INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active)
        VALUES ($1, $2, $3, $4, TRUE)
        """,
        project_1_id,
        agent_1_id,
        api_key_1[:12],
        hash_api_key(api_key_1),
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active)
        VALUES ($1, $2, $3, $4, TRUE)
        """,
        project_2_id,
        agent_3_id,
        api_key_2[:12],
        hash_api_key(api_key_2),
    )

    return {
        "project_1_id": str(project_1_id),
        "project_2_id": str(project_2_id),
        "agent_1_id": str(agent_1_id),
        "agent_2_id": str(agent_2_id),
        "agent_3_id": str(agent_3_id),
        "agent_4_id": str(agent_4_id),
        "api_key_1": api_key_1,
        "api_key_2": api_key_2,
    }


@pytest.mark.asyncio
async def test_aweb_cross_project_actions_are_rejected(aweb_db_infra):
    seeded = await _seed_two_projects(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Mail: cannot address an agent outside your project.
            send = await client.post(
                "/v1/messages",
                headers=headers_1,
                json={
                    "to_agent_id": seeded["agent_3_id"],  # other project
                    "subject": "cross-project",
                    "body": "nope",
                    "priority": "normal",
                },
            )
            assert send.status_code == 404, send.text

            # Chat: cannot create a session with an alias outside your project.
            chat = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={
                    "to_aliases": ["agent-3"],  # other project
                    "message": "hello",
                    "leaving": False,
                },
            )
            assert chat.status_code == 404, chat.text

            # Reservations: spoof attempt by supplying actor fields is rejected.
            acquire = await client.post(
                "/v1/reservations",
                headers=headers_1,
                json={
                    "agent_id": seeded["agent_3_id"],
                    "alias": "agent-3",
                    "resource_key": f"cross-project:{uuid.uuid4().hex}",
                    "ttl_seconds": 60,
                    "metadata": {},
                },
            )
            assert acquire.status_code == 422, acquire.text

            # Session access: project 1 cannot read messages for a project 2 session.
            create_sess = await client.post(
                "/v1/chat/sessions",
                headers=headers_2,
                json={
                    "to_aliases": ["agent-4"],
                    "message": "baseline",
                    "leaving": False,
                },
            )
            assert create_sess.status_code == 200, create_sess.text
            session_id = create_sess.json()["session_id"]

            read = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_1,
                params={"unread_only": False, "limit": 10},
            )
            assert read.status_code == 404, read.text

            # List isolation: reservations in another project do not appear.
            resource_key = f"isolation:{uuid.uuid4().hex}"
            ok = await client.post(
                "/v1/reservations",
                headers=headers_2,
                json={
                    "resource_key": resource_key,
                    "ttl_seconds": 60,
                    "metadata": {},
                },
            )
            assert ok.status_code in (200, 201), ok.text

            listed = await client.get("/v1/reservations", headers=headers_1, params={"prefix": "isolation:"})
            assert listed.status_code == 200, listed.text
            keys = [r.get("resource_key") for r in (listed.json().get("reservations") or [])]
            assert resource_key not in keys
