import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


@pytest.mark.asyncio
async def test_introspect_does_not_enrich_cross_project_agent(aweb_db_infra):
    """Introspection must not leak agent metadata across projects."""
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_a = uuid.uuid4()
    project_b = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_a,
        "introspect-a",
        "Project A",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_b,
        "introspect-b",
        "Project B",
    )

    victim_agent_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type)
        VALUES ($1, $2, $3, $4, $5)
        """,
        victim_agent_id,
        project_b,
        "victim",
        "Victim Human",
        "agent",
    )

    # Create an API key for project A but (mis)bind its agent_id to the victim agent in project B.
    token = "aw_sk_" + uuid.uuid4().hex + uuid.uuid4().hex
    key_prefix = token[:12]
    await aweb_db.execute(
        """
        INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active)
        VALUES ($1, $2, $3, $4, true)
        """,
        project_a,
        victim_agent_id,
        key_prefix,
        hash_api_key(token),
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get(
                "/v1/auth/introspect",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200, res.text
            payload = res.json()

        # Still returns scoped project_id and key id, but must not enrich alias/human_name
        # for an agent that doesn't belong to the authenticated project.
        assert payload["project_id"] == str(project_a)
        assert "alias" not in payload
        assert "human_name" not in payload
        assert "agent_type" not in payload
