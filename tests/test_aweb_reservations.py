from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed(aweb_db_infra):
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

    return {
        "api_key_1": api_key_1,
        "api_key_2": api_key_2,
        "agent_1_id": str(agent_1_id),
        "agent_2_id": str(agent_2_id),
    }


@pytest.mark.asyncio
async def test_aweb_reservation_acquire_conflict_release_cycle(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])
            resource_key = f"conformance:{uuid.uuid4().hex}"

            acquire_1 = await client.post(
                "/v1/reservations",
                headers=headers_1,
                json={
                    "resource_key": resource_key,
                    "ttl_seconds": 60,
                    "metadata": {},
                },
            )
            assert acquire_1.status_code in (200, 201), acquire_1.text

            acquire_2 = await client.post(
                "/v1/reservations",
                headers=headers_2,
                json={
                    "resource_key": resource_key,
                    "ttl_seconds": 60,
                    "metadata": {},
                },
            )
            assert acquire_2.status_code == 409, acquire_2.text
            assert acquire_2.json().get("holder_alias") == "agent-1"

            release_wrong = await client.post(
                "/v1/reservations/release",
                headers=headers_2,
                json={"resource_key": resource_key},
            )
            assert release_wrong.status_code == 409, release_wrong.text

            release_right = await client.post(
                "/v1/reservations/release",
                headers=headers_1,
                json={"resource_key": resource_key},
            )
            assert release_right.status_code == 200, release_right.text

            acquire_2_after = await client.post(
                "/v1/reservations",
                headers=headers_2,
                json={
                    "resource_key": resource_key,
                    "ttl_seconds": 60,
                    "metadata": {},
                },
            )
            assert acquire_2_after.status_code in (200, 201), acquire_2_after.text


@pytest.mark.asyncio
async def test_aweb_reservations_list_prefix_filter(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            prefix = f"conformance:{uuid.uuid4().hex}:"
            key_in = prefix + "a"
            key_out = f"conformance:{uuid.uuid4().hex}:b"

            for key in (key_in, key_out):
                resp = await client.post(
                    "/v1/reservations",
                    headers=headers,
                    json={
                        "resource_key": key,
                        "ttl_seconds": 60,
                        "metadata": {},
                    },
                )
                assert resp.status_code in (200, 201), resp.text

            listed = await client.get(
                "/v1/reservations", headers=headers, params={"prefix": prefix}
            )
            assert listed.status_code == 200, listed.text
            items = listed.json().get("reservations") or []
            keys = [i.get("resource_key") for i in items]
            assert key_in in keys
            assert key_out not in keys
