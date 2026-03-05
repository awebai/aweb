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
        "project_id": str(project_id),
        "api_key_1": api_key_1,
        "api_key_2": api_key_2,
        "agent_1_id": str(agent_1_id),
        "agent_2_id": str(agent_2_id),
    }


# -- Step 1: Create task --


@pytest.mark.asyncio
async def test_create_task(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/tasks",
                headers=_auth_headers(seeded["api_key_1"]),
                json={"title": "Fix bug"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["task_ref"] == "test-project-001"
            assert data["status"] == "open"
            assert data["created_by_agent_id"] == seeded["agent_1_id"]
            assert data["title"] == "Fix bug"


# -- Step 2: Get task by UUID, integer, slug-NNN, and not-found --


@pytest.mark.asyncio
async def test_get_task_by_uuid(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            resp = await client.get(f"/v1/tasks/{created['task_id']}", headers=headers)
            assert resp.status_code == 200, resp.text
            assert resp.json()["title"] == "T1"


@pytest.mark.asyncio
async def test_get_task_by_integer(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            await client.post("/v1/tasks", headers=headers, json={"title": "T1"})

            resp = await client.get("/v1/tasks/1", headers=headers)
            assert resp.status_code == 200, resp.text
            assert resp.json()["title"] == "T1"


@pytest.mark.asyncio
async def test_get_task_by_slug(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            await client.post("/v1/tasks", headers=headers, json={"title": "T1"})

            resp = await client.get("/v1/tasks/test-project-001", headers=headers)
            assert resp.status_code == 200, resp.text
            assert resp.json()["title"] == "T1"


@pytest.mark.asyncio
async def test_get_task_not_found(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            resp = await client.get("/v1/tasks/999", headers=headers)
            assert resp.status_code == 404, resp.text


# -- Step 3: List tasks --


@pytest.mark.asyncio
async def test_list_tasks_empty(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            resp = await client.get("/v1/tasks", headers=headers)
            assert resp.status_code == 200, resp.text
            assert resp.json()["tasks"] == []


@pytest.mark.asyncio
async def test_list_tasks_with_status_filter(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            await client.post("/v1/tasks", headers=headers, json={"title": "T1"})
            await client.post("/v1/tasks", headers=headers, json={"title": "T2"})

            # All tasks
            resp = await client.get("/v1/tasks", headers=headers)
            assert len(resp.json()["tasks"]) == 2

            # Filter by status=open
            resp = await client.get("/v1/tasks", headers=headers, params={"status": "open"})
            assert len(resp.json()["tasks"]) == 2

            # Filter by status=closed should be empty
            resp = await client.get("/v1/tasks", headers=headers, params={"status": "closed"})
            assert len(resp.json()["tasks"]) == 0


# -- Step 4: Update basic fields --


@pytest.mark.asyncio
async def test_update_task_basic_fields(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"title": "Updated", "priority": 3},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["title"] == "Updated"
            assert data["priority"] == 3


# -- Step 5: Claim semantics --


@pytest.mark.asyncio
async def test_claim_auto_assigns(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["assignee_agent_id"] == seeded["agent_1_id"]
            assert resp.json()["status"] == "in_progress"


@pytest.mark.asyncio
async def test_claim_same_agent_ok(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            # Claim first
            await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"status": "in_progress"},
            )
            # Re-claim same agent should succeed
            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_claim_different_agent_conflict(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])
            created = (
                await client.post("/v1/tasks", headers=headers_1, json={"title": "T1"})
            ).json()

            # Agent 1 claims
            await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers_1,
                json={"status": "in_progress"},
            )
            # Agent 2 tries to claim — conflict
            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers_2,
                json={"status": "in_progress"},
            )
            assert resp.status_code == 409, resp.text


# -- Step 6: Close sets closed_by/closed_at --


@pytest.mark.asyncio
async def test_close_task(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"status": "closed"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["status"] == "closed"
            assert data["closed_by_agent_id"] == seeded["agent_1_id"]
            assert data["closed_at"] is not None


# -- Step 7: Parent close cascade --


@pytest.mark.asyncio
async def test_parent_close_cascades(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])

            parent = (
                await client.post("/v1/tasks", headers=headers, json={"title": "Parent"})
            ).json()
            child = (
                await client.post(
                    "/v1/tasks",
                    headers=headers,
                    json={"title": "Child", "parent_task_id": parent["task_id"]},
                )
            ).json()
            grandchild = (
                await client.post(
                    "/v1/tasks",
                    headers=headers,
                    json={"title": "Grandchild", "parent_task_id": child["task_id"]},
                )
            ).json()

            # Close parent
            resp = await client.patch(
                f"/v1/tasks/{parent['task_ref']}",
                headers=headers,
                json={"status": "closed"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            auto_closed_refs = [ac["task_ref"] for ac in data.get("auto_closed", [])]
            assert child["task_ref"] in auto_closed_refs
            assert grandchild["task_ref"] in auto_closed_refs

            # Verify child and grandchild are closed
            child_resp = await client.get(f"/v1/tasks/{child['task_ref']}", headers=headers)
            assert child_resp.json()["status"] == "closed"
            gc_resp = await client.get(f"/v1/tasks/{grandchild['task_ref']}", headers=headers)
            assert gc_resp.json()["status"] == "closed"


# -- Step 8: Soft delete --


@pytest.mark.asyncio
async def test_soft_delete(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            # Delete
            resp = await client.delete(f"/v1/tasks/{created['task_ref']}", headers=headers)
            assert resp.status_code == 200, resp.text

            # GET returns 404
            resp = await client.get(f"/v1/tasks/{created['task_ref']}", headers=headers)
            assert resp.status_code == 404

            # Not in list
            resp = await client.get("/v1/tasks", headers=headers)
            assert len(resp.json()["tasks"]) == 0


# -- Step 9: Dependencies --


@pytest.mark.asyncio
async def test_dependencies(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task_a = (await client.post("/v1/tasks", headers=headers, json={"title": "A"})).json()
            task_b = (await client.post("/v1/tasks", headers=headers, json={"title": "B"})).json()

            # A depends on B
            resp = await client.post(
                f"/v1/tasks/{task_a['task_ref']}/deps",
                headers=headers,
                json={"depends_on": task_b["task_ref"]},
            )
            assert resp.status_code == 200, resp.text

            # GET A shows B in blocked_by
            a_data = (await client.get(f"/v1/tasks/{task_a['task_ref']}", headers=headers)).json()
            assert any(d["task_ref"] == task_b["task_ref"] for d in a_data["blocked_by"])

            # GET B shows A in blocks
            b_data = (await client.get(f"/v1/tasks/{task_b['task_ref']}", headers=headers)).json()
            assert any(d["task_ref"] == task_a["task_ref"] for d in b_data["blocks"])

            # Remove dependency
            resp = await client.delete(
                f"/v1/tasks/{task_a['task_ref']}/deps/{task_b['task_ref']}",
                headers=headers,
            )
            assert resp.status_code == 200, resp.text

            # Verify removed
            a_data = (await client.get(f"/v1/tasks/{task_a['task_ref']}", headers=headers)).json()
            assert len(a_data["blocked_by"]) == 0


@pytest.mark.asyncio
async def test_self_dependency_rejected(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task = (await client.post("/v1/tasks", headers=headers, json={"title": "A"})).json()

            resp = await client.post(
                f"/v1/tasks/{task['task_ref']}/deps",
                headers=headers,
                json={"depends_on": task["task_ref"]},
            )
            assert resp.status_code == 422, resp.text


# -- Step 10: Ready tasks --


@pytest.mark.asyncio
async def test_ready_tasks(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task_a = (await client.post("/v1/tasks", headers=headers, json={"title": "A"})).json()
            task_b = (await client.post("/v1/tasks", headers=headers, json={"title": "B"})).json()

            # A depends on B
            await client.post(
                f"/v1/tasks/{task_a['task_ref']}/deps",
                headers=headers,
                json={"depends_on": task_b["task_ref"]},
            )

            # Ready should return B but not A
            resp = await client.get("/v1/tasks/ready", headers=headers)
            assert resp.status_code == 200, resp.text
            refs = [t["task_ref"] for t in resp.json()["tasks"]]
            assert task_b["task_ref"] in refs
            assert task_a["task_ref"] not in refs

            # Close B
            await client.patch(
                f"/v1/tasks/{task_b['task_ref']}", headers=headers, json={"status": "closed"}
            )

            # Now A should be ready
            resp = await client.get("/v1/tasks/ready", headers=headers)
            refs = [t["task_ref"] for t in resp.json()["tasks"]]
            assert task_a["task_ref"] in refs


# -- Step 11: Sequential numbering --


@pytest.mark.asyncio
async def test_sequential_numbering(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            t1 = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()
            t2 = (await client.post("/v1/tasks", headers=headers, json={"title": "T2"})).json()
            t3 = (await client.post("/v1/tasks", headers=headers, json={"title": "T3"})).json()

            assert t1["task_number"] == 1
            assert t2["task_number"] == 2
            assert t3["task_number"] == 3


# -- Step 12: Create with all optional fields --


@pytest.mark.asyncio
async def test_create_with_all_fields(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])

            parent = (
                await client.post("/v1/tasks", headers=headers, json={"title": "Parent"})
            ).json()

            resp = await client.post(
                "/v1/tasks",
                headers=headers,
                json={
                    "title": "Full task",
                    "description": "A description",
                    "notes": "Some notes",
                    "priority": 0,
                    "task_type": "feature",
                    "labels": ["urgent", "backend"],
                    "parent_task_id": parent["task_id"],
                    "assignee_agent_id": seeded["agent_2_id"],
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["description"] == "A description"
            assert data["notes"] == "Some notes"
            assert data["priority"] == 0
            assert data["task_type"] == "feature"
            assert data["labels"] == ["urgent", "backend"]
            assert data["parent_task_id"] == parent["task_id"]
            assert data["assignee_agent_id"] == seeded["agent_2_id"]


# -- Step 13: Additional filters --


@pytest.mark.asyncio
async def test_filter_by_assignee(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            await client.post("/v1/tasks", headers=headers_1, json={"title": "T1"})
            await client.post("/v1/tasks", headers=headers_2, json={"title": "T2"})

            # Claim T1 as agent-1
            await client.patch("/v1/tasks/1", headers=headers_1, json={"status": "in_progress"})

            # Filter by assignee
            resp = await client.get(
                "/v1/tasks",
                headers=headers_1,
                params={"assignee_agent_id": seeded["agent_1_id"]},
            )
            assert resp.status_code == 200, resp.text
            tasks = resp.json()["tasks"]
            assert len(tasks) == 1
            assert tasks[0]["title"] == "T1"


@pytest.mark.asyncio
async def test_filter_by_labels(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])

            await client.post(
                "/v1/tasks", headers=headers, json={"title": "T1", "labels": ["backend", "urgent"]}
            )
            await client.post(
                "/v1/tasks", headers=headers, json={"title": "T2", "labels": ["frontend"]}
            )

            resp = await client.get("/v1/tasks", headers=headers, params={"labels": "backend"})
            assert resp.status_code == 200, resp.text
            tasks = resp.json()["tasks"]
            assert len(tasks) == 1
            assert tasks[0]["title"] == "T1"


# -- Validation tests from code review --


@pytest.mark.asyncio
async def test_invalid_status_rejected(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"status": "bogus"},
            )
            assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_invalid_task_type_rejected(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            resp = await client.post(
                "/v1/tasks", headers=headers, json={"title": "T1", "task_type": "epic"}
            )
            assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_transitive_cycle_rejected(aweb_db_infra):
    """A->B->C, then C->A should be rejected."""
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            a = (await client.post("/v1/tasks", headers=headers, json={"title": "A"})).json()
            b = (await client.post("/v1/tasks", headers=headers, json={"title": "B"})).json()
            c = (await client.post("/v1/tasks", headers=headers, json={"title": "C"})).json()

            # A depends on B
            resp = await client.post(
                f"/v1/tasks/{a['task_ref']}/deps",
                headers=headers,
                json={"depends_on": b["task_ref"]},
            )
            assert resp.status_code == 200, resp.text

            # B depends on C
            resp = await client.post(
                f"/v1/tasks/{b['task_ref']}/deps",
                headers=headers,
                json={"depends_on": c["task_ref"]},
            )
            assert resp.status_code == 200, resp.text

            # C depends on A — would create cycle A->B->C->A
            resp = await client.post(
                f"/v1/tasks/{c['task_ref']}/deps",
                headers=headers,
                json={"depends_on": a["task_ref"]},
            )
            assert resp.status_code == 422, resp.text
            assert "cycle" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_clear_assignee(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            created = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            # Claim it
            await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"status": "in_progress"},
            )
            # Verify assigned
            task = (await client.get(f"/v1/tasks/{created['task_ref']}", headers=headers)).json()
            assert task["assignee_agent_id"] == seeded["agent_1_id"]

            # Clear assignee
            resp = await client.patch(
                f"/v1/tasks/{created['task_ref']}",
                headers=headers,
                json={"assignee_agent_id": None},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["assignee_agent_id"] is None


# -- Task comments --


@pytest.mark.asyncio
async def test_add_and_list_comments(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])
            task = (await client.post("/v1/tasks", headers=headers_1, json={"title": "T1"})).json()

            # Add two comments from different agents
            resp1 = await client.post(
                f"/v1/tasks/{task['task_ref']}/comments",
                headers=headers_1,
                json={"body": "Started investigating"},
            )
            assert resp1.status_code == 200, resp1.text
            c1 = resp1.json()
            assert c1["body"] == "Started investigating"
            assert c1["agent_id"] == seeded["agent_1_id"]
            assert "comment_id" in c1
            assert "created_at" in c1

            resp2 = await client.post(
                f"/v1/tasks/{task['task_ref']}/comments",
                headers=headers_2,
                json={"body": "Found the root cause"},
            )
            assert resp2.status_code == 200, resp2.text

            # List comments — ordered by created_at
            resp = await client.get(f"/v1/tasks/{task['task_ref']}/comments", headers=headers_1)
            assert resp.status_code == 200, resp.text
            comments = resp.json()["comments"]
            assert len(comments) == 2
            assert comments[0]["body"] == "Started investigating"
            assert comments[1]["body"] == "Found the root cause"


@pytest.mark.asyncio
async def test_comments_empty_list(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()

            resp = await client.get(f"/v1/tasks/{task['task_ref']}/comments", headers=headers)
            assert resp.status_code == 200, resp.text
            assert resp.json()["comments"] == []


@pytest.mark.asyncio
async def test_comment_on_nonexistent_task(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            resp = await client.post(
                "/v1/tasks/999/comments",
                headers=headers,
                json={"body": "hello"},
            )
            assert resp.status_code == 404, resp.text


# -- Blocked tasks --


@pytest.mark.asyncio
async def test_blocked_tasks(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task_a = (await client.post("/v1/tasks", headers=headers, json={"title": "A"})).json()
            task_b = (await client.post("/v1/tasks", headers=headers, json={"title": "B"})).json()
            task_c = (await client.post("/v1/tasks", headers=headers, json={"title": "C"})).json()

            # A depends on B (A is blocked by B)
            await client.post(
                f"/v1/tasks/{task_a['task_ref']}/deps",
                headers=headers,
                json={"depends_on": task_b["task_ref"]},
            )

            # Blocked should return A (has unresolved dep on B), not B or C
            resp = await client.get("/v1/tasks/blocked", headers=headers)
            assert resp.status_code == 200, resp.text
            refs = [t["task_ref"] for t in resp.json()["tasks"]]
            assert task_a["task_ref"] in refs
            assert task_b["task_ref"] not in refs
            assert task_c["task_ref"] not in refs

            # Claim A (move to in_progress) — still blocked
            await client.patch(
                f"/v1/tasks/{task_a['task_ref']}",
                headers=headers,
                json={"status": "in_progress"},
            )
            resp = await client.get("/v1/tasks/blocked", headers=headers)
            refs = [t["task_ref"] for t in resp.json()["tasks"]]
            assert task_a["task_ref"] in refs

            # Close B — A is no longer blocked
            await client.patch(
                f"/v1/tasks/{task_b['task_ref']}", headers=headers, json={"status": "closed"}
            )

            resp = await client.get("/v1/tasks/blocked", headers=headers)
            refs = [t["task_ref"] for t in resp.json()["tasks"]]
            assert task_a["task_ref"] not in refs


# -- Mutation hook payloads --


@pytest.mark.asyncio
async def test_hook_task_created_payload(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    events = []

    async def on_mutation(event_type, context):
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])

            # Create a parent task first
            parent = (
                await client.post("/v1/tasks", headers=headers, json={"title": "Parent"})
            ).json()
            events.clear()

            # Create child with assignee
            resp = await client.post(
                "/v1/tasks",
                headers=headers,
                json={
                    "title": "Child",
                    "parent_task_id": parent["task_id"],
                    "assignee_agent_id": seeded["agent_2_id"],
                },
            )
            assert resp.status_code == 200, resp.text
            created = resp.json()

            assert len(events) == 1
            evt_type, ctx = events[0]
            assert evt_type == "task.created"
            assert ctx["task_id"] == created["task_id"]
            assert ctx["task_ref"] == created["task_ref"]
            assert ctx["title"] == "Child"
            assert ctx["parent_task_id"] == parent["task_id"]
            assert ctx["assignee_agent_id"] == seeded["agent_2_id"]
            assert ctx["actor_agent_id"] == seeded["agent_1_id"]


@pytest.mark.asyncio
async def test_hook_task_status_changed(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    events = []

    async def on_mutation(event_type, context):
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()
            events.clear()

            # Move to in_progress (claim)
            resp = await client.patch(
                f"/v1/tasks/{task['task_ref']}",
                headers=headers,
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text
            assert "old_status" not in resp.json()  # internal field, not in API response

            # Should fire task.status_changed (not just task.updated)
            status_events = [(t, c) for t, c in events if t == "task.status_changed"]
            assert len(status_events) == 1
            _, ctx = status_events[0]
            assert ctx["old_status"] == "open"
            assert ctx["new_status"] == "in_progress"
            assert ctx["task_ref"] == task["task_ref"]
            assert ctx["task_id"] == task["task_id"]
            assert ctx["title"] == "T1"
            assert ctx["assignee_agent_id"] == seeded["agent_1_id"]  # auto-assigned
            assert ctx["parent_task_id"] is None
            assert ctx["actor_agent_id"] == seeded["agent_1_id"]

            events.clear()

            # Close
            resp = await client.patch(
                f"/v1/tasks/{task['task_ref']}",
                headers=headers,
                json={"status": "closed"},
            )
            assert resp.status_code == 200, resp.text

            status_events = [(t, c) for t, c in events if t == "task.status_changed"]
            assert len(status_events) == 1
            _, ctx = status_events[0]
            assert ctx["old_status"] == "in_progress"
            assert ctx["new_status"] == "closed"


@pytest.mark.asyncio
async def test_hook_task_deleted_has_ref(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    events = []

    async def on_mutation(event_type, context):
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()
            events.clear()

            resp = await client.delete(f"/v1/tasks/{task['task_ref']}", headers=headers)
            assert resp.status_code == 200, resp.text

            assert len(events) == 1
            evt_type, ctx = events[0]
            assert evt_type == "task.deleted"
            assert ctx["task_id"] == task["task_id"]
            assert ctx["task_ref"] == task["task_ref"]


@pytest.mark.asyncio
async def test_hook_non_status_update_fires_task_updated(aweb_db_infra):
    """Title/description changes should fire task.updated, not task.status_changed."""
    seeded = await _seed(aweb_db_infra)
    events = []

    async def on_mutation(event_type, context):
        events.append((event_type, context))

    app = create_app(db_infra=aweb_db_infra, redis=None)
    app.state.on_mutation = on_mutation

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            task = (await client.post("/v1/tasks", headers=headers, json={"title": "T1"})).json()
            events.clear()

            resp = await client.patch(
                f"/v1/tasks/{task['task_ref']}",
                headers=headers,
                json={"title": "Updated Title"},
            )
            assert resp.status_code == 200, resp.text

            event_types = [t for t, _ in events]
            assert "task.updated" in event_types
            assert "task.status_changed" not in event_types


@pytest.mark.asyncio
async def test_list_comments_on_nonexistent_task(aweb_db_infra):
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = _auth_headers(seeded["api_key_1"])
            resp = await client.get("/v1/tasks/999/comments", headers=headers)
            assert resp.status_code == 404, resp.text
