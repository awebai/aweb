"""Tests for task mutation hooks triggering beadhub claim lifecycle.

When aweb tasks are mutated (status changes, deletions), beadhub should
update bead_claims, workspace focus, and publish coordination events —
mirroring what the JSONL sync handler does for bd-backed workflows.
"""

import asyncio
import json
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app


async def _collect_events(pubsub, max_events=10, first_timeout=2.0, next_timeout=0.2):
    """Collect events from pubsub. Waits longer for first, shorter for subsequent."""
    events = []
    await asyncio.sleep(0.1)
    timeout = first_timeout
    for _ in range(max_events):
        msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=timeout)
        if msg is None:
            break
        if msg["type"] == "message":
            events.append(json.loads(msg["data"]))
        timeout = next_timeout
    return events


async def _subscribe(redis, workspace_id):
    """Subscribe to workspace event channel, consuming the confirmation."""
    pubsub = redis.pubsub()
    await pubsub.subscribe(f"events:{workspace_id}")
    msg = await pubsub.get_message(timeout=1.0)
    assert msg is not None and msg["type"] == "subscribe"
    return pubsub


async def _setup_agent_with_task(client):
    """Create a project with one agent and one open task.

    Returns dict with workspace_id, api_key, alias, task_ref, task_id.
    """
    project_slug = f"tclaim-{uuid.uuid4().hex[:8]}"
    repo_origin = f"git@github.com:test/task-claims-{project_slug}.git"

    # Create agent
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": project_slug,
            "project_name": project_slug,
            "alias": f"agent-{uuid.uuid4().hex[:4]}",
            "human_name": "Test Agent",
            "agent_type": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    api_key = resp.json()["api_key"]

    reg = await client.post(
        "/v1/workspaces/register",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"repo_origin": repo_origin, "role": "developer"},
    )
    assert reg.status_code == 200, reg.text
    workspace_id = reg.json()["workspace_id"]
    alias = reg.json()["alias"]

    # Heartbeat to populate Redis presence
    await client.post(
        "/v1/workspaces/heartbeat",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"workspace_id": workspace_id, "alias": alias, "repo_origin": repo_origin},
    )

    # Create a task via aweb tasks API
    task_resp = await client.post(
        "/v1/tasks",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"title": "Fix the login bug", "task_type": "bug", "priority": 1},
    )
    assert task_resp.status_code == 200, task_resp.text
    task_data = task_resp.json()

    return {
        "workspace_id": workspace_id,
        "api_key": api_key,
        "alias": alias,
        "task_ref": task_data["task_ref"],
        "task_id": task_data["task_id"],
        "project_slug": project_slug,
    }


@pytest.mark.asyncio
async def test_task_claimed_creates_bead_claim(db_infra, redis_client_async):
    """Updating a task to in_progress via aweb API creates a bead_claims row."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            # Claim the task by setting status to in_progress
            resp = await client.patch(
                f"/v1/tasks/{setup['task_ref']}",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text

            # Allow async hook to complete
            await asyncio.sleep(0.3)

            # Verify bead_claims has a row
            claims = await client.get(
                "/v1/claims",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert claims.status_code == 200, claims.text
            claim_list = claims.json()["claims"]
            matching = [c for c in claim_list if c["bead_id"] == setup["task_ref"]]
            assert len(matching) == 1, f"Expected 1 claim for {setup['task_ref']}, got {claim_list}"
            assert matching[0]["workspace_id"] == setup["workspace_id"]


@pytest.mark.asyncio
async def test_task_claimed_publishes_event(db_infra, redis_client_async):
    """Updating a task to in_progress publishes BeadClaimedEvent."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            pubsub = await _subscribe(redis_client_async, setup["workspace_id"])
            try:
                resp = await client.patch(
                    f"/v1/tasks/{setup['task_ref']}",
                    headers={"Authorization": f"Bearer {setup['api_key']}"},
                    json={"status": "in_progress"},
                )
                assert resp.status_code == 200, resp.text

                events = await _collect_events(pubsub)
                claimed = [e for e in events if e["type"] == "bead.claimed"]
                assert len(claimed) == 1, f"Expected 1 bead.claimed event, got {events}"
                assert claimed[0]["bead_id"] == setup["task_ref"]
                assert claimed[0]["workspace_id"] == setup["workspace_id"]
            finally:
                await pubsub.unsubscribe()
                await pubsub.aclose()


@pytest.mark.asyncio
async def test_task_closed_releases_claim(db_infra, redis_client_async):
    """Closing a task releases the bead claim and publishes BeadUnclaimedEvent."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            # First claim it
            resp = await client.patch(
                f"/v1/tasks/{setup['task_ref']}",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text
            await asyncio.sleep(0.3)

            # Verify claim exists
            claims = await client.get(
                "/v1/claims",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert len(claims.json()["claims"]) == 1

            # Now close it
            pubsub = await _subscribe(redis_client_async, setup["workspace_id"])
            try:
                resp = await client.patch(
                    f"/v1/tasks/{setup['task_ref']}",
                    headers={"Authorization": f"Bearer {setup['api_key']}"},
                    json={"status": "closed"},
                )
                assert resp.status_code == 200, resp.text
                await asyncio.sleep(0.3)

                # Claim should be gone
                claims = await client.get(
                    "/v1/claims",
                    headers={"Authorization": f"Bearer {setup['api_key']}"},
                )
                assert claims.json()["claims"] == [], "Closing a task should release all claims"

                # BeadUnclaimedEvent should have been published
                events = await _collect_events(pubsub)
                unclaimed = [e for e in events if e["type"] == "bead.unclaimed"]
                assert len(unclaimed) == 1, f"Expected 1 bead.unclaimed event, got {events}"
                assert unclaimed[0]["bead_id"] == setup["task_ref"]
            finally:
                await pubsub.unsubscribe()
                await pubsub.aclose()


@pytest.mark.asyncio
async def test_task_deleted_releases_claim(db_infra, redis_client_async):
    """Deleting a task releases the bead claim."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            # Claim it first
            resp = await client.patch(
                f"/v1/tasks/{setup['task_ref']}",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text
            await asyncio.sleep(0.3)

            # Verify claim exists
            claims = await client.get(
                "/v1/claims",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert len(claims.json()["claims"]) == 1

            # Delete the task
            resp = await client.delete(
                f"/v1/tasks/{setup['task_ref']}",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert resp.status_code == 200, resp.text
            await asyncio.sleep(0.3)

            # Claim should be gone
            claims = await client.get(
                "/v1/claims",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert claims.json()["claims"] == [], "Deleting a task should release all claims"


@pytest.mark.asyncio
async def test_task_claim_resolves_apex_from_parent(db_infra, redis_client_async):
    """Claiming a child task sets apex to the root parent task."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            # The setup task is a root task. Create a child task under it.
            child_resp = await client.post(
                "/v1/tasks",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
                json={
                    "title": "Subtask of the bug",
                    "task_type": "task",
                    "priority": 1,
                    "parent_task_id": setup["task_id"],
                },
            )
            assert child_resp.status_code == 200, child_resp.text
            child_ref = child_resp.json()["task_ref"]

            # Claim the child task
            resp = await client.patch(
                f"/v1/tasks/{child_ref}",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text
            await asyncio.sleep(0.3)

            # Check that the claim's apex points to the parent task
            server_db = db_infra.get_manager("server")
            claim = await server_db.fetch_one(
                "SELECT apex_bead_id FROM {{tables.bead_claims}} WHERE bead_id = $1",
                child_ref,
            )
            assert claim is not None, f"Expected claim for {child_ref}"
            assert (
                claim["apex_bead_id"] == setup["task_ref"]
            ), f"Expected apex to be parent {setup['task_ref']}, got {claim['apex_bead_id']}"


@pytest.mark.asyncio
async def test_task_claim_idempotent(db_infra, redis_client_async):
    """Setting a task to in_progress twice doesn't create duplicate claims."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            # Claim the task twice
            for _ in range(2):
                resp = await client.patch(
                    f"/v1/tasks/{setup['task_ref']}",
                    headers={"Authorization": f"Bearer {setup['api_key']}"},
                    json={"status": "in_progress"},
                )
                assert resp.status_code == 200, resp.text
                await asyncio.sleep(0.3)

            # Should still have exactly one claim
            claims = await client.get(
                "/v1/claims",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert claims.status_code == 200, claims.text
            matching = [c for c in claims.json()["claims"] if c["bead_id"] == setup["task_ref"]]
            assert len(matching) == 1, f"Expected 1 claim, got {matching}"


@pytest.mark.asyncio
async def test_task_title_in_workspace_list(db_infra, redis_client_async):
    """Claiming an aweb task shows its title in the workspace list."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            setup = await _setup_agent_with_task(client)

            # Claim the task
            resp = await client.patch(
                f"/v1/tasks/{setup['task_ref']}",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
                json={"status": "in_progress"},
            )
            assert resp.status_code == 200, resp.text
            await asyncio.sleep(0.3)

            # Fetch workspace list — claim should have the task title
            ws_resp = await client.get(
                "/v1/workspaces?include_claims=true",
                headers={"Authorization": f"Bearer {setup['api_key']}"},
            )
            assert ws_resp.status_code == 200, ws_resp.text
            workspaces = ws_resp.json()["workspaces"]
            ws = [w for w in workspaces if w["workspace_id"] == setup["workspace_id"]]
            assert len(ws) == 1
            claims = ws[0]["claims"]
            assert len(claims) == 1, f"Expected 1 claim, got {claims}"
            assert (
                claims[0]["title"] == "Fix the login bug"
            ), f"Expected task title in claim, got {claims[0]}"
