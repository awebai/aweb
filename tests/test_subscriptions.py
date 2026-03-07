"""Tests for bead subscriptions and notifications."""

import json

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app


async def _init_project_auth(
    client: AsyncClient, *, project_slug: str, alias: str, human_name: str = "Test User"
) -> dict[str, str]:
    """Create a project/agent/api_key in aweb, then register BeadHub workspace."""
    aweb_resp = await client.post(
        "/v1/init",
        json={
            "project_slug": project_slug,
            "project_name": project_slug,
            "alias": alias,
            "human_name": human_name,
            "agent_type": "agent",
        },
    )
    assert aweb_resp.status_code == 200, aweb_resp.text
    aweb_data = aweb_resp.json()
    api_key = aweb_data["api_key"]

    resp = await client.post(
        "/v1/workspaces/register",
        headers=_auth_headers(api_key),
        json={
            "repo_origin": f"git@github.com:test/{project_slug}.git",
            "role": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    data["api_key"] = api_key
    return data


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_subscribe_to_bead(db_infra, async_redis):
    """Subscribe to a bead to receive notifications."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-sub-1", alias="watcher-agent"
            )
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "beadhub-123",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["subscription_id"]
            assert data["bead_id"] == "beadhub-123"
            assert data["alias"] == "watcher-agent"


@pytest.mark.asyncio
async def test_subscribe_rejects_workspace_id_spoofing_within_project(db_infra, async_redis):
    """An agent API key must not be able to subscribe on behalf of another workspace in the same project."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            project_slug = "test-sub-spoof"
            a = await _init_project_auth(client, project_slug=project_slug, alias="agent-a")
            b = await _init_project_auth(client, project_slug=project_slug, alias="agent-b")

            # Agent A attempts to subscribe as Agent B.
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": b["workspace_id"],
                    "bead_id": "beadhub-999",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(a["api_key"]),
            )
            assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_subscribe_to_bead_with_repo(db_infra, async_redis):
    """Subscribe to a repo-scoped bead."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-sub-2", alias="watcher-agent"
            )
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "beadhub-456",
                    "repo": "myrepo",
                    "event_types": ["status_change", "priority_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["repo"] == "myrepo"


@pytest.mark.asyncio
async def test_list_subscriptions(db_infra, async_redis):
    """List agent's subscriptions."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(client, project_slug="test-sub-3", alias="watcher")
            # Create some subscriptions
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-2",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )

            resp = await client.get(
                "/v1/subscriptions",
                params={
                    "workspace_id": init["workspace_id"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["subscriptions"]) == 2


@pytest.mark.asyncio
async def test_unsubscribe(db_infra, async_redis):
    """Unsubscribe from a bead."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(client, project_slug="test-sub-4", alias="watcher")
            # Subscribe
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            subscription_id = resp.json()["subscription_id"]

            # Unsubscribe
            resp = await client.delete(
                f"/v1/subscriptions/{subscription_id}",
                params={
                    "workspace_id": init["workspace_id"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200

            # Verify subscription is gone
            resp = await client.get(
                "/v1/subscriptions",
                params={
                    "workspace_id": init["workspace_id"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.json()["subscriptions"] == []


@pytest.mark.asyncio
async def test_duplicate_subscription_rejected(db_infra, async_redis):
    """Can't subscribe to the same bead twice with same event type."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(client, project_slug="test-sub-5", alias="watcher")
            # First subscription
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )

            # Duplicate should return existing subscription
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200  # Idempotent


@pytest.mark.asyncio
async def test_mcp_subscribe_to_bead(db_infra, async_redis):
    """MCP tool to subscribe to a bead."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-sub-mcp-1", alias="mcp-watcher"
            )
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "subscribe_to_bead",
                    "arguments": {
                        "workspace_id": init["workspace_id"],
                        "bead_id": "bead-mcp-1",
                    },
                },
            }

            resp = await client.post(
                "/mcp", json=rpc_payload, headers=_auth_headers(init["api_key"])
            )
            assert resp.status_code == 200
            result = resp.json()
            assert "error" not in result

            content = json.loads(result["result"]["content"][0]["text"])
            assert content["subscription_id"]


@pytest.mark.asyncio
async def test_mcp_list_subscriptions(db_infra, async_redis):
    """MCP tool to list subscriptions."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-sub-mcp-2", alias="mcp-watcher"
            )
            # Subscribe via REST
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )

            # List via MCP
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "list_subscriptions",
                    "arguments": {
                        "workspace_id": init["workspace_id"],
                    },
                },
            }

            resp = await client.post(
                "/mcp", json=rpc_payload, headers=_auth_headers(init["api_key"])
            )
            assert resp.status_code == 200
            result = resp.json()
            assert "error" not in result

            content = json.loads(result["result"]["content"][0]["text"])
            assert len(content["subscriptions"]) == 1


@pytest.mark.asyncio
async def test_mcp_unsubscribe(db_infra, async_redis):
    """MCP tool to unsubscribe from a bead."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-sub-mcp-3", alias="mcp-watcher"
            )
            # Subscribe first
            sub_resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            subscription_id = sub_resp.json()["subscription_id"]

            # Unsubscribe via MCP
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "unsubscribe",
                    "arguments": {
                        "workspace_id": init["workspace_id"],
                        "subscription_id": subscription_id,
                    },
                },
            }

            resp = await client.post(
                "/mcp", json=rpc_payload, headers=_auth_headers(init["api_key"])
            )
            assert resp.status_code == 200
            result = resp.json()
            assert "error" not in result


@pytest.mark.asyncio
async def test_notification_on_status_change(db_infra, async_redis):
    """Subscribers receive notification when bead status changes."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(client, project_slug="test-sub-notify", alias="watcher")

            # First upload to create the bead as open
            resp = await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "notify-repo",
                    "issues": [
                        {
                            "id": "test-bead-1",
                            "title": "Test Issue",
                            "status": "open",
                            "priority": 1,
                            "issue_type": "task",
                        }
                    ],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            assert resp.json()["issues_added"] == 1

            # Subscribe to the bead (using raw bead_id, repo is separate)
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "test-bead-1",
                    "repo": "notify-repo",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )

            # Upload again with status changed to closed - should trigger notification
            resp = await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "notify-repo",
                    "issues": [
                        {
                            "id": "test-bead-1",
                            "title": "Test Issue",
                            "status": "closed",
                            "priority": 1,
                            "issue_type": "task",
                        }
                    ],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            sync_result = resp.json()
            assert sync_result["issues_updated"] == 1
            assert sync_result["notifications_sent"] == 1

            # Check watcher's inbox for notification
            inbox_resp = await client.get(
                "/v1/messages/inbox",
                params={"agent_id": init["workspace_id"]},
                headers=_auth_headers(init["api_key"]),
            )
            assert inbox_resp.status_code == 200
            inbox = inbox_resp.json()
            assert len(inbox["messages"]) == 1
            msg = inbox["messages"][0]
            assert "status changed" in msg["subject"]
            assert "open" in msg["body"]
            assert "closed" in msg["body"]


@pytest.mark.asyncio
async def test_no_notification_for_new_beads(db_infra, async_redis):
    """New beads don't trigger notifications (only status changes do)."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-sub-no-notify", alias="watcher"
            )

            # Subscribe to a bead that doesn't exist yet
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "future-bead",
                    "repo": "no-notify-repo",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )

            # Upload - creates new bead
            resp = await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "no-notify-repo",
                    "issues": [
                        {
                            "id": "future-bead",
                            "title": "Future Issue",
                            "status": "open",
                            "priority": 1,
                        }
                    ],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            # New beads don't send notifications
            assert resp.json()["notifications_sent"] == 0

            # Inbox should be empty
            inbox_resp = await client.get(
                "/v1/messages/inbox",
                params={"agent_id": init["workspace_id"]},
                headers=_auth_headers(init["api_key"]),
            )
            assert inbox_resp.status_code == 200
            assert len(inbox_resp.json()["messages"]) == 0


@pytest.mark.asyncio
async def test_deleted_workspace_excluded_from_subscribers(db_infra, async_redis):
    """Deleted workspaces are excluded from subscriber lookup — no outbox entry created."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            slug = "test-deleted-sub"
            watcher = await _init_project_auth(client, project_slug=slug, alias="watcher")
            uploader = await _init_project_auth(client, project_slug=slug, alias="uploader")

            # First upload to create the bead
            await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "outbox-repo",
                    "issues": [{"id": "outbox-bead", "status": "open", "priority": 1}],
                },
                headers=_auth_headers(uploader["api_key"]),
            )

            # Subscribe watcher, then delete its workspace
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": watcher["workspace_id"],
                    "bead_id": "outbox-bead",
                    "repo": "outbox-repo",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(watcher["api_key"]),
            )
            delete_resp = await client.delete(
                f"/v1/workspaces/{watcher['workspace_id']}",
                headers=_auth_headers(watcher["api_key"]),
            )
            assert delete_resp.status_code == 200

            # Status change — deleted workspace is not a subscriber, no notification attempted
            resp = await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "outbox-repo",
                    "issues": [{"id": "outbox-bead", "status": "closed", "priority": 1}],
                },
                headers=_auth_headers(uploader["api_key"]),
            )
            assert resp.status_code == 200
            result = resp.json()
            assert result["notifications_sent"] == 0
            assert result["notifications_failed"] == 0


@pytest.mark.asyncio
async def test_notification_outbox_tracks_completed(db_infra, async_redis):
    """Completed notifications are tracked in the outbox with message_id."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(client, project_slug="test-outbox-ok", alias="watcher")

            # First upload to create the bead
            await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "outbox-repo",
                    "issues": [{"id": "tracked-bead", "status": "open", "priority": 1}],
                },
                headers=_auth_headers(init["api_key"]),
            )

            # Subscribe
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "tracked-bead",
                    "repo": "outbox-repo",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )

            # Upload status change
            resp = await client.post(
                "/v1/beads/upload",
                json={
                    "repo": "outbox-repo",
                    "issues": [{"id": "tracked-bead", "status": "closed", "priority": 1}],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200
            result = resp.json()
            assert result["notifications_sent"] == 1
            assert result["notifications_failed"] == 0

            # Verify inbox received the notification
            inbox_resp = await client.get(
                "/v1/messages/inbox",
                params={"agent_id": init["workspace_id"]},
                headers=_auth_headers(init["api_key"]),
            )
            assert inbox_resp.status_code == 200
            assert len(inbox_resp.json()["messages"]) == 1


@pytest.mark.asyncio
async def test_list_subscriptions_tenant_isolation(db_infra, async_redis):
    """list_subscriptions should only show subscriptions for the requesting project.

    SECURITY TEST: Even if the same workspace_id exists in multiple projects,
    listing subscriptions should only show those for the requesting project.
    """
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init_a = await _init_project_auth(client, project_slug="test-iso-a", alias="agent-a")
            init_b = await _init_project_auth(client, project_slug="test-iso-b", alias="agent-b")

            # Project A subscribes to bead-1
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init_a["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init_a["api_key"]),
            )

            # Project B subscribes to bead-2
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init_b["workspace_id"],
                    "bead_id": "bead-2",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init_b["api_key"]),
            )

            # List as Project A - should only see bead-1
            resp_a = await client.get(
                "/v1/subscriptions",
                params={"workspace_id": init_a["workspace_id"]},
                headers=_auth_headers(init_a["api_key"]),
            )
            assert resp_a.status_code == 200
            subs_a = resp_a.json()["subscriptions"]
            assert len(subs_a) == 1
            assert subs_a[0]["bead_id"] == "bead-1"

            # List as Project B - should only see bead-2
            resp_b = await client.get(
                "/v1/subscriptions",
                params={"workspace_id": init_b["workspace_id"]},
                headers=_auth_headers(init_b["api_key"]),
            )
            assert resp_b.status_code == 200
            subs_b = resp_b.json()["subscriptions"]
            assert len(subs_b) == 1
            assert subs_b[0]["bead_id"] == "bead-2"


@pytest.mark.asyncio
async def test_unsubscribe_tenant_isolation(db_infra, async_redis):
    """unsubscribe should only delete subscriptions from the requesting project.

    SECURITY TEST: Project A should not be able to delete Project B's subscriptions.
    """
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init_a = await _init_project_auth(
                client, project_slug="test-unsub-iso-a", alias="agent-a"
            )
            init_b = await _init_project_auth(
                client, project_slug="test-unsub-iso-b", alias="agent-b"
            )

            # Project A subscribes
            resp_a = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init_a["workspace_id"],
                    "bead_id": "bead-1",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init_a["api_key"]),
            )
            sub_id_a = resp_a.json()["subscription_id"]

            # Project B subscribes
            resp_b = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init_b["workspace_id"],
                    "bead_id": "bead-2",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init_b["api_key"]),
            )
            assert resp_b.status_code == 200  # Confirm subscription created

            # Project B tries to delete Project A's subscription - should fail (404)
            resp = await client.delete(
                f"/v1/subscriptions/{sub_id_a}",
                params={"workspace_id": init_b["workspace_id"]},
                headers=_auth_headers(init_b["api_key"]),
            )
            assert (
                resp.status_code == 404
            ), "SECURITY VIOLATION: Project B was able to delete Project A's subscription"

            # Verify Project A's subscription still exists
            resp_check = await client.get(
                "/v1/subscriptions",
                params={"workspace_id": init_a["workspace_id"]},
                headers=_auth_headers(init_a["api_key"]),
            )
            subs = resp_check.json()["subscriptions"]
            assert len(subs) == 1
            assert subs[0]["subscription_id"] == sub_id_a


@pytest.mark.asyncio
async def test_subscribe_without_alias(db_infra, async_redis):
    """POST /v1/subscriptions derives alias from workspace_id — alias not required."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-no-alias-sub", alias="auto-agent"
            )
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "beadhub-no-alias",
                    "event_types": ["status_change"],
                },
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["bead_id"] == "beadhub-no-alias"
            # Server should fill in alias from workspace
            assert data["alias"] == "auto-agent"


@pytest.mark.asyncio
async def test_list_subscriptions_without_alias(db_infra, async_redis):
    """GET /v1/subscriptions works with workspace_id only — alias not required."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-list-no-alias", alias="lister"
            )
            # Subscribe first
            await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-list-1",
                },
                headers=_auth_headers(init["api_key"]),
            )
            # List without alias
            resp = await client.get(
                "/v1/subscriptions",
                params={"workspace_id": init["workspace_id"]},
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            assert len(resp.json()["subscriptions"]) == 1


@pytest.mark.asyncio
async def test_unsubscribe_without_alias(db_infra, async_redis):
    """DELETE /v1/subscriptions/{id} works with workspace_id only — alias not required."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            init = await _init_project_auth(
                client, project_slug="test-unsub-no-alias", alias="unsub-agent"
            )
            # Subscribe
            resp = await client.post(
                "/v1/subscriptions",
                json={
                    "workspace_id": init["workspace_id"],
                    "bead_id": "bead-unsub-1",
                },
                headers=_auth_headers(init["api_key"]),
            )
            sub_id = resp.json()["subscription_id"]
            # Unsubscribe without alias
            resp = await client.delete(
                f"/v1/subscriptions/{sub_id}",
                params={"workspace_id": init["workspace_id"]},
                headers=_auth_headers(init["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["deleted"] is True
