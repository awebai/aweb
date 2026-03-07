"""Tests for escalation input validation.

These tests verify that list_escalations properly validates:
- status: only allows valid values (pending, responded, expired)
- alias: only allows valid format (alphanumeric with hyphens/underscores)
"""

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app


async def _init_auth(client: AsyncClient) -> None:
    project_slug = f"escalations-{uuid.uuid4().hex[:8]}"
    repo_origin = f"git@github.com:test/escalations-{uuid.uuid4().hex[:8]}.git"
    aweb_resp = await client.post(
        "/v1/init",
        json={
            "project_slug": project_slug,
            "project_name": project_slug,
            "alias": f"init-{uuid.uuid4().hex[:8]}",
            "human_name": "Init User",
            "agent_type": "agent",
        },
    )
    assert aweb_resp.status_code == 200, aweb_resp.text
    api_key = aweb_resp.json()["api_key"]

    reg = await client.post(
        "/v1/workspaces/register",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"repo_origin": repo_origin, "role": "agent"},
    )
    assert reg.status_code == 200, reg.text
    client.headers["Authorization"] = f"Bearer {api_key}"


class TestListEscalationsValidation:
    """Tests for list_escalations input validation."""

    @pytest.mark.asyncio
    async def test_list_escalations_rejects_invalid_status(self, db_infra, redis_client_async):
        """Invalid status values should return 422."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                # Short SQL injection attempt (within max_length)
                resp = await client.get("/v1/escalations?status=pending'--")
                assert resp.status_code == 422
                assert "Invalid status" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_escalations_rejects_malformed_status(self, db_infra, redis_client_async):
        """Status with special characters should return 422."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?status=not_a_valid_status")
                assert resp.status_code == 422
                assert "Invalid status" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_escalations_accepts_valid_status_pending(
        self, db_infra, redis_client_async
    ):
        """Status 'pending' should be accepted."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?status=pending")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_escalations_accepts_valid_status_responded(
        self, db_infra, redis_client_async
    ):
        """Status 'responded' should be accepted."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?status=responded")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_escalations_accepts_valid_status_expired(
        self, db_infra, redis_client_async
    ):
        """Status 'expired' should be accepted."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?status=expired")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_escalations_rejects_invalid_alias(self, db_infra, redis_client_async):
        """Invalid alias format should return 422."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                # SQL injection attempt in alias
                resp = await client.get("/v1/escalations?alias=test'; DROP TABLE escalations;--")
                assert resp.status_code == 422
                assert "Invalid alias" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_escalations_rejects_alias_with_spaces(self, db_infra, redis_client_async):
        """Alias with spaces should return 422."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?alias=test%20agent")
                assert resp.status_code == 422
                assert "Invalid alias" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_escalations_accepts_valid_alias(self, db_infra, redis_client_async):
        """Valid alias format should be accepted."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?alias=claude-main")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_escalations_accepts_valid_alias_with_underscore(
        self, db_infra, redis_client_async
    ):
        """Valid alias with underscore should be accepted."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?alias=claude_main")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_escalations_combined_valid_filters(self, db_infra, redis_client_async):
        """Combined valid status and alias should work."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?status=pending&alias=claude-main")
                assert resp.status_code == 200


class TestListEscalationsPagination:
    """Tests for list_escalations pagination."""

    @pytest.mark.asyncio
    async def test_list_escalations_pagination_response_schema(self, db_infra, redis_client_async):
        """Response should include pagination fields."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations")
                assert resp.status_code == 200
                data = resp.json()
                assert "escalations" in data
                assert "has_more" in data
                assert isinstance(data["has_more"], bool)
                assert "next_cursor" in data
                # next_cursor should be None when has_more is False
                if not data["has_more"]:
                    assert data["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_list_escalations_accepts_limit_param(self, db_infra, redis_client_async):
        """Limit parameter should be accepted."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations?limit=10")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_escalations_rejects_invalid_limit(self, db_infra, redis_client_async):
        """Invalid limit values should return 422."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                # Limit too high
                resp = await client.get("/v1/escalations?limit=1000")
                assert resp.status_code == 422

                # Limit zero
                resp = await client.get("/v1/escalations?limit=0")
                assert resp.status_code == 422

                # Limit negative
                resp = await client.get("/v1/escalations?limit=-1")
                assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_list_escalations_rejects_invalid_cursor(self, db_infra, redis_client_async):
        """Invalid cursor should return 422."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                # Not valid base64
                resp = await client.get("/v1/escalations?cursor=not-valid-base64!!!")
                assert resp.status_code == 422
                assert "cursor" in resp.json()["detail"].lower()


class TestEscalationIdValidation:
    """Tests for escalation_id UUID validation in path parameters."""

    @pytest.mark.asyncio
    async def test_get_escalation_rejects_non_uuid(self, db_infra, redis_client_async):
        """GET /v1/escalations/{id} should return 422 for non-UUID escalation_id."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.get("/v1/escalations/not-a-uuid")
                assert resp.status_code == 422
                assert "escalation_id" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_respond_escalation_rejects_non_uuid(self, db_infra, redis_client_async):
        """POST /v1/escalations/{id}/respond should return 422 for non-UUID escalation_id."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                resp = await client.post(
                    "/v1/escalations/not-a-uuid/respond",
                    json={"response": "approve"},
                )
                assert resp.status_code == 422
                assert "escalation_id" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_get_escalation_accepts_valid_uuid(self, db_infra, redis_client_async):
        """GET /v1/escalations/{uuid} should not fail on UUID validation (may 404)."""
        app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
        async with LifespanManager(app):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                await _init_auth(client)
                valid_uuid = str(uuid.uuid4())
                resp = await client.get(f"/v1/escalations/{valid_uuid}")
                # Should pass UUID validation (404 is fine — escalation doesn't exist)
                assert resp.status_code == 404
