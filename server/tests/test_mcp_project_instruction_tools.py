from __future__ import annotations

import json
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.coordination.routes.project_instructions import (
    activate_project_instructions,
    create_project_instructions_version,
    instructions_router,
)
from aweb.coordination.routes.project_roles import roles_router
from aweb.db import get_db_infra
from aweb.mcp.auth import AuthContext, _auth_context
from aweb.mcp.tools.project_instructions import instructions_history, instructions_show
from aweb.mcp.tools.project_roles import roles_show
from aweb.redis_client import get_redis
from aweb.routes.init import bootstrap_router


class _FakeRedis:
    async def eval(self, _script: str, _num_keys: int, _key: str, _window_seconds: int) -> int:
        return 1


class _DbInfra:
    is_initialized = True

    def __init__(self, *, aweb_db, server_db):
        self._aweb_db = aweb_db
        self._server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self._aweb_db
        if name == "server":
            return self._server_db
        raise KeyError(name)


def _build_app(*, aweb_db, server_db) -> FastAPI:
    app = FastAPI(title="aweb mcp tools test")
    app.include_router(bootstrap_router)
    app.include_router(instructions_router)
    app.include_router(roles_router)
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra(aweb_db=aweb_db, server_db=server_db)
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_mcp_instruction_tools_match_roles_only_model(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    aweb_db = aweb_cloud_db.aweb_db
    app = _build_app(aweb_db=aweb_db, server_db=server_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        slug = f"mcp-instructions-{uuid.uuid4().hex[:8]}"
        created = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": slug,
                "namespace_slug": slug,
                "alias": "alice",
            },
        )
        assert created.status_code == 200, created.text
        created_data = created.json()

        active = await client.get(
            "/v1/instructions/active",
            headers=_auth_headers(created_data["api_key"]),
        )
        assert active.status_code == 200, active.text
        active_data = active.json()

        second_version = await create_project_instructions_version(
            server_db,
            project_id=created_data["project_id"],
            base_project_instructions_id=active_data["project_instructions_id"],
            document={
                "body_md": "## Shared Rules\n\nUse `aw instructions show`.\n",
                "format": "markdown",
            },
            created_by_workspace_id=created_data["workspace_id"],
        )
        await activate_project_instructions(
            server_db,
            project_id=created_data["project_id"],
            project_instructions_id=second_version.project_instructions_id,
        )

    db_infra = _DbInfra(aweb_db=aweb_db, server_db=server_db)
    token = _auth_context.set(
        AuthContext(
            project_id=created_data["project_id"],
            agent_id=created_data["agent_id"],
        )
    )
    try:
        roles_payload = json.loads(await roles_show(db_infra, only_selected=False))
        assert "invariants" not in roles_payload
        assert "roles" in roles_payload
        assert "developer" in roles_payload["roles"]

        active_payload = json.loads(await instructions_show(db_infra))
        assert active_payload["project_instructions_id"] == second_version.project_instructions_id
        assert (
            active_payload["active_project_instructions_id"]
            == second_version.project_instructions_id
        )
        assert "Use `aw instructions show`." in active_payload["document"]["body_md"]

        explicit_payload = json.loads(
            await instructions_show(
                db_infra, project_instructions_id=active_data["project_instructions_id"]
            )
        )
        assert explicit_payload["project_instructions_id"] == active_data["project_instructions_id"]
        assert (
            explicit_payload["active_project_instructions_id"]
            == second_version.project_instructions_id
        )

        history_payload = json.loads(await instructions_history(db_infra, limit=5))
        versions = history_payload["project_instructions_versions"]
        assert [item["version"] for item in versions[:2]] == [2, 1]
        assert versions[0]["is_active"] is True
        assert versions[1]["is_active"] is False
    finally:
        _auth_context.reset(token)
