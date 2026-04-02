from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.coordination.routes.project_instructions import (
    get_active_project_instructions,
    instructions_router,
)
from aweb.coordination.routes.project_roles import roles_router
from aweb.db import get_db_infra
from aweb.redis_client import get_redis
from aweb.routes.init import bootstrap_router
from aweb.routes.reservations import router as reservations_router


class _FakeRedis:
    async def eval(self, _script: str, _num_keys: int, _key: str, _window_seconds: int) -> int:
        return 1


def _build_roles_test_app(*, aweb_db, server_db) -> FastAPI:
    class _DbInfra:
        is_initialized = True

        def get_manager(self, name: str = "aweb"):
            if name == "aweb":
                return aweb_db
            if name == "server":
                return server_db
            raise KeyError(name)

    app = FastAPI(title="aweb roles bootstrap test")
    app.include_router(bootstrap_router)
    app.include_router(instructions_router)
    app.include_router(roles_router)
    app.include_router(reservations_router)
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra()
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_fresh_project_bootstraps_canonical_project_roles_and_instructions(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db

    project_roles_exists = await server_db.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'server' AND table_name = 'project_roles'
        )
        """
    )
    project_policies_exists = await server_db.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'server' AND table_name = 'project_policies'
        )
        """
    )
    active_project_roles_id_exists = await server_db.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'server'
              AND table_name = 'projects'
              AND column_name = 'active_project_roles_id'
        )
        """
    )
    project_instructions_exists = await server_db.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'server' AND table_name = 'project_instructions'
        )
        """
    )
    active_project_instructions_id_exists = await server_db.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'server'
              AND table_name = 'projects'
              AND column_name = 'active_project_instructions_id'
        )
        """
    )
    active_policy_id_exists = await server_db.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'server'
              AND table_name = 'projects'
              AND column_name = 'active_policy_id'
        )
        """
    )

    assert project_roles_exists is True
    assert project_instructions_exists is True
    assert project_policies_exists is False
    assert active_project_roles_id_exists is True
    assert active_project_instructions_id_exists is True
    assert active_policy_id_exists is False

    app = _build_roles_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=server_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        slug = f"roles-bootstrap-{uuid.uuid4().hex[:8]}"
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
        api_key = created_data["api_key"]
        assert created_data["workspace_id"] == created_data["identity_id"]
        assert created_data["workspace_created"] is True

        roles = await client.get(
            "/v1/roles/active",
            params={"only_selected": "false"},
            headers=_auth_headers(api_key),
        )
        assert roles.status_code == 200, roles.text
        data = roles.json()
        assert data["project_roles_id"]
        assert data["active_project_roles_id"] == data["project_roles_id"]
        assert data["roles"]
        assert "developer" in data["roles"]
        assert "invariants" not in data

        instructions = await client.get(
            "/v1/instructions/active",
            headers=_auth_headers(api_key),
        )
        assert instructions.status_code == 200, instructions.text
        instructions_data = instructions.json()
        assert instructions_data["project_instructions_id"]
        assert (
            instructions_data["active_project_instructions_id"]
            == instructions_data["project_instructions_id"]
        )
        assert instructions_data["document"]["format"] == "markdown"
        assert instructions_data["document"]["body_md"]

        acquired = await client.post(
            "/v1/reservations",
            headers=_auth_headers(api_key),
            json={"resource_key": "src/app.py", "ttl_seconds": 60},
        )
        assert acquired.status_code == 200, acquired.text

        renewed = await client.post(
            "/v1/reservations/renew",
            headers=_auth_headers(api_key),
            json={"resource_key": "src/app.py", "ttl_seconds": 60},
        )
        assert renewed.status_code == 200, renewed.text

        released = await client.post(
            "/v1/reservations/release",
            headers=_auth_headers(api_key),
            json={"resource_key": "src/app.py"},
        )
        assert released.status_code == 200, released.text


@pytest.mark.asyncio
async def test_legacy_invariants_backfill_active_project_instructions(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    app = _build_roles_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=server_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        slug = f"roles-legacy-{uuid.uuid4().hex[:8]}"
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
        api_key = created_data["api_key"]
        project_id = created_data["project_id"]

        await server_db.execute(
            "DELETE FROM {{tables.project_instructions}} WHERE project_id = $1",
            project_id,
        )
        await server_db.execute(
            "UPDATE {{tables.projects}} SET active_project_instructions_id = NULL WHERE id = $1",
            project_id,
        )

        legacy_bundle = {
            "invariants": [
                {
                    "id": "communication.mail-first",
                    "title": "Mail first",
                    "body_md": "Use `aw mail` for non-blocking coordination.",
                }
            ],
            "roles": {
                "developer": {
                    "title": "Developer",
                    "playbook_md": "Ship code",
                }
            },
            "adapters": {},
        }
        legacy_role = await server_db.fetch_one(
            """
            INSERT INTO {{tables.project_roles}} (
                project_id,
                version,
                bundle_json,
                created_by_workspace_id
            )
            VALUES ($1, $2, $3::jsonb, NULL)
            RETURNING project_roles_id
            """,
            project_id,
            99,
            json.dumps(legacy_bundle),
        )
        await server_db.execute(
            "UPDATE {{tables.projects}} SET active_project_roles_id = $2 WHERE id = $1",
            project_id,
            legacy_role["project_roles_id"],
        )

        instructions = await client.get(
            "/v1/instructions/active",
            headers=_auth_headers(api_key),
        )
        assert instructions.status_code == 200, instructions.text
        data = instructions.json()
        assert data["project_instructions_id"]
        assert "Mail first" in data["document"]["body_md"]
        assert "Use `aw mail` for non-blocking coordination." in data["document"]["body_md"]


@pytest.mark.asyncio
async def test_concurrent_bootstrap_does_not_500(aweb_cloud_db):
    """Two concurrent first reads must not race on bootstrap INSERT."""
    server_db = aweb_cloud_db.oss_db
    app = _build_roles_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=server_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        slug = f"race-{uuid.uuid4().hex[:8]}"
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
        api_key = created_data["api_key"]
        project_id = created_data["project_id"]

        # Remove bootstrapped instructions so the next reads trigger bootstrap
        await server_db.execute(
            "DELETE FROM {{tables.project_instructions}} WHERE project_id = $1",
            project_id,
        )
        await server_db.execute(
            "UPDATE {{tables.projects}} SET active_project_instructions_id = NULL WHERE id = $1",
            project_id,
        )

        # Concurrent bootstrap calls — both see no active instructions and
        # both attempt to create version 1.  Depending on timing, one may
        # hit a duplicate-key UniqueViolationError.  The fix must ensure
        # neither call raises and both return a valid result.
        results = await asyncio.gather(
            get_active_project_instructions(
                server_db, project_id, bootstrap_if_missing=True
            ),
            get_active_project_instructions(
                server_db, project_id, bootstrap_if_missing=True
            ),
        )
        assert results[0] is not None
        assert results[1] is not None

        # After the race, the project must have exactly one active version
        active = await client.get(
            "/v1/instructions/active",
            headers=_auth_headers(api_key),
        )
        assert active.status_code == 200, active.text


@pytest.mark.asyncio
async def test_project_roles_can_be_deactivated_to_empty_bundle(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    app = _build_roles_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=server_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        slug = f"roles-deactivate-{uuid.uuid4().hex[:8]}"
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
        api_key = created_data["api_key"]

        initial_roles = await client.get(
            "/v1/roles/active",
            params={"only_selected": "false"},
            headers=_auth_headers(api_key),
        )
        assert initial_roles.status_code == 200, initial_roles.text
        initial_data = initial_roles.json()
        assert initial_data["roles"]

        deactivated = await client.post(
            "/v1/roles/deactivate",
            headers=_auth_headers(api_key),
        )
        assert deactivated.status_code == 200, deactivated.text
        deactivated_data = deactivated.json()
        assert deactivated_data["deactivated"] is True
        assert deactivated_data["version"] == initial_data["version"] + 1
        assert deactivated_data["active_project_roles_id"] != initial_data["project_roles_id"]

        roles = await client.get(
            "/v1/roles/active",
            params={"only_selected": "false"},
            headers=_auth_headers(api_key),
        )
        assert roles.status_code == 200, roles.text
        data = roles.json()
        assert data["project_roles_id"] == deactivated_data["active_project_roles_id"]
        assert data["active_project_roles_id"] == deactivated_data["active_project_roles_id"]
        assert data["roles"] == {}
        assert data["adapters"] == {}
