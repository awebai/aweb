from __future__ import annotations
import pytest; pytest.skip("Tests reference removed schema — to be deleted in aaez.5", allow_module_level=True)

import uuid
from datetime import datetime
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.coordination.routes.workspaces import router as workspaces_router
from aweb.db import get_db_infra
from aweb.redis_client import get_redis
from aweb.routes._reservation_utils import reservation_prefix_like
from aweb.routes.init import bootstrap_router, router as init_router
from aweb.routes.reservations import router as reservations_router
from aweb.routes.status import router as status_router


class _FakeRedis:
    class _Pipeline:
        def __init__(self) -> None:
            self._responses: list[dict[str, str]] = []

        def hgetall(self, _key: str) -> "_FakeRedis._Pipeline":
            self._responses.append({})
            return self

        async def execute(self) -> list[dict[str, str]]:
            return self._responses

    async def eval(self, _script: str, _num_keys: int, _key: str, _window_seconds: int) -> int:
        return 1

    async def ttl(self, _key: str) -> int:
        return -1

    async def delete(self, _key: str) -> int:
        return 1

    def pipeline(self) -> "_FakeRedis._Pipeline":
        return self._Pipeline()


def _build_reservations_test_app(*, aweb_db, server_db) -> FastAPI:
    class _DbInfra:
        is_initialized = True

        def get_manager(self, name: str = "aweb"):
            if name == "aweb":
                return aweb_db
            if name == "server":
                return server_db
            raise KeyError(name)

    app = FastAPI(title="aweb reservations test")
    app.include_router(bootstrap_router)
    app.include_router(init_router)
    app.include_router(workspaces_router)
    app.include_router(reservations_router)
    app.include_router(status_router)
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra()
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.parametrize(
    ("prefix", "want"),
    [
        ("src/foo_bar/", r"src/foo\_bar/%"),
        ("src/foo%bar/", r"src/foo\%bar/%"),
        (r"src/foo\bar/", r"src/foo\\bar/%"),
    ],
)
def test_reservation_prefix_like_escapes_wildcards(prefix: str, want: str):
    assert reservation_prefix_like(prefix) == want


async def _create_registered_workspace(
    client: AsyncClient,
    *,
    project_slug: str,
    alias: str,
    role: str,
    repo_origin: str,
) -> dict[str, str]:
    created = await client.post(
        "/api/v1/create-project",
        json={
            "project_slug": project_slug,
            "namespace_slug": project_slug,
            "alias": alias,
        },
    )
    assert created.status_code == 200, created.text
    data = created.json()

    registered = await client.post(
        "/v1/workspaces/register",
        headers=_auth_headers(data["api_key"]),
        json={
            "repo_origin": repo_origin,
            "role": role,
            "hostname": "test-host",
            "workspace_path": f"/tmp/{alias}",
        },
    )
    assert registered.status_code == 200, registered.text
    return data


async def _init_workspace(
    client: AsyncClient,
    *,
    project_api_key: str,
    project_id: str,
    alias: str,
    role: str,
    repo_origin: str,
) -> dict[str, str]:
    created = await client.post(
        "/v1/workspaces/init",
        headers=_auth_headers(project_api_key),
        json={
            "project_id": project_id,
            "alias": alias,
            "role": role,
            "repo_origin": repo_origin,
            "hostname": "test-host",
            "workspace_path": f"/tmp/{alias}",
        },
    )
    assert created.status_code == 200, created.text
    return created.json()


@pytest.mark.asyncio
async def test_reservation_lifecycle_conflict_and_list_metadata(aweb_cloud_db):
    app = _build_reservations_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        suffix = uuid.uuid4().hex[:8]
        project_slug = f"reservations-{suffix}"
        repo_origin = f"https://github.com/example/{project_slug}.git"
        coordinator = await _create_registered_workspace(
            client,
            project_slug=project_slug,
            alias="coord-bot",
            role="coordinator",
            repo_origin=repo_origin,
        )
        peer = await _init_workspace(
            client,
            project_api_key=coordinator["api_key"],
            project_id=coordinator["project_id"],
            alias="peer-bot",
            role="developer",
            repo_origin=repo_origin,
        )

        acquired = await client.post(
            "/v1/reservations",
            headers=_auth_headers(coordinator["api_key"]),
            json={
                "resource_key": "src/app.py",
                "ttl_seconds": 60,
                "metadata": {"reason": "editing coordinator task"},
            },
        )
        assert acquired.status_code == 200, acquired.text
        acquired_data = acquired.json()
        assert acquired_data["status"] == "acquired"
        assert acquired_data["holder_alias"] == "coord-bot"

        listed = await client.get(
            "/v1/reservations",
            headers=_auth_headers(coordinator["api_key"]),
        )
        assert listed.status_code == 200, listed.text
        reservations = listed.json()["reservations"]
        assert len(reservations) == 1
        assert reservations[0]["resource_key"] == "src/app.py"
        assert reservations[0]["holder_alias"] == "coord-bot"
        assert reservations[0]["reason"] == "editing coordinator task"
        assert reservations[0]["ttl_remaining_seconds"] > 0

        conflicted = await client.post(
            "/v1/reservations",
            headers=_auth_headers(peer["api_key"]),
            json={"resource_key": "src/app.py", "ttl_seconds": 30},
        )
        assert conflicted.status_code == 409, conflicted.text
        assert conflicted.json()["detail"] == "reservation is already held"
        assert conflicted.json()["holder_alias"] == "coord-bot"

        renewed = await client.post(
            "/v1/reservations/renew",
            headers=_auth_headers(coordinator["api_key"]),
            json={"resource_key": "src/app.py", "ttl_seconds": 120},
        )
        assert renewed.status_code == 200, renewed.text
        assert renewed.json()["status"] == "renewed"
        assert datetime.fromisoformat(renewed.json()["expires_at"]) > datetime.fromisoformat(
            acquired_data["expires_at"]
        )

        released = await client.post(
            "/v1/reservations/release",
            headers=_auth_headers(coordinator["api_key"]),
            json={"resource_key": "src/app.py"},
        )
        assert released.status_code == 200, released.text
        assert released.json() == {
            "status": "released",
            "resource_key": "src/app.py",
        }

        reacquired = await client.post(
            "/v1/reservations",
            headers=_auth_headers(peer["api_key"]),
            json={"resource_key": "src/app.py", "ttl_seconds": 30},
        )
        assert reacquired.status_code == 200, reacquired.text
        assert reacquired.json()["holder_alias"] == "peer-bot"


@pytest.mark.asyncio
async def test_reservation_expiry_allows_takeover(aweb_cloud_db):
    app = _build_reservations_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        suffix = uuid.uuid4().hex[:8]
        project_slug = f"reservations-expiry-{suffix}"
        repo_origin = f"https://github.com/example/{project_slug}.git"
        coordinator = await _create_registered_workspace(
            client,
            project_slug=project_slug,
            alias="coord-bot",
            role="coordinator",
            repo_origin=repo_origin,
        )
        peer = await _init_workspace(
            client,
            project_api_key=coordinator["api_key"],
            project_id=coordinator["project_id"],
            alias="peer-bot",
            role="developer",
            repo_origin=repo_origin,
        )

        acquired = await client.post(
            "/v1/reservations",
            headers=_auth_headers(coordinator["api_key"]),
            json={"resource_key": "src/expired.py", "ttl_seconds": 30},
        )
        assert acquired.status_code == 200, acquired.text

        await aweb_cloud_db.oss_db.execute(
            """
            UPDATE {{tables.reservations}}
            SET expires_at = NOW() - INTERVAL '1 second'
            WHERE project_id = $1 AND resource_key = $2
            """,
            UUID(coordinator["project_id"]),
            "src/expired.py",
        )

        takeover = await client.post(
            "/v1/reservations",
            headers=_auth_headers(peer["api_key"]),
            json={"resource_key": "src/expired.py", "ttl_seconds": 30},
        )
        assert takeover.status_code == 200, takeover.text
        assert takeover.json()["holder_alias"] == "peer-bot"


@pytest.mark.asyncio
async def test_reservation_revoke_requires_coordinator_and_applies_prefix(aweb_cloud_db):
    app = _build_reservations_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        suffix = uuid.uuid4().hex[:8]
        project_slug = f"reservations-revoke-{suffix}"
        repo_origin = f"https://github.com/example/{project_slug}.git"
        coordinator = await _create_registered_workspace(
            client,
            project_slug=project_slug,
            alias="coord-bot",
            role="coordinator",
            repo_origin=repo_origin,
        )
        peer = await _init_workspace(
            client,
            project_api_key=coordinator["api_key"],
            project_id=coordinator["project_id"],
            alias="peer-bot",
            role="developer",
            repo_origin=repo_origin,
        )

        first = await client.post(
            "/v1/reservations",
            headers=_auth_headers(peer["api_key"]),
            json={
                "resource_key": "src/feature.py",
                "ttl_seconds": 60,
                "metadata": {"reason": "peer review"},
            },
        )
        assert first.status_code == 200, first.text

        second = await client.post(
            "/v1/reservations",
            headers=_auth_headers(coordinator["api_key"]),
            json={"resource_key": "docs/readme.md", "ttl_seconds": 60},
        )
        assert second.status_code == 200, second.text

        forbidden = await client.post(
            "/v1/reservations/revoke",
            headers=_auth_headers(peer["api_key"]),
            json={"prefix": "src/"},
        )
        assert forbidden.status_code == 403, forbidden.text

        revoked = await client.post(
            "/v1/reservations/revoke",
            headers=_auth_headers(coordinator["api_key"]),
            json={"prefix": "src/"},
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json() == {
            "revoked_count": 1,
            "revoked_keys": ["src/feature.py"],
        }

        remaining = await aweb_cloud_db.oss_db.fetch_all(
            """
            SELECT resource_key
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND expires_at > NOW()
            ORDER BY resource_key
            """,
            UUID(coordinator["project_id"]),
        )
        assert [row["resource_key"] for row in remaining] == ["docs/readme.md"]


@pytest.mark.asyncio
async def test_reservation_revoke_prefix_treats_underscore_literally(aweb_cloud_db):
    app = _build_reservations_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        suffix = uuid.uuid4().hex[:8]
        project_slug = f"reservations-escape-{suffix}"
        repo_origin = f"https://github.com/example/{project_slug}.git"
        coordinator = await _create_registered_workspace(
            client,
            project_slug=project_slug,
            alias="coord-bot",
            role="coordinator",
            repo_origin=repo_origin,
        )

        for resource_key in ("src/foo_bar/held.py", "src/fooXbar/held.py"):
            acquired = await client.post(
                "/v1/reservations",
                headers=_auth_headers(coordinator["api_key"]),
                json={"resource_key": resource_key, "ttl_seconds": 60},
            )
            assert acquired.status_code == 200, acquired.text

        revoked = await client.post(
            "/v1/reservations/revoke",
            headers=_auth_headers(coordinator["api_key"]),
            json={"prefix": "src/foo_bar/"},
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json() == {
            "revoked_count": 1,
            "revoked_keys": ["src/foo_bar/held.py"],
        }

        remaining = await client.get(
            "/v1/reservations",
            headers=_auth_headers(coordinator["api_key"]),
        )
        assert remaining.status_code == 200, remaining.text
        assert [row["resource_key"] for row in remaining.json()["reservations"]] == [
            "src/fooXbar/held.py"
        ]


@pytest.mark.asyncio
async def test_status_fail_closed_for_empty_repo_and_projects_reservations(aweb_cloud_db):
    app = _build_reservations_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        suffix = uuid.uuid4().hex[:8]
        project_slug = f"status-reservations-{suffix}"
        repo_origin = f"https://github.com/example/{project_slug}.git"
        coordinator = await _create_registered_workspace(
            client,
            project_slug=project_slug,
            alias="coord-bot",
            role="coordinator",
            repo_origin=repo_origin,
        )

        acquired = await client.post(
            "/v1/reservations",
            headers=_auth_headers(coordinator["api_key"]),
            json={
                "resource_key": "src/status.py",
                "ttl_seconds": 60,
                "metadata": {"reason": "status projection"},
            },
        )
        assert acquired.status_code == 200, acquired.text

        status_resp = await client.get(
            "/v1/status",
            headers=_auth_headers(coordinator["api_key"]),
        )
        assert status_resp.status_code == 200, status_resp.text
        status_data = status_resp.json()
        assert len(status_data["agents"]) == 1
        assert len(status_data["locks"]) == 1
        assert status_data["locks"][0]["resource_key"] == "src/status.py"
        assert status_data["locks"][0]["reason"] == "status projection"
        assert "escalations_pending" not in status_data

        empty_repo_resp = await client.get(
            f"/v1/status?repo_id={uuid.uuid4()}",
            headers=_auth_headers(coordinator["api_key"]),
        )
        assert empty_repo_resp.status_code == 200, empty_repo_resp.text
        empty_repo_data = empty_repo_resp.json()
        assert empty_repo_data["workspace"]["workspace_count"] == 0
        assert empty_repo_data["agents"] == []
        assert empty_repo_data["claims"] == []
        assert empty_repo_data["locks"] == []
        assert empty_repo_data["conflicts"] == []
