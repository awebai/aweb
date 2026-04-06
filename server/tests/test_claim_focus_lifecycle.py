from __future__ import annotations
import pytest; pytest.skip("Tests reference removed schema (projects/api_keys/bootstrap) — to be deleted in aaez.5", allow_module_level=True)

import uuid

import pytest

from aweb.claims import release_task_claims, upsert_claim
from aweb.coordination.tasks_service import update_task


class _DbInfra:
    def __init__(self, *, server_db, aweb_db) -> None:
        self._server_db = server_db
        self._aweb_db = aweb_db

    def get_manager(self, name: str = "aweb"):
        if name == "server":
            return self._server_db
        if name == "aweb":
            return self._aweb_db
        raise KeyError(name)


async def _seed_project(server_db) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = uuid.uuid4()
    repo_id = uuid.uuid4()
    await server_db.execute(
        """
        INSERT INTO {{tables.projects}} (id, slug, name)
        VALUES ($1, 'aweb', 'aweb')
        """,
        project_id,
    )
    await server_db.execute(
        """
        INSERT INTO {{tables.repos}} (id, project_id, origin_url, canonical_origin, name)
        VALUES ($1, $2, 'git@github.com:awebai/aweb.git', 'github.com/awebai/aweb', 'aweb')
        """,
        repo_id,
        project_id,
    )
    return project_id, repo_id


async def _seed_workspace(server_db, *, project_id: uuid.UUID, repo_id: uuid.UUID) -> uuid.UUID:
    workspace_id = uuid.uuid4()
    await server_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, project_id, repo_id, alias, human_name, role, current_branch, workspace_type)
        VALUES ($1, $2, $3, 'eve', 'Eve', 'developer', 'feat/focus', 'agent')
        """,
        workspace_id,
        project_id,
        repo_id,
    )
    return workspace_id


async def _insert_task(
    server_db,
    *,
    task_id: uuid.UUID,
    project_id: uuid.UUID,
    task_number: int,
    root_task_seq: int,
    task_ref_suffix: str,
    title: str,
    parent_task_id: uuid.UUID | None = None,
    status: str = "open",
    task_type: str = "task",
) -> None:
    await server_db.execute(
        """
        INSERT INTO {{tables.tasks}}
            (task_id, project_id, task_number, root_task_seq, task_ref_suffix, title, status, priority, task_type,
             parent_task_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9)
        """,
        task_id,
        project_id,
        task_number,
        root_task_seq,
        task_ref_suffix,
        title,
        status,
        task_type,
        parent_task_id,
    )


async def _fetch_workspace_focus(server_db, *, project_id: uuid.UUID, workspace_id: uuid.UUID) -> str | None:
    row = await server_db.fetch_one(
        """
        SELECT focus_task_ref
        FROM {{tables.workspaces}}
        WHERE project_id = $1 AND workspace_id = $2
        """,
        project_id,
        workspace_id,
    )
    return row["focus_task_ref"] if row else None


async def _fetch_claim(server_db, *, project_id: uuid.UUID, workspace_id: uuid.UUID, task_ref: str):
    return await server_db.fetch_one(
        """
        SELECT task_ref, apex_task_ref
        FROM {{tables.task_claims}}
        WHERE project_id = $1 AND workspace_id = $2 AND task_ref = $3
        """,
        project_id,
        workspace_id,
        task_ref,
    )


@pytest.mark.asyncio
async def test_upsert_claim_sets_workspace_focus_to_apex_task(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    db = _DbInfra(server_db=server_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id, repo_id = await _seed_project(server_db)
    workspace_id = await _seed_workspace(server_db, project_id=project_id, repo_id=repo_id)

    root_task_id = uuid.uuid4()
    child_task_id = uuid.uuid4()
    await _insert_task(
        server_db,
        task_id=root_task_id,
        project_id=project_id,
        task_number=1,
        root_task_seq=1,
        task_ref_suffix="aaaa",
        title="Parent task",
        task_type="epic",
    )
    await _insert_task(
        server_db,
        task_id=child_task_id,
        project_id=project_id,
        task_number=2,
        root_task_seq=1,
        task_ref_suffix="aaaa.1",
        title="Child task",
        parent_task_id=root_task_id,
    )

    result = await upsert_claim(
        db,
        project_id=str(project_id),
        workspace_id=str(workspace_id),
        alias="eve",
        human_name="Eve",
        task_ref="aweb-aaaa.1",
    )

    assert result is None
    claim = await _fetch_claim(
        server_db,
        project_id=project_id,
        workspace_id=workspace_id,
        task_ref="aweb-aaaa.1",
    )
    assert claim["apex_task_ref"] == "aweb-aaaa"
    assert (
        await _fetch_workspace_focus(server_db, project_id=project_id, workspace_id=workspace_id)
        == "aweb-aaaa"
    )


@pytest.mark.asyncio
async def test_release_task_claims_restores_next_claim_focus(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    db = _DbInfra(server_db=server_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id, repo_id = await _seed_project(server_db)
    workspace_id = await _seed_workspace(server_db, project_id=project_id, repo_id=repo_id)

    root_task_id = uuid.uuid4()
    child_task_id = uuid.uuid4()
    side_task_id = uuid.uuid4()
    await _insert_task(
        server_db,
        task_id=root_task_id,
        project_id=project_id,
        task_number=1,
        root_task_seq=1,
        task_ref_suffix="aaaa",
        title="Parent task",
    )
    await _insert_task(
        server_db,
        task_id=child_task_id,
        project_id=project_id,
        task_number=2,
        root_task_seq=1,
        task_ref_suffix="aaaa.1",
        title="Child task",
        parent_task_id=root_task_id,
    )
    await _insert_task(
        server_db,
        task_id=side_task_id,
        project_id=project_id,
        task_number=3,
        root_task_seq=2,
        task_ref_suffix="aaab",
        title="Side task",
    )

    await upsert_claim(
        db,
        project_id=str(project_id),
        workspace_id=str(workspace_id),
        alias="eve",
        human_name="Eve",
        task_ref="aweb-aaab",
    )
    await upsert_claim(
        db,
        project_id=str(project_id),
        workspace_id=str(workspace_id),
        alias="eve",
        human_name="Eve",
        task_ref="aweb-aaaa.1",
    )

    await release_task_claims(
        db,
        project_id=str(project_id),
        task_ref="aweb-aaaa.1",
        workspace_id=str(workspace_id),
    )

    assert (
        await _fetch_workspace_focus(server_db, project_id=project_id, workspace_id=workspace_id)
        == "aweb-aaab"
    )


@pytest.mark.asyncio
async def test_release_task_claims_keeps_focus_on_open_apex_without_other_claims(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    db = _DbInfra(server_db=server_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id, repo_id = await _seed_project(server_db)
    workspace_id = await _seed_workspace(server_db, project_id=project_id, repo_id=repo_id)

    epic_task_id = uuid.uuid4()
    child_task_id = uuid.uuid4()
    await _insert_task(
        server_db,
        task_id=epic_task_id,
        project_id=project_id,
        task_number=1,
        root_task_seq=1,
        task_ref_suffix="aaay",
        title="Fix e2e user journey failures",
        task_type="epic",
    )
    await _insert_task(
        server_db,
        task_id=child_task_id,
        project_id=project_id,
        task_number=2,
        root_task_seq=1,
        task_ref_suffix="aaal",
        title="aw spawn accept-invite stays interactive",
        parent_task_id=epic_task_id,
    )

    await upsert_claim(
        db,
        project_id=str(project_id),
        workspace_id=str(workspace_id),
        alias="eve",
        human_name="Eve",
        task_ref="aweb-aaal",
    )

    await release_task_claims(
        db,
        project_id=str(project_id),
        task_ref="aweb-aaal",
        workspace_id=str(workspace_id),
    )

    assert (
        await _fetch_workspace_focus(server_db, project_id=project_id, workspace_id=workspace_id)
        == "aweb-aaay"
    )


@pytest.mark.asyncio
async def test_release_task_claims_clears_focus_when_apex_is_closed(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    db = _DbInfra(server_db=server_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id, repo_id = await _seed_project(server_db)
    workspace_id = await _seed_workspace(server_db, project_id=project_id, repo_id=repo_id)

    epic_task_id = uuid.uuid4()
    child_task_id = uuid.uuid4()
    await _insert_task(
        server_db,
        task_id=epic_task_id,
        project_id=project_id,
        task_number=1,
        root_task_seq=1,
        task_ref_suffix="aaay",
        title="Fix e2e user journey failures",
        task_type="epic",
        status="closed",
    )
    await _insert_task(
        server_db,
        task_id=child_task_id,
        project_id=project_id,
        task_number=2,
        root_task_seq=1,
        task_ref_suffix="aaal",
        title="aw spawn accept-invite stays interactive",
        parent_task_id=epic_task_id,
    )

    await upsert_claim(
        db,
        project_id=str(project_id),
        workspace_id=str(workspace_id),
        alias="eve",
        human_name="Eve",
        task_ref="aweb-aaal",
    )

    await release_task_claims(
        db,
        project_id=str(project_id),
        task_ref="aweb-aaal",
        workspace_id=str(workspace_id),
    )

    assert await _fetch_workspace_focus(
        server_db,
        project_id=project_id,
        workspace_id=workspace_id,
    ) is None


@pytest.mark.asyncio
async def test_update_task_in_progress_preacquires_claim_and_focus(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    db = _DbInfra(server_db=server_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id, repo_id = await _seed_project(server_db)
    workspace_id = await _seed_workspace(server_db, project_id=project_id, repo_id=repo_id)

    root_task_id = uuid.uuid4()
    child_task_id = uuid.uuid4()
    await _insert_task(
        server_db,
        task_id=root_task_id,
        project_id=project_id,
        task_number=1,
        root_task_seq=1,
        task_ref_suffix="aaaa",
        title="Parent task",
    )
    await _insert_task(
        server_db,
        task_id=child_task_id,
        project_id=project_id,
        task_number=2,
        root_task_seq=1,
        task_ref_suffix="aaaa.1",
        title="Child task",
        parent_task_id=root_task_id,
    )

    result = await update_task(
        db,
        project_id=str(project_id),
        ref="aweb-aaaa.1",
        actor_agent_id=str(workspace_id),
        status="in_progress",
    )

    assert result["status"] == "in_progress"
    assert result["claim_preacquired"] is True
    claim = await _fetch_claim(
        server_db,
        project_id=project_id,
        workspace_id=workspace_id,
        task_ref="aweb-aaaa.1",
    )
    assert claim["apex_task_ref"] == "aweb-aaaa"
    assert (
        await _fetch_workspace_focus(server_db, project_id=project_id, workspace_id=workspace_id)
        == "aweb-aaaa"
    )
