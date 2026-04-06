from __future__ import annotations
import pytest; pytest.skip("Tests reference removed schema (projects/api_keys/bootstrap) — to be deleted in aaez.5", allow_module_level=True)

import uuid

import pytest

from aweb.coordination.tasks_service import list_active_work


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


@pytest.mark.asyncio
async def test_list_active_work_enriches_repo_branch_and_owner(aweb_cloud_db):
    server_db = aweb_cloud_db.oss_db
    aweb_db = aweb_cloud_db.aweb_db
    db = _DbInfra(server_db=server_db, aweb_db=aweb_db)

    project_id = uuid.uuid4()
    claimed_workspace_id = uuid.uuid4()
    claimed_repo_id = uuid.uuid4()
    assignee_workspace_id = uuid.uuid4()
    assignee_repo_id = uuid.uuid4()
    claimed_task_id = uuid.uuid4()
    assignee_task_id = uuid.uuid4()

    await server_db.execute(
        """
        INSERT INTO {{tables.projects}} (id, slug, name)
        VALUES ($1, 'aweb', 'aweb')
        """,
        project_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name)
        VALUES ($1, 'aweb', 'aweb')
        """,
        project_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.repos}} (id, project_id, origin_url, canonical_origin, name)
        VALUES
            ($1, $3, 'git@github.com:awebai/aweb.git', 'github.com/awebai/aweb', 'aweb'),
            ($2, $3, 'git@github.com:awebai/ac.git', 'github.com/awebai/ac', 'ac')
        """,
        claimed_repo_id,
        assignee_repo_id,
        project_id,
    )
    await server_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, project_id, repo_id, alias, human_name, role, current_branch, workspace_type)
        VALUES
            ($1, $5, $3, 'eve', 'Eve', 'developer', 'feat/summary', 'agent'),
            ($2, $5, $4, 'alice', 'Alice', 'developer', 'main', 'agent')
        """,
        claimed_workspace_id,
        assignee_workspace_id,
        claimed_repo_id,
        assignee_repo_id,
        project_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type)
        VALUES
            ($1, $3, 'eve', 'Eve', 'agent'),
            ($2, $3, 'alice', 'Alice', 'agent')
        """,
        claimed_workspace_id,
        assignee_workspace_id,
        project_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.tasks}}
            (task_id, project_id, task_number, root_task_seq, task_ref_suffix, title, status, priority, task_type,
             assignee_agent_id, created_by_agent_id)
        VALUES
            ($1, $3, 1, 1, 'aaaa', 'Claim-backed task', 'in_progress', 1, 'task', $4, $4),
            ($2, $3, 2, 2, 'aaab', 'Assignee-backed task', 'in_progress', 2, 'bug', $5, $5)
        """,
        claimed_task_id,
        assignee_task_id,
        project_id,
        claimed_workspace_id,
        assignee_workspace_id,
    )
    await server_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (project_id, workspace_id, alias, human_name, task_ref, apex_task_ref)
        VALUES ($1, $2, 'eve', 'Eve', 'aweb-aaaa', 'aweb-aaaa')
        """,
        project_id,
        claimed_workspace_id,
    )

    items = await list_active_work(db, project_id=str(project_id))

    assert [item["task_ref"] for item in items] == ["aweb-aaab", "aweb-aaaa"]

    assignee_backed = items[0]
    assert assignee_backed["owner_alias"] == "alice"
    assert assignee_backed["canonical_origin"] == "github.com/awebai/ac"
    assert assignee_backed["branch"] == "main"
    assert assignee_backed["claimed_at"] is None

    claim_backed = items[1]
    assert claim_backed["owner_alias"] == "eve"
    assert claim_backed["canonical_origin"] == "github.com/awebai/aweb"
    assert claim_backed["branch"] == "feat/summary"
    assert claim_backed["claimed_at"] is not None
