from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aweb.gc import gc_inactive_scopes


def _db_infra(aweb_db):
    class _DbInfra:
        def get_manager(self, name="aweb"):
            assert name == "aweb"
            return aweb_db

    return _DbInfra()


@pytest.mark.asyncio
async def test_gc_inactive_scopes_hard_deletes_populated_team(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    team_id = "acme.com/backend"
    active_team_id = "acme.com/active"
    created_at = datetime.now(timezone.utc) - timedelta(days=45)
    agent_id = uuid4()
    active_agent_id = uuid4()
    repo_id = uuid4()
    workspace_id = uuid4()
    task_id = uuid4()
    other_task_id = uuid4()
    session_id = uuid4()
    chat_message_id = uuid4()
    read_receipt_agent_id = agent_id

    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key, created_at)
        VALUES
            ($1, 'acme.com', 'Backend', 'did:key:team-inactive', $2),
            ($3, 'acme.com', 'Active', 'did:key:team-active', $2)
        """,
        team_id,
        created_at,
        active_team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, alias, human_name, role, created_at
        )
        VALUES
            ($1, $2, $3, $4, $5, $6, $7),
            ($8, $9, $10, $11, $12, $13, NOW())
        """,
        agent_id,
        team_id,
        "did:key:inactive",
        "alice",
        "Alice",
        "developer",
        created_at,
        active_agent_id,
        active_team_id,
        "did:key:active",
        "bob",
        "Bob",
        "developer",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.repos}} (id, team_id, origin_url, canonical_origin, name, created_at)
        VALUES ($1, $2, $3, $3, $4, $5)
        """,
        repo_id,
        team_id,
        "https://example.com/acme/backend.git",
        "backend",
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, repo_id, alias, human_name,
            role, hostname, workspace_path, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
        """,
        workspace_id,
        team_id,
        agent_id,
        repo_id,
        "alice",
        "Alice",
        "developer",
        "mac.local",
        "/tmp/backend",
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            team_id, from_agent_id, to_agent_id, from_alias, to_alias, subject, body, created_at
        )
        VALUES ($1, $2, $2, 'alice', 'alice', 'subject', 'body', $3)
        """,
        team_id,
        agent_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by, created_at)
        VALUES ($1, $2, 'alice', $3)
        """,
        session_id,
        team_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, agent_id, alias, joined_at)
        VALUES ($1, $2, 'alice', $3)
        """,
        session_id,
        agent_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (
            message_id, session_id, from_agent_id, from_alias, body, created_at
        )
        VALUES ($1, $2, $3, 'alice', 'hello', $4)
        """,
        chat_message_id,
        session_id,
        agent_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}} (
            session_id, agent_id, last_read_message_id, last_read_at
        )
        VALUES ($1, $2, $3, $4)
        """,
        session_id,
        read_receipt_agent_id,
        chat_message_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (team_id, contact_address, label, created_at)
        VALUES ($1, 'did:key:carol', 'Carol', $2)
        """,
        team_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.control_signals}} (
            team_id, target_agent_id, from_agent_id, signal_type, created_at
        )
        VALUES ($1, $2, $2, 'interrupt', $3)
        """,
        team_id,
        agent_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, task_ref_suffix, title, created_at
        )
        VALUES
            ($1, $2, 1, '1', 'Root task', $3),
            ($4, $2, 2, '2', 'Dependent task', $3)
        """,
        task_id,
        team_id,
        created_at,
        other_task_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_comments}} (task_id, team_id, author_alias, body, created_at)
        VALUES ($1, $2, 'alice', 'comment', $3)
        """,
        task_id,
        team_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_dependencies}} (task_id, depends_on_id, team_id)
        VALUES ($1, $2, $3)
        """,
        other_task_id,
        task_id,
        team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_counters}} (team_id, next_number)
        VALUES ($1, 3)
        """,
        team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_root_counters}} (team_id, next_number)
        VALUES ($1, 2)
        """,
        team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, apex_task_ref, claimed_at
        )
        VALUES ($1, $2, 'alice', 'Alice', 'aweb-aafx.63', 'aweb-aafx.63', $3)
        """,
        team_id,
        workspace_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.reservations}} (
            team_id, resource_key, holder_alias, holder_agent_id, acquired_at
        )
        VALUES ($1, 'repo:backend', 'alice', $2, $3)
        """,
        team_id,
        agent_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.team_roles}} (
            team_id, version, bundle_json, is_active, created_by_alias, created_at, updated_at
        )
        VALUES ($1, 1, '[]'::jsonb, TRUE, 'alice', $2, $2)
        """,
        team_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.team_instructions}} (
            team_id, version, document_json, is_active, created_by_alias, created_at, updated_at
        )
        VALUES ($1, 1, '{}'::jsonb, TRUE, 'alice', $2, $2)
        """,
        team_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (
            team_id, alias, event_type, resource, details, created_at
        )
        VALUES ($1, 'alice', 'task.created', 'task', '{}'::jsonb, $2)
        """,
        team_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            team_id, from_agent_id, to_agent_id, from_alias, to_alias, subject, body, created_at
        )
        VALUES ($1, $2, $2, 'bob', 'bob', 'recent', 'keep', NOW())
        """,
        active_team_id,
        active_agent_id,
    )

    result = await gc_inactive_scopes(_db_infra(aweb_db), ttl_days=30)

    assert result == {"scopes_deleted": 1}

    counts = {
        "teams": "SELECT COUNT(*) AS count FROM aweb.teams WHERE team_id = $1",
        "agents": "SELECT COUNT(*) AS count FROM aweb.agents WHERE team_id = $1",
        "messages": "SELECT COUNT(*) AS count FROM aweb.messages WHERE team_id = $1",
        "chat_sessions": "SELECT COUNT(*) AS count FROM aweb.chat_sessions WHERE team_id = $1",
        "chat_participants": """
            SELECT COUNT(*) AS count
            FROM aweb.chat_participants cp
            JOIN aweb.agents a ON a.agent_id = cp.agent_id
            WHERE a.team_id = $1
        """,
        "chat_messages": """
            SELECT COUNT(*) AS count
            FROM aweb.chat_messages cm
            JOIN aweb.chat_sessions cs ON cs.session_id = cm.session_id
            WHERE cs.team_id = $1
        """,
        "chat_read_receipts": """
            SELECT COUNT(*) AS count
            FROM aweb.chat_read_receipts crr
            JOIN aweb.chat_sessions cs ON cs.session_id = crr.session_id
            WHERE cs.team_id = $1
        """,
        "contacts": "SELECT COUNT(*) AS count FROM aweb.contacts WHERE team_id = $1",
        "control_signals": "SELECT COUNT(*) AS count FROM aweb.control_signals WHERE team_id = $1",
        "repos": "SELECT COUNT(*) AS count FROM aweb.repos WHERE team_id = $1",
        "workspaces": "SELECT COUNT(*) AS count FROM aweb.workspaces WHERE team_id = $1",
        "tasks": "SELECT COUNT(*) AS count FROM aweb.tasks WHERE team_id = $1",
        "task_comments": "SELECT COUNT(*) AS count FROM aweb.task_comments WHERE team_id = $1",
        "task_dependencies": "SELECT COUNT(*) AS count FROM aweb.task_dependencies WHERE team_id = $1",
        "task_counters": "SELECT COUNT(*) AS count FROM aweb.task_counters WHERE team_id = $1",
        "task_root_counters": "SELECT COUNT(*) AS count FROM aweb.task_root_counters WHERE team_id = $1",
        "task_claims": "SELECT COUNT(*) AS count FROM aweb.task_claims WHERE team_id = $1",
        "reservations": "SELECT COUNT(*) AS count FROM aweb.reservations WHERE team_id = $1",
        "team_roles": "SELECT COUNT(*) AS count FROM aweb.team_roles WHERE team_id = $1",
        "team_instructions": "SELECT COUNT(*) AS count FROM aweb.team_instructions WHERE team_id = $1",
        "audit_log": "SELECT COUNT(*) AS count FROM aweb.audit_log WHERE team_id = $1",
    }
    for table, sql in counts.items():
        row = await aweb_db.fetch_one(sql, team_id)
        assert row is not None
        assert row["count"] == 0, table

    active_team = await aweb_db.fetch_one(
        """
        SELECT team_id FROM {{tables.teams}}
        WHERE team_id = $1
        """,
        active_team_id,
    )
    assert active_team is not None
