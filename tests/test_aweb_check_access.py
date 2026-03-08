"""Tests for check_access helper — pure DB tests, no HTTP."""

from __future__ import annotations

import uuid

import pytest

from aweb.contacts import check_access


async def _seed_two_projects(aweb_db_infra):
    """Seed two projects with agents and contacts table ready."""
    aweb_db = aweb_db_infra.get_manager("aweb")

    namespace_1_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_1_id,
        "test-ns-1",
    )

    project_1_id = uuid.uuid4()
    agent_1_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_1_id,
        "org-alpha",
        "Org Alpha",
        namespace_1_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6)",
        agent_1_id,
        project_1_id,
        "alice",
        "Alice",
        "agent",
        namespace_1_id,
    )

    namespace_2_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_2_id,
        "test-ns-2",
    )

    project_2_id = uuid.uuid4()
    agent_2_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_2_id,
        "org-beta",
        "Org Beta",
        namespace_2_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6)",
        agent_2_id,
        project_2_id,
        "bob",
        "Bob",
        "agent",
        namespace_2_id,
    )

    return {
        "project_1_id": str(project_1_id),
        "agent_1_id": str(agent_1_id),
        "project_2_id": str(project_2_id),
        "agent_2_id": str(agent_2_id),
    }


@pytest.mark.asyncio
async def test_check_access_open_allows_all(aweb_db_infra):
    seeded = await _seed_two_projects(aweb_db_infra)
    db = aweb_db_infra

    result = await check_access(
        db,
        target_project_id=seeded["project_1_id"],
        target_agent_id=seeded["agent_1_id"],
        sender_address="random-org/stranger",
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_access_contacts_only_no_contact_denied(aweb_db_infra):
    seeded = await _seed_two_projects(aweb_db_infra)
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    # Set target to contacts_only
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET access_mode = 'contacts_only' WHERE agent_id = $1",
        uuid.UUID(seeded["agent_1_id"]),
    )

    result = await check_access(
        db,
        target_project_id=seeded["project_1_id"],
        target_agent_id=seeded["agent_1_id"],
        sender_address="random-org/stranger",
    )
    assert result is False


@pytest.mark.asyncio
async def test_check_access_contacts_only_exact_match(aweb_db_infra):
    seeded = await _seed_two_projects(aweb_db_infra)
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET access_mode = 'contacts_only' WHERE agent_id = $1",
        uuid.UUID(seeded["agent_1_id"]),
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.contacts}} (project_id, contact_address) VALUES ($1, $2)",
        uuid.UUID(seeded["project_1_id"]),
        "org-beta/bob",
    )

    result = await check_access(
        db,
        target_project_id=seeded["project_1_id"],
        target_agent_id=seeded["agent_1_id"],
        sender_address="org-beta/bob",
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_access_contacts_only_org_level_match(aweb_db_infra):
    seeded = await _seed_two_projects(aweb_db_infra)
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET access_mode = 'contacts_only' WHERE agent_id = $1",
        uuid.UUID(seeded["agent_1_id"]),
    )
    # Add org-level contact (just the slug, not a specific agent)
    await aweb_db.execute(
        "INSERT INTO {{tables.contacts}} (project_id, contact_address) VALUES ($1, $2)",
        uuid.UUID(seeded["project_1_id"]),
        "org-beta",
    )

    result = await check_access(
        db,
        target_project_id=seeded["project_1_id"],
        target_agent_id=seeded["agent_1_id"],
        sender_address="org-beta/bob",
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_access_same_project_always_allowed(aweb_db_infra):
    seeded = await _seed_two_projects(aweb_db_infra)
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    # Set target to contacts_only
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET access_mode = 'contacts_only' WHERE agent_id = $1",
        uuid.UUID(seeded["agent_1_id"]),
    )

    # Sender is in the same project (org-alpha/other-agent)
    result = await check_access(
        db,
        target_project_id=seeded["project_1_id"],
        target_agent_id=seeded["agent_1_id"],
        sender_address="org-alpha/other-agent",
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_access_multi_segment_slug_no_false_positive(aweb_db_infra):
    """A sender from 'test/sub' must NOT match project 'test' via org extraction.

    Regression: split('/')[0] took only the first segment, so 'test/sub/alice'
    matched project 'test'.  The org should be 'test/sub' (everything before the
    last '/').
    """
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    # Create a project with slug 'test' and a contacts_only agent
    ns_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "test",
    )
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        "test",
        "Test Proj",
        ns_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, access_mode, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7)",
        agent_id,
        project_id,
        "target",
        "Target",
        "agent",
        "contacts_only",
        ns_id,
    )

    # Sender is 'test/sub/alice' — org is 'test/sub', NOT 'test'
    result = await check_access(
        db,
        target_project_id=str(project_id),
        target_agent_id=str(agent_id),
        sender_address="test/sub/alice",
    )
    # Should be denied: 'test/sub' != 'test' (different project)
    assert result is False


@pytest.mark.asyncio
async def test_check_access_multi_segment_slug_same_project_allowed(aweb_db_infra):
    """A sender from 'org-sub' matches project 'org-sub' via same-project bypass."""
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    ns_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "org-sub",
    )
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        "org-sub",
        "Org Sub",
        ns_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, access_mode, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7)",
        agent_id,
        project_id,
        "target",
        "Target",
        "agent",
        "contacts_only",
        ns_id,
    )

    result = await check_access(
        db,
        target_project_id=str(project_id),
        target_agent_id=str(agent_id),
        sender_address="org-sub/alice",
    )
    assert result is True


@pytest.mark.asyncio
async def test_check_access_multi_segment_org_contact_no_false_positive(aweb_db_infra):
    """Org-level contact 'test' must NOT grant access to sender 'test/sub/alice'."""
    db = aweb_db_infra
    aweb_db = db.get_manager("aweb")

    ns_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "other-ns",
    )
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        "other",
        "Other Proj",
        ns_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type, access_mode, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7)",
        agent_id,
        project_id,
        "target",
        "Target",
        "agent",
        "contacts_only",
        ns_id,
    )
    # Add org-level contact for 'test' (single segment)
    await aweb_db.execute(
        "INSERT INTO {{tables.contacts}} (project_id, contact_address) VALUES ($1, $2)",
        project_id,
        "test",
    )

    # Sender 'test/sub/alice' has org 'test/sub', NOT 'test'
    result = await check_access(
        db,
        target_project_id=str(project_id),
        target_agent_id=str(agent_id),
        sender_address="test/sub/alice",
    )
    assert result is False


@pytest.mark.asyncio
async def test_check_access_nonexistent_agent(aweb_db_infra):
    db = aweb_db_infra

    result = await check_access(
        db,
        target_project_id=str(uuid.uuid4()),
        target_agent_id=str(uuid.uuid4()),
        sender_address="any/sender",
    )
    assert result is False
