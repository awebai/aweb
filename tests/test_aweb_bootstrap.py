"""Tests for ensure_project() and bootstrap_identity() with caller-provided project_id."""

from __future__ import annotations

import uuid

import pytest

from aweb.bootstrap import bootstrap_identity, ensure_project
from aweb.db import DatabaseInfra


@pytest.mark.asyncio
async def test_ensure_project_by_slug(aweb_db_infra: DatabaseInfra):
    """Default path: lookup/create by slug."""
    result = await ensure_project(aweb_db_infra, project_slug="test-slug")
    assert result.slug == "test-slug"
    assert result.project_id

    # Calling again returns the same project.
    again = await ensure_project(aweb_db_infra, project_slug="test-slug")
    assert again.project_id == result.project_id


@pytest.mark.asyncio
async def test_ensure_project_with_project_id_creates(aweb_db_infra: DatabaseInfra):
    """When project_id is provided and doesn't exist, create with that ID."""
    pid = str(uuid.uuid4())
    result = await ensure_project(aweb_db_infra, project_slug="cloud-proj", project_id=pid)
    assert result.project_id == pid
    assert result.slug == "cloud-proj"


@pytest.mark.asyncio
async def test_ensure_project_with_project_id_returns_existing(aweb_db_infra: DatabaseInfra):
    """When project_id is provided and already exists, return it."""
    pid = str(uuid.uuid4())
    first = await ensure_project(aweb_db_infra, project_slug="cloud-proj", project_id=pid)
    second = await ensure_project(aweb_db_infra, project_slug="cloud-proj", project_id=pid)
    assert first.project_id == second.project_id == pid


@pytest.mark.asyncio
async def test_ensure_project_with_project_id_ignores_slug_mismatch(aweb_db_infra: DatabaseInfra):
    """When project_id exists, slug param is ignored — stored slug is returned."""
    pid = str(uuid.uuid4())
    await ensure_project(aweb_db_infra, project_slug="original-slug", project_id=pid)

    result = await ensure_project(aweb_db_infra, project_slug="different-slug", project_id=pid)
    assert result.project_id == pid
    assert result.slug == "original-slug"


@pytest.mark.asyncio
async def test_ensure_project_same_slug_different_project_ids(aweb_db_infra: DatabaseInfra):
    """Two cloud tenants with different project_ids but same slug get separate projects."""
    pid1 = str(uuid.uuid4())
    pid2 = str(uuid.uuid4())
    tid1 = str(uuid.uuid4())
    tid2 = str(uuid.uuid4())
    r1 = await ensure_project(
        aweb_db_infra, project_slug="shared-slug", project_id=pid1, tenant_id=tid1
    )
    r2 = await ensure_project(
        aweb_db_infra, project_slug="shared-slug", project_id=pid2, tenant_id=tid2
    )
    assert r1.project_id != r2.project_id
    assert r1.project_id == pid1
    assert r2.project_id == pid2


@pytest.mark.asyncio
async def test_bootstrap_identity_with_project_id(aweb_db_infra: DatabaseInfra):
    """bootstrap_identity uses caller-provided project_id."""
    pid = str(uuid.uuid4())
    result = await bootstrap_identity(
        aweb_db_infra,
        project_slug="cloud-proj",
        project_id=pid,
        alias="alice",
    )
    assert result.project_id == pid
    assert result.alias == "alice"
    assert result.api_key.startswith("aw_sk_")


@pytest.mark.asyncio
async def test_bootstrap_identity_two_tenants_same_slug(aweb_db_infra: DatabaseInfra):
    """Two cloud tenants with same slug but different project_ids get isolated agents."""
    pid1 = str(uuid.uuid4())
    pid2 = str(uuid.uuid4())
    tid1 = str(uuid.uuid4())
    tid2 = str(uuid.uuid4())
    r1 = await bootstrap_identity(
        aweb_db_infra,
        project_slug="shared-slug",
        project_id=pid1,
        tenant_id=tid1,
        alias="alice",
    )
    r2 = await bootstrap_identity(
        aweb_db_infra,
        project_slug="shared-slug",
        project_id=pid2,
        tenant_id=tid2,
        alias="alice",
    )
    # Same alias in different projects — should be separate agents.
    assert r1.project_id != r2.project_id
    assert r1.agent_id != r2.agent_id
    assert r1.alias == r2.alias == "alice"
