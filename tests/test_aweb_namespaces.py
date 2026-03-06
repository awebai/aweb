"""Tests for namespace as a first-class core concept (aweb-1mo)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import validate_namespace_slug


class TestValidateNamespaceSlug:
    """validate_namespace_slug: single-segment, lowercase, no slashes."""

    def test_accepts_simple_slug(self):
        assert validate_namespace_slug("acme") == "acme"

    def test_accepts_slug_with_hyphens(self):
        assert validate_namespace_slug("my-org") == "my-org"

    def test_accepts_slug_with_digits(self):
        assert validate_namespace_slug("org123") == "org123"

    def test_accepts_single_char(self):
        assert validate_namespace_slug("a") == "a"

    def test_accepts_single_digit(self):
        assert validate_namespace_slug("1") == "1"

    def test_accepts_max_length_slug(self):
        # 64 chars: starts and ends with alnum, hyphens in between
        slug = "a" + "-b" * 31 + "c"  # a-b-b-b...-bc = 1 + 62 + 1 = 64
        assert validate_namespace_slug(slug) == slug

    def test_rejects_uppercase(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("Acme")

    def test_rejects_slash(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("a/b")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("a" * 65)

    def test_rejects_underscore(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("my_org")

    def test_rejects_dot(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("my.org")

    def test_rejects_starts_with_hyphen(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("-acme")

    def test_rejects_ends_with_hyphen(self):
        with pytest.raises(ValueError, match="namespace_slug"):
            validate_namespace_slug("acme-")

    def test_accepts_consecutive_hyphens(self):
        assert validate_namespace_slug("a--b") == "a--b"

    def test_strips_whitespace(self):
        assert validate_namespace_slug("  acme  ") == "acme"


@pytest.mark.asyncio
async def test_namespaces_table_exists(aweb_db_infra):
    """Migration 021 creates the namespaces table."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.namespaces}} (namespace_id, slug, display_name)
        VALUES ($1, $2, $3)
        """,
        ns_id,
        "test-ns",
        "Test Namespace",
    )
    row = await aweb_db.fetch_one(
        "SELECT slug, display_name FROM {{tables.namespaces}} WHERE namespace_id = $1",
        ns_id,
    )
    assert row is not None
    assert row["slug"] == "test-ns"
    assert row["display_name"] == "Test Namespace"


@pytest.mark.asyncio
async def test_namespace_slug_unique_index(aweb_db_infra):
    """Active namespaces must have unique slugs."""
    from pgdbm.errors import QueryError

    aweb_db = aweb_db_infra.get_manager("aweb")
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (slug) VALUES ($1)", "unique-slug"
    )
    with pytest.raises(QueryError, match="unique constraint"):
        await aweb_db.execute(
            "INSERT INTO {{tables.namespaces}} (slug) VALUES ($1)", "unique-slug"
        )


@pytest.mark.asyncio
async def test_namespace_slug_reusable_after_soft_delete(aweb_db_infra):
    """Soft-deleted namespace slug can be reused."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "reuse-slug",
    )
    await aweb_db.execute(
        "UPDATE {{tables.namespaces}} SET deleted_at = NOW() WHERE namespace_id = $1",
        ns_id,
    )
    # Should succeed — the original is soft-deleted
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (slug) VALUES ($1)", "reuse-slug"
    )


@pytest.mark.asyncio
async def test_projects_have_namespace_id_column(aweb_db_infra):
    """Projects table has namespace_id FK column."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "proj-ns",
    )
    proj_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id)
        VALUES ($1, $2, $3, $4)
        """,
        proj_id,
        "proj-ns",
        "Test",
        ns_id,
    )
    row = await aweb_db.fetch_one(
        "SELECT namespace_id FROM {{tables.projects}} WHERE project_id = $1", proj_id
    )
    assert row is not None
    assert row["namespace_id"] == ns_id


@pytest.mark.asyncio
async def test_agents_have_namespace_id_column(aweb_db_infra):
    """Agents table has namespace_id FK column."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "agent-ns",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        proj_id,
        "agent-ns",
        "Test",
        ns_id,
    )
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, project_id, alias, namespace_id)
        VALUES ($1, $2, $3, $4)
        """,
        agent_id,
        proj_id,
        "alice",
        ns_id,
    )
    row = await aweb_db.fetch_one(
        "SELECT namespace_id FROM {{tables.agents}} WHERE agent_id = $1", agent_id
    )
    assert row is not None
    assert row["namespace_id"] == ns_id


@pytest.mark.asyncio
async def test_agents_namespace_alias_unique_index(aweb_db_infra):
    """Same alias in same namespace is rejected (unique index)."""
    from pgdbm.errors import QueryError

    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_id = uuid.uuid4()
    proj_id_a = uuid.uuid4()
    proj_id_b = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "ns-dup",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        proj_id_a,
        "ns-dup-a",
        "",
        ns_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        proj_id_b,
        "ns-dup-b",
        "",
        ns_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (project_id, alias, namespace_id) VALUES ($1, $2, $3)",
        proj_id_a,
        "bob",
        ns_id,
    )
    with pytest.raises(QueryError, match="unique constraint"):
        await aweb_db.execute(
            "INSERT INTO {{tables.agents}} (project_id, alias, namespace_id) VALUES ($1, $2, $3)",
            proj_id_b,
            "bob",
            ns_id,
        )


@pytest.mark.asyncio
async def test_namespace_id_fk_enforced_on_projects(aweb_db_infra):
    """Project with non-existent namespace_id is rejected by FK constraint."""
    from pgdbm.errors import QueryError

    aweb_db = aweb_db_infra.get_manager("aweb")
    with pytest.raises(QueryError, match="foreign key"):
        await aweb_db.execute(
            "INSERT INTO {{tables.projects}} (slug, name, namespace_id) VALUES ($1, $2, $3)",
            "orphan-proj",
            "",
            uuid.uuid4(),  # non-existent namespace
        )


@pytest.mark.asyncio
async def test_namespace_id_fk_enforced_on_agents(aweb_db_infra):
    """Agent with non-existent namespace_id is rejected by FK constraint."""
    from pgdbm.errors import QueryError

    aweb_db = aweb_db_infra.get_manager("aweb")
    proj_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        proj_id,
        "fk-test",
        "",
    )
    with pytest.raises(QueryError, match="foreign key"):
        await aweb_db.execute(
            "INSERT INTO {{tables.agents}} (project_id, alias, namespace_id) VALUES ($1, $2, $3)",
            proj_id,
            "alice",
            uuid.uuid4(),  # non-existent namespace
        )


@pytest.mark.asyncio
async def test_agent_alias_reusable_after_soft_delete(aweb_db_infra):
    """Soft-deleted agent alias can be reused in the same namespace."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        ns_id,
        "ns-alias-reuse",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        proj_id,
        "ns-alias-reuse",
        "",
        ns_id,
    )
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, namespace_id) VALUES ($1, $2, $3, $4)",
        agent_id,
        proj_id,
        "charlie",
        ns_id,
    )
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET deleted_at = NOW() WHERE agent_id = $1",
        agent_id,
    )
    # Should succeed — the original is soft-deleted
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (project_id, alias, namespace_id) VALUES ($1, $2, $3)",
        proj_id,
        "charlie",
        ns_id,
    )


# ---------------------------------------------------------------------------
# Bootstrap / Init endpoint tests (beads aweb-1mo.2 and aweb-1mo.3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_with_namespace_slug(aweb_db_infra):
    """POST /v1/init with namespace_slug creates namespace and returns both slugs."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "namespace_slug": "test-ns",
                    "alias": "alice",
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["namespace_slug"] == "test-ns"
            assert body["project_slug"] == "test-ns"
            assert body["alias"] == "alice"
            assert body["api_key"].startswith("aw_sk_")


@pytest.mark.asyncio
async def test_init_with_namespace_slug_and_project_slug(aweb_db_infra):
    """POST /v1/init with both namespace_slug and project_slug uses namespace_slug."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "namespace_slug": "my-ns",
                    "project_slug": "my-proj",
                    "alias": "bob",
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["namespace_slug"] == "my-ns"
            assert body["project_slug"] == "my-proj"


@pytest.mark.asyncio
async def test_init_with_project_slug_only_backward_compat(aweb_db_infra):
    """POST /v1/init with only project_slug uses it as namespace slug (backward compat)."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "compat-ns",
                    "alias": "charlie",
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["namespace_slug"] == "compat-ns"
            assert body["project_slug"] == "compat-ns"


@pytest.mark.asyncio
async def test_init_with_neither_slug_returns_422(aweb_db_infra):
    """POST /v1/init with neither namespace_slug nor project_slug returns 422."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "alias": "dave",
                },
            )
            assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_init_namespace_sets_namespace_id_on_project_and_agent(aweb_db_infra):
    """Bootstrap sets namespace_id on both project and agent rows."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "namespace_slug": "ns-check",
                    "alias": "eve",
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()

    aweb_db = aweb_db_infra.get_manager("aweb")
    ns_row = await aweb_db.fetch_one(
        "SELECT namespace_id FROM {{tables.namespaces}} WHERE slug = $1 AND deleted_at IS NULL",
        "ns-check",
    )
    assert ns_row is not None
    ns_id = ns_row["namespace_id"]

    proj_row = await aweb_db.fetch_one(
        "SELECT namespace_id FROM {{tables.projects}} WHERE project_id = $1",
        uuid.UUID(body["project_id"]),
    )
    assert proj_row is not None
    assert proj_row["namespace_id"] == ns_id

    agent_row = await aweb_db.fetch_one(
        "SELECT namespace_id FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(body["agent_id"]),
    )
    assert agent_row is not None
    assert agent_row["namespace_id"] == ns_id


@pytest.mark.asyncio
async def test_init_reinit_same_namespace(aweb_db_infra):
    """Re-init with same namespace_slug and alias reuses existing agent."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp1 = await c.post(
                "/v1/init",
                json={"namespace_slug": "reinit-ns", "alias": "frank"},
            )
            assert resp1.status_code == 200
            body1 = resp1.json()
            assert body1["created"] is True

            resp2 = await c.post(
                "/v1/init",
                json={"namespace_slug": "reinit-ns", "alias": "frank"},
            )
            assert resp2.status_code == 200
            body2 = resp2.json()
            assert body2["created"] is False
            assert body2["agent_id"] == body1["agent_id"]
            assert body2["namespace_slug"] == "reinit-ns"
