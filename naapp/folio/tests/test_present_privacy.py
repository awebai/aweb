"""Real PostgreSQL and production present routes; no capability/auth stubs."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.runtime.db import NaappDatabase
from aweb_naapp.runtime.team_auth import Principal

from folio.api import create_app
from folio.config import Settings
from folio.repository import mint_presentation_link

OWNER = Principal(
    "team:editor.test", "did:key:editor", None, None, "editor", "cert-editor", "did:key:team"
)


@pytest.fixture
async def present_world(test_db_factory):
    database = await test_db_factory.create_db(suffix="folio_present")
    settings = Settings(
        _env_file=None,
        database_url=database.config.get_dsn(),
        db_schema="naapp_test",
        public_origin="http://folio.test",
        app_id="folio-test",
    )
    storage = NaappDatabase(
        settings,
        module_name="folio",
        migrations_path=Path(__file__).resolve().parents[1] / "src/folio/migrations",
    )
    await storage.connect()
    try:
        db = storage.db
        document_id = uuid4()
        await db.execute(
            "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)",
            OWNER.team_id,
            OWNER.team_did_key,
        )
        await db.execute(
            """INSERT INTO {{tables.documents}}
            (document_id, team_id, slug, title, created_by_did_key, created_by_alias)
            VALUES ($1, $2, 'draft', 'Draft', $3, $4)""",
            document_id,
            OWNER.team_id,
            OWNER.did_key,
            OWNER.alias,
        )
        await db.execute(
            """INSERT INTO {{tables.document_versions}}
            (version_id, document_id, version_number, body, created_by_did_key, created_by_alias, certificate_id)
            VALUES ($1, $2, 1, 'Original', $3, $4, $5)""",
            uuid4(),
            document_id,
            OWNER.did_key,
            OWNER.alias,
            OWNER.certificate_id,
        )
        app = create_app(settings)
        # Inject the real, independently migrated database. Everything after this
        # dependency (SQL, CAS, serialization, HTML/JS, headers) is production code.
        for route in app.routes:
            for dependency in getattr(getattr(route, "dependant", None), "dependencies", ()):
                if dependency.name == "database":
                    app.dependency_overrides[dependency.call] = lambda: db
        yield app, db, settings

    finally:
        await storage.disconnect()


async def mint(world, *, editable=True, ttl_seconds=None):
    _, db, settings = world
    return await mint_presentation_link(
        db,
        principal=OWNER,
        settings=settings,
        slug="draft",
        version=None,
        editable=editable,
        ttl_seconds=ttl_seconds,
    )


def assert_private(response):
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("referrer-policy") == "no-referrer"


async def test_editable_ttl_default_and_explicit_maximum(present_world):
    app, db, _ = present_world
    link = await mint(present_world)
    row = await db.fetch_one(
        "SELECT created_at, expires_at FROM {{tables.presentation_links}} WHERE token=$1",
        link["token"],
    )
    assert 299 <= (row["expires_at"] - row["created_at"]).total_seconds() <= 300
    assert await mint(present_world, ttl_seconds=300)
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as error:
        await mint(present_world, ttl_seconds=301)
    assert 400 <= error.value.status_code < 500
    read_only = await mint(present_world, editable=False, ttl_seconds=604800)
    assert (read_only["expires_at"] - datetime.now(UTC)).total_seconds() > 604790
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        assert (await client.get(f"/present/{link['token']}")).status_code == 200


@pytest.mark.parametrize("ttl_seconds,expected", [(None, 86_400), (2_592_000, 2_592_000)])
async def test_read_only_ttl_default_and_thirty_day_maximum(present_world, ttl_seconds, expected):
    app, db, _ = present_world
    link = await mint(present_world, editable=False, ttl_seconds=ttl_seconds)
    row = await db.fetch_one(
        "SELECT created_at, expires_at, editable FROM {{tables.presentation_links}} WHERE token=$1",
        link["token"],
    )
    assert not row["editable"]
    assert (row["expires_at"] - row["created_at"]).total_seconds() == expected
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        assert (await client.get(f"/present/{link['token']}")).status_code == 200


@pytest.mark.parametrize("maximum,requested", [(2_592_000, 2_592_001), (604_800, 604_801)])
async def test_read_only_ttl_over_maximum_refuses_without_minting(present_world, maximum, requested):
    from fastapi import HTTPException

    _, db, settings = present_world
    settings.max_present_ttl_seconds = maximum
    before = await db.fetch_one("SELECT count(*) AS n FROM {{tables.presentation_links}}")
    with pytest.raises(HTTPException) as refused:
        await mint(present_world, editable=False, ttl_seconds=requested)
    assert refused.value.status_code == 422
    after = await db.fetch_one("SELECT count(*) AS n FROM {{tables.presentation_links}}")
    assert after["n"] == before["n"]


@pytest.mark.parametrize("state", ["valid", "expired", "revoked", "legacy-long"])
async def test_present_responses_are_private_and_legacy_edit_links_refuse(present_world, state):
    app, db, _ = present_world
    link = await mint(present_world, ttl_seconds=300)
    if state == "expired":
        await db.execute(
            "UPDATE {{tables.presentation_links}} SET created_at=NOW()-interval '301 seconds', expires_at=NOW()-interval '1 second' WHERE token=$1",
            link["token"],
        )
    elif state == "revoked":
        await db.execute(
            "UPDATE {{tables.presentation_links}} SET revoked_at=NOW() WHERE token=$1",
            link["token"],
        )
    elif state == "legacy-long":
        await db.execute(
            "UPDATE {{tables.presentation_links}} SET expires_at=created_at+interval '1 day' WHERE token=$1",
            link["token"],
        )
    prefix = f"/present/{link['token']}"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        responses = [
            await client.get(prefix),
            await client.get(prefix + "/state"),
            await client.post(prefix + "/preview", json={"body": "Draft"}),
            await client.post(prefix + "/edit", json={"body": "Changed", "base_version": 1}),
        ]
        assert [r.status_code for r in responses] == ([200] * 4 if state == "valid" else [404] * 4)
        for response in responses:
            assert_private(response)
        for response in [
            await client.get("/present/absent"),
            await client.get(prefix + "/missing"),
        ]:
            assert response.status_code >= 400
            assert_private(response)
    count = await db.fetch_one("SELECT COUNT(*) AS n FROM {{tables.document_versions}}")
    assert count["n"] == (2 if state == "valid" else 1)


async def test_read_only_long_links_still_render_privately(present_world):
    app, _, _ = present_world
    link = await mint(present_world, editable=False, ttl_seconds=604800)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        response = await client.get(f"/present/{link['token']}")
    assert response.status_code == 200
    assert_private(response)


def test_uvicorn_access_records_redact_capabilities_even_in_queries(caplog):
    # Actual Uvicorn format/args: filters must run before every handler and
    # must not alter the ASGI path used for routing or signature checks.
    create_app(Settings(_env_file=None))
    logger = logging.getLogger("uvicorn.access")
    with caplog.at_level(logging.INFO, logger="uvicorn.access"):
        for path in [
            "/present/secret-123",
            "/present/secret-123/edit?copy=secret-123",
            "/v1/present/secret-123/revoke",
            "/v1/links/public-id/query?bind=%7B%22private-filter%22%3A%22secret-value%22%7D&snapshot_rev=17",
        ]:
            logger.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "POST", path, "1.1", 404)
        logger.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", "/health", "1.1", 200)
    messages = [record.getMessage() for record in caplog.records if record.name == "uvicorn.access"]
    assert len(messages) == 5
    assert all("secret-123" not in value for value in messages)
    assert "/present/[redacted]/edit" in messages[1]
    assert "/v1/links/public-id/query" in messages[3]
    assert all(
        "?" not in value and "secret-value" not in value and "snapshot_rev" not in value
        for value in messages
    )
    assert "/health" in messages[4]
