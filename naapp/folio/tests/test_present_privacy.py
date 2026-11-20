"""Real PostgreSQL and production present routes; no capability/auth stubs.

``present_world`` runs Folio as deployed: its runtime reads AWID by its
``awid_registry_url`` setting and its installation grants from the team's
coordination server, both real services on local sockets
(``aweb_naapp_testing.server.listening_coordination``), and the team installs
Folio through the server's public install route
(``aweb_naapp_testing.installations``).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.runtime.team_auth import Principal
from aweb_naapp_testing import SERVICE_TOKEN, Member
from aweb_naapp_testing.installations import AppOrigin, Installations, app_origin
from aweb_naapp_testing.server import ListeningCoordination

from folio.api import create_app
from folio.config import Settings
from folio.repository import mint_presentation_link

FOLIO_SCOPES = ["folio:read", "folio:write"]
# Grant answers live this long, so a test sees an install change after it.
GRANT_MAX_AGE_SECONDS = 1


@dataclass
class World:
    """Folio installed for ``member``'s team, with the services it runs on."""

    app: Any
    db: Any
    settings: Settings
    member: Member
    principal: Principal
    coordination: ListeningCoordination
    installations: Installations
    origin: AppOrigin
    installation: dict

    async def reinstall(self) -> dict:
        """Installs Folio again over its current installation (a repin)."""
        self.installation = await self.installations.install(
            self.origin,
            app_id=self.settings.app_id,
            manifest=self.app.state.folio_runtime.manifest_bytes,
            granted_scopes=FOLIO_SCOPES,
            expected_generation=self.installation["generation"],
        )
        await grants_refresh()
        return self.installation

    async def uninstall(self) -> dict:
        self.installation = await self.installations.uninstall(
            app_id=self.settings.app_id, expected_generation=self.installation["generation"]
        )
        await grants_refresh()
        return self.installation


async def grants_refresh() -> None:
    """Waits out the grant max age, so Folio's next read sees the server's state."""
    await asyncio.sleep(GRANT_MAX_AGE_SECONDS + 0.1)


def _principal(member: Member) -> Principal:
    return Principal(
        member.team_id, member.did_key, None, None, member.alias, member.certificate_id,
        member.team_did_key,
    )


@pytest.fixture
async def present_world(listening_coordination, test_db_factory, monkeypatch, tmp_path):
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(GRANT_MAX_AGE_SECONDS))
    # Team keys are cached in the Redis other runs share; a fresh team per test.
    member = Member(
        team_id=f"t{uuid4().hex[:12]}:editor.test", alias="editor", certificate_id="cert-editor"
    )
    installations = Installations(listening_coordination, member)
    await installations.admit()
    database = await test_db_factory.create_db(suffix="folio_present")
    async with app_origin(tmp_path / "origin") as origin:
        settings = Settings(
            _env_file=None,
            database_url=database.config.get_dsn(),
            db_schema="naapp_test",
            public_origin=origin.url,
            app_id="folio-test",
            awid_registry_url=listening_coordination.registry_url,
            awid_service_token=SERVICE_TOKEN,
        )
        app = create_app(settings)
        origin.serve(app)
        async with app.router.lifespan_context(app):
            runtime = app.state.folio_runtime
            installation = await installations.install(
                origin,
                app_id=settings.app_id,
                manifest=runtime.manifest_bytes,
                granted_scopes=FOLIO_SCOPES,
            )
            db = runtime.db()
            principal = _principal(member)
            document_id = uuid4()
            await db.execute(
                "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)",
                principal.team_id,
                principal.team_did_key,
            )
            await db.execute(
                """INSERT INTO {{tables.documents}}
                (document_id, team_id, slug, title, created_by_did_key, created_by_alias)
                VALUES ($1, $2, 'draft', 'Draft', $3, $4)""",
                document_id,
                principal.team_id,
                principal.did_key,
                principal.alias,
            )
            await db.execute(
                """INSERT INTO {{tables.document_versions}}
                (version_id, document_id, version_number, body, created_by_did_key, created_by_alias, certificate_id)
                VALUES ($1, $2, 1, 'Original', $3, $4, $5)""",
                uuid4(),
                document_id,
                principal.did_key,
                principal.alias,
                principal.certificate_id,
            )
            yield World(
                app=app,
                db=db,
                settings=settings,
                member=member,
                principal=principal,
                coordination=listening_coordination,
                installations=installations,
                origin=origin,
                installation=installation,
            )


async def mint(world, *, editable=True, ttl_seconds=None):
    return await mint_presentation_link(
        world.db,
        installation_id=world.installation["installation_id"],
        principal=world.principal,
        settings=world.settings,
        slug="draft",
        version=None,
        editable=editable,
        ttl_seconds=ttl_seconds,
    )


def assert_private(response):
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("referrer-policy") == "no-referrer"


async def test_editable_ttl_default_and_explicit_maximum(present_world):
    app = present_world.app
    db = present_world.db
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
        assert (await client.get(f"/present/edit/{link['token']}")).status_code == 200


@pytest.mark.parametrize("ttl_seconds,expected", [(None, 86_400), (2_592_000, 2_592_000)])
async def test_read_only_ttl_default_and_thirty_day_maximum(present_world, ttl_seconds, expected):
    app = present_world.app
    db = present_world.db
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

    db = present_world.db
    settings = present_world.settings
    settings.max_present_ttl_seconds = maximum
    before = await db.fetch_one("SELECT count(*) AS n FROM {{tables.presentation_links}}")
    with pytest.raises(HTTPException) as refused:
        await mint(present_world, editable=False, ttl_seconds=requested)
    assert refused.value.status_code == 422
    after = await db.fetch_one("SELECT count(*) AS n FROM {{tables.presentation_links}}")
    assert after["n"] == before["n"]


@pytest.mark.parametrize("state", ["valid", "expired", "revoked", "legacy-long"])
async def test_present_responses_are_private_and_legacy_edit_links_refuse(present_world, state):
    app = present_world.app
    db = present_world.db
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
    from urllib.parse import parse_qs, urlsplit
    parts = urlsplit(link["url"])
    prefix = parts.path
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        shell = await client.get(prefix)
        assert shell.status_code == 200
        assert_private(shell)
        opened = await client.post(prefix + "/session", json={"opener": parse_qs(parts.fragment)["k"][0]})
        assert opened.status_code == (200 if state == "valid" else 404)
        assert_private(opened)
        headers = {"X-Folio-Edit-Session": opened.json()["session_secret"]} if state == "valid" else {}
        responses = [
            await client.get(prefix + "/state?after_version=1", headers=headers),
            await client.post(prefix + "/preview", headers=headers, json={"body": "Draft"}),
            await client.post(prefix + "/edit", headers=headers, json={"body": "Changed", "base_version": 1}),
        ]
        assert [r.status_code for r in responses] == ([200] * 3 if state == "valid" else [404] * 3)
        for response in responses:
            assert_private(response)
        assert (await client.get(f"/present/{link['token']}")).status_code == 404
    count = await db.fetch_one("SELECT COUNT(*) AS n FROM {{tables.document_versions}}")
    assert count["n"] == (2 if state == "valid" else 1)


async def test_read_only_long_links_still_render_privately(present_world):
    app = present_world.app
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
