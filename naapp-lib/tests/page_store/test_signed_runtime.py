"""Real certificates, signed requests, admission, PostgreSQL and page projections."""

import json
import time
from typing import Annotated

import httpx
from aweb_naapp_testing import REGISTRY_URL, Member
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from aweb_naapp.manifest import write_manifest_file
from aweb_naapp.page_store import Access, PageStore, Scope, StoreError, apply_page_store_migrations
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import Authorization, Grant
from aweb_naapp.runtime.settings import NaappSettings
from tests.page_store.test_store import POLICY, page

ORIGIN = "https://fixture.example"
MANIFEST = {
    "manifest_version": 1,
    "app": {"id": "fixture", "origin": ORIGIN},
    "tools": [
        {"name": "fixture_read", "method": "GET", "path": "/fixture", "scopes": ["page:read"]},
        {
            "name": "fixture_query",
            "method": "POST",
            "path": "/fixture/query",
            "scopes": ["page:read"],
        },
        {
            "name": "fixture_create",
            "method": "POST",
            "path": "/fixture",
            "scopes": ["page:write"],
        },
        {
            "name": "fixture_edit",
            "method": "POST",
            "path": "/fixture/edit",
            "scopes": ["page:write"],
        },
    ],
}


class InstalledGrant:
    def __init__(self, team):
        self.team, self.active = team, True

    async def grant_for(self, team_id):
        if self.active and team_id == self.team:
            return Grant(
                team_id=team_id,
                scopes=frozenset({"page:read", "page:write"}),
                fresh_until=time.monotonic() + 30,
                installation_id="fixture-install",
                generation=1,
            )
        return None


async def page_policy(request, principal, tool):
    # This fixture app has no app-level restriction beyond its installed team.
    # PageStore applies the actual owner, row and field policy below admission.
    return True


async def test_signed_member_operations_and_revoked_install_cannot_bypass_acl(
    registry, test_db_factory, tmp_path
):
    owner = Member(team_id="fixture:example.com")
    stranger = Member(
        team_id=owner.team_id, team_key=owner.team_key, certificate_id="cert-2", alias="bob"
    )
    await registry.add_team(owner.team_id, owner.team_did_key)
    await registry.add_certificate(owner.certificate())
    await registry.add_certificate(stranger.certificate())
    content = await test_db_factory.create_db(suffix="signed_pages")
    ledger = await test_db_factory.create_db(suffix="signed_ledger")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_fixture.sql").write_text(
        "CREATE TABLE {{tables.fixture_versions}} (version int);\n"
    )
    manifest_path = tmp_path / "aweb-app.json"
    write_manifest_file(manifest_path, MANIFEST)
    runtime = NaappRuntime(
        NaappSettings(
            _env_file=None,
            database_url=content.config.get_dsn(),
            public_origin=ORIGIN,
            app_id="fixture",
            awid_registry_url=REGISTRY_URL,
        ),
        module_name="signed_page_fixture",
        migrations_path=migrations,
        manifest_path=manifest_path,
        awid_transport=registry.transport,
    )
    grants = InstalledGrant(owner.team_id)
    authorized = runtime.authorized(grants=grants, policy=page_policy)
    app = FastAPI(lifespan=runtime.lifespan)
    scope = Scope("fixture-install", owner.team_id, "fixture", "fixture-home")

    @app.exception_handler(StoreError)
    async def failure(request, error):
        return JSONResponse(status_code=error.status, content={"code": error.code})

    @app.get("/fixture")
    async def read(auth: Annotated[Authorization, Depends(authorized)]):
        return await app.state.pages.read(scope, auth.principal)

    @app.post("/fixture")
    async def create(request: Request, auth: Annotated[Authorization, Depends(authorized)]):
        return await app.state.pages.create(
            scope,
            auth.principal,
            await request.json(),
            access=Access(owner=owner.did_key),
            key="create",
        )

    @app.post("/fixture/query")
    async def query(request: Request, auth: Annotated[Authorization, Depends(authorized)]):
        return await app.state.pages.read_widget(
            scope, auth.principal, widget_id="items", **await request.json()
        )

    @app.post("/fixture/edit")
    async def edit(request: Request, auth: Annotated[Authorization, Depends(authorized)]):
        return await app.state.pages.mutate(scope, auth.principal, **await request.json())

    async with app.router.lifespan_context(app):
        await apply_page_store_migrations(runtime.db(), ledger)
        app.state.pages = PageStore(runtime.db(), ledger=ledger, retention=POLICY)
        await app.state.pages.start()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN
        ) as client:

            async def call(member, method, path, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                return await client.request(
                    method,
                    path,
                    content=raw,
                    headers=member.headers(aud=ORIGIN, method=method, path=path, body=raw),
                )

            assert (await call(owner, "POST", "/fixture", page())).status_code == 200
            initial = await call(owner, "GET", "/fixture")
            assert initial.status_code == 200 and initial.json()["rev"] == 1
            assert (await call(stranger, "GET", "/fixture")).status_code == 404
            edit_body = {
                "expected_rev": 1,
                "key": "edit",
                "records": [
                    {
                        "op": "update",
                        "collection": "items",
                        "id": "item-1",
                        "expected_rev": 1,
                        "value": {"label": "Signed owner edit", "checked": True},
                    }
                ],
            }
            assert (await call(owner, "POST", "/fixture/edit", edit_body)).json()["page_rev"] == 2
            queried = await call(
                owner,
                "POST",
                "/fixture/query",
                {"expected_page_rev": 2, "bind": {"collection": "items"}},
            )
            assert queried.json()["records"][0]["value"]["label"] == "Signed owner edit"
            # A valid signed request still needs the current installation grant.
            grants.active = False
            assert (await call(owner, "GET", "/fixture")).status_code == 403
            assert (await call(owner, "POST", "/fixture/edit", edit_body)).status_code == 403
