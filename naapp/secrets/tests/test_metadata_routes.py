"""Metadata tools use real B1 signatures/AWID membership and a PostgreSQL catalog."""

from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest
from aweb_naapp.roles import PrincipalKey, assign, unassign
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp_testing import Member
from fastapi import FastAPI

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME, STORES
from aweb_secrets.catalog import Catalog
from aweb_secrets.jobs import apply_job_migrations
from aweb_secrets.manifest import MANIFEST_PATH
from aweb_secrets.metadata_routes import MetadataServices, metadata_router
from tests.test_admission import TEAM, _grant_source_grant
from tests.test_app import API, _settings, allow_all
from tests.test_catalog import ROLE, SECRET, seed


class Installed:
    async def grant_for(self, team_id):
        return (
            replace(_grant_source_grant(), scopes=frozenset({"secrets:read"}))
            if team_id == TEAM
            else None
        )


@asynccontextmanager
async def serving(registry, database_url, tmp_path):
    runtime = NaappRuntime(
        _settings(database_url, tmp_path),
        module_name=MODULE_NAME,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=MANIFEST_PATH,
        awid_transport=registry.transport,
        stores=(*STORES, apply_job_migrations),
    )
    grants = Installed()
    authorized = runtime.authorized(grants=grants, policy=allow_all)
    # Exactly the supplied runtime guard is recorded in the app and routes.
    api = FastAPI(lifespan=runtime.lifespan)
    api.include_router(
        metadata_router(
            MetadataServices(
                catalog=lambda: Catalog(
                    runtime.db(),
                    fence=InstallationFence(runtime.db(), app_id="secrets-test", grants=grants),
                )
            ),
            authorized=authorized,
        )
    )
    async with api.router.lifespan_context(api):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(api), base_url=API) as client:
            yield runtime, client


def headers(member, path):
    return member.headers(aud=API, method="GET", path=path, body=b"")


@pytest.fixture
async def members(registry):
    alice = Member(team_id=TEAM)
    bob = Member(team_id=TEAM, team_key=alice.team_key, certificate_id="cert-2", alias="bob")
    await registry.add_team(TEAM, alice.team_did_key)
    await registry.add_certificate(alice.certificate())
    await registry.add_certificate(bob.certificate())
    return alice, bob


async def test_real_role_members_get_metadata_and_revocation_is_immediate(
    registry, test_db_factory, tmp_path, members
):
    database = await test_db_factory.create_db(suffix="metadata_http")
    alice, bob = members
    async with serving(registry, database.config.get_dsn(), tmp_path) as (runtime, client):
        await seed(runtime.db())
        async with runtime.db().transaction() as tx:
            for member in members:
                await assign(tx, PrincipalKey(TEAM, member.did_key), ROLE)
        for member in members:
            response = await client.get("/v1/secrets", headers=headers(member, "/v1/secrets"))
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["state"] == "completed" and body["request_id"] is None
            assert [item["ref"] for item in body["result"]["secrets"]] == [SECRET["ref"]]
        async with runtime.db().transaction() as tx:
            await unassign(tx, PrincipalKey(TEAM, alice.did_key), ROLE)
        path = "/v1/secrets/" + SECRET["ref"]
        denied = await client.get(path, headers=headers(alice, path))
        assert denied.status_code == 404
        assert denied.json() == {"state": "refused", "request_id": None, "code": "secret_not_found"}
        allowed = await client.get(path, headers=headers(bob, path))
        assert allowed.status_code == 200
        assert set(allowed.json()["result"]) == {
            "ref",
            "kind",
            "sensitivity",
            "approval_required",
            "destinations",
            "operations",
            "jobs",
        }
        assert not await runtime.db().fetch_value("SELECT count(*) FROM {{tables.intents}}")


async def test_unsigned_or_wrong_audience_calls_never_reach_metadata(
    registry, test_db_factory, tmp_path, members
):
    database = await test_db_factory.create_db(suffix="metadata_auth")
    alice, _ = members
    async with serving(registry, database.config.get_dsn(), tmp_path) as (_, client):
        assert (await client.get("/v1/secrets")).status_code == 401
        bad = alice.headers(aud="https://other.example", method="GET", path="/v1/secrets", body=b"")
        assert (await client.get("/v1/secrets", headers=bad)).status_code == 401
