"""The server's real request resolver accepts only a witnessed child controller."""

from pathlib import Path
import runpy

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request

from aweb.team_key_pins import pinned_team_key_for_request
from awid_service.db import AwidDatabaseInfra

world = runpy.run_path(
    str(
        Path(__file__).resolve().parents[2]
        / "awid/tests/team_key_delegation_support.py"
    )
)["world"]


@pytest_asyncio.fixture
async def awid_db_infra(shared_test_pool):
    infra = AwidDatabaseInfra(schema="awid")
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        yield infra
    finally:
        await infra.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("delegated", [True, False])
async def test_request_pin_checks_the_actual_delegated_namespace(
    world, aweb_cloud_db, monkeypatch, delegated
):
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    db = aweb_cloud_db.aweb_db
    team_id = "base:" + world.domain
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) "
        "VALUES ($1,$2,$3,$4)",
        team_id,
        world.domain,
        "base",
        world.parent[1],
    )
    if not delegated:
        await world.db.execute(
            "UPDATE {{tables.dns_namespaces}} SET parent_domain=NULL,parent_controller_key=NULL WHERE domain=$1",
            world.domain,
        )
    app = FastAPI()
    app.state.awid_registry_client = world.sdk
    app.state.awid_txt_resolver = world.resolver

    @app.get("/key")
    async def key(request: Request):
        return {
            "key": await pinned_team_key_for_request(
                request, team_id, world.team[1], db=aweb_cloud_db
            )
        }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://server.example.com"
    ) as client:
        response = await client.get("/key")
    if delegated:
        assert response.status_code == 200, response.text
        assert response.json()["key"] == world.team[1]
        assert (
            await db.fetch_value(
                "SELECT team_key_act_key FROM {{tables.teams}} WHERE team_id=$1",
                team_id,
            )
            == world.team[1]
        )
    else:
        assert response.status_code == 401, response.text
        assert response.json()["detail"] == "team_key_unverified"
        assert (
            await db.fetch_value(
                "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1", team_id
            )
            == world.parent[1]
        )
