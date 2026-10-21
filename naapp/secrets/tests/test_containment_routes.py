"""Containment's agent route uses real B1 team-auth and the PG services."""

import json
import os
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
from aweb_naapp.roles import PrincipalKey, assign
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing import Member
from fastapi import FastAPI

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME, STORES
from aweb_secrets.containment_routes import containment_api_router
from aweb_secrets.manifest import MANIFEST_PATH
from aweb_secrets.owners import OWNER_ROLE
from tests.test_app import _settings, allow_all
from tests.test_change_sets import TEAM, Installations, world  # noqa: F401
from tests.test_containment_service import service
from tests.test_use_approval_lineage import seed
from tests.test_use_approvals import SECRET_ID
from tests.test_use_approvals import uses as _uses

uses = _uses
API = "https://api.secrets.test"
CONSOLE = "https://console.secrets.test"
PATH = "/v1/containment"


class AdminInstallations(Installations):
    @property
    def grant(self):
        return replace(super().grant, scopes=frozenset({"secrets:admin"}))


@asynccontextmanager
async def running(uses, registry):
    svc = await service(uses)
    with TemporaryDirectory() as directory:
        runtime = NaappRuntime(
            _settings(uses.world.db.config.get_dsn(), Path(directory)).model_copy(
                update={"db_schema": "naapp_test"}
            ),
            module_name=MODULE_NAME,
            migrations_path=MIGRATIONS_PATH,
            manifest_path=MANIFEST_PATH,
            awid_transport=registry.transport,
            stores=STORES,
        )
        api = FastAPI(lifespan=runtime.lifespan)
        api.include_router(
            containment_api_router(
                svc,
                authorized=runtime.authorized(grants=AdminInstallations(), policy=allow_all),
            )
        )
        app = split_origins(api, FastAPI(), agent_origin=API, human_origin=CONSOLE)
        async with runtime.lifespan(api):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=API
            ) as client:
                yield client


async def test_signed_owner_can_contain_and_unsigned_cookie_or_console_cannot(uses, registry):
    await seed(uses)
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key)
    await registry.add_certificate(member.certificate())
    async with uses.world.db.transaction() as tx:
        await assign(tx, PrincipalKey(team_id=TEAM, principal_did=member.did_key), OWNER_ROLE)
    body = json.dumps(
        {"request_id": "api-disable", "action": "disable-secret", "target": SECRET_ID}
    ).encode()
    async with running(uses, registry) as api:
        assert (
            await api.post(PATH, content=body, headers={"Cookie": "__Host-console=invalid"})
        ).status_code == 401
        assert (await api.post(CONSOLE + PATH, content=body)).status_code == 404
        headers = member.headers(aud=API, method="POST", path=PATH, body=body)
        response = await api.post(
            PATH, content=body, headers={**headers, "Content-Type": "application/json"}
        )
        assert response.status_code == 200, response.text
        assert response.json()["affected_secret_ids"] == [SECRET_ID]
        assert "set-cookie" not in response.headers
        assert "cookie" not in response.headers


async def test_bad_body_and_reenable_never_echo_arbitrary_input(uses, registry):
    await seed(uses)
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key)
    await registry.add_certificate(member.certificate())
    async with uses.world.db.transaction() as tx:
        await assign(tx, PrincipalKey(team_id=TEAM, principal_did=member.did_key), OWNER_ROLE)
    canary = os.urandom(24).hex()
    async with running(uses, registry) as api:
        for value in (
            {"request_id": "bad", "action": "disable-secret", "target": SECRET_ID, "value": canary},
            {"request_id": "enable", "action": "reenable", "target": SECRET_ID},
        ):
            body = json.dumps(value).encode()
            response = await api.post(
                PATH,
                content=body,
                headers={
                    **member.headers(aud=API, method="POST", path=PATH, body=body),
                    "Content-Type": "application/json",
                },
            )
            assert response.status_code == 400, response.text
            assert canary not in response.text
