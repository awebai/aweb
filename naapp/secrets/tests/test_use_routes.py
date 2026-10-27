"""Actual member signatures/AWID, broker service, PostgreSQL and TLS transport."""

import asyncio
import json
from dataclasses import replace

import httpx
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp_testing import Member
from awid_service.testing import REGISTRY_URL

from aweb_secrets.app import create_app
from aweb_secrets.status_service import UseStatus
from aweb_secrets.use_routes import UseServices, use_router
from tests.harness import running_upstream
from tests.test_admission import TEAM, _grant_source_grant, _install
from tests.test_app import _settings, allow_all, kms_check
from tests.test_broker_audit import INSTALLATION
from tests.test_broker_service import SECRET, setup

API = "https://api.localhost"


class Installed:
    async def grant_for(self, team_id, certificate_id=None):
        return (
            replace(
                _grant_source_grant(installation_id=INSTALLATION),
                scopes=frozenset({"secrets:use", "secrets:read"}),
            )
            if team_id == TEAM
            else None
        )


def unused_run_service():
    raise AssertionError("this broker integration must not resolve the run service")


async def test_actual_guard_binds_submission_and_status_never_sends(
    registry,
    test_db_factory,
    tmp_path,
):
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key)
    await registry.add_certificate(member.certificate())
    database = await test_db_factory.create_db(suffix="broker_http")
    grants, shared = Installed(), {}

    def routes(runtime, authorized):
        return use_router(
            UseServices(
                broker=lambda: shared["broker"],
                runs=unused_run_service,
                status=lambda: UseStatus(runtime.db(), fence=shared["fence"]),
            ),
            authorized=authorized,
        )

    settings = _settings(database.config.get_dsn(), tmp_path).model_copy(
        update={"app_id": "secrets", "public_origin": API}
    )
    service = create_app(
        settings,
        grants=grants,
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        tool_routers=(routes,),
    )
    discovery_domains = []

    async def registry_override(domain):
        discovery_domains.append(domain)
        assert domain == TEAM.split(":", 1)[1]
        return REGISTRY_URL

    # Keep the runtime's real hook drain and directory, with the same
    # in-process registry discovery answer as the member verifier.
    service.runtime.team_server_directory()._registry_override = registry_override
    async with service.api_app.router.lifespan_context(service.api_app):
        db = service.runtime.db()
        fence = InstallationFence(db, app_id="secrets", grants=grants)
        async with running_upstream(tmp_path) as upstream:
            shared.update(broker=await setup(db, fence, tmp_path, upstream), fence=fence)
            await _install(
                db,
                installation_id=INSTALLATION,
                subject={"principal": member.did_key},
                grant_id="grt_http001",
            )
            path = f"/v1/secrets/{SECRET['ref']}/requests"
            target = path + "?transport=original"
            body = json.dumps(
                {
                    "request_id": "http-use",
                    "method": "POST",
                    "url": upstream.url("/bearer/echo"),
                    "data": "hello",
                }
            ).encode()
            headers = member.headers(aud=API, method="POST", path=target, body=body)
            headers["Content-Type"] = "application/json"
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(service), base_url=API
            ) as client:
                assert (await client.post(target, content=body)).status_code == 401
                assert (
                    await client.post(target, content=body + b" ", headers=headers)
                ).status_code == 401
                assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 0
                response = await client.post(target, content=body, headers=headers)
                assert response.status_code == 200 and response.json()["state"] == "completed"
                receipt = response.json()
                again = await client.post(
                    target,
                    content=body,
                    headers=member.headers(
                        aud=API,
                        method="POST",
                        path=target,
                        body=body,
                    )
                    | {"Content-Type": "application/json"},
                )
                assert again.status_code == 200 and again.json() == receipt
                status_path = "/v1/status/" + receipt["request_ref"]
                status = await client.get(
                    status_path,
                    headers=member.headers(
                        aud=API,
                        method="GET",
                        path=status_path,
                        body=b"",
                    ),
                )
                assert status.status_code == 200 and status.json() == receipt
                assert upstream.paths == ["/bearer/echo"]
                assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 1
                # Observe the background drain using the configured external
                # discovery seam; a fast test must not hide an untested default.
                async with asyncio.timeout(10):
                    while not discovery_domains:
                        await asyncio.sleep(0.01)
                assert set(discovery_domains) == {TEAM.split(":", 1)[1]}
