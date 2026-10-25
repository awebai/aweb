"""Real B1 revocation commits while a broker waits outside its final fence."""

import asyncio
import json

import httpx
from aweb_naapp.runtime.approvals import ApprovalState, Assurance, Decision
from aweb_naapp_testing import Member
from nacl.signing import SigningKey

from aweb_secrets.app import create_app
from aweb_secrets.containment_routes import containment_api_router
from aweb_secrets.use_routes import UseServices, use_router
from tests.harness import running_upstream
from tests.test_app import _settings, allow_all, kms_check
from tests.test_broker_approved_service import setup
from tests.test_broker_containment import API, InstalledTools
from tests.test_containment_service import service as containment_service
from tests.test_use_approvals import REQUESTER, SECRET, TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_routes import unused_run_service


async def test_mounted_revoke_commits_before_final_fence_and_prevents_any_send(
    uses, registry, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        broker, audit, view, _ = await setup(uses, tmp_path, upstream)
        containment = await containment_service(uses)
        db = uses.world.db
        member = Member(
            team_id=TEAM,
            member_key=SigningKey(bytes([7]) * 32),
            extra_cert_fields={"member_did_aw": REQUESTER.did_aw},
        )
        assert await registry.register_did(member.member_key) == REQUESTER.did_aw
        await registry.add_team(TEAM, member.team_did_key)
        await registry.add_certificate(member.certificate())

        def broker_routes(runtime, authorized):
            return use_router(
                UseServices(
                    broker=lambda: broker,
                    runs=unused_run_service,
                    status=lambda: broker._status,
                ),
                authorized=authorized,
            )

        def containment_routes(runtime, authorized):
            return containment_api_router(containment, authorized=authorized)

        app = create_app(
            _settings(db.config.get_dsn(), tmp_path).model_copy(
                update={"app_id": "secrets", "public_origin": API, "db_schema": "naapp_test"}
            ),
            grants=InstalledTools(),
            policy=allow_all,
            kms=kms_check(True),
            awid_transport=registry.transport,
            tool_routers=(broker_routes, containment_routes),
        )
        async with app.api_app.router.lifespan_context(app.api_app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url=API
            ) as client:

                async def post(path, body):
                    raw = json.dumps(body).encode()
                    return await client.post(
                        path,
                        content=raw,
                        headers=member.headers(aud=API, method="POST", path=path, body=raw)
                        | {"Content-Type": "application/json"},
                    )

                path = f"/v1/secrets/{SECRET['ref']}/requests"
                body = {
                    "request_id": "revoke-before-publication",
                    "method": "POST",
                    "url": upstream.url("/bearer/echo"),
                    "data": "hello",
                }
                pending = await post(path, body)
                assert pending.status_code == 202 and pending.json()["state"] == "awaiting_approval"
                association = await db.fetch_one("SELECT * FROM {{tables.use_approvals}}")
                approval_id = association["approval_id"]
                [token] = [
                    token
                    for candidate, token in uses.world.inbox.links["finance@acme.com"]
                    if candidate == approval_id
                ]
                options = await uses.approvals.challenge(
                    approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
                )
                with audit.prepared_view(view):
                    await uses.approvals.decide(
                        approval_id,
                        Decision.APPROVE,
                        Assurance.PASSKEY,
                        uses.world.devices["finance@acme.com"].get(dict(options)),
                        link_token=token,
                    )

                sender = None
                try:
                    async with db.transaction() as barrier:
                        # Initial admission reads metadata, not custody. This
                        # blocks the real observation SELECT after that tx has
                        # committed, while no publication authority is held.
                        await barrier.execute(
                            "LOCK TABLE {{tables.custody_secrets}} IN ACCESS EXCLUSIVE MODE"
                        )
                        blocker = await barrier.fetch_value("SELECT pg_backend_pid()")
                        sender = asyncio.create_task(post(path, body))
                        async with asyncio.timeout(5):
                            while not await db.fetch_value(
                                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                                "WHERE $1=ANY(pg_blocking_pids(pid)))",
                                blocker,
                            ):
                                if sender.done():
                                    response = await sender
                                    raise AssertionError(
                                        (response.status_code, response.json().get("code"))
                                    )
                                await asyncio.sleep(0.01)
                        assert (
                            await db.fetch_value("SELECT state FROM {{tables.dispatches}}")
                            == "awaiting_approval"
                        )
                        revoked = await asyncio.wait_for(
                            post(
                                "/v1/containment",
                                {
                                    "request_id": "revoke-during-observation",
                                    "action": "revoke-approvals",
                                    "target": approval_id,
                                },
                            ),
                            5,
                        )
                        assert revoked.status_code == 200
                        approval = await uses.approvals.get(approval_id)
                        assert approval.state is ApprovalState.REVOKED
                        assert (
                            await db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
                        )
                    response = await asyncio.wait_for(sender, 5)
                    assert (
                        response.status_code == 403
                        and response.json()["code"] == "approval_revoked"
                    )
                    assert (
                        await db.fetch_value("SELECT state FROM {{tables.dispatches}}")
                        == "cancelled"
                    )
                    assert await db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 0
                    assert upstream.paths == []
                finally:
                    if sender is not None and not sender.done():
                        sender.cancel()
                        await asyncio.gather(sender, return_exceptions=True)
