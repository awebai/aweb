"""Signed runner transport through create_app and the real durable S13 service.

This is the bounded transport mount, not the production root or HO6 journey.
"""

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager

import httpx
from aweb_naapp.hooks.strictjson import encode_base64url
from aweb_naapp_testing.databases import TEST_SCHEMA
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import runners
from aweb_secrets.app import create_app
from aweb_secrets.run_service import RunDispatch
from aweb_secrets.runner_routes import runner_dispatch_router
from tests.run_world import ORIGIN
from tests.test_app import CONSOLE, InstalledTeams, _settings, allow_all, kms_check
from tests.test_run_dispatch_service import report, setup
from tests.test_run_runner_routes import headers
from tests.test_use_approvals import TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


@asynccontextmanager
async def mounted(uses, registry, tmp_path):
    active = []

    @asynccontextmanager
    async def prepare(runtime):
        context = await setup(uses)
        run = RunDispatch(runtime.db(), **context.arguments)
        active.append((context, run))
        try:
            yield
        finally:
            active.clear()

    def runner_factory(runtime):
        return runner_dispatch_router(service=lambda: active[0][1])

    settings = _settings(uses.world.db.config.get_dsn(), tmp_path).model_copy(
        update={"db_schema": TEST_SCHEMA, "app_id": "secrets", "public_origin": ORIGIN}
    )
    service = create_app(
        settings,
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
        awid_transport=registry.transport,
        prepare=prepare,
        runner_routers=(runner_factory,),
    )
    async with service.api_app.router.lifespan_context(service.api_app):
        context, run = active[0]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(service), base_url=ORIGIN
        ) as client:
            yield client, context, run


async def report_state(db):
    return (
        dict(await db.fetch_one("SELECT state,result,late_results FROM {{tables.dispatches}}")),
        await db.fetch_value("SELECT report_sha256 FROM {{tables.run_deliveries}}"),
        await db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}"),
        await db.fetch_value("SELECT count(*) FROM {{tables.broker_use_events}}"),
    )


async def test_mounted_signed_roundtrip_replays_exact_bytes_and_rolls_back_conflict(
    uses, registry, tmp_path
):
    async with mounted(uses, registry, tmp_path) as (client, context, run):
        admitted = await run.submit(job=context.job.job_id, submission=context.submission)
        assert admitted.status == 202
        first = context.signed("/runner/v1/claim", b" \n{}\t")
        assignment = await client.post(first.raw_target, content=first.body, headers=headers(first))
        assert assignment.status_code == 200
        stored = await uses.world.db.fetch_value("SELECT assignment FROM {{tables.run_deliveries}}")
        assert assignment.content == bytes(stored)
        retry = context.signed("/runner/v1/claim")
        replay = await client.post(retry.raw_target, content=retry.body, headers=headers(retry))
        assert replay.status_code == 200 and replay.content == assignment.content
        repeated = await client.post(first.raw_target, content=first.body, headers=headers(first))
        assert repeated.status_code == 409
        assert repeated.json()["detail"]["code"] == "runner_request_replayed"
        assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1
        target = "/runner/v1/dispatches/" + assignment.json()["assignment"]["dispatch_id"]
        started = context.signed(target + "/started")
        response = await client.post(
            started.raw_target, content=started.body, headers=headers(started)
        )
        assert response.status_code == 204 and response.content == b""
        raw = b"\n" + report(context.credential) + b" "
        signed = context.signed(target + "/result", raw)

        async def stream():
            for index in range(0, len(raw), 7):
                yield raw[index : index + 7]

        response = await client.post(signed.raw_target, content=stream(), headers=headers(signed))
        assert response.status_code == 204 and response.content == b""
        assert response.headers["cache-control"] == "no-store"
        before = await report_state(uses.world.db)
        assert bytes(before[1]) == hashlib.sha256(raw).digest()
        receipt = await run.submit(job=context.job.job_id, submission=context.submission)
        assert receipt.body["state"] == "completed"
        if context.credential in json.dumps(receipt.body):
            raise AssertionError("mounted result released the original credential")
        duplicate = context.signed(target + "/result", raw)
        response = await client.post(
            duplicate.raw_target, content=duplicate.body, headers=headers(duplicate)
        )
        assert response.status_code == 204
        after = await report_state(uses.world.db)
        assert after[:2] == before[:2] and after[3] == before[3]
        assert after[2] == before[2] + 1
        conflict = context.signed(target + "/result", report("changed"))
        response = await client.post(
            conflict.raw_target, content=conflict.body, headers=headers(conflict)
        )
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "runner_result_conflict"
        assert await report_state(uses.world.db) == after


async def test_mounted_runner_authority_is_api_only_and_distinct_from_member_b1(
    uses, registry, tmp_path
):
    async with mounted(uses, registry, tmp_path) as (client, context, _run):
        signed = context.signed("/runner/v1/claim")
        response = await client.post(
            CONSOLE + signed.raw_target, content=signed.body, headers=headers(signed)
        )
        assert response.status_code == 403
        assert response.json()["code"] == "team_auth_refused"
        assert (await client.post(CONSOLE + signed.raw_target, json={})).status_code == 404
        member = await client.post(f"/v1/jobs/{context.job.job_id}/runs", json={})
        assert member.status_code == 401
        missing = await client.post("/runner/v1/claim", json={})
        assert missing.status_code == 400
        tampered = await client.post(
            signed.raw_target, content=b'{"unexpected":true}', headers=headers(signed)
        )
        assert tampered.status_code == 400
        assert tampered.json()["detail"]["code"] == "runner_request_binding_mismatch"
        assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 0
        valid = await client.post(signed.raw_target, content=signed.body, headers=headers(signed))
        assert valid.status_code == 204 and valid.content == b""
        assert valid.headers["cache-control"] == "no-store"
        assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 1
        assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 0


async def test_mounted_stream_key_rotation_rechecks_authority_and_rolls_back_report(
    uses, registry, tmp_path
):
    async with mounted(uses, registry, tmp_path) as (client, context, run):
        await run.submit(job=context.job.job_id, submission=context.submission)
        claim = context.signed("/runner/v1/claim")
        assigned = await client.post(claim.raw_target, content=claim.body, headers=headers(claim))
        assert assigned.status_code == 200
        target = "/runner/v1/dispatches/" + assigned.json()["assignment"]["dispatch_id"] + "/result"
        signed = context.signed(target, report())
        before = await report_state(uses.world.db)
        rotated = False

        async def stream():
            nonlocal rotated
            # This receive runs after the real result preflight. A held runner
            # lock would prevent this separate authoritative rotation completing.
            async with asyncio.timeout(3):
                async with uses.world.db.transaction() as tx:
                    code = await runners.replace_runner(
                        tx,
                        uses.world.admitted.installation_id,
                        TEAM,
                        context.runner,
                        now=uses.clock(),
                    )
                    signing, encryption = SigningKey.generate(), X25519PrivateKey.generate()
                    await runners.register_runner(
                        tx,
                        code=code,
                        signing_key=did_from_public_key(bytes(signing.verify_key)),
                        encryption_key=encode_base64url(encryption.public_key().public_bytes_raw()),
                        clock=uses.clock,
                    )
            rotated = True
            yield signed.body

        response = await client.post(target, content=stream(), headers=headers(signed))
        assert rotated and response.status_code == 401
        assert response.json()["detail"]["code"] == "runner_unknown"
        assert response.headers["cache-control"] == "no-store"
        assert await report_state(uses.world.db) == before
