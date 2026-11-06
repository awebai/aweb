"""The real S15a framing adapter against the actual S13 run service and PG."""

import httpx
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_secrets.runner_routes import runner_dispatch_router
from tests.run_world import ORIGIN
from tests.test_run_dispatch_service import report, setup
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


def headers(signed):
    return {"Content-Type": "application/json", "X-Aweb-Secrets-Runner-Request": signed.header}


async def test_framed_claim_started_and_streamed_report_use_one_actual_service(uses):
    context = await setup(uses)
    await context.service.submit(job=context.job.job_id, submission=context.submission)
    app = FastAPI()
    app.include_router(runner_dispatch_router(service=lambda: context.service))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        signed = context.signed("/runner/v1/claim")
        assignment = await client.post(
            signed.raw_target, content=signed.body, headers=headers(signed)
        )
        assert assignment.status_code == 200 and assignment.headers["cache-control"] == "no-store"
        dispatch_ref = assignment.json()["assignment"]["dispatch_id"]
        target = f"/runner/v1/dispatches/{dispatch_ref}"
        started = context.signed(target + "/started")
        response = await client.post(
            started.raw_target, content=started.body, headers=headers(started)
        )
        assert response.status_code == 204 and response.content == b""
        raw = report(context.credential)
        signed = context.signed(target + "/result", raw)

        async def stream():
            for index in range(0, len(raw), 7):
                yield raw[index : index + 7]

        response = await client.post(signed.raw_target, content=stream(), headers=headers(signed))
        assert response.status_code == 204 and response.content == b""
        assert response.headers["cache-control"] == "no-store"
    receipt = await context.service.submit(job=context.job.job_id, submission=context.submission)
    assert receipt.body["state"] == "completed"
    if context.credential in repr(receipt):
        raise AssertionError("HTTP result released the original credential")
    assert await uses.world.db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == 3


async def test_result_signature_preflight_refuses_before_streaming_any_body(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    dispatch_ref = wire["assignment"]["dispatch_id"]
    target = f"/runner/v1/dispatches/{dispatch_ref}/result"
    signed = context.signed(target, report(), key=SigningKey.generate())
    app = FastAPI()
    app.include_router(runner_dispatch_router(service=lambda: context.service))
    streamed = False

    async def unread():
        nonlocal streamed
        streamed = True
        yield signed.body

    before = await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        response = await client.post(target, content=unread(), headers=headers(signed))
    assert response.status_code == 401 and response.json()["detail"]["code"] == "runner_unknown"
    assert not streamed
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.scoped_nonces}}") == before
    )
    assert (
        await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "dispatching"
    )
