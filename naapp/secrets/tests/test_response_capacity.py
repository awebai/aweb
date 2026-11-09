"""Response reservations gate real broker effects and survive every exit path."""

import asyncio

import pytest
from fastapi import Request, Response
from starlette.responses import StreamingResponse

from tests.harness import running_upstream
from tests.test_admission import POLICY_BODY, SECRET
from tests.test_broker_service import db as db
from tests.test_broker_service import fence as fence
from tests.test_broker_service import setup, submission

LIMIT = POLICY_BODY["result"]["max_bytes"]


async def test_capacity_refuses_immediately_before_send_and_preserves_resubmission(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        entered = {name: asyncio.Event() for name in ("one", "two")}
        released = {name: asyncio.Event() for name in entered}
        applied = []

        @upstream.app.post("/bearer/capacity/{name}")
        async def effect(name: str, request: Request):
            if request.headers.get("authorization") != "Bearer " + upstream.creds.bearer:
                return Response(status_code=403)
            applied.append(name)
            if name in entered:
                entered[name].set()
                await released[name].wait()
            return Response(b'{"ok":true}', media_type="application/json")

        service = await setup(db, fence, tmp_path, upstream, response_budget_bytes=2 * LIMIT)

        def call(name):
            return service.submit(
                secret=SECRET["ref"],
                submission=submission(
                    upstream, request_id=name, url=upstream.url(f"/bearer/capacity/{name}")
                ),
            )

        first = asyncio.create_task(call("one"))
        second = asyncio.create_task(call("two"))
        try:
            async with asyncio.timeout(5):
                await entered["one"].wait()
                await entered["two"].wait()
            # Neither response is released: a waiting reservation cannot pass.
            async with asyncio.timeout(0.5):
                third = await call("three")
            assert third.status == 503 and third.body["code"] == "capacity_unavailable"
            assert third.headers["Retry-After"] == "1"
            assert set(applied) == {"one", "two"}
            assert (
                await db.fetch_value(
                    "SELECT count(*) FROM {{tables.dispatches}} WHERE state='dispatching'"
                )
                == 2
            )
            released["one"].set()
            assert (await first).body["state"] == "completed"
            # Same grant, while 'two' remains blocked: no capacity or DB lock leak.
            async with asyncio.timeout(1):
                fourth = await call("four")
            assert fourth.body["state"] == "completed"
            retry = await call("three")
            assert retry.body["state"] == "completed"
            assert applied.count("three") == 1
        finally:
            for event in released.values():
                event.set()
            await asyncio.gather(first, second, return_exceptions=True)


@pytest.mark.parametrize("exit_path", ["success", "stream_failure", "cancelled"])
async def test_response_capacity_is_released_after_success_failure_and_cancellation(
    db, fence, tmp_path, exit_path
):
    async with running_upstream(tmp_path) as upstream:
        entered, release = asyncio.Event(), asyncio.Event()

        @upstream.app.post("/bearer/reservation")
        async def effect():
            entered.set()
            await release.wait()
            if exit_path == "stream_failure":

                async def broken():
                    yield b'{"ok":'
                    raise RuntimeError("fixture response stream interrupted")

                return StreamingResponse(broken(), media_type="application/json")
            return Response(b'{"ok":true}', media_type="application/json")

        service = await setup(db, fence, tmp_path, upstream, response_budget_bytes=LIMIT)
        sender = asyncio.create_task(
            service.submit(
                secret=SECRET["ref"],
                submission=submission(upstream, url=upstream.url("/bearer/reservation")),
            )
        )
        try:
            await asyncio.wait_for(entered.wait(), 5)
            if exit_path == "cancelled":
                sender.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await sender
            else:
                release.set()
                original = await sender
                assert original.body["state"] == (
                    "outcome_unknown" if exit_path == "stream_failure" else "completed"
                )
            following = await service.submit(
                secret=SECRET["ref"],
                submission=submission(upstream, request_id="after-release"),
            )
            assert following.body["state"] == "completed"
            assert upstream.paths.count("/bearer/echo") == 1
        finally:
            release.set()
            if not sender.done():
                sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
