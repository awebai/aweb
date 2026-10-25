"""Member use/status routes under the root's exact registered B1 dependency."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

from aweb_naapp.hooks.commitment import RequestBytes
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.team_auth import raw_request_target, signed_payload_bytes
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from aweb_secrets.broker_service import BrokerRequests
from aweb_secrets.member_types import JobRunRequests, MemberSubmission, ToolReply
from aweb_secrets.status_service import UseStatus


@dataclass(frozen=True)
class UseServices:
    broker: Callable[[], BrokerRequests]
    runs: Callable[[], JobRunRequests]
    status: Callable[[], UseStatus]


async def _submission(request: Request, authorization: Authorization) -> MemberSubmission:
    # The dependency has already authenticated these exact signed bytes and
    # matched the manifest tool; no parallel verifier or authority is added.
    trace = json.loads(signed_payload_bytes(request)).get("trace_id")
    return MemberSubmission(
        authorization=authorization,
        inbound=RequestBytes(
            method=request.method.upper(),
            raw_target=raw_request_target(request).encode("ascii"),
            content_types=tuple(
                value
                for name, value in request.scope.get("headers", ())
                if name.lower() == b"content-type"
            ),
            body=await request.body(),
        ),
        signed_trace_id=trace if isinstance(trace, str) else None,
    )


def _reply(reply: ToolReply) -> JSONResponse:
    return JSONResponse(dict(reply.body), status_code=reply.status, headers=dict(reply.headers))


def use_router(services: UseServices, *, authorized: Any) -> APIRouter:
    router = APIRouter()

    @router.post("/v1/secrets/{secret}/requests", name="request")
    async def request_secret(
        secret: str, request: Request, authorization: Annotated[Authorization, Depends(authorized)]
    ):
        return _reply(
            await services.broker().submit(
                secret=secret,
                submission=await _submission(request, authorization),
            )
        )

    @router.post("/v1/jobs/{job}/runs", name="run")
    async def run_job(
        job: str, request: Request, authorization: Annotated[Authorization, Depends(authorized)]
    ):
        return _reply(
            await services.runs().submit(
                job=job,
                submission=await _submission(request, authorization),
            )
        )

    @router.get("/v1/status/{ref}", name="status")
    async def status(ref: str, authorization: Annotated[Authorization, Depends(authorized)]):
        return _reply(await services.status().get(ref=ref, authorization=authorization))

    return router
