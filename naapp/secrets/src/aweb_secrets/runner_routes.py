"""Runner HTTP adapters for composition on the public API origin.

Registration is the pre-key code exchange. Claim/start/result use the signed
request protocol and S13's fenced dispatch service; they do not use team-auth.
The registration response carries only public identifiers and the service pin.
"""

from collections.abc import Callable
from typing import Any

from aweb_naapp.runtime.approvals.request import parse_request_json
from awid.did import did_from_public_key
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.routing import APIRoute
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager
from starlette.types import Receive, Scope, Send

from aweb_secrets.runner_framing import (
    MAX_RESULT_FRAME,
    _declared_length,
    _error,
    _FramingRefused,
    _log_failure,
    _read_body,
    _request_head,
    _runner_refusal,
    _runner_reply,
)
from aweb_secrets.runner_protocol import RunnerRefused
from aweb_secrets.runner_types import RunDispatchAPI, RunnerSubmission
from aweb_secrets.runners import register_runner


def runner_registration_router(
    *,
    db: Callable[[], AsyncDatabaseManager],
    origin: str,
    service_key: SigningKey,
) -> APIRouter:
    router = APIRouter()
    service_kid = did_from_public_key(bytes(service_key.verify_key))

    @router.post("/runner/v1/register")
    async def register(request: Request, response: Response) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 4096:
                raise HTTPException(
                    413,
                    detail={"code": "registration_request_invalid"},
                    headers={"Cache-Control": "no-store"},
                )
        try:
            body = parse_request_json(bytes(raw))
            if set(body) != {"code", "signing_key", "encryption_key"} or not all(
                isinstance(v, str) for v in body.values()
            ):
                raise ValueError("registration shape")
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(
                400,
                detail={"code": "registration_request_invalid"},
                headers={"Cache-Control": "no-store"},
            ) from None
        try:
            async with db().transaction() as tx:
                runner = await register_runner(tx, **body)
        except RunnerRefused as refused:
            raise HTTPException(
                401 if refused.code == "registration_code_invalid" else 400,
                detail={"code": refused.code},
                headers={"Cache-Control": "no-store"},
            ) from None
        return {"runner_id": runner.runner_id, "origin": origin, "service_kid": service_kid}

    return router


class _RunnerRoute(APIRoute):
    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Starlette's method refusal occurs outside the endpoint handler.
        if self.methods and scope["method"] not in self.methods:
            response = _error(405, "runner_request_invalid")
            response.headers["Allow"] = ", ".join(sorted(self.methods))
            await response(scope, receive, send)
            return
        await super().handle(scope, receive, send)


def runner_dispatch_router(*, service: Callable[[], RunDispatchAPI]) -> APIRouter:
    """Frame exact bytes; S13 owns preflight, final verification and all effects.

    The root supplies a request-time getter and mounts this outside B1. No
    service, custody opener or transaction is constructed by this router.
    """
    router = APIRouter(route_class=_RunnerRoute)

    async def dispatch(request: Request, operation: str, dispatch_ref: str = "") -> Response:
        try:
            header, target = _request_head(request)
            limit = MAX_RESULT_FRAME if operation == "result" else 4096
            _declared_length(request, limit=limit)
            current = service()
            if operation == "result":
                limit = await current.result_body_limit(
                    dispatch_ref=dispatch_ref,
                    header=header,
                    method=request.method,
                    raw_target=target,
                )
            body = await _read_body(request, limit=limit)
            submission = RunnerSubmission(header, request.method, target, body)
            if operation == "claim":
                reply = await current.claim(submission)
            elif operation == "started":
                reply = await current.started(dispatch_ref, submission)
            else:
                reply = await current.result(dispatch_ref, submission)
            return _runner_reply(reply, operation=operation)
        except RunnerRefused as refused:
            return _runner_refusal(refused)
        except _FramingRefused as refused:
            code = (
                "runner_request_too_large"
                if refused.status_code == 413
                else "runner_request_invalid"
            )
            return _error(refused.status_code, code)
        except Exception as failed:
            _log_failure(failed)
            return _error(503, "runner_unavailable")

    @router.post("/runner/v1/claim")
    async def claim(request: Request) -> Response:
        return await dispatch(request, "claim")

    @router.post("/runner/v1/dispatches/{dispatch_id}/started")
    async def started(dispatch_id: str, request: Request) -> Response:
        return await dispatch(request, "started", dispatch_id)

    @router.post("/runner/v1/dispatches/{dispatch_id}/result")
    async def result(dispatch_id: str, request: Request) -> Response:
        return await dispatch(request, "result", dispatch_id)

    return router
