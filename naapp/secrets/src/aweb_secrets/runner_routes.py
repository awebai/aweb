"""Runner registration HTTP adapter, composed on the public API origin.

Registration is the pre-key code exchange. Claim/start/result use the signed
request protocol and S13's fenced dispatch service; they do not use team-auth.
The registration response carries only public identifiers and the service pin.
"""

from collections.abc import Callable
from typing import Any

from aweb_naapp.runtime.approvals.request import parse_request_json
from awid.did import did_from_public_key
from fastapi import APIRouter, HTTPException, Request, Response
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager

from aweb_secrets.runner_protocol import RunnerRefused
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
