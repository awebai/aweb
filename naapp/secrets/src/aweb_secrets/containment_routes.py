"""Value-free containment routers for their separate API and human origins."""

import base64
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from typing import Annotated, Any

import asyncpg
from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from aweb_secrets.console import OwnerConsole
from aweb_secrets.containment import Containment, ContainmentRefused
from aweb_secrets.credential_audit import GovernanceUnavailable


async def _request(request: Request) -> dict[str, Any]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(status_code=415, detail="json_required")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="request_invalid") from None
    if (
        not isinstance(body, dict)
        or set(body) - {"request_id", "action", "target", "credential_id"}
        or not {"request_id", "action"} <= set(body)
        or not isinstance(body["request_id"], str)
        or not isinstance(body["action"], str)
        or ("target" in body and not isinstance(body["target"], str))
    ):
        raise HTTPException(status_code=400, detail="request_invalid")
    if "credential_id" in body:
        value = body["credential_id"]
        try:
            if not isinstance(value, str) or not value or len(value) > 2048:
                raise ValueError
            decoded = base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
            )
            # The wire form is the canonical unpadded base64url credential ID.
            if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
                raise ValueError
            body["credential_id"] = decoded
        except ValueError:
            raise HTTPException(status_code=400, detail="request_invalid") from None
    return body


def containment_api_router(
    services: Containment,
    *,
    authorized: Callable[..., Awaitable[Authorization]],
) -> APIRouter:
    """The runtime supplies its real manifest/scope/team-auth dependency."""
    router = APIRouter()

    @router.post("/v1/containment")
    async def contain(
        request: Request, auth: Annotated[Authorization, Depends(authorized)]
    ) -> dict[str, Any]:
        body = await _request(request)
        try:
            return asdict(
                await services.by_member(
                    grant=auth.grant,
                    principal=auth.principal,
                    **body,
                )
            )
        except (ContainmentRefused, InstallationRefused, GovernanceUnavailable) as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None

    return router


def containment_console_router(
    services: Containment, *, console: OwnerConsole, prefix: str = ""
) -> APIRouter:
    """Mount alongside this same OwnerConsole only on the human origin."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)

    @router.post("/installations/{installation_id}/containment")
    async def contain(
        installation_id: str,
        request: Request,
        current: Annotated[ConsoleSession, Depends(console.sessions.current)],
    ) -> dict[str, Any]:
        body = await _request(request)
        try:
            admitted = await console.installation(installation_id)
            if admitted.installation_id != installation_id:
                raise HTTPException(403, "owner_required")
            return asdict(await services.by_console(admitted=admitted, session=current, **body))
        except (ContainmentRefused, InstallationRefused, GovernanceUnavailable) as refused:
            if refused.status == 401:
                await console.sessions.close(current)
                response = Response()
                console.sessions.clear_cookie(response)
                raise HTTPException(
                    401,
                    "console_session_required",
                    headers={"Set-Cookie": response.headers["set-cookie"]},
                ) from None
            raise HTTPException(refused.status, refused.code) from None
        except LookupError:
            raise HTTPException(403, "owner_required") from None
        except asyncpg.DeadlockDetectedError:
            # A self-revocation can upgrade its own LOGIN credential lock.
            # PostgreSQL rolls back the whole effect; a fresh request may retry.
            raise HTTPException(409, "containment_retry", headers={"Retry-After": "0"}) from None

    return router
