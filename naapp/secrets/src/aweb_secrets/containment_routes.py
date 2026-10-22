"""Value-free containment endpoint, mounted only on the team-auth API origin."""

import base64
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from typing import Annotated, Any

from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request

from aweb_secrets.containment import Containment, ContainmentRefused


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
        except (ContainmentRefused, InstallationRefused) as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None

    return router
