"""The list/describe tool routes, composed with the runtime's exact B1 guard."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from aweb_secrets import tool_results
from aweb_secrets.catalog import Catalog, CatalogRefused


@dataclass(frozen=True)
class MetadataServices:
    # Runtime database services exist only after startup. Resolve at request time.
    catalog: Callable[[], Catalog]


def metadata_router(services: MetadataServices, *, authorized: Any) -> APIRouter:
    """Use the supplied registered B1 dependency, without a parallel verifier."""
    router = APIRouter()

    async def read(authorization: Authorization, ref: str | None = None) -> JSONResponse:
        try:
            catalog = services.catalog()
            if ref is None:
                result = {
                    "secrets": await catalog.list(
                        grant=authorization.grant, principal=authorization.principal
                    )
                }
            else:
                result = await catalog.describe(
                    ref, grant=authorization.grant, principal=authorization.principal
                )
            return JSONResponse(tool_results.completed(result, request_id=None))
        except (CatalogRefused, InstallationRefused) as refused:
            return JSONResponse(
                tool_results.refused(refused.code, request_id=None), status_code=refused.status
            )

    @router.get("/v1/secrets", name="list")
    async def list_secrets(authorization: Annotated[Authorization, Depends(authorized)]):
        return await read(authorization)

    @router.get("/v1/secrets/{secret}", name="describe")
    async def describe_secret(
        secret: str, authorization: Annotated[Authorization, Depends(authorized)]
    ):
        return await read(authorization, secret)

    return router
