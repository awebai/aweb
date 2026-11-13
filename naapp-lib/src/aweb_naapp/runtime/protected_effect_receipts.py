"""Fixed proof-gated historical receipt read for relying applications."""

from awid.protected_effect import HEADER
from awid.protected_receipts import PATH, read_receipt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse


def receipt_router(database):
    router = APIRouter()

    @router.get(PATH + "/{operation_id}")
    async def receipt(operation_id: str, request: Request):
        headers = {"Cache-Control": "no-store"}
        try:
            result = await read_receipt(database(request), operation_id, request.headers.get(HEADER))
        except Exception:  # Includes an unavailable database provider; never log proof headers.
            return JSONResponse({"detail": "protected_state_unavailable"}, status_code=503, headers=headers)
        return JSONResponse(result if result is not None else {"detail": "Not found"},
                            status_code=200 if result is not None else 404, headers=headers)

    return router
