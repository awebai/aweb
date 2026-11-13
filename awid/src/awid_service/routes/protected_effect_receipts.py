"""Proof-gated read of committed history, never renewed effect authority."""

from awid.protected_effect import HEADER
from awid.protected_receipts import PATH, read_receipt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from awid_service.deps import get_db

router = APIRouter()


@router.get(PATH + "/{operation_id}")
async def receipt(operation_id: str, request: Request, db_infra=Depends(get_db)):
    headers = {"Cache-Control": "no-store"}
    try:
        result = await read_receipt(db_infra.get_manager("aweb"), operation_id, request.headers.get(HEADER))
    except Exception:  # Includes an unavailable database provider; never log proof headers.
        return JSONResponse({"detail": "protected_state_unavailable"}, status_code=503, headers=headers)
    return JSONResponse(result if result is not None else {"detail": "Not found"},
                        status_code=200 if result is not None else 404, headers=headers)
