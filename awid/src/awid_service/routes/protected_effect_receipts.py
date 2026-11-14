"""Proof-gated read of committed history, never renewed effect authority."""

from awid.protected_effect import HEADER
from awid.protected_receipts import PATH, read_receipt
from awid.ratelimit import get_rate_limiter, rate_limit_dep
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from awid_service.deps import get_db

router = APIRouter()
_limit_receipts = rate_limit_dep("protected_effect_receipt", allow_trusted_service=True)


async def _receipt_limit(request: Request, response: Response, limiter=Depends(get_rate_limiter)):
    try:
        await _limit_receipts(request, response, limiter)
    except HTTPException as exc:
        exc.headers = {**(exc.headers or {}), "Cache-Control": "no-store"}
        raise


@router.get(PATH + "/{operation_id}", dependencies=[Depends(_receipt_limit)])
async def receipt(operation_id: str, request: Request, response: Response, db_infra=Depends(get_db)):
    headers = {**response.headers, "Cache-Control": "no-store"}
    try:
        result = await read_receipt(
            db_infra.get_manager("aweb"), operation_id, request.headers.get(HEADER)
        )
    except (
        Exception
    ):  # Includes an unavailable database provider; never log proof headers.
        return JSONResponse(
            {"detail": "protected_state_unavailable"}, status_code=503, headers=headers
        )
    return JSONResponse(
        result if result is not None else {"detail": "Not found"},
        status_code=200 if result is not None else 404,
        headers=headers,
    )
