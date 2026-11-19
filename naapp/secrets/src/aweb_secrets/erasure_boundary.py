"""Project erasure failures after request transactions unwind (§Backup operations)."""

import asyncpg
from fastapi import FastAPI, Request
from pgdbm.errors import AsyncDBError
from starlette.responses import JSONResponse

from aweb_secrets.erasure import ErasureUnavailable, map_erasure_failure


async def _erasure_response(request: Request, error: Exception) -> JSONResponse:
    refusal = map_erasure_failure(error)
    if refusal is None:
        raise error
    return JSONResponse(
        status_code=503,
        content={"detail": refusal.code, "message": str(refusal)},
        headers={"Cache-Control": "no-store"},
    )


def mount_erasure_failures(app: FastAPI) -> None:
    """Keep trigger failures on the fixed owner vocabulary on both origins."""
    for error_type in (ErasureUnavailable, AsyncDBError, asyncpg.PostgresError):
        app.add_exception_handler(error_type, _erasure_response)
