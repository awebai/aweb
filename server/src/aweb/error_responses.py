"""HTTP serialization of service errors, independent of delivery decisions."""

import logging
from fastapi import Request
from fastapi.responses import JSONResponse
from aweb.messaging.refusals import DeliveryRefusal
from aweb.service_errors import ServiceError

logger = logging.getLogger(__name__)


async def service_error_handler(request: Request, exc: ServiceError) -> JSONResponse:
    """Preserve expected refusal data and hide unexpected server internals.

    docs/mail-and-chat.md's shared HTTP/MCP send contract carries one refusal
    from its service owner; this adapter does not reinterpret its human detail.
    """
    if exc.status_code >= 500 and not isinstance(exc, DeliveryRefusal):
        logger.error("Unhandled service error", exc_info=exc)
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )
    if exc.status_code >= 500:
        logger.warning(
            "Delivery dependency refused status=%s", exc.status_code, exc_info=exc
        )
    return JSONResponse(
        status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers
    )
