"""One unexpected-error boundary for the public messaging tools."""

import json
import logging
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import ParamSpec

from fastapi import HTTPException
from awid.federation_errors import FederationAuthorityError
from aweb.messaging.refusals import DeliveryRefusal
from aweb.service_errors import ServiceError, IdentityBindingError
from aweb.service_errors import (
    INTERNAL_SERVICE_ERROR_MESSAGE as INTERNAL_DELIVERY_ERROR,
)
from aweb.application_state import RegistryClientUnavailable

logger = logging.getLogger(__name__)
P = ParamSpec("P")


def messaging_tool(fn: Callable[P, Awaitable[str]]) -> Callable[P, Awaitable[str]]:
    """Retain expected refusals; log unexpected failures without exposing internals.

    This wraps public Python tool functions as well as their registered MCP
    calls. It uses no private SDK member or result-shape guess.
    """

    @wraps(fn)
    async def guarded(*args: P.args, **kwargs: P.kwargs) -> str:
        from aweb.mcp.tools.refusals import send_refusal

        try:
            return await fn(*args, **kwargs)
        except (ServiceError, HTTPException, FederationAuthorityError) as exc:
            if (
                isinstance(exc, ServiceError)
                and exc.status_code >= 500
                and not isinstance(
                    exc,
                    (DeliveryRefusal, IdentityBindingError, RegistryClientUnavailable),
                )
            ):
                logger.error(
                    "messaging_tool_internal_error tool=%s failure_type=%s",
                    fn.__name__,
                    type(exc).__name__,
                )
                return json.dumps({"error": INTERNAL_DELIVERY_ERROR})
            return send_refusal(exc)
        except Exception as exc:
            logger.error(
                "messaging_tool_internal_error tool=%s failure_type=%s",
                fn.__name__,
                type(exc).__name__,
            )
            return json.dumps({"error": INTERNAL_DELIVERY_ERROR})

    return guarded
