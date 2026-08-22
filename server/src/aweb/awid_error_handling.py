from __future__ import annotations

import http

import httpx
from fastapi import HTTPException

from awid.dns_verify import DnsVerificationError
from awid.registry import RegistryError

AWID_DEPENDENCY_ERRORS = (
    DnsVerificationError,
    httpx.RequestError,
    httpx.HTTPStatusError,
    RegistryError,
)


def awid_registry_not_configured_detail(*, operation: str = "AWID registry") -> str:
    operation = (operation or "AWID registry").strip()
    return f"{operation} registry client not configured"


def awid_registry_not_configured_exception(*, operation: str = "AWID registry") -> HTTPException:
    return HTTPException(status_code=500, detail=awid_registry_not_configured_detail(operation=operation))


def awid_dependency_http_exception(exc: Exception, *, operation: str = "AWID registry") -> HTTPException:
    status_code, detail = classify_awid_dependency_error(exc, operation=operation)
    return HTTPException(status_code=status_code, detail=detail)


def awid_dependency_error_detail(exc: Exception, *, operation: str = "AWID registry") -> str:
    _, detail = classify_awid_dependency_error(exc, operation=operation)
    return detail


def _classify_upstream_status(status_code: int) -> tuple[int, str]:
    if not status_code:
        return 503, "upstream status error"
    if 500 <= status_code < 600:
        return 503, "upstream error"
    if status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
        return 503, "upstream rate limited"
    return http.HTTPStatus.BAD_GATEWAY, "upstream returned unexpected status"


def classify_awid_dependency_error(exc: Exception, *, operation: str = "AWID registry") -> tuple[int, str]:
    operation = (operation or "AWID registry").strip()
    class_name = type(exc).__name__
    message = str(exc).strip()
    suffix = f": {message}" if message else ""

    if isinstance(exc, DnsVerificationError):
        return 503, f"{operation} DNS resolution failed ({class_name}){suffix}"
    if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError)):
        return 503, f"{operation} upstream unavailable ({class_name}){suffix}"
    if isinstance(exc, httpx.RequestError):
        return 503, f"{operation} request failed ({class_name}){suffix}"
    if isinstance(exc, httpx.HTTPStatusError):
        response = getattr(exc, "response", None)
        status_code = int(getattr(response, "status_code", 0) or 0)
        mapped_status, status_label = _classify_upstream_status(status_code)
        if status_code:
            return mapped_status, f"{operation} {status_label} ({class_name} status={status_code}){suffix}"
        return mapped_status, f"{operation} {status_label} ({class_name}){suffix}"
    if isinstance(exc, RegistryError):
        detail = (getattr(exc, "detail", None) or message or class_name).strip()
        status_code = int(getattr(exc, "status_code", 500) or 500)
        if status_code == http.HTTPStatus.FORBIDDEN and "team_private" in detail:
            return 503, (
                f"{operation} cannot read private team metadata because the AWID trusted lane "
                "rejected the request. Configure the same >=32-byte AWID_SERVICE_TOKEN on "
                "aweb and AWID, restart aweb, then rerun `aw init`."
            )
        mapped_status, status_label = _classify_upstream_status(status_code)
        return mapped_status, f"{operation} {status_label} ({class_name} status={status_code}): {detail}"
    return 500, f"Unexpected {operation} dependency error ({class_name}){suffix}"
