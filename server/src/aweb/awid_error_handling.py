from __future__ import annotations

import httpx
from fastapi import HTTPException

from awid.dns_verify import DnsVerificationError
from awid.registry import RegistryError

AWID_DEPENDENCY_ERRORS = (DnsVerificationError, httpx.RequestError, RegistryError)


def awid_registry_not_configured_exception(*, operation: str = "AWID registry") -> HTTPException:
    operation = (operation or "AWID registry").strip()
    return HTTPException(status_code=500, detail=f"{operation} registry client not configured")


def awid_dependency_http_exception(exc: Exception, *, operation: str = "AWID registry") -> HTTPException:
    status_code, detail = classify_awid_dependency_error(exc, operation=operation)
    return HTTPException(status_code=status_code, detail=detail)


def awid_dependency_error_detail(exc: Exception, *, operation: str = "AWID registry") -> str:
    _, detail = classify_awid_dependency_error(exc, operation=operation)
    return detail


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
    if isinstance(exc, RegistryError):
        detail = (getattr(exc, "detail", None) or message or class_name).strip()
        status_code = int(getattr(exc, "status_code", 500) or 500)
        if 500 <= status_code < 600:
            return 503, f"{operation} upstream error ({class_name} status={status_code}): {detail}"
        return status_code, f"{operation} returned error ({class_name} status={status_code}): {detail}"
    return 500, f"Unexpected {operation} dependency error ({class_name}){suffix}"
