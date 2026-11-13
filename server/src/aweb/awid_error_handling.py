from __future__ import annotations

import http

import httpx
from fastapi import HTTPException

from awid.dns_verify import DnsVerificationError
from awid.registry import RegistryError

from aweb.config import get_awid_service_token

# The registry client reports a failed request as RegistryError; TimeoutError is a
# caller's own deadline around a registry call.
AWID_DEPENDENCY_ERRORS = (
    DnsVerificationError,
    httpx.RequestError,
    httpx.HTTPStatusError,
    RegistryError,
    TimeoutError,
)


def awid_registry_not_configured_detail(*, operation: str = "AWID registry") -> str:
    operation = (operation or "AWID registry").strip()
    return f"{operation} registry client not configured"


def awid_registry_not_configured_exception(*, operation: str = "AWID registry") -> HTTPException:
    return HTTPException(status_code=500, detail=awid_registry_not_configured_detail(operation=operation))


def awid_dependency_http_exception(
    exc: Exception, *, operation: str = "AWID registry", team_id: str | None = None
) -> HTTPException:
    status_code, detail = classify_awid_dependency_error(exc, operation=operation, team_id=team_id)
    return HTTPException(status_code=status_code, detail=detail)


def is_private_team_refusal(exc: Exception) -> bool:
    """The registry refused a read of a private team's records."""
    if not isinstance(exc, RegistryError):
        return False
    if int(getattr(exc, "status_code", 0) or 0) != http.HTTPStatus.FORBIDDEN:
        return False
    detail = str(getattr(exc, "detail", None) or exc)
    return exc.code == "team_private" or "team_private" in detail


def serves_team(registry_client, team_id: str) -> bool:
    """Whether this registry client holds a credential that reads the private
    team: the registry service token, or a member key of that team. A team
    deployment holds member keys of its own teams only."""
    if getattr(registry_client, "service_token", None):
        return True
    return team_id in (getattr(registry_client, "member_signing_keys", None) or {})


def team_not_served_exception(team_id: str, *, operation: str) -> HTTPException:
    return HTTPException(status_code=403, detail=f"{operation}: team {team_id} is not served by this server")


def _classify_upstream_status(status_code: int) -> tuple[int, str]:
    if not status_code:
        return 503, "upstream status error"
    if 500 <= status_code < 600:
        return 503, "upstream error"
    if status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
        return 503, "upstream rate limited"
    return http.HTTPStatus.BAD_GATEWAY, "upstream returned unexpected status"


def classify_awid_dependency_error(
    exc: Exception, *, operation: str = "AWID registry", team_id: str | None = None
) -> tuple[int, str]:
    operation = (operation or "AWID registry").strip()
    class_name = type(exc).__name__
    message = str(exc).strip()
    suffix = f": {message}" if message else ""

    if isinstance(exc, DnsVerificationError):
        return 503, f"{operation} DNS resolution failed ({class_name}){suffix}"
    if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError, TimeoutError)):
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
    if isinstance(exc, RegistryError) and exc.code == "unavailable" and exc.__cause__ is not None:
        # The registry client reports a transport failure as unavailable; the
        # failure behind it is what the operator needs to see.
        return classify_awid_dependency_error(exc.__cause__, operation=operation, team_id=team_id)
    if is_private_team_refusal(exc):
        if get_awid_service_token() is not None:
            return 503, (
                f"{operation} cannot read private team metadata because the AWID trusted lane "
                "rejected the request. Configure the same >=32-byte AWID_SERVICE_TOKEN on "
                "aweb and AWID, restart aweb, then rerun `aw init`."
            )
        team = f"team {team_id}" if team_id else "the team"
        return 503, (
            f"{operation}: the AWID registry refused this server's member key for {team}. "
            "The team's controller must issue this server a current member certificate "
            "for the key named in AWID_MEMBER_KEYS_FILE."
        )
    if isinstance(exc, RegistryError):
        detail = (getattr(exc, "detail", None) or message or class_name).strip()
        status_code = int(getattr(exc, "status_code", 500) or 500)
        mapped_status, status_label = _classify_upstream_status(status_code)
        return mapped_status, f"{operation} {status_label} ({class_name} status={status_code}): {detail}"
    return 500, f"Unexpected {operation} dependency error ({class_name}){suffix}"
