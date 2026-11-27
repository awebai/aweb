from __future__ import annotations

import http

import httpx
from fastapi import HTTPException

from awid.dns_verify import DnsVerificationError
from awid.registry import MalformedTeamKeyError, RegistryError

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


def awid_dependency_http_exception(
    exc: Exception, *, operation: str = "AWID registry", team_id: str | None = None
) -> HTTPException:
    status_code, detail = classify_awid_dependency_error(
        exc, operation=operation, team_id=team_id
    )
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
    return HTTPException(
        status_code=403,
        detail=f"{operation}: team {team_id} is not served by this server",
    )


def _retryable_registry_failure(operation: str, reason: str) -> tuple[int, str]:
    return http.HTTPStatus.SERVICE_UNAVAILABLE, (
        f"{operation} {reason}. Retry when the registry is available. "
        "If this persists, ask the server operator to check the registry connection."
    )


def _unusable_registry_response(operation: str) -> tuple[int, dict[str, str]]:
    return http.HTTPStatus.UNPROCESSABLE_ENTITY, {
        "code": "registry_response_unusable",
        "message": (
            f"{operation} received an unusable registry response. "
            "Ask the server operator to check the registry."
        ),
    }


def _classify_upstream_status(
    status_code: int, *, operation: str, failure_type: str
) -> tuple[int, str | dict[str, str]]:
    if not status_code:
        return _retryable_registry_failure(
            operation, f"upstream status error ({failure_type})"
        )
    if 500 <= status_code < 600:
        return _retryable_registry_failure(
            operation, f"upstream error ({failure_type} status={status_code})"
        )
    if status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
        return _retryable_registry_failure(
            operation, f"upstream rate limited ({failure_type} status={status_code})"
        )
    return _unusable_registry_response(operation)


def classify_awid_dependency_error(
    exc: Exception, *, operation: str = "AWID registry", team_id: str | None = None
) -> tuple[int, str | dict[str, str]]:
    """Build the public refusal shared by HTTP verification and message delivery."""
    operation = (operation or "AWID registry").strip()
    class_name = type(exc).__name__

    if isinstance(exc, MalformedTeamKeyError):
        return _unusable_registry_response(operation)
    if isinstance(exc, DnsVerificationError):
        return _retryable_registry_failure(
            operation, f"DNS resolution failed ({class_name})"
        )
    if isinstance(
        exc,
        (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError, TimeoutError),
    ):
        return _retryable_registry_failure(
            operation, f"upstream unavailable ({class_name})"
        )
    if isinstance(exc, httpx.RequestError):
        return _retryable_registry_failure(operation, f"request failed ({class_name})")
    if isinstance(exc, httpx.HTTPStatusError):
        response = getattr(exc, "response", None)
        status_code = int(getattr(response, "status_code", 0) or 0)
        return _classify_upstream_status(
            status_code, operation=operation, failure_type=class_name
        )
    if (
        isinstance(exc, RegistryError)
        and exc.code == "unavailable"
        and exc.__cause__ is not None
    ):
        # Preserve the safe category of an error wrapped by the client.
        return classify_awid_dependency_error(
            exc.__cause__, operation=operation, team_id=team_id
        )
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
        status_code = int(getattr(exc, "status_code", 500) or 500)
        return _classify_upstream_status(
            status_code, operation=operation, failure_type=class_name
        )
    return http.HTTPStatus.INTERNAL_SERVER_ERROR, (
        f"Unexpected {operation} dependency error ({class_name}). "
        "Ask the server operator to investigate."
    )
