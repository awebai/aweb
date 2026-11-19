"""Public registry reads shared by native authentication and status consumers.

SDK clients own acquisition and freshness. This module applies native team
scope, dependency errors and the admitted team-key rule; it creates no cache.
"""

from __future__ import annotations
import logging
from typing import Any
from awid.team_ids import build_team_id, parse_team_id
from fastapi import HTTPException, Request
from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
    is_private_team_refusal,
    serves_team,
    team_not_served_exception,
)
from aweb.team_scope import member_team_scope
from aweb.team_key_reader import read_team_key as read_team_key
from aweb.team_key_pins import (
    team_key_unverified_exception,
    txt_resolver_for,
)
from aweb.application_state import application_registry_client, native_application_state
from aweb.certificate_evidence import EvidenceMode
from awid.team_key_acts import TeamKeyMemo, TeamKeyUnverified

logger = logging.getLogger(__name__)


def native_database_manager(db_or_manager):
    """Use the native manager directly, or obtain it from the serving DB resource."""
    return (
        db_or_manager.get_manager("aweb")
        if hasattr(db_or_manager, "get_manager")
        else db_or_manager
    )


def request_auth_audiences(request: Request) -> list[str]:
    """The configured public origin required by team-auth-envelope-v2.md:21-28."""
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    if configured:
        return [configured]
    raise HTTPException(
        status_code=503, detail="Request authentication public origin is not configured"
    )


def _team_read_failure(
    exc: Exception, registry_client, team_id: str, *, operation: str, reading: str
) -> HTTPException:
    """The answer to a failed registry read of one team's records.

    A private team this server holds no credential for is a team it does not
    serve: its members are refused with 403, and that is not a registry fault.
    """
    if is_private_team_refusal(exc) and not serves_team(registry_client, team_id):
        logger.info("Refused %s for team %s, which this server does not serve", reading, team_id)
        return team_not_served_exception(team_id, operation=operation)
    logger.warning("AWID registry dependency failed for %s: %s", reading, team_id, exc_info=True)
    return awid_dependency_http_exception(exc, operation=operation, team_id=team_id)


async def resolve_team_key(request: Request, team_id: str, *, db: Any = None) -> str:
    """Request adapter preserving native unknown-team, pin and dependency errors."""
    try:
        domain, name = parse_team_id(team_id)
    except ValueError:
        return ""
    state = native_application_state(request.app.state)
    registry_client = application_registry_client(request.app.state)
    memo = getattr(state, "team_key_pin_memo", None)
    if memo is None:
        memo = state.team_key_pin_memo = TeamKeyMemo()
    try:
        return await read_team_key(
            db=db if db is not None else native_database_manager(state.db),
            registry_client=registry_client,
            txt_resolver=txt_resolver_for(state),
            team_id=build_team_id(domain, name),
            evidence=EvidenceMode.CACHED,
            pin_memo=memo,
        )
    except TeamKeyUnverified:
        raise team_key_unverified_exception() from None
    except HTTPException:
        raise
    except AWID_DEPENDENCY_ERRORS as exc:
        raise _team_read_failure(
            exc,
            registry_client,
            build_team_id(domain, name),
            operation="AWID team key resolution",
            reading="team key resolution",
        ) from exc
    except Exception as exc:
        logger.exception(
            "Unexpected AWID registry dependency error for team key resolution: %s",
            team_id,
        )
        raise awid_dependency_http_exception(exc, operation="AWID team key resolution") from exc


async def request_revoked_certificates(
    request: Request,
    team_id: str,
    *,
    certificate_ids: list[str] | None = None,
    fresh: bool = False,
) -> set[str]:
    """Get the set of revoked certificate IDs from awid.

    Raises HTTPException(503) if awid is unreachable.
    """
    return await revoked_certificates(
        getattr(request.app.state, "awid_registry_client", None),
        team_id,
        certificate_ids=certificate_ids,
        fresh=fresh,
    )


async def revoked_certificates(
    registry_client,
    team_id: str,
    *,
    certificate_ids: list[str] | None = None,
    fresh: bool = False,
) -> set[str]:
    """The revoked certificate IDs of a team, read through this registry client.

    Raises HTTPException(503) if awid is unreachable.
    """
    domain, team_name = member_team_scope(team_id)

    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID team revocation check")

    try:
        select = getattr(registry_client, "get_team_revocations_for_certificates", None)
        if certificate_ids is not None and callable(select):
            return await select(domain, team_name, certificate_ids, fresh=fresh)
        if fresh:
            return await registry_client.get_team_revocations_fresh(domain, team_name)
        return await registry_client.get_team_revocations(domain, team_name)
    except AWID_DEPENDENCY_ERRORS as exc:
        raise _team_read_failure(
            exc,
            registry_client,
            build_team_id(domain, team_name),
            operation="AWID team revocation check",
            reading="revocation check",
        ) from exc
    except Exception as exc:
        logger.exception(
            "Unexpected AWID registry dependency error for revocation check: %s",
            team_id,
        )
        raise awid_dependency_http_exception(exc, operation="AWID team revocation check") from exc


async def request_registered_certificates(request: Request, team_id: str) -> set[str]:
    """Read registered IDs for both enforcement and non-failing staged measurement.

    hosted-certificate-anchoring.md:286-294 distinguishes unknown acquisition
    from an empty authoritative list. The SDK owns cache freshness.
    """
    return await registered_certificates(
        getattr(request.app.state, "awid_registry_client", None), team_id
    )


async def registered_certificates(
    registry_client, team_id: str, *, missing_certificate_id: str | None = None
) -> set[str]:
    """The certificate IDs the AWID registry knows for a team, read through this registry client."""
    domain, team_name = member_team_scope(team_id)

    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID certificate existence check")

    try:
        if missing_certificate_id is not None:
            certificates = await registry_client.refresh_team_certificates_after_miss(
                domain, team_name, certificate_id=missing_certificate_id
            )
        else:
            certificates = await registry_client.list_team_certificates(
                domain, team_name, active_only=False
            )
    except AWID_DEPENDENCY_ERRORS as exc:
        status_code = getattr(exc, "status_code", None)
        if status_code == 404:
            # Team unknown to the registry: nothing is registered. Mirrors
            # the revocation read's 404-means-empty behavior rather than
            # treating a definitive answer as an outage.
            return set()
        raise _team_read_failure(
            exc,
            registry_client,
            build_team_id(domain, team_name),
            operation="AWID certificate existence check",
            reading="certificate existence check",
        ) from exc
    except Exception as exc:
        logger.exception(
            "Unexpected AWID registry dependency error for certificate existence check: %s",
            team_id,
        )
        raise awid_dependency_http_exception(
            exc, operation="AWID certificate existence check"
        ) from exc

    return {
        cert_id
        for cert_id in ((cert.certificate_id or "").strip() for cert in certificates)
        if cert_id
    }
