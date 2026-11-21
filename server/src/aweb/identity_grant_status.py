"""One grant-validity observation for authentication, streams and presence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from fastapi import Request

from aweb.application_state import application_registry_client
from aweb.certificate_registration import (
    RegistrationDecision,
    RegistrationMode,
    configured_registration_mode,
)
from aweb.grant_expiry import GrantLifetimeState, grant_lifetime_state
from aweb.member_team_key import (
    GRANT_ISSUER_RECOVERY_DETAIL,
    CertificateStandingState,
    grant_issuer_current,
    member_row_active,
    read_certificate_standings,
)


class GrantValidityState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUBJECT_INACTIVE = "subject_inactive"
    ISSUER_SUPERSEDED = "issuer_superseded"
    ISSUER_REVOKED = "issuer_revoked"
    ISSUER_UNREGISTERED = "issuer_unregistered"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, kw_only=True)
class GrantValidityObservation:
    """A validity result, retaining registration and unavailable evidence."""

    state: GrantValidityState
    registration: RegistrationDecision | None = None
    unavailable_cause: Exception | None = field(default=None, repr=False, compare=False)

    def raise_if_unavailable(self) -> None:
        """Retain existing dependency-error responses at requiring adapters."""
        if self.state is GrantValidityState.UNAVAILABLE:
            if self.unavailable_cause is None:
                raise ValueError("Unavailable grant validity requires its cause")
            raise self.unavailable_cause


def grant_status(row: Mapping[str, Any], now: datetime) -> GrantLifetimeState:
    """A grant's own status, before subject and issuer eligibility."""
    return grant_lifetime_state(
        issued_at=row.get("issued_at"),
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
        now=now,
    )


def _stored_grant_validity(row: Mapping[str, Any], *, now: datetime) -> GrantValidityState:
    """Apply lifetime, subject and retained issuer rules before registry reads.

    Session grants (docs/identity.md:773-811): no default lifetime cap; delegation ends with its
    issuing certificate. Reacceptance does not revive it in this release.
    """
    lifetime = grant_status(row, now)
    if lifetime is GrantLifetimeState.REVOKED:
        return GrantValidityState.REVOKED
    if lifetime is GrantLifetimeState.EXPIRED:
        return GrantValidityState.EXPIRED
    if not member_row_active({"status": row["subject_status"], "deleted_at": row["subject_deleted_at"]}):
        return GrantValidityState.SUBJECT_INACTIVE
    if not grant_issuer_current(row):
        return GrantValidityState.ISSUER_SUPERSEDED
    return GrantValidityState.ACTIVE


async def grant_validity(
    *,
    row: Mapping[str, Any],
    now: datetime,
    registry_client,
    registration_mode: RegistrationMode,
    request: Request | None = None,
) -> GrantValidityObservation:
    """Decide grant eligibility once for every native transport and read.

    Session grants (docs/identity.md:773-811) requires the same subject, issuer and lifetime
    rule everywhere. SDK readers own freshness. Invalid authority scope is
    distinct from unavailable evidence; staged registration never waives the
    ordinary issuer revocation check or adds an off-mode refusal.
    """
    state = _stored_grant_validity(row, now=now)
    if state is not GrantValidityState.ACTIVE:
        return GrantValidityObservation(state=state)
    issuer = str(row.get("issued_by_certificate_id") or "").strip()
    if not issuer:
        return GrantValidityObservation(state=GrantValidityState.ACTIVE)
    standings = await read_certificate_standings(
        registry_client, row["team_id"], [issuer], request=request, mode=registration_mode,
    )
    standing = standings[issuer]
    return GrantValidityObservation(
        state={
            CertificateStandingState.ACTIVE: GrantValidityState.ACTIVE,
            CertificateStandingState.REVOKED: GrantValidityState.ISSUER_REVOKED,
            CertificateStandingState.UNREGISTERED: GrantValidityState.ISSUER_UNREGISTERED,
            CertificateStandingState.UNAVAILABLE: GrantValidityState.UNAVAILABLE,
        }[standing.state],
        registration=standing.registration,
        unavailable_cause=standing.unavailable_cause,
    )


async def effective_grant_status(
    request: Request, row: Mapping[str, Any], now: datetime
) -> tuple[str, str | None]:
    """Adapt the common observation to the released status vocabulary."""
    observation = await grant_validity(
        row=row,
        now=now,
        registry_client=application_registry_client(request.app.state),
        registration_mode=configured_registration_mode(),
        request=request,
    )
    observation.raise_if_unavailable()
    state = observation.state
    if state in (
        GrantValidityState.ACTIVE,
        GrantValidityState.REVOKED,
        GrantValidityState.EXPIRED,
    ):
        return state.value, None
    if state is GrantValidityState.SUBJECT_INACTIVE:
        return "subject_inactive", "grant subject identity is not active"
    if state is GrantValidityState.ISSUER_SUPERSEDED:
        return (
            "issuer_revoked",
            "grant issuing certificate superseded. " + GRANT_ISSUER_RECOVERY_DETAIL,
        )
    if state is GrantValidityState.ISSUER_REVOKED:
        return (
            "issuer_revoked",
            "grant issuing certificate revoked. " + GRANT_ISSUER_RECOVERY_DETAIL,
        )
    if state is GrantValidityState.ISSUER_UNREGISTERED:
        return (
            "issuer_not_registered",
            "grant issuing certificate not registered. " + GRANT_ISSUER_RECOVERY_DETAIL,
        )
    raise ValueError(f"Unsupported grant validity state: {state}")
