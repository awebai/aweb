"""One grant-validity observation for authentication, streams and presence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from fastapi import Request

from aweb.application_state import application_registry_client
from aweb.certificate_registration import RegistrationDecision, RegistrationMode
from aweb.grant_expiry import GrantLifetimeState, grant_lifetime_state
from aweb.member_team_key import (
    GRANT_ISSUER_RECOVERY_DETAIL,
    CertificateStanding,
    CertificateStandingState,
    grant_issuer_current,
    member_row_active,
    read_certificate_standings,
)
from aweb.team_auth_deps import admitted_certificate_standing


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
    registration_mode: RegistrationMode | None = None,
    request: Request | None = None,
) -> GrantValidityObservation:
    """Decide grant eligibility once for every native transport and read.

    Session grants (docs/identity.md:773-811) requires the same subject, issuer and lifetime
    rule everywhere. SDK readers own freshness. Invalid authority scope is
    distinct from unavailable evidence. The standing owner selects the
    configured registration policy unless a caller requests an explicit
    observation. Issuer revocation is checked in either case.
    """
    (validity,) = await grant_validities(
        rows=[row], now=now, registry_client=registry_client,
        registration_mode=registration_mode, request=request,
    )
    return validity


async def grant_validities(
    *,
    rows: Sequence[Mapping[str, Any]],
    now: datetime,
    registry_client,
    registration_mode: RegistrationMode | None = None,
    request: Request | None = None,
    reuse_admitted: bool = False,
) -> list[GrantValidityObservation]:
    """Resolve stored eligibility and read the remaining issuers once per team."""
    issuer_ids_by_team: dict[str, set[str]] = {}
    reused: dict[tuple[str, str], CertificateStanding] = {}
    candidates: list[tuple[GrantValidityState, tuple[str, str] | None]] = []
    for row in rows:
        state = _stored_grant_validity(row, now=now)
        issuer = str(row.get("issued_by_certificate_id") or "").strip()
        if state is not GrantValidityState.ACTIVE or not issuer:
            candidates.append((state, None))
            continue
        team = row["team_id"]
        key = (team, issuer)
        candidates.append((state, key))
        if request is not None and reuse_admitted and registration_mode is None:
            admitted = admitted_certificate_standing(
                request, registry_client, team_id=team, certificate_id=issuer,
                team_key=row["current_team_did_key"],
            )
            if admitted is not None:
                reused[key] = admitted
                continue
        issuer_ids_by_team.setdefault(team, set()).add(issuer)

    standings = reused
    for team, issuer_ids in issuer_ids_by_team.items():
        batch = await read_certificate_standings(
            registry_client, team, issuer_ids, request=request, mode=registration_mode,
        )
        standings.update({(team, issuer): standing for issuer, standing in batch.items()})
    return [
        GrantValidityObservation(state=state) if key is None else _issuer_validity(standings[key])
        for state, key in candidates
    ]


def _issuer_validity(standing: CertificateStanding) -> GrantValidityObservation:
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
