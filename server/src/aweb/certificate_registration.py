"""Certificate registration facts, staged policy and bounded observation counts.

Acquisition and freshness belong to the registry SDK and request pipeline. A
registration result never waives request proof, signature or other authority
checks. This owner decides only the staged registration requirement.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from enum import StrEnum

from awid.team_certificate import (
    TeamCertificateStanding,
    evaluate_team_certificate_standing,
)
from fastapi import HTTPException
from prometheus_client import Counter
from starlette.requests import Request

from aweb.team_scope import member_team_scope


class RegistrationMode(StrEnum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"


class RegistrationState(StrEnum):
    NOT_OBSERVED = "not_observed"
    REGISTERED = "registered"
    UNREGISTERED = "unregistered"
    UNAVAILABLE = "unavailable"


class _MetricOutcome(StrEnum):
    REGISTERED = "registered"
    WOULD_REFUSE = "would_refuse"
    UNAVAILABLE = "unavailable"


_REGISTRATION_OBSERVATIONS = Counter(
    "aweb_certificate_registration_observations_total",
    "Certificate registration observations, including staged would-refuse facts.",
    ("enforcement", "outcome"),
)


@dataclass(frozen=True, kw_only=True)
class CertificateRegistrationObservation:
    """Known registry registrations or a distinct failed acquisition.

    Scope errors are invalid authority, never an empty list or measurement
    unavailability. IDs are snapshotted and are never exported as metric labels.
    """

    team_id: str
    registered_certificate_ids: Collection[str] | None
    unavailable_cause: Exception | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        member_team_scope(self.team_id)
        known = self.registered_certificate_ids
        cause = self.unavailable_cause
        if (known is None) == (cause is None):
            raise ValueError("Provide known registrations or an unavailability cause")
        if cause is not None and not isinstance(cause, Exception):
            raise TypeError(
                "Registration unavailability must retain its exception cause"
            )
        if known is not None:
            if isinstance(known, (str, bytes)) or not isinstance(known, Collection):
                raise TypeError("Registered certificate IDs must be a collection")
            if any(not isinstance(value, str) or not value.strip() for value in known):
                raise ValueError("Registered certificate IDs must be nonempty strings")
            object.__setattr__(self, "registered_certificate_ids", frozenset(known))


@dataclass(frozen=True, kw_only=True)
class RegistrationDecision:
    """Disposition of this requirement alone, not whole-request admission."""

    mode: RegistrationMode
    state: RegistrationState
    unavailable_cause: Exception | None = field(default=None, repr=False, compare=False)

    @property
    def allows_registration(self) -> bool:
        standing = evaluate_team_certificate_standing(
            revoked=False,
            registered=(
                self.state is RegistrationState.REGISTERED
                if self.mode is RegistrationMode.REQUIRED
                else None
            ),
        )
        return standing is TeamCertificateStanding.ACTIVE


def evaluate_certificate_registration(
    *,
    observation: CertificateRegistrationObservation,
    certificate_id: str,
    mode: RegistrationMode,
) -> RegistrationDecision:
    """Apply the staging rule in docs/aweb-sot.md, Staged certificate-registration observations.

    NOT_REQUIRED preserves ordinary flow while exposing would-refuse facts;
    unavailable evidence stays unknown instead of becoming an empty registry.
    REQUIRED adapters retain distinct unavailable/unregistered refusals.
    """
    if not isinstance(mode, RegistrationMode):
        raise TypeError("Registration policy requires a named RegistrationMode")
    if not isinstance(certificate_id, str) or not certificate_id.strip():
        raise ValueError("A certificate ID is required for registration evaluation")
    known = observation.registered_certificate_ids
    if known is None:
        state = RegistrationState.UNAVAILABLE
    elif certificate_id in known:
        state = RegistrationState.REGISTERED
    else:
        state = RegistrationState.UNREGISTERED
    return RegistrationDecision(
        mode=mode, state=state, unavailable_cause=observation.unavailable_cause
    )


def record_certificate_registration(
    request: Request | None,
    *,
    observation: CertificateRegistrationObservation,
    certificate_id: str,
    mode: RegistrationMode,
) -> RegistrationDecision:
    """Count usable would-refuse facts once per request/certificate/disposition.

    No team, certificate ID, key, signature or raw target becomes a metric label.
    Collection is independent of enforcement; unavailable measurement cannot
    turn NOT_REQUIRED into a refusal (Antares2c74f907).
    """
    decision = evaluate_certificate_registration(
        observation=observation, certificate_id=certificate_id, mode=mode
    )
    counted = None
    if request is not None:
        counted = getattr(
            request.state, "certificate_registration_observations_counted", None
        )
        if counted is None:
            counted = request.state.certificate_registration_observations_counted = (
                set()
            )
    key = (observation.team_id, certificate_id, mode, decision.state)
    if counted is None or key not in counted:
        if counted is not None:
            counted.add(key)
        outcome = {
            RegistrationState.REGISTERED: _MetricOutcome.REGISTERED,
            RegistrationState.UNREGISTERED: _MetricOutcome.WOULD_REFUSE,
            RegistrationState.UNAVAILABLE: _MetricOutcome.UNAVAILABLE,
        }[decision.state]
        _REGISTRATION_OBSERVATIONS.labels(
            enforcement=mode.value, outcome=outcome.value
        ).inc()
    return decision


def configured_registration_mode() -> RegistrationMode:
    """Translate the existing enforcement flag into the shared named policy."""
    from aweb.config import require_registered_certificates

    return (
        RegistrationMode.REQUIRED
        if require_registered_certificates()
        else RegistrationMode.NOT_REQUIRED
    )


async def observe_certificate_registrations(
    *,
    registry_client,
    team_id: str,
    mode: RegistrationMode,
) -> CertificateRegistrationObservation:
    """Acquire the registration snapshot shared by one standing check or batch.

    The configured off-mode request path skips this acquisition. Explicit
    observation still supports census without making its unavailability a
    refusal. SDK cache and freshness remain with registered_certificates.
    Invalid authority scope is rejected before acquisition, never counted as
    an unavailable observation. Adapters retain their existing wire outcomes.
    """
    from aweb.team_registry import registered_certificates

    member_team_scope(team_id)
    try:
        # OFF measurement follows revocation verification, so the SDK active
        # view avoids scanning that history. REQUIRED keeps the complete-list
        # cache shared with signature-verified miss refreshes.
        registered = await registered_certificates(
            registry_client, team_id, active_only=mode is RegistrationMode.NOT_REQUIRED
        )
    except HTTPException as exc:
        if exc.status_code < 500:
            raise
        return CertificateRegistrationObservation(
            team_id=team_id,
            registered_certificate_ids=None,
            unavailable_cause=exc,
        )
    return CertificateRegistrationObservation(
        team_id=team_id,
        registered_certificate_ids=registered,
    )
