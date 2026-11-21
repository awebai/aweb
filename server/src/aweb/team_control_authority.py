"""Fresh registry authority for ordinary controller import."""

from enum import StrEnum

from awid.did import public_key_from_did
from awid.dns_auth import enforce_timestamp_skew
from awid.team_ids import build_team_id, parse_team_id
from awid.team_key_acts import TeamKeyUnverified
from fastapi import HTTPException

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.certificate_auth import (
    CertificateAuthorityContext as TeamControlAuthorityContext,
)
from aweb.certificate_evidence import EvidenceMode
from aweb.service_errors import ServiceError
from aweb.team_key_pins import team_key_unverified_exception
from aweb.team_key_reader import read_team_key


class TeamControlRequestReason(StrEnum):
    TEAM_SCOPE_INVALID = "team_control_scope_invalid"
    TIMESTAMP_INVALID = "team_control_timestamp_invalid"
    SIGNATURE_INVALID = "team_control_signature_invalid"
    CONTROLLER_CHANGED = "team_control_controller_changed"


class TeamControlError(ServiceError):
    """An expected controller-operation refusal with its own transport mapping."""


class TeamControlRequestInvalid(TeamControlError):
    """A controller request cannot be used; retain the exact actionable reason."""

    status_code = 422

    def __init__(self, reason: TeamControlRequestReason) -> None:
        self.reason = reason
        self.message = {
            TeamControlRequestReason.TEAM_SCOPE_INVALID: (
                "The team-control request must name its canonical team. "
                "Select the exact team and regenerate the controller-signed command."
            ),
            TeamControlRequestReason.TIMESTAMP_INVALID: (
                "The signed team-control request is invalid or expired. "
                "Regenerate the controller-signed command and retry."
            ),
            TeamControlRequestReason.SIGNATURE_INVALID: (
                "The controller signature is invalid. "
                "Regenerate the signed request with the controller key and retry."
            ),
            TeamControlRequestReason.CONTROLLER_CHANGED: (
                "The team's controller changed while its registry facts were read. "
                "Regenerate the import request with the current controller and retry."
            ),
        }[reason]
        super().__init__({"code": reason.value, "message": self.message})


class TeamControlTeamNotFound(TeamControlError):
    """The registry gave a definitive absence answer for the team."""

    status_code = 404
    code = "awid_team_not_found"
    message = (
        "The AWID team is not registered. "
        "Select a registered team or register it before importing."
    )

    def __init__(self) -> None:
        super().__init__({"code": self.code, "message": self.message})


class TeamControlRegistryDataInvalid(TeamControlError):
    """A registry response supplied unusable team or certificate data."""

    status_code = 422
    code = "registry_response_unusable"
    message = (
        "AWID returned invalid team or certificate data. "
        "Ask the registry operator to correct the team record before importing."
    )

    def __init__(self) -> None:
        super().__init__({"code": self.code, "message": self.message})


class TeamControlAuthorityUnavailable(TeamControlError):
    """The registry could not establish current controller authority."""

    status_code = 503
    code = "team_control_authority_unavailable"
    message = (
        "The team's current controller could not be confirmed. "
        "Nothing was imported. Retry when the registry can be read."
    )

    def __init__(self) -> None:
        super().__init__({"code": self.code, "message": self.message})


def require_canonical_team_control_scope(team_id: str) -> tuple[str, str]:
    """Keep the signed team exact, per byot-onboarding-contract.md:213-216."""
    if not isinstance(team_id, str):
        raise TeamControlRequestInvalid(TeamControlRequestReason.TEAM_SCOPE_INVALID)
    try:
        domain, name = parse_team_id(team_id)
    except ValueError as exc:
        raise TeamControlRequestInvalid(
            TeamControlRequestReason.TEAM_SCOPE_INVALID
        ) from exc
    if build_team_id(domain, name) != team_id:
        raise TeamControlRequestInvalid(TeamControlRequestReason.TEAM_SCOPE_INVALID)
    return domain, name


def require_fresh_team_control_request(*, timestamp: str) -> None:
    """Apply the released import's 300-second window without restamping it.

    byot-onboarding-contract.md:213-216 requires a fresh controller request.
    Callers retain the signed timestamp and recheck it after acquisition/lock waits.
    """
    try:
        enforce_timestamp_skew(timestamp)
    except HTTPException as exc:
        raise TeamControlRequestInvalid(
            TeamControlRequestReason.TIMESTAMP_INVALID
        ) from exc


async def read_fresh_team_controller(
    *, context: TeamControlAuthorityContext, team_id: str
) -> str:
    """Borrow fresh registry evidence and the one native key-pin decision.

    byot-onboarding-contract.md:213-216 requires the current
    registry controller, never a stored setup controller or stale fallback.
    The R2 reader owns acquisition/pin admission; its typed pin failures keep
    their existing mapping. The registry's absence answer remains distinct
    from an unreadable or invalid result.
    """
    require_canonical_team_control_scope(team_id)
    try:
        key = await read_team_key(
            db=context.db,
            registry_client=context.registry_client,
            txt_resolver=context.txt_resolver,
            team_id=team_id,
            evidence=EvidenceMode.FRESH,
        )
    except TeamKeyUnverified as exc:
        raise team_key_unverified_exception() from exc
    except AWID_DEPENDENCY_ERRORS as exc:
        raise TeamControlAuthorityUnavailable() from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise TeamControlRegistryDataInvalid() from exc
    if key == "":
        raise TeamControlTeamNotFound()
    try:
        public_key_from_did(key)
    except (TypeError, ValueError) as exc:
        raise TeamControlRegistryDataInvalid() from exc
    return key
