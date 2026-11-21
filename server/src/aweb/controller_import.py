"""Fresh owner-read metadata admits ordinary BYOT imports without fake artifacts.

byot-onboarding-contract.md:213-216 and Antares69b3a50a ruling1 preserve the
released controller-signed selector request. The signature does not cover
caller-supplied roster data: this factory acquires the registry facts itself.
"""

from dataclasses import dataclass

from awid.did import public_key_from_did
from awid.registry import RegistryError, Team, TeamCertificate
from awid.team_control_requests import TeamControlSignatureError, TeamImportRequest
from awid.utc_timestamps import parse_zoned_timestamp

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlError,
    TeamControlRegistryDataInvalid,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
    TeamControlTeamNotFound,
    read_fresh_team_controller,
    require_canonical_team_control_scope,
    require_fresh_team_control_request,
)


class ControllerImportEvidenceUnavailable(TeamControlError):
    """An unreadable registry snapshot supplies no import proof."""

    status_code = 503
    code = "team_import_evidence_unavailable"
    message = (
        "The team's current registry facts could not be confirmed. "
        "Nothing was imported. Retry when the registry can be read."
    )

    def __init__(self) -> None:
        super().__init__({"code": self.code, "message": self.message})


@dataclass(frozen=True, kw_only=True)
class VerifiedControllerImportMember:
    """Exact nonrevoked metadata checked by this owner's fresh import batch.

    No artifact, fingerprint, member signature or global binding/kind proof is
    implied. The sole native constructor consumes this distinct input and
    rechecks the admitted controller under its existing team lock. Account and
    target authorization, planned resource IDs and projection stay with hosts.
    """

    request: TeamImportRequest
    controller_signature: str
    verified_team_did_key: str
    certificate: TeamCertificate

    @property
    def team_id(self) -> str:
        return self.request.awid_team_id.strip()

    def require_freshness(self) -> None:
        """Retain the original signed time through host/native lock waits."""
        require_fresh_team_control_request(timestamp=self.request.timestamp)


@dataclass(frozen=True, kw_only=True)
class VerifiedControllerImport:
    """One immutable owner-acquired snapshot for planning and live admission.

    certificates retains revoked rows for existing planning/counts. members
    contains nonrevoked admission inputs only for an apply request; preview
    members is empty so its signature cannot authorize native admission. None
    is a request certificate or generation proof. Original signed selectors,
    dry_run and time remain in request.
    """

    request: TeamImportRequest
    controller_signature: str
    verified_team_did_key: str
    team: Team
    certificates: tuple[TeamCertificate, ...]
    members: tuple[VerifiedControllerImportMember, ...]

    def require_freshness(self) -> None:
        require_fresh_team_control_request(timestamp=self.request.timestamp)


def _validate_registry_certificates(
    certificates: tuple[TeamCertificate, ...],
) -> None:
    """Validate the metadata boundary, preserving valid released spellings."""
    seen: set[str] = set()
    for certificate in certificates:
        if not isinstance(certificate, TeamCertificate):
            raise ValueError("Registry certificate row is not typed metadata")
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (certificate.certificate_id, certificate.alias)
        ):
            raise ValueError("Registry certificate ID/alias is missing")
        if certificate.certificate_id in seen:
            raise ValueError("Registry certificate ID is repeated")
        seen.add(certificate.certificate_id)
        public_key_from_did(certificate.member_did_key)
        if certificate.identity_scope not in {"local", "global"}:
            raise ValueError("Registry certificate scope is invalid")
        parse_zoned_timestamp(certificate.issued_at)
        if certificate.revoked_at is not None:
            parse_zoned_timestamp(certificate.revoked_at)
        for value in (certificate.member_did_aw, certificate.member_address):
            if value is not None and not isinstance(value, str):
                raise ValueError("Registry certificate identity claim is not text")


async def _read_import_snapshot(
    *, context: TeamControlAuthorityContext, team_id: str, domain: str, name: str
) -> tuple[Team, tuple[TeamCertificate, ...]]:
    """Acquire actual fresh public SDK facts, never a host's roster arguments."""
    try:
        team = await context.registry_client.get_team_fresh(domain, name)
        if team is None:
            raise TeamControlTeamNotFound()
        if (team.team_id, team.domain, team.name) != (team_id, domain, name):
            raise ValueError("Registry team metadata does not match the requested team")
        public_key_from_did(team.team_did_key)
        certificates = tuple(
            await context.registry_client.list_team_certificates_fresh(
                domain, name, active_only=False
            )
        )
        _validate_registry_certificates(certificates)
    except RegistryError as exc:
        if exc.status_code == 404 and exc.body == {"detail": "Team not found"}:
            raise TeamControlTeamNotFound() from exc
        raise ControllerImportEvidenceUnavailable() from exc
    except AWID_DEPENDENCY_ERRORS as exc:
        raise ControllerImportEvidenceUnavailable() from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise TeamControlRegistryDataInvalid() from exc
    return team, certificates


async def verify_controller_import(
    *,
    context: TeamControlAuthorityContext,
    request: TeamImportRequest,
    controller_signature: str,
) -> VerifiedControllerImport:
    """Check released controller bytes and acquire exact current roster facts.

    byot-onboarding-contract.md:213-216: fresh controller signature and live
    registry facts, without a member key/upload. R2 independently admits the
    current key, R13 verifies the released preimage, SDK fresh reads obtain the
    team/complete roster, and a second fresh key read fences acquisition across
    controller changes. Original signed time is rechecked after acquisition.
    No native member/workspace, host credential or registry write is made here.
    """
    if not isinstance(request, TeamImportRequest):
        raise TypeError("Controller import requires the shared TeamImportRequest")
    team_id = request.awid_team_id.strip()
    domain, name = require_canonical_team_control_scope(team_id)
    require_fresh_team_control_request(timestamp=request.timestamp)
    key = await read_fresh_team_controller(context=context, team_id=team_id)
    try:
        request.verify_signature(signer_did_key=key, signature=controller_signature)
    except TeamControlSignatureError as exc:
        raise TeamControlRequestInvalid(
            TeamControlRequestReason.SIGNATURE_INVALID
        ) from exc
    team, certificates = await _read_import_snapshot(
        context=context, team_id=team_id, domain=domain, name=name
    )
    current_key = await read_fresh_team_controller(context=context, team_id=team_id)
    if team.team_did_key != key or current_key != key:
        raise TeamControlRequestInvalid(TeamControlRequestReason.CONTROLLER_CHANGED)
    result = VerifiedControllerImport(
        request=request,
        controller_signature=controller_signature,
        verified_team_did_key=key,
        team=team,
        certificates=certificates,
        members=tuple(
            VerifiedControllerImportMember(
                request=request,
                controller_signature=controller_signature,
                verified_team_did_key=key,
                certificate=certificate,
            )
            for certificate in certificates
            if certificate.revoked_at is None and not request.dry_run
        ),
    )
    result.require_freshness()
    return result
