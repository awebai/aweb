"""One certificate authority owner for request and generation consumers.

Generation acceptance is independent of registration completion. Mint bytes do
not establish the current controller; this owner admits that evidence before
R13 checks the exact signed artifact. No native member is created here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from awid.external_authority import TXTOutcomeResolver
from awid.registry import CachedRegistryClient, RegistryClient
from awid.team_certificate import (
    CheckedTeamCertificate,
    TeamCertificateError,
    verify_team_certificate_claims,
)
from awid.team_ids import build_team_id, parse_team_id
from awid.team_key_acts import TeamKeyUnverified
from pgdbm import AsyncDatabaseManager

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.certificate_evidence import EvidenceMode
from aweb.service_errors import ServiceError
from aweb.team_key_pins import pinned_team_key, team_key_unverified_exception
from aweb.team_key_reader import read_team_key


class CertificateVerificationReason(StrEnum):
    """Named primitive refusal consumed by the common orchestration owner."""

    BAD_SIGNATURE = "bad_signature"


@dataclass(frozen=True, kw_only=True)
class CertificateAuthorityContext:
    """Borrowed native resources, never a supplied authority stamp.

    registry_client is the serving owner's exact configured client. Its SDK
    owns cache age, outage grace and authorized-reader partitioning. db is used
    by the existing team-key pin owner before member projection locks begin.
    """

    db: AsyncDatabaseManager
    registry_client: RegistryClient
    txt_resolver: TXTOutcomeResolver


class TeamControllerUnavailable(ServiceError):
    """Creation has no current-controller proof; pending material is unusable."""

    status_code = 503
    code = "team_controller_evidence_unavailable"
    message = (
        "The team's current controller could not be confirmed. "
        "The agent is not usable yet. Repeat the creation request when the "
        "registry is reachable and the team's controller can be confirmed."
    )

    def __init__(self) -> None:
        super().__init__({"code": self.code, "message": self.message})


@dataclass(frozen=True, kw_only=True)
class VerifiedCertificateGeneration:
    """Actual signed generation under an independently admitted current key.

    Produced by verify_certificate_generation before native projection locks.
    It is neither a request proof nor a registration-completion claim. A caller
    with only minted bytes must retain admission-pending material and must not
    call the native constructor (hosted-certificate-anchoring.md:391-397;
    Antares0ffc3028 / coordinatora6ae0bfb).
    """

    certificate: CheckedTeamCertificate

    @property
    def verified_team_did_key(self) -> str:
        return self.certificate.team_did_key

    @property
    def certificate_fingerprint(self) -> str:
        return self.certificate.fingerprint


def _certificate_team_scope(team_id: str) -> tuple[str, str]:
    if not isinstance(team_id, str):
        raise TeamCertificateError("invalid_field", "team_id")
    try:
        domain, name = parse_team_id(team_id)
    except (TypeError, ValueError) as exc:
        raise TeamCertificateError("invalid_field", "team_id") from exc
    if build_team_id(domain, name) != team_id:
        raise TeamCertificateError("invalid_field", "team_id")
    return domain, name


async def _admit_refreshed_controller(
    *, context: CertificateAuthorityContext, team_id: str, served_key: str | None
) -> str:
    """Admit the SDK's refreshed key through the same pin owner, without rereads.

    The signature-failure refresh has already acquired this evidence. The
    existing pin owner (docs/drafts/team-key-pinning.md) applies unchanged;
    a certificate's asserted key is never input.
    """
    if not served_key:
        raise TeamControllerUnavailable()
    try:
        return await pinned_team_key(
            db=context.db,
            registry_client=context.registry_client,
            txt_resolver=context.txt_resolver,
            team_id=team_id,
            served_key=served_key,
        )
    except TeamKeyUnverified as exc:
        raise team_key_unverified_exception() from exc


async def read_certificate_controller(
    *, context: CertificateAuthorityContext, team_id: str, evidence: EvidenceMode
) -> str:
    """Read current controller evidence using SDK age/grace, or truly fresh I/O.

    docs/team-auth-envelope-v2.md:60-70 requires the current team key. CACHED
    preserves the SDK's existing admitted-evidence policy; FRESH never consumes
    cached or outage-grace data. No registration list is read here.
    """
    # This validates the certificate factory's exact scope before any I/O;
    # selection, cached/fresh acquisition and pin admission belong to R2.
    _certificate_team_scope(team_id)
    try:
        key = await read_team_key(
            db=context.db,
            registry_client=context.registry_client,
            txt_resolver=context.txt_resolver,
            team_id=team_id,
            evidence=evidence,
        )
    except TeamKeyUnverified as exc:
        raise team_key_unverified_exception() from exc
    except AWID_DEPENDENCY_ERRORS as exc:
        raise TeamControllerUnavailable() from exc
    if not key:
        raise TeamControllerUnavailable()
    return key


async def _refresh_rejected_controller(
    *, context: CertificateAuthorityContext, team_id: str, rejected_key: str
) -> str:
    domain, name = _certificate_team_scope(team_id)
    try:
        client = context.registry_client
        if isinstance(client, CachedRegistryClient):
            key = await client.refresh_team_key_after_signature_failure(
                domain, name, rejected_key=rejected_key
            )
        else:
            # An uncached client's first key read was already live.
            return rejected_key
        return await _admit_refreshed_controller(
            context=context, team_id=team_id, served_key=key
        )
    except AWID_DEPENDENCY_ERRORS as exc:
        raise TeamControllerUnavailable() from exc


async def verify_certificate_generation(
    *,
    context: CertificateAuthorityContext,
    team_id: str,
    encoded_certificate: str,
    member_did_key: str,
    evidence: EvidenceMode = EvidenceMode.CACHED,
) -> VerifiedCertificateGeneration:
    """Verify mint material under independent current-key evidence, outside locks.

    Registration may remain pending (hosted-certificate-anchoring.md:391-397).
    Without current-key proof this returns no generation, so R27 retains only
    pending intent. R13 alone parses/verifies the immutable signed artifact.
    """
    key = await read_certificate_controller(
        context=context, team_id=team_id, evidence=evidence
    )
    try:
        checked = verify_team_certificate_claims(
            encoded_certificate, subject_did_key=member_did_key, team_did_key=key
        )
    except TeamCertificateError as exc:
        if (
            exc.reason != CertificateVerificationReason.BAD_SIGNATURE
            or evidence is EvidenceMode.FRESH
        ):
            raise
        refreshed_key = await _refresh_rejected_controller(
            context=context, team_id=team_id, rejected_key=key
        )
        if refreshed_key == key:
            raise
        checked = verify_team_certificate_claims(
            encoded_certificate,
            subject_did_key=member_did_key,
            team_did_key=refreshed_key,
        )
    if checked.claims["team_id"] != team_id:
        raise TeamCertificateError("certificate_binding_mismatch", "team_id")
    return VerifiedCertificateGeneration(certificate=checked)
