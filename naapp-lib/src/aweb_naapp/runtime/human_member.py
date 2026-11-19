"""Current human admission, separate from app-owned role and B3 holdings."""

import copy
import math
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic_ns
from typing import Any, ClassVar, Literal

from awid.did import validate_stable_id
from awid.identity_observation import (
    IdentityObservationRefused,
    observe_identity_binding,
    observe_identity_kind,
)
from awid.registry import RegistryClient
from awid.team_certificate import TeamCertificateError, verify_team_certificate_signature
from fastapi import HTTPException

from aweb_naapp.runtime.team_auth import (
    AWIDTeamCache,
    MembershipProof,
    require_active_certificate,
)


@dataclass(frozen=True)
class HumanMemberProof:
    """Trusted in-process output, never a request DTO or role authorization.

    The earliest original membership, binding or identity-chain deadline
    survives all effect-lock waits. App holdings and exact B3 credentials
    remain separate. Never serialize or persist monotonic evidence.
    """

    principal: str
    did_key: str
    membership: MembershipProof
    checked_at: int
    fresh_until: int

    @property
    def team_id(self) -> str:
        """The team checked by the original membership proof."""
        return self.membership.team_id

    def require_fresh(self) -> None:
        """Recheck the original remote deadline after local authority waits."""
        now = monotonic_ns()
        if not (self.checked_at <= now <= self.fresh_until and self.membership.is_fresh_at(now)):
            raise PrincipalStatusUnavailable()


HumanMemberCode = Literal[
    "principal_not_member", "principal_not_human", "principal_status_unavailable"
]


class HumanMemberRefused(HTTPException):
    """A human-member check that refused. The HTTP boundary answers ``status``
    with the refusal's ``code`` as its detail."""

    code: ClassVar[HumanMemberCode]
    status: ClassVar[int]

    def __init__(self) -> None:
        super().__init__(status_code=self.status, detail=self.code)


class PrincipalNotMember(HumanMemberRefused):
    """The evidence definitively shows no current membership of the team."""

    code = "principal_not_member"
    status = 403


class PrincipalNotHuman(HumanMemberRefused):
    """The member is current, but its own identity is not a human's."""

    code = "principal_not_human"
    status = 403


class PrincipalStatusUnavailable(HumanMemberRefused):
    """The membership or identity evidence could not be read fresh enough."""

    code = "principal_status_unavailable"
    status = 503


async def check_human_member(
    team_cache: AWIDTeamCache,
    registry: RegistryClient,
    *,
    team_id: str,
    principal: str,
    certificate: Mapping[str, Any],
) -> HumanMemberProof:
    """Check the exact signed certificate, current key and subject's OWN kind.

    `registry` is the caller-owned SDK client: plain means live reads, and an
    existing CachedRegistryClient retains its public bounded cache. Resolve
    this remote evidence before opening effect transactions. An observed row,
    certificate ID or nearest-human label cannot substitute for these checks.
    """
    try:
        validate_stable_id(principal)
        cert = copy.deepcopy(dict(certificate))
        certificate_id = cert.get("certificate_id")
        did_key = cert.get("member_did_key")
        if (
            cert.get("team_id") != team_id
            or cert.get("member_did_aw") != principal
            or not isinstance(certificate_id, str)
            or not certificate_id.strip()
            or not isinstance(did_key, str)
            or not did_key
        ):
            raise ValueError()
    except (TypeError, ValueError, RecursionError):
        raise PrincipalNotMember() from None
    try:
        facts = await require_active_certificate(
            team_cache, team_id=team_id, certificate_id=certificate_id
        )
    except HTTPException as exc:
        # The public verifier uses 401 for definitive unknown/revoked evidence;
        # an unreadable private listing is unavailable, including its 403.
        raise (
            PrincipalNotMember() if exc.status_code == 401 else PrincipalStatusUnavailable()
        ) from None
    try:
        verify_team_certificate_signature(cert, facts.team_did_key)
    except TeamCertificateError:
        raise PrincipalNotMember() from None
    try:
        membership = await team_cache.check_current_member(
            team_id, certificate_id=certificate_id, team_did_key=facts.team_did_key
        )
    except HTTPException as exc:
        raise (
            PrincipalNotMember() if exc.status_code == 403 else PrincipalStatusUnavailable()
        ) from None
    binding_started = monotonic_ns()
    try:
        binding = await observe_identity_binding(registry, did_key=did_key, did_aw=principal)
    except IdentityObservationRefused as exc:
        if exc.code == "identity_binding_unavailable":
            raise PrincipalStatusUnavailable() from None
        raise PrincipalNotMember() from None
    kind_started = monotonic_ns()
    observation = await observe_identity_kind(registry, binding)
    if observation.result["outcome"] == "unavailable":
        raise PrincipalStatusUnavailable()
    if not observation.is_human:
        raise PrincipalNotHuman()
    age = observation.evidence_age_seconds
    if (
        not isinstance(age, (int, float))
        or isinstance(age, bool)
        or not math.isfinite(age)
        or not 0 <= age <= 60
    ):
        # A legacy hand-constructed classification does not retain evidence age.
        # It keeps its old classification, but cannot mint current effect proof.
        raise PrincipalStatusUnavailable()
    proof = HumanMemberProof(
        principal,
        did_key,
        membership,
        binding_started,
        min(
            binding_started + 60_000_000_000,
            kind_started + math.floor((60 - age) * 1_000_000_000),
            membership.fresh_until,
        ),
    )
    proof.require_fresh()
    return proof
