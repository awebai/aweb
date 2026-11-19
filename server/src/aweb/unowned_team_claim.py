"""Current-controller authority for the fully unowned ownership-claim lane.

Member HTTP authentication still identifies the requester. Only this checked
artifact supplies claim authority (Antares132d7fc6, coordinator5f41129f).
Account normalization and the final unowned/account locks belong to the host.
"""

from dataclasses import dataclass

from awid.team_control_requests import (
    SignedUnownedTeamClaim,
    TeamControlRequestError,
    TeamControlSignatureError,
    read_unowned_team_claim,
)

from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
    read_fresh_team_controller,
    require_canonical_team_control_scope,
    require_fresh_team_control_request,
)


@dataclass(frozen=True, kw_only=True)
class UnownedTeamClaimTarget:
    """Exact canonical team and account-owner-normalized prospective account.

    Email/username are matched verbatim, per coordinator0597a38a. This object
    does not apply Cloud's account grammar or prove account authorization.
    """

    team_id: str
    email: str
    username: str

    def __post_init__(self) -> None:
        require_canonical_team_control_scope(self.team_id)
        if any(
            not isinstance(value, str) or not value
            for value in (self.email, self.username)
        ):
            raise TeamControlRequestInvalid(TeamControlRequestReason.TARGET_MISMATCH)


@dataclass(frozen=True, kw_only=True)
class VerifiedUnownedTeamClaim:
    """A shared signed artifact checked against the independently current key.

    This is ownership-claim authority only, never a member request proof or
    certificate generation. The host rechecks target/freshness under its own
    final ownership locks before effects, without restamping the signed time.
    """

    artifact: SignedUnownedTeamClaim
    verified_team_did_key: str

    def require_target(self, *, target: UnownedTeamClaimTarget) -> None:
        """Recheck the exact account/team and original age after lock waits."""
        _require_target(self.artifact, target)
        require_fresh_team_control_request(timestamp=self.artifact.request.timestamp)


def _require_target(
    artifact: SignedUnownedTeamClaim, target: UnownedTeamClaimTarget
) -> None:
    request = artifact.request
    # R13 signs the stripped team; it signs account values verbatim.
    team_id = request.awid_team_id.strip()
    require_canonical_team_control_scope(team_id)
    if (team_id, request.email, request.username) != (
        target.team_id,
        target.email,
        target.username,
    ):
        raise TeamControlRequestInvalid(TeamControlRequestReason.TARGET_MISMATCH)


async def verify_unowned_team_claim(
    *,
    context: TeamControlAuthorityContext,
    claim: object,
    target: UnownedTeamClaimTarget,
) -> VerifiedUnownedTeamClaim:
    """Read one shared artifact, then establish fresh claim authority.

    Antares132d7fc6/coordinator0597a38a: verify the canonical team, normalized
    account and original signed time before account/org/registry effects.
    Shared integrity verification happens once before registry I/O. Matching
    its immutable signer to the independently read current key then binds
    that same proof to current authority; no local/stored controller fallback.
    """
    try:
        artifact = (
            claim
            if isinstance(claim, SignedUnownedTeamClaim)
            else read_unowned_team_claim(claim)
        )
    except TeamControlRequestError as exc:
        raise TeamControlRequestInvalid(
            TeamControlRequestReason.ARTIFACT_INVALID
        ) from exc
    _require_target(artifact, target)
    require_fresh_team_control_request(timestamp=artifact.request.timestamp)
    try:
        artifact.verify_integrity()
    except TeamControlSignatureError as exc:
        raise TeamControlRequestInvalid(
            TeamControlRequestReason.SIGNATURE_INVALID
        ) from exc
    key = await read_fresh_team_controller(context=context, team_id=target.team_id)
    if artifact.signer_did_key != key:
        raise TeamControlRequestInvalid(TeamControlRequestReason.CONTROLLER_MISMATCH)
    result = VerifiedUnownedTeamClaim(artifact=artifact, verified_team_did_key=key)
    result.require_target(target=target)
    return result
