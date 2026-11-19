"""Borrow SDK controller evidence and apply the single native pin owner."""

from awid.external_authority import TXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_key_acts import TeamKeyMemo
from pgdbm import AsyncDatabaseManager

from aweb.certificate_evidence import EvidenceMode
from aweb.team_key_pins import pinned_team_key
from aweb.team_scope import member_team_scope


async def read_team_key(
    *,
    db: AsyncDatabaseManager,
    registry_client: RegistryClient,
    txt_resolver: TXTOutcomeResolver,
    team_id: str,
    evidence: EvidenceMode,
    pin_memo: TeamKeyMemo | None = None,
) -> str:
    """Read SDK controller evidence and admit it through the single pin owner.

    team-auth-envelope-v2.md:60-70 requires the current team key. The SDK
    retains cached age/grace or performs fresh acquisition; this function
    neither constructs a client nor reads a registration list. Generation
    callers retain raw SDK/pin failures for their own policy adapter.
    """
    domain, name = member_team_scope(team_id)
    if not isinstance(evidence, EvidenceMode):
        raise TypeError("Team key reads require a named EvidenceMode")
    if evidence is EvidenceMode.FRESH:
        key = await registry_client.get_team_public_key_fresh(domain, name)
    else:
        key = await registry_client.get_team_public_key(domain, name)
    if not key:
        return ""
    return await pinned_team_key(
        db=db,
        registry_client=registry_client,
        txt_resolver=txt_resolver,
        team_id=team_id,
        served_key=key,
        pin_memo=pin_memo,
    )
