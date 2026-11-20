"""Borrow SDK controller evidence and apply the single native pin owner."""

from collections.abc import Awaitable, Callable

from awid.external_authority import TXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_key_acts import TeamKeyMemo
from pgdbm import AsyncDatabaseManager

from aweb.certificate_evidence import EvidenceMode
from aweb.team_key_pins import pinned_team_key
from aweb.team_scope import member_team_scope


async def read_team_key(
    *,
    db: AsyncDatabaseManager | None = None,
    registry_client: RegistryClient,
    txt_resolver: TXTOutcomeResolver | None = None,
    team_id: str,
    evidence: EvidenceMode,
    pin_memo: TeamKeyMemo | None = None,
    check_key: Callable[[str], None] | None = None,
    pin_key: Callable[[str, str], Awaitable[str]] | None = None,
) -> str:
    """Read SDK controller evidence and admit it through the single pin owner.

    team-auth-envelope-v2.md:60-70 requires the current team key. The SDK
    retains cached age/grace or performs fresh acquisition; this function
    neither constructs a client nor reads a registration list. Generation
    callers retain raw SDK/pin failures for their own policy adapter. A
    controller request can check its signature before the pin changes; owner-act
    consumers can retain their existing bound native pin callback.
    """
    if pin_key is None and (db is None or txt_resolver is None):
        raise TypeError("Team key reads require the native pin resources")
    if pin_key is not None and (db is not None or txt_resolver is not None or pin_memo is not None):
        raise TypeError("Use either native pin resources or their bound callback")
    domain, name = member_team_scope(team_id)
    if not isinstance(evidence, EvidenceMode):
        raise TypeError("Team key reads require a named EvidenceMode")
    if evidence is EvidenceMode.FRESH:
        key = await registry_client.get_team_public_key_fresh(domain, name)
    else:
        key = await registry_client.get_team_public_key(domain, name)
    if not key:
        return ""
    if check_key is not None:
        check_key(key)
    if pin_key is not None:
        return await pin_key(team_id, key)
    assert db is not None and txt_resolver is not None
    return await pinned_team_key(
        db=db,
        registry_client=registry_client,
        txt_resolver=txt_resolver,
        team_id=team_id,
        served_key=key,
        pin_memo=pin_memo,
    )
