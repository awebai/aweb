"""Explicit legacy registry metadata for focused scope/stream unit fixtures.

Native protection admission and outages use real AWID in the membership tests.
These fixtures model an upgraded registry's positive legacy projection.
"""

from awid.registry import Team
from did_key_fixtures import named_did_key


def legacy_team(domain: str, name: str) -> Team:
    return Team(
        team_id=f"{name}:{domain}", domain=domain, name=name, display_name=name,
        team_did_key=named_did_key("legacy-unit-team"), visibility="public",
        created_at="2026-11-13T00:00:00Z", protection={"mode": "legacy"},
    )
