"""Explicit upgraded legacy registry facts for routing/authentication unit worlds.

These are test doubles, never a fallback for production or protection tests.
Native protection admission and outage tests use actual AWID. Cache-only worlds
may mix LegacyTeamFacts into a real SDK client to hold the independent protection
observation fixed while exercising key/revocation/registration cache behavior.
"""

import hashlib
from dataclasses import asdict
from unittest.mock import DEFAULT, AsyncMock, Mock

from awid.did import did_key_from_signing_key
from awid.registry import Team


def _legacy_controller_did_key():
    # Preserve the existing named server fixture key when sharing the helper.
    seed = hashlib.sha256(b"aweb-test-did-key:legacy-unit-team").digest()
    return did_key_from_signing_key(seed)


def legacy_team(domain: str, name: str, *, team_did_key: str | None = None) -> Team:
    return Team(
        team_id=f"{name}:{domain}", domain=domain, name=name, display_name=name,
        team_did_key=team_did_key or _legacy_controller_did_key(), visibility="public",
        created_at="2026-11-13T00:00:00Z", protection={"mode": "legacy"},
    )


def legacy_team_response(domain: str, name: str, *, team_did_key: str) -> dict:
    return asdict(legacy_team(domain, name, team_did_key=team_did_key))


class LegacyTeamFacts:
    """Explicitly unmarked team projection shared by unit registry doubles."""

    async def get_team_fresh(self, domain, name):
        key_reader = getattr(self, "get_team_public_key", None)
        if callable(key_reader):
            key = await key_reader(domain, name)
            if key is None:
                return None
            # An unconstrained AsyncMock has no controller configured. Identity
            # routing worlds still need one valid explicit legacy team fact.
            if isinstance(key, Mock):
                key = None
        else:
            key = getattr(self, "team_did_key", None)
        return legacy_team(domain, name, team_did_key=key)


_UNSET = object()


def legacy_registry(registry=_UNSET):
    """Complete an explicitly legacy AsyncMock world, retaining configured reads.

    Never overwrite a deliberate missing/malformed/outage/protected observation,
    or wrap a real SDK registry. Those tests own their authoritative response.
    """
    if registry is _UNSET:
        registry = AsyncMock()
    if not isinstance(registry, Mock):
        return registry
    fresh = registry.get_team_fresh
    if (isinstance(fresh, AsyncMock) and fresh.side_effect is None
            and fresh._mock_return_value is DEFAULT):
        async def read(domain, name):
            return await LegacyTeamFacts.get_team_fresh(registry, domain, name)

        fresh.side_effect = read
    return registry


def legacy_certificate_status(team_id, certificate_id, *, team_did_key, revoked_at=None):
    """Complete negotiated legacy facts for a test's own certificate catalog.

    A primitive certificate vector has no registry artifact commitment. Legacy
    status therefore supplies no protected digest; protected tests must use
    their own full authoritative evidence rather than this fixture.
    """
    return {"team_id": team_id, "certificate_id": certificate_id,
        "team_did_key": team_did_key, "status": "active" if revoked_at is None else "revoked",
        "revoked_at": revoked_at, "protection": {"mode": "legacy"}, "certificate_sha256": None}
