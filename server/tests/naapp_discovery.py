"""The naapp runtime's team-server discovery against the real stack's AWID."""

from __future__ import annotations

from collections.abc import Callable

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_server import TeamServerDirectory
from tests.real_stack import REGISTRY_URL, RealStack


def team_server_directory(
    stack: RealStack, *, clock: Callable[[], float] | None = None, ttl_seconds: int | None = None
) -> TeamServerDirectory:
    """Team-server discovery against the stack's AWID."""

    async def no_registry_override(domain: str) -> str | None:
        return None

    team_cache = AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=60, service_token=stack.service_token, transport=stack.awid
    )
    options: dict = {} if clock is None else {"clock": clock}
    if ttl_seconds is not None:
        options["ttl_seconds"] = ttl_seconds
    return TeamServerDirectory(
        team_cache=team_cache, transport=stack.awid, registry_override=no_registry_override, **options
    )
