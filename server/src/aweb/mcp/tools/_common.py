from __future__ import annotations

import json

from aweb.mcp.auth import AuthContext, get_auth
from aweb.team_auth_deps import TeamIdentity

TEAM_CONTEXT_ERROR = json.dumps({"error": "This tool requires team context. Use a team certificate."})


def require_team_context() -> tuple[AuthContext | None, str | None]:
    auth = get_auth()
    if auth.team_id and (auth.certificate_id or auth.trusted_proxy):
        return auth, None
    return None, TEAM_CONTEXT_ERROR


def team_identity(auth: AuthContext) -> TeamIdentity:
    """The authenticated team member, as the services shared with the REST routes take it."""
    return TeamIdentity(
        team_id=auth.team_id or "",
        alias=auth.alias or "",
        did_key=auth.did_key,
        did_aw=auth.did_aw or "",
        address=auth.address or "",
        agent_id=auth.agent_id or "",
        identity_scope=auth.identity_scope or "",
        certificate_id=auth.certificate_id or "",
    )
