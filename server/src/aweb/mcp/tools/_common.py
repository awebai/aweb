from __future__ import annotations

import json

from aweb.mcp.auth import AuthContext, get_auth

TEAM_CONTEXT_ERROR = json.dumps({"error": "This tool requires team context. Use a team certificate."})


def require_team_context() -> tuple[AuthContext | None, str | None]:
    auth = get_auth()
    if auth.team_id and (auth.certificate_id or auth.trusted_proxy):
        return auth, None
    return None, TEAM_CONTEXT_ERROR
