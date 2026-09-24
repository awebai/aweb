from __future__ import annotations

from datetime import timedelta
from typing import Any

DEFAULT_GRANT_LIVENESS_TTL_SECONDS = 1800


async def cleanup_expired_grant_liveness(db, *, ttl_seconds: int = DEFAULT_GRANT_LIVENESS_TTL_SECONDS) -> int:
    """Delete grant liveness rows that can no longer make a worker online."""
    status = await db.execute(
        """
        DELETE FROM {{tables.identity_grant_liveness}}
        WHERE expires_at <= NOW()
           OR last_seen_at < NOW() - ($1::int * INTERVAL '1 second')
        """,
        ttl_seconds,
    )
    try:
        return int(str(status).split()[-1])
    except Exception:
        return 0


async def valid_grant_liveness_by_workspace(
    db,
    workspace_ids: list[str],
    *,
    ttl_seconds: int = DEFAULT_GRANT_LIVENESS_TTL_SECONDS,
) -> dict[str, dict[str, Any]]:
    """Return the newest valid grant liveness row for each workspace.

    Liveness rows are only trusted when their backing grant is still active,
    unrevoked, unexpired, bound to the same session did:key and subject, and the
    subject agent is still active. Stale rows are ignored even before cleanup.
    """
    if not workspace_ids:
        return {}
    await cleanup_expired_grant_liveness(db, ttl_seconds=ttl_seconds)
    rows = await db.fetch_all(
        """
        SELECT DISTINCT ON (l.workspace_id)
               l.workspace_id, l.grant_id, l.subject_agent_id, l.alias,
               l.session_did_key, l.last_seen_at, l.expires_at
        FROM {{tables.identity_grant_liveness}} l
        JOIN {{tables.identity_session_grants}} g ON g.grant_id = l.grant_id
        JOIN {{tables.agents}} a ON a.agent_id = l.subject_agent_id
        WHERE l.workspace_id = ANY($1::uuid[])
          AND l.last_seen_at >= NOW() - ($2::int * INTERVAL '1 second')
          AND l.expires_at > NOW()
          AND g.expires_at > NOW()
          AND g.revoked_at IS NULL
          AND g.team_id = l.team_id
          AND g.subject_agent_id = l.subject_agent_id
          AND g.grant_did_key = l.session_did_key
          AND a.team_id = l.team_id
          AND a.agent_id = l.subject_agent_id
          AND a.status = 'active'
          AND a.deleted_at IS NULL
        ORDER BY l.workspace_id, l.last_seen_at DESC, l.grant_id
        """,
        workspace_ids,
        ttl_seconds,
    )
    return {str(row["workspace_id"]): dict(row) for row in rows}
