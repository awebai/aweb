from __future__ import annotations

from typing import Any
from datetime import datetime, timedelta, timezone

from .auth_context import GrantContext
from .member_team_key import grant_issuer_current_sql, member_key_columns_sql
from .identity_grant_status import GrantValidityState, grant_validity
from .grant_expiry import never_expires
from .certificate_registration import configured_registration_mode
from starlette.requests import Request

DEFAULT_GRANT_LIVENESS_TTL_SECONDS = 1800


def grant_liveness_expiry(grant: GrantContext) -> datetime:
    # Presence is ephemeral even when delegation is not. Do not write the
    # storage sentinel as a heartbeat deadline after its calendar horizon.
    if grant.never_expires:
        return datetime.now(timezone.utc) + timedelta(
            seconds=DEFAULT_GRANT_LIVENESS_TTL_SECONDS
        )
    return grant.expires_at


async def cleanup_expired_grant_liveness(
    db, *, ttl_seconds: int = DEFAULT_GRANT_LIVENESS_TTL_SECONDS
) -> int:
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
    registry_client,
    request: Request | None = None,
    ttl_seconds: int = DEFAULT_GRANT_LIVENESS_TTL_SECONDS,
) -> dict[str, dict[str, Any]]:
    """Return the newest valid grant liveness row for each workspace.

    Liveness rows are only trusted when their backing grant is still active,
    unrevoked, unexpired, bound to the same session did:key and subject, and the
    subject agent is still active under its current team key and issuing
    certificate. Reacceptance cannot revive a previous delegation. Stale rows
    are ignored even before cleanup.
    """
    if not workspace_ids:
        return {}
    rows = await db.fetch_all(
        f"""
        SELECT l.workspace_id, l.grant_id, l.subject_agent_id, l.alias,
               l.session_did_key, l.last_seen_at, l.expires_at AS liveness_expires_at,
               g.team_id, g.issued_at, g.expires_at, g.revoked_at, g.issued_by_certificate_id,
               a.status AS subject_status, a.deleted_at AS subject_deleted_at,
               a.certificate_id, {member_key_columns_sql("a")}
        FROM {{{{tables.identity_grant_liveness}}}} l
        JOIN {{{{tables.identity_session_grants}}}} g ON g.grant_id = l.grant_id
        JOIN {{{{tables.agents}}}} a ON a.agent_id = l.subject_agent_id
        WHERE l.workspace_id = ANY($1::uuid[])
          AND l.last_seen_at >= NOW() - ($2::int * INTERVAL '1 second')
          AND g.team_id = l.team_id
          AND g.subject_agent_id = l.subject_agent_id
          AND g.grant_did_key = l.session_did_key
          AND a.team_id = l.team_id
          AND a.agent_id = l.subject_agent_id
          AND a.status = 'active'
          AND a.deleted_at IS NULL
          AND {grant_issuer_current_sql(agent="a", grant="g")}
        ORDER BY l.workspace_id, l.last_seen_at DESC, l.grant_id
        """,
        workspace_ids,
        ttl_seconds,
    )
    result = {}
    now = datetime.now(timezone.utc)
    for row in rows:
        workspace = str(row["workspace_id"])
        if workspace in result:
            continue
        validity = await grant_validity(
            row=row,
            now=now,
            registry_client=registry_client,
            registration_mode=configured_registration_mode(),
            request=request,
        )
        if validity.state is not GrantValidityState.ACTIVE:
            # Unknown registry evidence cannot assert that this worker is online.
            continue
        if (
            not never_expires(row["issued_at"], row["expires_at"])
            and row["liveness_expires_at"] <= now
        ):
            continue
        result[workspace] = {
            name: row[name]
            for name in (
                "workspace_id",
                "grant_id",
                "subject_agent_id",
                "alias",
                "session_did_key",
                "last_seen_at",
            )
        }
        result[workspace]["expires_at"] = row["liveness_expires_at"]
    return result
