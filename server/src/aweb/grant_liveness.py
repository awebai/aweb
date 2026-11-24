from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from datetime import datetime, timedelta, timezone

from .grant_liveness_policy import (
    GrantLivenessFailurePolicy as GrantLivenessFailurePolicy,
)
from .auth_context import GrantContext
from .member_team_key import grant_issuer_current_sql, member_key_columns_sql
from .identity_grant_status import GrantValidityState, grant_validity
from .grant_expiry import never_expires
from starlette.requests import Request


DEFAULT_GRANT_LIVENESS_TTL_SECONDS = 1800


def grant_liveness_expiry(grant: GrantContext) -> datetime:
    # Presence is ephemeral even when delegation is not. Do not write the
    # storage sentinel as a heartbeat deadline after its calendar horizon.
    if grant.never_expires:
        return datetime.now(timezone.utc) + timedelta(seconds=DEFAULT_GRANT_LIVENESS_TTL_SECONDS)
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
    if not isinstance(status, str) or not status.startswith("DELETE "):
        raise ValueError("Grant liveness cleanup did not return a DELETE count")
    try:
        return int(status.removeprefix("DELETE "))
    except ValueError as exc:
        raise ValueError("Grant liveness cleanup returned an invalid DELETE count") from exc


_GRANT_CANDIDATE_FIELDS = (
    "workspace_id",
    "grant_id",
    "subject_agent_id",
    "alias",
    "session_did_key",
    "last_seen_at",
    "liveness_expires_at",
    "team_id",
    "issued_at",
    "expires_at",
    "revoked_at",
    "issued_by_certificate_id",
    "subject_status",
    "subject_deleted_at",
    "certificate_id",
    "accepted_team_did_key",
    "current_team_did_key",
)


def _grant_liveness_candidates_sql(*, workspace_predicate: str, ttl_seconds_parameter: str) -> str:
    """One eligibility query for direct reads and workspace-statement composition."""
    return f"""
        SELECT l.workspace_id, l.grant_id, l.subject_agent_id, l.alias,
               l.session_did_key, l.last_seen_at, l.expires_at AS liveness_expires_at,
               g.team_id, g.issued_at, g.expires_at, g.revoked_at, g.issued_by_certificate_id,
               a.status AS subject_status, a.deleted_at AS subject_deleted_at,
               a.certificate_id, {member_key_columns_sql("a")}
        FROM {{{{tables.identity_grant_liveness}}}} l
        JOIN {{{{tables.identity_session_grants}}}} g ON g.grant_id = l.grant_id
        JOIN {{{{tables.agents}}}} a ON a.agent_id = l.subject_agent_id
        WHERE {workspace_predicate}
          AND l.last_seen_at >= NOW() - ({ttl_seconds_parameter}::int * INTERVAL '1 second')
          AND g.team_id = l.team_id
          AND g.subject_agent_id = l.subject_agent_id
          AND g.grant_did_key = l.session_did_key
          AND a.team_id = l.team_id
          AND a.agent_id = l.subject_agent_id
          AND a.status = 'active'
          AND a.deleted_at IS NULL
          AND {grant_issuer_current_sql(agent="a", grant="g")}
        ORDER BY l.workspace_id, l.last_seen_at DESC, l.grant_id
    """


def workspace_grant_liveness_join_sql(*, workspace: str, ttl_seconds_parameter: str) -> str:
    """Join every eligible candidate, retaining native values and distinct column names.

    The caller selects grant_liveness.* and orders candidates by the projected
    last_seen_at DESC, grant_id. SQL fragments are internal identifiers/parameters.
    Validation still belongs to the same grant-validity owner after acquisition.
    """
    columns = ", ".join(
        f"candidate.{name} AS grant_liveness_{name}" for name in _GRANT_CANDIDATE_FIELDS
    )
    candidates = _grant_liveness_candidates_sql(
        workspace_predicate=f"l.workspace_id = {workspace}.workspace_id",
        ttl_seconds_parameter=ttl_seconds_parameter,
    )
    return (
        f"LEFT JOIN LATERAL (SELECT {columns} FROM ({candidates}) candidate) grant_liveness ON TRUE"
    )


async def valid_grant_liveness_from_workspace_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    registry_client,
    request: Request | None = None,
    failure_policy: GrantLivenessFailurePolicy = GrantLivenessFailurePolicy.OMIT_UNPROVEN,
) -> dict[str, dict[str, Any]]:
    """Validate actual ordered rows acquired with workspace_grant_liveness_join_sql."""
    candidates = [
        {name: row[f"grant_liveness_{name}"] for name in _GRANT_CANDIDATE_FIELDS}
        for row in rows
        if row["grant_liveness_grant_id"] is not None
    ]
    return await _valid_grant_liveness_candidates(
        candidates, registry_client=registry_client, request=request, failure_policy=failure_policy
    )


async def valid_grant_liveness_by_workspace(
    db,
    workspace_ids: list[str],
    *,
    registry_client,
    request: Request | None = None,
    ttl_seconds: int = DEFAULT_GRANT_LIVENESS_TTL_SECONDS,
    failure_policy: GrantLivenessFailurePolicy = GrantLivenessFailurePolicy.OMIT_UNPROVEN,
) -> dict[str, dict[str, Any]]:
    """Return the newest valid grant liveness row for each workspace.

    Liveness rows are only trusted when their backing grant is still active,
    unrevoked, unexpired, bound to the same session did:key and subject, and the
    subject agent is still active under its current team key and issuing
    certificate. Reacceptance cannot revive a previous delegation. Stale rows
    are ignored even before cleanup. REQUIRE_KNOWN retains unavailable
    authority as a failure for consumers that decide stale deletion.
    """
    if not isinstance(failure_policy, GrantLivenessFailurePolicy):
        raise TypeError("Grant liveness requires a named failure policy")
    if not workspace_ids:
        return {}
    rows = await db.fetch_all(
        _grant_liveness_candidates_sql(
            workspace_predicate="l.workspace_id = ANY($1::uuid[])",
            ttl_seconds_parameter="$2",
        ),
        workspace_ids,
        ttl_seconds,
    )
    return await _valid_grant_liveness_candidates(
        rows, registry_client=registry_client, request=request, failure_policy=failure_policy
    )


async def _valid_grant_liveness_candidates(
    rows: Sequence[Mapping[str, Any]],
    *,
    registry_client,
    request: Request | None,
    failure_policy: GrantLivenessFailurePolicy,
) -> dict[str, dict[str, Any]]:
    if not isinstance(failure_policy, GrantLivenessFailurePolicy):
        raise TypeError("Grant liveness requires a named failure policy")
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
            request=request,
        )
        if failure_policy is GrantLivenessFailurePolicy.REQUIRE_KNOWN:
            # docs/aweb-sot.md:1199-1209: unknown authority is not proof of
            # inactivity for a stale-workspace deletion. Displays can omit an
            # unproven online state; destructive eligibility must fail visibly.
            validity.raise_if_unavailable()
        if validity.state is not GrantValidityState.ACTIVE:
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
