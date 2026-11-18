"""Identity session grant status, as identity-grant-status.v1 reports it."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import Request

from aweb.config import require_registered_certificates
from aweb.grant_expiry import GrantLifetimeState, grant_lifetime_state
from aweb.member_team_key import GRANT_ISSUER_RECOVERY_DETAIL, grant_issuer_current
from aweb.team_auth_deps import _get_registered_certificates, _get_revoked_certificates


def grant_status(row, now: datetime) -> GrantLifetimeState:
    """A grant's own status: revoked, expired or active."""
    return grant_lifetime_state(
        issued_at=row.get("issued_at"),
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
        now=now,
    )


async def effective_grant_status(
    request: Request, row, now: datetime
) -> tuple[str, Optional[str]]:
    """The grant's status after its subject and issuing certificate are checked."""
    status = grant_status(row, now)
    if status is not GrantLifetimeState.ACTIVE:
        return status, None
    if (
        row.get("subject_status") != "active"
        or row.get("subject_deleted_at") is not None
    ):
        return "subject_inactive", "grant subject identity is not active"
    if not grant_issuer_current(row):
        return (
            "issuer_revoked",
            "grant issuing certificate superseded. " + GRANT_ISSUER_RECOVERY_DETAIL,
        )
    issuing_certificate_id = (row.get("issued_by_certificate_id") or "").strip()
    if issuing_certificate_id:
        revoked_certs = await _get_revoked_certificates(
            request, row["team_id"], certificate_ids=[issuing_certificate_id]
        )
        if issuing_certificate_id in revoked_certs:
            return (
                "issuer_revoked",
                "grant issuing certificate revoked. " + GRANT_ISSUER_RECOVERY_DETAIL,
            )
        if require_registered_certificates():
            registered_certs = await _get_registered_certificates(
                request, row["team_id"]
            )
            if issuing_certificate_id not in registered_certs:
                return (
                    "issuer_not_registered",
                    "grant issuing certificate not registered. "
                    + GRANT_ISSUER_RECOVERY_DETAIL,
                )
    return "active", None
