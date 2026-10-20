"""Identity session grant status, as identity-grant-status.v1 reports it."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import Request

from aweb.config import require_registered_certificates
from aweb.grant_expiry import never_expires
from aweb.credential_policy import team_credential_policy
from aweb.team_auth_deps import _get_registered_certificates, _get_revoked_certificates


def grant_status(row, now: datetime) -> str:
    """A grant's own status: revoked, expired or active."""
    if row["revoked_at"] is not None:
        return "revoked"
    if not never_expires(row.get("issued_at"), row["expires_at"]) and row["expires_at"] <= now:
        return "expired"
    return "active"


async def effective_grant_status(request: Request, row, now: datetime) -> tuple[str, Optional[str]]:
    """The grant's status after its subject and issuing certificate are checked."""
    status = grant_status(row, now)
    if status != "active":
        return status, None
    if row.get("subject_status") != "active" or row.get("subject_deleted_at") is not None:
        return "subject_inactive", "grant subject identity is not active"
    issuing_certificate_id = (row.get("issued_by_certificate_id") or "").strip()
    if issuing_certificate_id:
        if row.get('issued_by_certificate_version', 1) == 2:
            from aweb.credential_policy import v2_issuer_revoked
            revoked_certs = {issuing_certificate_id} if await v2_issuer_revoked(request, row['team_id'], issuing_certificate_id) else set()
        else:
            revoked_certs = await _get_revoked_certificates(request, row["team_id"])
        if issuing_certificate_id in revoked_certs:
            return "issuer_revoked", "grant issuing certificate revoked"
        if require_registered_certificates() and row.get('issued_by_certificate_version', 1) != 2:
            registered_certs = await _get_registered_certificates(request, row["team_id"])
            if issuing_certificate_id not in registered_certs:
                return "issuer_not_registered", "grant issuing certificate not registered"
    parent_expiry = row.get('issued_by_certificate_expires_at')
    if parent_expiry is not None and parent_expiry <= now:
        return 'expired', 'grant issuing certificate expired'
    policy = await team_credential_policy(request, row['team_id'])
    maximum = policy['identity_grant'] if policy else None
    if maximum is not None and (never_expires(row.get('issued_at'), row['expires_at']) or (row['expires_at'] - row['issued_at']).total_seconds() > maximum):
        return 'lifetime_exceeded', 'grant exceeds current team lifetime policy'
    return "active", None
