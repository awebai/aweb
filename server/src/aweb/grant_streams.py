from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from aweb.grant_expiry import never_expires
from aweb.auth_context import GrantContext
from aweb.config import require_registered_certificates
from aweb.team_auth_deps import TeamIdentity, _aweb_db, _get_registered_certificates, _get_revoked_certificates

GRANT_STREAM_RECHECK_SECONDS = 30

GRANT_TERMINAL_DETAILS = {
    "verification_unavailable": "identity grant verification unavailable",
    "grant_expired": "identity grant expired",
    "grant_revoked": "identity grant revoked",
    "grant_subject_inactive": "identity grant subject inactive",
    "grant_issuer_revoked": "identity grant issuer revoked",
}


def clamp_deadline_to_grant(deadline: datetime, identity: TeamIdentity) -> datetime:
    grant = identity.grant
    if grant is None or grant.never_expires:
        return deadline
    expires_at = _as_utc(grant.expires_at)
    return min(_as_utc(deadline), expires_at)


def grant_terminal_sse(reason: str) -> str:
    payload = {"type": reason, "detail": GRANT_TERMINAL_DETAILS.get(reason, reason)}
    return f"event: {reason}\ndata: {json.dumps(payload)}\n\n"


def grant_expiry_reason(identity: TeamIdentity) -> str | None:
    if identity.grant is not None and not identity.grant.never_expires and _as_utc(identity.grant.expires_at) <= datetime.now(timezone.utc):
        return "grant_expired"
    return None


async def require_valid_stream_grant(request: Request, db, identity: TeamIdentity) -> None:
    """Check before constructing StreamingResponse, while HTTP errors are legal."""
    reason = await grant_terminal_reason(request, db, identity)
    if reason:
        raise HTTPException(status_code=403, detail=GRANT_TERMINAL_DETAILS[reason])


async def grant_terminal_reason(request: Request, db, identity: TeamIdentity) -> str | None:
    grant = identity.grant
    if grant is None:
        return None
    now = datetime.now(timezone.utc)
    if not grant.never_expires and _as_utc(grant.expires_at) <= now:
        return "grant_expired"

    aweb_db = _aweb_db(db)
    row = await aweb_db.fetch_one(
        """
        SELECT g.team_id, g.grant_did_key, g.issued_at, g.expires_at, g.revoked_at,
               g.issued_by_certificate_id,
               a.agent_id, a.status, a.deleted_at
        FROM {{tables.identity_session_grants}} AS g
        JOIN {{tables.agents}} AS a ON a.agent_id = g.subject_agent_id
        WHERE g.grant_id = $1::UUID
        """,
        grant.grant_id,
    )
    if row is None or row["grant_did_key"] != grant.session_did_key:
        return "grant_revoked"
    if row["revoked_at"] is not None:
        return "grant_revoked"
    if not never_expires(row.get("issued_at"), row["expires_at"]) and _as_utc(row["expires_at"]) <= now:
        return "grant_expired"
    if str(row["agent_id"]) != str(identity.agent_id) or row["status"] != "active" or row["deleted_at"] is not None:
        return "grant_subject_inactive"

    issuing_certificate_id = (row.get("issued_by_certificate_id") or "").strip()
    if issuing_certificate_id:
        revoked_certs = await _get_revoked_certificates(request, row["team_id"])
        if issuing_certificate_id in revoked_certs:
            return "grant_issuer_revoked"
        if require_registered_certificates():
            registered_certs = await _get_registered_certificates(request, row["team_id"])
            if issuing_certificate_id not in registered_certs:
                return "grant_issuer_revoked"
    return None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def grant_has_scope(identity: TeamIdentity, scope: str) -> bool:
    grant = identity.grant
    if grant is None:
        return True
    return scope in set(grant.scopes or ())


def agent_event_allowed(identity: TeamIdentity, event: dict[str, Any]) -> bool:
    if identity.grant is None:
        return True
    event_type = str(event.get("type") or "")
    if event_type == "actionable_mail":
        return grant_has_scope(identity, "mail.read")
    if event_type == "actionable_chat":
        return grant_has_scope(identity, "chat.read")
    if event_type.startswith("control_") or event_type in GRANT_TERMINAL_DETAILS:
        return grant_has_scope(identity, "events.read")
    # Unknown/app/work events may carry coordination/application data. Fail
    # closed for grants unless coord.read is also present.
    return grant_has_scope(identity, "coord.read")


_STATUS_CATEGORY_SCOPE = {
    "message": "mail.read",
    "chat": "chat.read",
    "reservation": "coord.read",
    "task": "coord.read",
}


def allowed_status_categories(identity: TeamIdentity) -> set[str] | None:
    if identity.grant is None:
        return None
    scopes = set(identity.grant.scopes or ())
    return {category for category, scope in _STATUS_CATEGORY_SCOPE.items() if scope in scopes}


def status_event_allowed(identity: TeamIdentity, event: dict[str, Any]) -> bool:
    if identity.grant is None:
        return True
    event_type = str(event.get("type") or "")
    category = event_type.split(".", 1)[0]
    allowed = allowed_status_categories(identity) or set()
    return category in allowed


class NeverGrantStreamGuard:
    """Retain finite-stream behavior; never grants revalidate at most every 30s."""
    def __init__(self, request, db, identity):
        self.request, self.db, self.identity = request, db, identity
        self.checked_at = time.monotonic()

    async def reason(self):
        grant = self.identity.grant
        if grant is None or not grant.never_expires:
            return grant_expiry_reason(self.identity)
        now = time.monotonic()
        if now - self.checked_at < GRANT_STREAM_RECHECK_SECONDS:
            return None
        self.checked_at = now
        try:
            return await grant_terminal_reason(self.request, self.db, self.identity)
        except Exception:
            logging.getLogger(__name__).warning("Never-grant stream revalidation failed", exc_info=True)
            return "verification_unavailable"
