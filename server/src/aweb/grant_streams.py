from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from aweb.application_state import application_registry_client
from aweb.auth_context import TeamIdentity
from aweb.certificate_registration import configured_registration_mode
from aweb.identity_grant_status import GrantValidityState, grant_validity
from aweb.member_team_key import (
    CURRENT_MEMBERSHIP_REQUIRED_DETAIL,
    GRANT_ISSUER_RECOVERY_DETAIL,
    current_member,
    current_membership,
    member_key_columns_sql,
    member_key_current,
    read_member_projection,
)
from aweb.team_registry import native_database_manager

GRANT_STREAM_RECHECK_SECONDS = 30

GRANT_TERMINAL_DETAILS = {
    "verification_unavailable": "identity grant verification unavailable",
    "grant_expired": "identity grant expired",
    "grant_revoked": "identity grant revoked",
    "grant_subject_inactive": "identity grant subject inactive",
    "grant_issuer_revoked": "identity grant issuer revoked. " + GRANT_ISSUER_RECOVERY_DETAIL,
    "team_membership_not_current": CURRENT_MEMBERSHIP_REQUIRED_DETAIL,
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
    if (
        identity.grant is not None
        and not identity.grant.never_expires
        and _as_utc(identity.grant.expires_at) <= datetime.now(timezone.utc)
    ):
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
        if not identity.certificate_id:
            # An identity-only conversation is not a certificate-auth stream.
            return None
        row = await read_member_projection(
            native_database_manager(db), team_id=identity.team_id, agent_id=identity.agent_id,
        )
        if (
            not row or not current_member(row) or row["did_key"] != identity.did_key
            or not member_key_current(row, checked_key=identity.verified_team_did_key or "")
        ):
            return "team_membership_not_current"
        member = await current_membership(
            application_registry_client(request.app.state),
            {**dict(row), "certificate_id": identity.certificate_id}, request=request,
        )
        return None if member and member.get("team_id") else "team_membership_not_current"
    now = datetime.now(timezone.utc)
    if not grant.never_expires and _as_utc(grant.expires_at) <= now:
        return "grant_expired"

    aweb_db = native_database_manager(db)
    row = await aweb_db.fetch_one(
        """
        SELECT g.team_id, g.grant_did_key, g.issued_at, g.expires_at, g.revoked_at,
               g.issued_by_certificate_id,
               a.agent_id, a.status AS subject_status, a.deleted_at AS subject_deleted_at,
               a.certificate_id, """
        + member_key_columns_sql("a")
        + """
        FROM {{tables.identity_session_grants}} AS g
        JOIN {{tables.agents}} AS a ON a.agent_id = g.subject_agent_id
        WHERE g.grant_id = $1::UUID
        """,
        grant.grant_id,
    )
    if row is None or row["grant_did_key"] != grant.session_did_key:
        return "grant_revoked"
    if str(row["agent_id"]) != str(identity.agent_id):
        return "grant_subject_inactive"
    observation = await grant_validity(
        row=row,
        now=now,
        registry_client=application_registry_client(request.app.state),
        registration_mode=configured_registration_mode(),
        request=request,
    )
    observation.raise_if_unavailable()
    return {
        GrantValidityState.ACTIVE: None,
        GrantValidityState.REVOKED: "grant_revoked",
        GrantValidityState.EXPIRED: "grant_expired",
        GrantValidityState.SUBJECT_INACTIVE: "grant_subject_inactive",
        GrantValidityState.ISSUER_SUPERSEDED: "grant_issuer_revoked",
        GrantValidityState.ISSUER_REVOKED: "grant_issuer_revoked",
        GrantValidityState.ISSUER_UNREGISTERED: "grant_issuer_revoked",
    }[observation.state]


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
    if event_type in {"actionable_chat", "actionable_room_post"}:
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
    """Revalidate certificate and never-grant streams on the shared 30s cadence."""

    def __init__(self, request, db, identity, expiry_reason=grant_expiry_reason):
        self.request, self.db, self.identity = request, db, identity
        self.expiry_reason = expiry_reason
        self.checked_at = time.monotonic()

    async def reason(self):
        grant = self.identity.grant
        if grant is not None and not grant.never_expires:
            return self.expiry_reason(self.identity)
        now = time.monotonic()
        if now - self.checked_at < GRANT_STREAM_RECHECK_SECONDS:
            return None
        self.checked_at = now
        try:
            return await grant_terminal_reason(self.request, self.db, self.identity)
        except Exception:
            logging.getLogger(__name__).warning(
                "Stream credential revalidation failed", exc_info=True
            )
            return "verification_unavailable"
