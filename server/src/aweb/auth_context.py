from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class GrantContext:
    """Typed provenance for an identity session grant.

    The grant is the authenticated credential; the enclosing identity/principal
    remains the subject identity the grant acts as.
    """

    grant_id: str
    session_did_key: str
    issuing_certificate_id: str | None
    scopes: tuple[str, ...]
    expires_at: datetime


GRANT_SCOPE_ANY = "__any_grant__"

GRANT_SCOPES = (
    "mail.read",
    "mail.send",
    "chat.read",
    "chat.send",
    "events.read",
    "coord.read",
    "coord.write",
    "presence.write",
    "contacts.read",
    "contacts.write",
)
