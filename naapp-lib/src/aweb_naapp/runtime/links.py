"""Bearer links: a high-entropy token handed out once, only its verifier at rest.

Approval links and enrolment links use this; other capability links can too.
Possessing a link never authenticates a human by itself.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime

TOKEN_BYTES = 32


def link_verifier(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_link_token() -> tuple[str, str]:
    """A fresh token and the verifier to store in its place."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    return token, link_verifier(token)


@dataclass(frozen=True)
class LinkLifetime:
    expires_at: datetime
    revoked_at: datetime | None
    used_at: datetime | None

    def usable_at(self, now: datetime) -> bool:
        return self.revoked_at is None and self.used_at is None and now < self.expires_at
