from __future__ import annotations

import hashlib
import hmac
import logging
import os
import uuid
from typing import Optional, TypedDict

import re

from fastapi import HTTPException
from starlette.requests import Request

logger = logging.getLogger(__name__)

_TEAM_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_DOMAIN_INVALID_RE = re.compile(r"[:/\s]")


def _is_valid_proxy_team_id(team_id: str) -> bool:
    """Validate that team_id is a canonical colon-form like ops:acme.com."""
    if team_id.count(":") != 1:
        return False
    name, domain = team_id.split(":", 1)
    if not name or not domain:
        return False
    if not _TEAM_NAME_RE.match(name):
        return False
    if _DOMAIN_INVALID_RE.search(domain):
        return False
    if domain != domain.lower().rstrip("."):
        return False
    if ".." in domain:
        return False
    return True


def _trust_aweb_proxy_headers() -> bool:
    """True when the operator has explicitly opted into proxy-header auth."""
    return os.getenv("AWEB_TRUST_PROXY_HEADERS", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


INTERNAL_AUTH_HEADER = "X-AWEB-Auth"
INTERNAL_TEAM_HEADER = "X-Team-ID"
INTERNAL_USER_HEADER = "X-User-ID"
INTERNAL_API_KEY_ID_HEADER = "X-API-Key"
INTERNAL_ACTOR_ID_HEADER = "X-AWEB-Actor-ID"


class InternalAuthContext(TypedDict):
    team_id: str
    principal_type: str
    principal_id: str
    actor_id: str


def _get_internal_auth_secret() -> Optional[str]:
    return os.getenv("AWEB_INTERNAL_AUTH_SECRET")


def build_internal_auth_header_value(
    *, secret: str, team_id: str, principal_type: str, principal_id: str, actor_id: str
) -> str:
    msg = f"v2:{team_id}:{principal_type}:{principal_id}:{actor_id}"
    sig = hmac.new(
        secret.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{msg}:{sig}"


def parse_internal_auth_context(request: Request) -> Optional[InternalAuthContext]:
    """Parse and validate trusted proxy auth headers.

    Returns None when proxy-header trust is disabled or no internal auth header
    is present. Raises 500 when proxy-header trust is enabled without a shared
    secret, and 401 when proxy auth is present but malformed or invalid.
    """
    if not _trust_aweb_proxy_headers():
        return None

    secret = _get_internal_auth_secret()
    if not secret:
        path = request.scope.get("path") or ""
        logger.error(
            "AWEB_TRUST_PROXY_HEADERS is enabled but %s is not configured (path=%s)",
            "AWEB_INTERNAL_AUTH_SECRET",
            path,
        )
        raise HTTPException(status_code=500, detail="Internal proxy authentication is misconfigured")

    internal_auth = request.headers.get(INTERNAL_AUTH_HEADER)
    if not internal_auth:
        return None

    team_id = (request.headers.get(INTERNAL_TEAM_HEADER) or "").strip()
    if not team_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not _is_valid_proxy_team_id(team_id):
        raise HTTPException(status_code=401, detail="Authentication required")

    user_id = request.headers.get(INTERNAL_USER_HEADER)
    api_key_id = request.headers.get(INTERNAL_API_KEY_ID_HEADER)
    if user_id:
        try:
            user_id = str(uuid.UUID(user_id))
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Authentication required") from exc
        principal_type = "u"
        principal_id = user_id
    elif api_key_id:
        try:
            api_key_id = str(uuid.UUID(api_key_id))
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Authentication required") from exc
        principal_type = "k"
        principal_id = api_key_id
    else:
        raise HTTPException(status_code=401, detail="Authentication required")

    actor_id = request.headers.get(INTERNAL_ACTOR_ID_HEADER)
    if not actor_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        actor_id = str(uuid.UUID(actor_id))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Authentication required") from exc

    expected = build_internal_auth_header_value(
        secret=secret,
        team_id=team_id,
        principal_type=principal_type,
        principal_id=principal_id,
        actor_id=actor_id,
    )
    if not hmac.compare_digest(internal_auth, expected):
        raise HTTPException(status_code=401, detail="Authentication required")

    return {
        "team_id": team_id,
        "principal_type": principal_type,
        "principal_id": principal_id,
        "actor_id": actor_id,
    }
