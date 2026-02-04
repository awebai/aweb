"""Authentication + project scoping for aweb.

This module was extracted from BeadHub's OSS core. It remains compatible with the
existing deployment patterns (standalone OSS Bearer project keys + proxy-injected
auth context headers), but it is now owned by `aweb`.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import uuid
from typing import Any, Optional, Protocol, TypedDict

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class DatabaseLike(Protocol):
    def get_manager(self, name: str = "aweb") -> Any: ...


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_api_key(key: str) -> str:
    """Hash an API key for storage.

    Args:
        key: The plaintext API key to hash.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    return _sha256_hex(key)


def verify_api_key_hash(key: str, key_hash: str) -> bool:
    """Verify an API key against its stored hash.

    Args:
        key: The plaintext API key to verify.
        key_hash: The stored hex SHA-256 digest.

    Returns:
        True if the key matches the hash, False otherwise.
    """
    if not key_hash:
        return False
    return hmac.compare_digest(_sha256_hex(key), str(key_hash))


# Valid project_slug pattern: alphanumeric, slashes, underscores, hyphens, dots
PROJECT_SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9/_.\\-]+$")
PROJECT_SLUG_MAX_LENGTH = 256


INTERNAL_BEADHUB_AUTH_HEADER = "X-BH-Auth"
INTERNAL_PROJECT_HEADER = "X-Project-ID"
INTERNAL_USER_HEADER = "X-User-ID"
INTERNAL_API_KEY_ID_HEADER = "X-API-Key"
INTERNAL_ACTOR_ID_HEADER = "X-Aweb-Actor-ID"


class InternalAuthContext(TypedDict):
    project_id: str
    principal_type: str  # "u" or "k"
    principal_id: str
    actor_id: str


def _get_aweb_internal_auth_secret() -> Optional[str]:
    """Get the internal auth secret for proxy header verification.

    Only returns AWEB_INTERNAL_AUTH_SECRET or BEADHUB_INTERNAL_AUTH_SECRET.
    Does NOT fall back to SESSION_SECRET_KEY - the internal auth secret must be
    explicitly configured when proxy headers are trusted.
    """
    return os.getenv("AWEB_INTERNAL_AUTH_SECRET") or os.getenv("BEADHUB_INTERNAL_AUTH_SECRET")


def _trust_aweb_proxy_headers() -> bool:
    return os.getenv("AWEB_TRUST_PROXY_HEADERS", "").strip().lower() in ("1", "true", "yes", "on")


class AuthConfigurationError(Exception):
    """Raised when auth configuration is invalid at startup."""

    pass


def validate_auth_config() -> None:
    """Validate auth configuration at startup.

    Call this during app initialization to fail fast if proxy headers are trusted
    but no internal auth secret is configured.

    Raises:
        AuthConfigurationError: If AWEB_TRUST_PROXY_HEADERS=1 but no internal
            auth secret (AWEB_INTERNAL_AUTH_SECRET or BEADHUB_INTERNAL_AUTH_SECRET)
            is configured.
    """
    if _trust_aweb_proxy_headers() and not _get_aweb_internal_auth_secret():
        msg = (
            "AWEB_TRUST_PROXY_HEADERS is enabled but no internal auth secret is configured. "
            "Set AWEB_INTERNAL_AUTH_SECRET or BEADHUB_INTERNAL_AUTH_SECRET."
        )
        logger.error(msg)
        raise AuthConfigurationError(msg)


def _internal_auth_header_value(
    *, secret: str, project_id: str, principal_type: str, principal_id: str, actor_id: str
) -> str:
    msg = f"v2:{project_id}:{principal_type}:{principal_id}:{actor_id}"
    sig = hmac.new(
        secret.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{msg}:{sig}"


def _parse_internal_auth_context(request: Request) -> Optional[InternalAuthContext]:
    """Parse and validate proxy-injected auth context headers.

    This is intended for proxy/wrapper deployments where the wrapper authenticates the caller
    (JWT/cookie/API key) and injects project scope to the core service.

    Supported signature:
    - `X-BH-Auth` signed with `AWEB_INTERNAL_AUTH_SECRET` (or `BEADHUB_INTERNAL_AUTH_SECRET`)
    """
    if not _trust_aweb_proxy_headers():
        return None

    internal_auth = request.headers.get(INTERNAL_BEADHUB_AUTH_HEADER)
    if not internal_auth:
        return None

    project_id = request.headers.get(INTERNAL_PROJECT_HEADER)
    if not project_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        project_id = str(uuid.UUID(project_id))
    except ValueError:
        raise HTTPException(status_code=401, detail="Authentication required")

    user_id = request.headers.get(INTERNAL_USER_HEADER)
    api_key_id = request.headers.get(INTERNAL_API_KEY_ID_HEADER)
    if user_id:
        try:
            user_id = str(uuid.UUID(user_id))
        except ValueError:
            raise HTTPException(status_code=401, detail="Authentication required")
        principal_type = "u"
        principal_id = user_id
    elif api_key_id:
        try:
            api_key_id = str(uuid.UUID(api_key_id))
        except ValueError:
            raise HTTPException(status_code=401, detail="Authentication required")
        principal_type = "k"
        principal_id = api_key_id
    else:
        raise HTTPException(status_code=401, detail="Authentication required")

    actor_id = request.headers.get(INTERNAL_ACTOR_ID_HEADER)
    if not actor_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        actor_id = str(uuid.UUID(actor_id))
    except ValueError:
        raise HTTPException(status_code=401, detail="Authentication required")

    secret = _get_aweb_internal_auth_secret()
    if not secret:
        logger.error(
            "AWEB_TRUST_PROXY_HEADERS is enabled but no internal auth secret is configured. "
            "Set AWEB_INTERNAL_AUTH_SECRET or BEADHUB_INTERNAL_AUTH_SECRET."
        )
        raise HTTPException(status_code=500, detail="Internal auth secret not configured")

    expected = _internal_auth_header_value(
        secret=secret,
        project_id=project_id,
        principal_type=principal_type,
        principal_id=principal_id,
        actor_id=actor_id,
    )
    if not hmac.compare_digest(internal_auth, expected):
        raise HTTPException(status_code=401, detail="Authentication required")

    return {
        "project_id": project_id,
        "principal_type": principal_type,
        "principal_id": principal_id,
        "actor_id": actor_id,
    }


def parse_bearer_token(request: Request) -> Optional[str]:
    """
    Extract Bearer token from Authorization header.

    Returns the token if Authorization header is present and properly formatted
    as "Bearer <token>". Returns None if header is absent.
    Raises HTTPException 401 if header is present but malformed.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return auth_header[7:]  # Strip "Bearer " prefix


async def verify_bearer_token(
    db: DatabaseLike,
    token: str,
    *,
    manager_name: str = "aweb",
) -> str:
    """
    Verify Bearer token and return associated project_id.

    Looks up the key by SHA-256 hash.
    Returns the project_id if token is valid.
    Raises HTTPException 401 if token is invalid or not found.
    """
    key_hash = hash_api_key(token)

    server_db = db.get_manager(manager_name)
    row = await server_db.fetch_one(
        """
        SELECT project_id, is_active
        FROM {{tables.api_keys}}
        WHERE key_hash = $1
        """,
        key_hash,
    )

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not row["is_active"]:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_used_at timestamp for usage tracking
    await server_db.execute(
        """
        UPDATE {{tables.api_keys}}
        SET last_used_at = NOW()
        WHERE key_hash = $1
        """,
        key_hash,
    )

    return str(row["project_id"])


async def verify_bearer_token_details(
    db: DatabaseLike,
    token: str,
    *,
    manager_name: str = "aweb",
) -> dict[str, str | None]:
    """Verify Bearer token and return the key's canonical identity context."""
    key_hash = hash_api_key(token)

    server_db = db.get_manager(manager_name)
    row = await server_db.fetch_one(
        """
        SELECT api_key_id, project_id, agent_id, user_id, is_active
        FROM {{tables.api_keys}}
        WHERE key_hash = $1
        """,
        key_hash,
    )
    if not row or not row["is_active"]:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await server_db.execute(
        """
        UPDATE {{tables.api_keys}}
        SET last_used_at = NOW()
        WHERE key_hash = $1
        """,
        key_hash,
    )

    return {
        "api_key_id": str(row["api_key_id"]),
        "project_id": str(row["project_id"]),
        "agent_id": str(row["agent_id"]) if row.get("agent_id") is not None else None,
        "user_id": str(row["user_id"]) if row.get("user_id") is not None else None,
    }


def validate_project_slug(project_slug: str) -> str:
    """Validate project_slug format and return normalized slug."""
    if not project_slug:
        raise ValueError("project_slug is required")
    if len(project_slug) > PROJECT_SLUG_MAX_LENGTH:
        raise ValueError("project_slug too long")
    if not PROJECT_SLUG_PATTERN.match(project_slug):
        raise ValueError("Invalid project_slug format")
    return project_slug


async def get_project_from_auth(
    request: Request,
    db: DatabaseLike,
    *,
    manager_name: str = "aweb",
) -> str:
    """
    Return the scoped project_id for this request.

    Priority order:
    1) Proxy header context:
       - `X-BH-Auth` (requires `AWEB_TRUST_PROXY_HEADERS=1`)
    2) Authorization: Bearer <project_api_key>
    """
    if _trust_aweb_proxy_headers():
        internal = _parse_internal_auth_context(request)
        if internal is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return internal["project_id"]

    token = parse_bearer_token(request)
    if token is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await verify_bearer_token(db, token, manager_name=manager_name)


async def get_actor_agent_id_from_auth(
    request: Request,
    db: DatabaseLike,
    *,
    manager_name: str = "aweb",
) -> str:
    """Return the authenticated *actor* agent_id for this request.

    In proxy-header mode, the wrapper must inject a signed actor identity via `X-Aweb-Actor-ID`.
    In direct mode, the Bearer API key must be bound to a specific agent.
    """
    if _trust_aweb_proxy_headers():
        internal = _parse_internal_auth_context(request)
        if internal is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return internal["actor_id"]

    token = parse_bearer_token(request)
    if token is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    details = await verify_bearer_token_details(db, token, manager_name=manager_name)
    actor_id = (details.get("agent_id") or "").strip()
    if not actor_id:
        raise HTTPException(status_code=403, detail="API key is not bound to an agent")
    return actor_id
