"""Authentication, validation, and project scoping for aweb."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import uuid
from typing import Any, Optional, Protocol

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class DatabaseLike(Protocol):
    def get_manager(self, name: str = "server") -> Any: ...


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_api_key(key: str) -> str:
    return _sha256_hex(key)


def verify_api_key_hash(key: str, key_hash: str) -> bool:
    if not key_hash:
        return False
    return hmac.compare_digest(_sha256_hex(key), str(key_hash))


PROJECT_SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")
PROJECT_SLUG_MAX_LENGTH = 256
AGENT_ALIAS_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
AGENT_ALIAS_MAX_LENGTH = 64
RESERVED_ALIASES = frozenset({"me"})


def validate_project_slug(project_slug: str) -> str:
    value = (project_slug or "").strip()
    if not value:
        raise ValueError("project_slug is required")
    if len(value) > PROJECT_SLUG_MAX_LENGTH:
        raise ValueError("project_slug too long")
    if not PROJECT_SLUG_PATTERN.match(value):
        raise ValueError("Invalid project_slug format")
    return value


def validate_agent_alias(alias: str) -> str:
    value = (alias or "").strip()
    if not value:
        raise ValueError("alias must not be empty")
    if len(value) > AGENT_ALIAS_MAX_LENGTH:
        raise ValueError("alias too long")
    if value.lower() in RESERVED_ALIASES:
        raise ValueError(f"'{value}' is a reserved alias")
    if "/" in value:
        raise ValueError("Invalid alias format")
    if not AGENT_ALIAS_PATTERN.match(value):
        raise ValueError("Invalid alias format")
    return value


INTERNAL_AUTH_HEADER = "X-AWEB-Auth"
INTERNAL_PROJECT_HEADER = "X-Project-ID"
INTERNAL_USER_HEADER = "X-User-ID"
INTERNAL_API_KEY_ID_HEADER = "X-API-Key"
INTERNAL_ACTOR_ID_HEADER = "X-AWEB-Actor-ID"


def _trust_aweb_proxy_headers() -> bool:
    return os.getenv("AWEB_TRUST_PROXY_HEADERS", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _parse_internal_auth_context(request: Request):
    from .internal_auth import parse_internal_auth_context

    return parse_internal_auth_context(request)


def parse_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth_header[7:]


async def verify_bearer_token(
    db: DatabaseLike,
    token: str,
    *,
    manager_name: str = "aweb",
) -> str:
    key_hash = hash_api_key(token)
    dbm = db.get_manager(manager_name)
    row = await dbm.fetch_one(
        """
        SELECT project_id, is_active
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
    await dbm.execute(
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
    key_hash = hash_api_key(token)
    dbm = db.get_manager(manager_name)
    row = await dbm.fetch_one(
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
    await dbm.execute(
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


async def get_project_from_auth(
    request: Request,
    db: DatabaseLike,
    *,
    manager_name: str = "aweb",
) -> str:
    internal = _parse_internal_auth_context(request) if _trust_aweb_proxy_headers() else None
    if internal is not None:
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
    internal = _parse_internal_auth_context(request) if _trust_aweb_proxy_headers() else None
    if internal is not None:
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


def enforce_actor_binding(
    identity,
    workspace_id: str,
    detail: str = "workspace_id does not match API key identity",
) -> None:
    """Reject requests where the caller's API key identity doesn't match the workspace."""
    if (
        identity.auth_mode == "bearer"
        and identity.agent_id is not None
        and identity.agent_id != workspace_id
    ):
        raise HTTPException(status_code=403, detail=detail)


def validate_workspace_id(workspace_id: str) -> str:
    """Validate workspace_id is a valid UUID string and return normalized format."""
    if workspace_id is None:
        raise ValueError("workspace_id cannot be empty")
    workspace_id = str(workspace_id).strip()
    if not workspace_id:
        raise ValueError("workspace_id cannot be empty")
    try:
        return str(uuid.UUID(workspace_id))
    except ValueError:
        raise ValueError("Invalid workspace_id format")


async def get_workspace_project_id(
    db: DatabaseLike,
    workspace_id: str,
) -> Optional[str]:
    """Return project_id for workspace_id or None if not found."""
    try:
        ws_uuid = uuid.UUID(workspace_id)
    except ValueError:
        return None

    server_db = db.get_manager("server")
    row = await server_db.fetch_one(
        """
        SELECT project_id
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND deleted_at IS NULL
        """,
        ws_uuid,
    )
    if not row:
        return None
    return str(row["project_id"])


async def verify_workspace_access(
    request: Request,
    workspace_id: str,
    db: DatabaseLike,
) -> str:
    """Verify workspace_id belongs to the authenticated project, return project_id."""
    try:
        workspace_id = validate_workspace_id(workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    from .aweb_introspection import get_identity_from_auth

    identity = await get_identity_from_auth(request, db)
    project_id = identity.project_id

    server_db = db.get_manager("server")
    row = await server_db.fetch_one(
        """
        SELECT project_id, deleted_at
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        uuid.UUID(workspace_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if row.get("deleted_at") is not None:
        raise HTTPException(status_code=410, detail="Workspace was deleted")

    ws_project_id = str(row["project_id"])
    if ws_project_id != project_id:
        raise HTTPException(
            status_code=403,
            detail="Workspace not found or does not belong to your project",
        )

    enforce_actor_binding(identity, workspace_id)

    return project_id
