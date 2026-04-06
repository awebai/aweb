"""Validation helpers for aweb."""

from __future__ import annotations

import re
import uuid


AGENT_ALIAS_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
AGENT_ALIAS_MAX_LENGTH = 64
RESERVED_ALIASES = frozenset({"me"})


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
