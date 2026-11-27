"""Validation helpers for aweb."""

from __future__ import annotations

import uuid


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
