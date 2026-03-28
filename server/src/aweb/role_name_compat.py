from __future__ import annotations

from typing import Optional

from .coordination.roles import ROLE_ERROR_MESSAGE, is_valid_role, normalize_role


def normalize_optional_role_name(value: Optional[str]) -> Optional[str]:
    """Validate and normalize a role/role_name selector value."""
    if value is None:
        return None
    if not value.strip():
        return None
    if not is_valid_role(value):
        raise ValueError(ROLE_ERROR_MESSAGE)
    return normalize_role(value)


def resolve_role_name_aliases(*, role: Optional[str], role_name: Optional[str]) -> Optional[str]:
    """Resolve old/new selector aliases into one canonical value."""
    if role is not None and role_name is not None and role != role_name:
        raise ValueError("role and role_name must match when both are provided")
    return role_name if role_name is not None else role
