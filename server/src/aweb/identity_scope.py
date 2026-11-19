from __future__ import annotations


from enum import StrEnum


class IdentityScope(StrEnum):
    LOCAL = "local"
    GLOBAL = "global"


LEGACY_IDENTITY_SCOPE_ALIASES = {
    "persistent": "global",
    "ephemeral": "local",
}


def normalize_identity_scope(value: str | None, *, default: str = "local") -> IdentityScope:
    scope = (value or default).strip().lower() or default
    scope = LEGACY_IDENTITY_SCOPE_ALIASES.get(scope, scope)
    if scope not in {"global", "local"}:
        raise ValueError("identity_scope must be 'global' or 'local'")
    return IdentityScope(scope)
