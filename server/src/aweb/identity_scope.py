from __future__ import annotations


LEGACY_IDENTITY_SCOPE_ALIASES = {
    "persistent": "global",
    "ephemeral": "local",
}


def normalize_identity_scope(value: str | None, *, default: str = "local") -> str:
    scope = (value or default).strip().lower() or default
    scope = LEGACY_IDENTITY_SCOPE_ALIASES.get(scope, scope)
    if scope not in {"global", "local"}:
        raise ValueError("identity_scope must be 'global' or 'local'")
    return scope


def legacy_lifetime_for_scope(identity_scope: str | None) -> str:
    return "persistent" if normalize_identity_scope(identity_scope) == "global" else "ephemeral"
