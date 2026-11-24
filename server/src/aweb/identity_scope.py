"""Canonical stored and authenticated identity-scope vocabulary."""

from enum import StrEnum


class IdentityScope(StrEnum):
    """Team-local keys and registry-addressed identities (identity.md:65-74)."""

    LOCAL = "local"
    GLOBAL = "global"


_CERTIFICATE_SCOPE_ALIASES = {
    "persistent": IdentityScope.GLOBAL,
    "ephemeral": IdentityScope.LOCAL,
}


def normalize_identity_scope(
    value: str | None, *, default: IdentityScope = IdentityScope.LOCAL
) -> IdentityScope:
    """Keep historical artifact spellings while returning one named scope.

    Signed artifact fields remain covered by their original signature; this
    normalization does not rewrite the artifact or grant team membership.
    """
    if value is not None and not isinstance(value, str):
        raise ValueError("identity_scope must be 'global' or 'local'")
    scope = (value or default).strip().lower() or default
    scope = _CERTIFICATE_SCOPE_ALIASES.get(scope, scope)
    try:
        return IdentityScope(scope)
    except ValueError as exc:
        raise ValueError("identity_scope must be 'global' or 'local'") from exc
