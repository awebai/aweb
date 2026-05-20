from __future__ import annotations

from dataclasses import dataclass

from awid.did import stable_id_from_did_key


IDENTITY_SCOPES = ("local", "global")
IDENTITY_CUSTODY_MODES = ("self", "custodial")
_LEGACY_SCOPE_ALIASES = {
    "ephemeral": "local",
    "persistent": "global",
}


def normalize_identity_scope(value: str | None) -> str:
    """Normalize current scope names and stale lifetime aliases."""
    scope = (value or "local").strip().lower() or "local"
    scope = _LEGACY_SCOPE_ALIASES.get(scope, scope)
    if scope not in IDENTITY_SCOPES:
        raise ValueError("identity_scope must be 'global' or 'local'")
    return scope


@dataclass(frozen=True)
class ResolvedIdentityContract:
    did: str | None
    public_key: str | None
    custody: str
    identity_scope: str
    stable_id: str | None

    @property
    def is_local(self) -> bool:
        return self.identity_scope == "local"

    @property
    def is_global(self) -> bool:
        return self.identity_scope == "global"

    @property
    def can_have_address(self) -> bool:
        return self.is_global

    @property
    def lifetime(self) -> str:
        """Deprecated compatibility alias for older callers."""
        return "persistent" if self.is_global else "ephemeral"

    @property
    def is_ephemeral(self) -> bool:
        """Deprecated compatibility alias for older callers."""
        return self.is_local

    @property
    def is_persistent(self) -> bool:
        """Deprecated compatibility alias for older callers."""
        return self.is_global


def resolve_identity_contract(
    *,
    did: str | None,
    public_key: str | None,
    custody: str | None,
    identity_scope: str | None = None,
    lifetime: str | None = None,
    namespace: str | None = None,
) -> ResolvedIdentityContract:
    did = (did or "").strip() or None
    public_key = (public_key or "").strip() or None
    custody = (custody or "").strip() or None
    scope = normalize_identity_scope(identity_scope if identity_scope is not None else lifetime)

    if (did is None) != (public_key is None):
        raise ValueError("did and public_key must be provided together")

    if custody is None:
        custody = "self" if (did is not None or public_key is not None) else "custodial"

    if custody not in IDENTITY_CUSTODY_MODES:
        raise ValueError("custody must be 'self' or 'custodial'")

    if custody == "self" and (did is None or public_key is None):
        raise ValueError("Self-custodial identities require both did and public_key")
    if custody == "custodial" and (did is not None or public_key is not None):
        raise ValueError("Custodial identities must not provide did/public_key")

    if namespace is not None and namespace.strip() and scope != "global":
        raise ValueError("Only global identities may own or publish addresses")

    stable_id = stable_id_from_did_key(did) if did is not None and scope == "global" else None
    return ResolvedIdentityContract(
        did=did,
        public_key=public_key,
        custody=custody,
        identity_scope=scope,
        stable_id=stable_id,
    )


def assert_global_identity(*, identity_scope: str | None = None, lifetime: str | None = None) -> None:
    if normalize_identity_scope(identity_scope if identity_scope is not None else lifetime) != "global":
        raise ValueError("Only global identities support this operation")


def assert_persistent_identity(*, lifetime: str | None = None, identity_scope: str | None = None) -> None:
    """Deprecated compatibility wrapper for older callers."""
    assert_global_identity(identity_scope=identity_scope, lifetime=lifetime)
