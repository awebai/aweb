from __future__ import annotations

from dataclasses import dataclass

from awid.did import stable_id_from_did_key


IDENTITY_LIFETIMES = ("ephemeral", "persistent")
IDENTITY_CUSTODY_MODES = ("self", "custodial")


@dataclass(frozen=True)
class ResolvedIdentityContract:
    did: str | None
    public_key: str | None
    custody: str
    lifetime: str
    stable_id: str | None

    @property
    def is_ephemeral(self) -> bool:
        return self.lifetime == "ephemeral"

    @property
    def is_persistent(self) -> bool:
        return self.lifetime == "persistent"

    @property
    def can_have_address(self) -> bool:
        return self.is_persistent


def resolve_identity_contract(
    *,
    did: str | None,
    public_key: str | None,
    custody: str | None,
    lifetime: str | None,
    namespace: str | None = None,
) -> ResolvedIdentityContract:
    did = (did or "").strip() or None
    public_key = (public_key or "").strip() or None
    custody = (custody or "").strip() or None
    lifetime = (lifetime or "ephemeral").strip() or "ephemeral"

    if lifetime not in IDENTITY_LIFETIMES:
        raise ValueError("lifetime must be 'persistent' or 'ephemeral'")

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

    if namespace is not None and namespace.strip() and lifetime != "persistent":
        raise ValueError("Only persistent identities may own or publish addresses")

    stable_id = stable_id_from_did_key(did) if did is not None and lifetime == "persistent" else None
    return ResolvedIdentityContract(
        did=did,
        public_key=public_key,
        custody=custody,
        lifetime=lifetime,
        stable_id=stable_id,
    )


def assert_persistent_identity(*, lifetime: str | None) -> None:
    if (lifetime or "").strip() != "persistent":
        raise ValueError("Only persistent identities support this operation")
