from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aweb.identity_address import AddressResolution
from aweb.identity_scope import IdentityScope, normalize_identity_scope


@dataclass(frozen=True)
class GrantContext:
    """Typed provenance for an identity session grant.

    The grant is the authenticated credential; the enclosing identity/principal
    remains the subject identity the grant acts as.
    """

    grant_id: str
    session_did_key: str
    issuing_certificate_id: str | None
    scopes: tuple[str, ...]
    expires_at: datetime
    never_expires: bool = False


GRANT_SCOPE_ANY = "__any_grant__"

GRANT_SCOPES = (
    "mail.read",
    "mail.send",
    "chat.read",
    "chat.send",
    "events.read",
    "coord.read",
    "coord.write",
    "presence.write",
    "contacts.read",
    "contacts.write",
)


@dataclass(frozen=True)
class TeamIdentity:
    """Authenticated agent identity within a team.

    Certificate verifiers mark admission and retain the checked controller key.
    """

    team_id: str
    alias: str
    did_key: str
    did_aw: str
    address: str
    agent_id: str
    identity_scope: IdentityScope
    certificate_id: str
    grant: GrantContext | None = None
    address_resolution: AddressResolution = field(default_factory=AddressResolution)
    # The verifier's checked key, retained for this credential's stream lifetime.
    verified_team_did_key: str | None = None
    certificate_verified: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "identity_scope", normalize_identity_scope(self.identity_scope)
        )


@dataclass(frozen=True)
class IdentityAuth:
    """Key possession and verified global identity, independent of membership."""

    did_key: str
    did_aw: str | None
    address: str | None
    address_resolution: AddressResolution = field(default_factory=AddressResolution)


@dataclass(frozen=True)
class MessagingAuth:
    """Original messaging principal with separately selected team and grant facts."""

    did_key: str
    did_aw: str | None
    address: str | None
    team_id: str | None = None
    alias: str | None = None
    agent_id: str | None = None
    identity_scope: IdentityScope | None = None
    certificate_id: str | None = None
    verified_team_id: str | None = None
    grant: GrantContext | None = None
    id_chain: dict | None = None
    address_resolution: AddressResolution = field(default_factory=AddressResolution)
    verified_team_did_key: str | None = None
    certificate_verified: bool = False

    def __post_init__(self) -> None:
        if self.identity_scope is not None:
            object.__setattr__(
                self, "identity_scope", normalize_identity_scope(self.identity_scope)
            )


def has_verified_team_certificate(identity: TeamIdentity | MessagingAuth) -> bool:
    """Read credential provenance recorded by the admitting verifier."""
    return getattr(identity, "certificate_verified", False) is True
