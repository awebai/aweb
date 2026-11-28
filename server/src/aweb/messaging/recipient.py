"""The identity and route a send resolved, distinct from actor authorization."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, fields, replace
from datetime import datetime
from enum import Enum, auto
from typing import Any
from uuid import UUID

from aweb.member_team_key import MemberProjection, messaging_identity_projection


class RecipientResidence(Enum):
    LOCAL = auto()
    REMOTE = auto()


@dataclass(frozen=True, kw_only=True)
class Recipient(Mapping[str, Any]):
    """An already-resolved delivery projection, never evidence of membership.

    Continuations (docs/identity-messaging-contract.md:274-310) keeps stored participation and
    independently validated residence separate from team authority. A local
    identity can have neither an agent nor a team. Only the resolver chooses
    residence; absent actor IDs do not imply federation.

    Mapping access preserves existing adapter reads during their conversion to
    these named fields. It adds no input validation or identity verification.
    """

    residence: RecipientResidence
    agent_id: UUID | str | None = None
    team_id: str | None = None
    alias: str | None = None
    address: str | None = None
    did_aw: str | None = None
    did_key: str | None = None
    identity_scope: str | None = None
    has_global_claim: bool = False
    policy_did_aw: str | None = None
    inbound_mode: str | None = None
    agent_type: str | None = None
    human_verified_key: str | None = None
    status: str | None = None
    deleted_at: datetime | None = None
    delivery_origin: str | None = None
    authority_controller_did: str = ""
    requires_local_address_authority: bool = False
    authority_route_current: bool = False
    session_id: str | None = None
    conversation_id: str | None = None
    did: str | None = None
    current_did_key: str | None = None
    local_resolved: bool = False
    policy_recipients: tuple[Recipient, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.residence, RecipientResidence):
            raise TypeError("Recipient residence requires a named RecipientResidence")
        object.__setattr__(
            self,
            "policy_recipients",
            tuple(
                item
                if isinstance(item, Recipient)
                else Recipient.from_local_projection(item)
                for item in self.policy_recipients
            ),
        )

    @classmethod
    def from_delivery_projection(cls, row: Mapping[str, Any]) -> Recipient:
        """Capture a resolver's explicit residence flag, never infer it from IDs."""
        if isinstance(row, cls):
            return row
        return (
            cls.from_remote_projection(row)
            if row.get("external")
            else cls.from_local_projection(row)
        )

    @classmethod
    def from_member_projection(cls, member: MemberProjection) -> Recipient:
        """Consume R2's verified projection; retain raw claims only for policy."""
        return cls.from_local_projection(messaging_identity_projection(member))

    @classmethod
    def from_local_projection(cls, row: Mapping[str, Any]) -> Recipient:
        """Capture already-attributed native facts without selecting membership."""
        return cls._from_projection(row, residence=RecipientResidence.LOCAL)

    @classmethod
    def from_remote_projection(cls, row: Mapping[str, Any]) -> Recipient:
        """Capture an admitted or stored remote route, without granting an actor."""
        return cls._from_projection(row, residence=RecipientResidence.REMOTE)

    @classmethod
    def _from_projection(
        cls, row: Mapping[str, Any], *, residence: RecipientResidence
    ) -> Recipient:
        names = {field.name for field in fields(cls)} - {
            "residence",
            "policy_recipients",
            "authority_route_current",
        }
        values = {name: row[name] for name in names if name in row}
        values.setdefault("policy_did_aw", row.get("did_aw"))
        policies = tuple(
            item if isinstance(item, cls) else cls.from_local_projection(item)
            for item in row.get("_policy_recipients") or ()
        )
        return cls(
            residence=residence,
            authority_route_current=row.get("_authority_route_current", False),
            policy_recipients=policies,
            **values,
        )

    def as_identity(self, *, address: str | None = None) -> Recipient:
        """Clear membership references while retaining the admitted identity."""
        projected = replace(
            self, agent_id=None, team_id=None if self.did_aw else self.team_id
        )
        if address is None:
            return projected
        return replace(
            projected,
            address=address or None,
            alias=address.split("/", 1)[-1] if address else self.did_aw or self.did_key,
        )

    def with_local_identity(self, resident: Recipient) -> Recipient:
        """Use validated residence while retaining the stored participant route."""
        return replace(
            self,
            residence=RecipientResidence.LOCAL,
            agent_id=resident.agent_id,
            team_id=resident.team_id,
            alias=resident.alias,
            address=resident.address,
            did_aw=resident.did_aw,
            did_key=resident.did_key,
            identity_scope=resident.identity_scope,
            has_global_claim=resident.has_global_claim,
            policy_did_aw=resident.policy_did_aw,
            inbound_mode=resident.inbound_mode,
            status=resident.status,
            deleted_at=resident.deleted_at,
            delivery_origin=None,
            current_did_key=resident.did_key,
        )

    def __getitem__(self, key: str) -> Any:
        if key == "external":
            return self.residence is RecipientResidence.REMOTE
        if key == "_authority_route_current":
            return self.authority_route_current
        if key == "_policy_recipients":
            return self.policy_recipients
        if key not in _RECIPIENT_FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(_RECIPIENT_FIELDS)

    def __len__(self) -> int:
        return len(_RECIPIENT_FIELDS)


_RECIPIENT_FIELDS = tuple(
    field.name
    for field in fields(Recipient)
    if field.name not in {"residence", "authority_route_current", "policy_recipients"}
) + ("external", "_authority_route_current", "_policy_recipients")
