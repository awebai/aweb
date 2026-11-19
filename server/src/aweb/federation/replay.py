"""Exact signed plaintext projections, separate from current delivery authority."""

from dataclasses import dataclass
from enum import Enum, auto
from aweb.service_errors import ConflictError
from uuid import UUID

from aweb.federation.envelope import FederationEnvelope
from aweb.messaging.kinds import ContentMode, MessageKind


@dataclass(frozen=True, kw_only=True)
class PlaintextProjectionClaim:
    kind: MessageKind
    message_id: UUID
    conversation_id: UUID
    sender_did: str
    signature: str
    signed_payload: str

    @classmethod
    def from_envelope(
        cls, envelope: FederationEnvelope, *, signature: str
    ) -> "PlaintextProjectionClaim":
        """Capture an envelope after its sender signature and bindings are verified."""
        return cls(
            kind=MessageKind(envelope.type),
            message_id=UUID(envelope.message_id),
            conversation_id=UUID(envelope.conversation_id or ""),
            sender_did=envelope.sender_did_aw,
            signature=signature,
            signed_payload=envelope.signed_payload or "",
        )


class PlaintextProjectionState(Enum):
    MISSING = auto()
    EXACT = auto()
    CONFLICT = auto()


@dataclass(frozen=True, kw_only=True)
class PlaintextProjectionLookup:
    state: PlaintextProjectionState
    message: dict | None = None

    def refuse_conflicting_message_id(self) -> None:
        """Refuse a fresh conflicting claim before the remote send can write."""
        if self.state is PlaintextProjectionState.CONFLICT:
            raise ConflictError(
                "message_id already exists for a different signed message. Choose a new message_id and retry."
            )


async def read_plaintext_projection(
    db, *, claim: PlaintextProjectionClaim
) -> PlaintextProjectionLookup:
    """Classify a stored signed plaintext projection; this grants no authority.

    docs/identity-messaging-contract.md:334-365 and Antares69b3a50a allow its
    plaintext age exemption. Callers verify the signature/bindings and current
    authority before this lookup. A changed or missing row supplies no exemption.
    """
    if not isinstance(claim.kind, MessageKind):
        raise TypeError(
            "Select a named MessageKind before reading an outbound projection."
        )
    table, conversation_field = (
        ("messages", "conversation_id")
        if claim.kind is MessageKind.MAIL
        else ("chat_messages", "session_id")
    )
    row = await db.get_manager("aweb").fetch_one(
        "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", claim.message_id
    )
    if row is None:
        return PlaintextProjectionLookup(state=PlaintextProjectionState.MISSING)
    if (
        row["content_mode"] != ContentMode.PLAINTEXT
        or row["from_did"] != claim.sender_did
        or row[conversation_field] != claim.conversation_id
        or not claim.signed_payload
        or not claim.signature
        or row["signed_payload"] != claim.signed_payload
        or row["signature"] != claim.signature
    ):
        return PlaintextProjectionLookup(state=PlaintextProjectionState.CONFLICT)
    return PlaintextProjectionLookup(
        state=PlaintextProjectionState.EXACT, message=dict(row)
    )
