"""Exact signed plaintext projections, separate from current delivery authority."""

from dataclasses import dataclass
from uuid import UUID

from aweb.federation.envelope import FederationEnvelope
from aweb.messaging.kinds import MessageKind
from aweb.messaging.message_replay import (
    StoredMessageClaim,
    StoredMessageState,
    StoredMessageLookup,
    PlaintextReplayArtifact,
    read_stored_message,
)


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


# Existing consumer ports retain the canonical result/enum identities.
PlaintextProjectionState = StoredMessageState
PlaintextProjectionLookup = StoredMessageLookup


async def read_plaintext_projection(
    db, *, claim: PlaintextProjectionClaim
) -> PlaintextProjectionLookup:
    """Read an outbound plaintext artifact using the common stored-message rule."""
    return await read_stored_message(
        db,
        claim=StoredMessageClaim(
            kind=claim.kind,
            message_id=claim.message_id,
            sender_did=claim.sender_did,
            conversation_id=claim.conversation_id,
            artifact=PlaintextReplayArtifact(
                signature=claim.signature,
                signed_payload=claim.signed_payload,
            ),
        ),
    )
