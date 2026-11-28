"""One stored-artifact identity rule for admitted message retries.

This proves a prior accepted artifact, never current sender/recipient authority.
Callers retain signature, binding, admission and encrypted freshness checks.
See Receiver-Wide Replay And Contact Compatibility
(docs/identity-messaging-contract.md:330-366; Antares69b3a50a).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any
from uuid import UUID

from aweb.messaging.kinds import ContentMode, MessageKind
from aweb.service_errors import ConflictError
from awid.federation_errors import FederationAuthorityError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class PlaintextReplayArtifact:
    signature: str | None
    signed_payload: str | None


@dataclass(frozen=True, kw_only=True)
class EncryptedReplayArtifact:
    envelope: Mapping[str, Any]


@dataclass(frozen=True, kw_only=True)
class ChatReplayControls:
    """Persisted chat controls outside the encrypted message envelope."""

    sender_leaving: bool
    hang_on: bool
    reply_to: UUID | None
    timestamp: str | None = None
    signing_did: str | None = None


@dataclass(frozen=True, kw_only=True)
class StoredMessageClaim:
    kind: MessageKind
    message_id: UUID
    sender_did: str
    conversation_id: UUID | None
    artifact: PlaintextReplayArtifact | EncryptedReplayArtifact
    chat_controls: ChatReplayControls | None = None
    chat_participant_dids: frozenset[str] | None = None
    chat_participant_current_keys: Mapping[str, str] | None = None


def replay_artifact(
    *,
    content_mode: str | None,
    encrypted_envelope: Mapping[str, Any] | None,
    signature: str | None,
    signed_payload: str | None,
) -> PlaintextReplayArtifact | EncryptedReplayArtifact:
    """Retain the request's proof using the canonical persisted content shape."""
    if content_mode == ContentMode.ENCRYPTED:
        return EncryptedReplayArtifact(envelope=encrypted_envelope or {})
    return PlaintextReplayArtifact(signature=signature, signed_payload=signed_payload)


def _require_named_claim(claim: StoredMessageClaim) -> None:
    if not isinstance(claim.kind, MessageKind):
        raise TypeError("Select a named MessageKind before reading a stored message.")
    if claim.chat_participant_dids is not None and (
        claim.kind is not MessageKind.CHAT
        or not isinstance(claim.chat_participant_dids, frozenset)
    ):
        raise TypeError("Supply a frozen participant DID set only for a chat retry.")
    if claim.chat_participant_current_keys is not None and (
        claim.chat_participant_dids is None
        or not isinstance(claim.chat_participant_current_keys, Mapping)
    ):
        raise TypeError("Current chat keys require the admitted participant DID set.")
    if claim.chat_controls is not None and (
        claim.kind is not MessageKind.CHAT
        or not isinstance(claim.chat_controls, ChatReplayControls)
    ):
        raise TypeError("Use named ChatReplayControls only for a chat retry.")
    if not isinstance(
        claim.artifact, (PlaintextReplayArtifact, EncryptedReplayArtifact)
    ):
        raise TypeError(
            "Build a named plaintext or encrypted artifact before comparing a stored message."
        )


class StoredMessageState(Enum):
    MISSING = auto()
    EXACT = auto()
    CONFLICT = auto()
    PARTICIPANTS_CHANGED = auto()


class StoredMessageConflict(ConflictError):
    """Only the canonical replay owner refused reuse of an accepted message ID."""


@dataclass(frozen=True, kw_only=True)
class StoredMessageLookup:
    state: StoredMessageState
    message: dict | None = None

    def refuse_conflicting_message_id(self) -> None:
        if self.state is StoredMessageState.PARTICIPANTS_CHANGED:
            raise StoredMessageConflict(
                "The stored chat participants differ from the resolved recipients. Retry the original conversation and recipient identities unchanged."
            )
        if self.state is StoredMessageState.CONFLICT:
            raise StoredMessageConflict(
                "message_id already exists for a different signed message. Retry the original request unchanged; choose a new message_id only if you intend to send a different message."
            )


def _stored_object(value: object) -> Mapping | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            logger.error(
                "stored_message_object_invalid failure_type=%s", type(exc).__name__
            )
            return None
    return value if isinstance(value, Mapping) else None


def stored_message_matches(row: Mapping, *, claim: StoredMessageClaim) -> bool:
    """Match sender, conversation and exact proof; unsigned ID reuse is not a retry.

    The request's body/recipient/flags must already agree with its proof at the
    admission boundary. A generated conversation ID can be absent in a create
    request; any supplied ID must match the stored conversation.
    """
    _require_named_claim(claim)
    conversation_field = (
        "conversation_id" if claim.kind is MessageKind.MAIL else "session_id"
    )
    if (
        row.get("message_id") != claim.message_id
        or row.get("from_did") != claim.sender_did
        or (
            claim.conversation_id is not None
            and row.get(conversation_field) != claim.conversation_id
        )
    ):
        return False
    if claim.chat_controls is not None:
        controls = claim.chat_controls
        if (
            bool(row.get("sender_leaving")) != controls.sender_leaving
            or bool(row.get("hang_on")) != controls.hang_on
            or row.get("reply_to") != controls.reply_to
        ):
            return False
    # wait_seconds changes session wait state, not a stored message field;
    # acknowledging a retry never reapplies that state transition.
    if isinstance(claim.artifact, EncryptedReplayArtifact):
        if claim.chat_controls is not None:
            controls = claim.chat_controls
            sender = claim.artifact.envelope.get("from")
            if (
                controls.timestamp is not None
                and controls.timestamp != claim.artifact.envelope.get("created_at")
            ) or (
                controls.signing_did is not None
                and (
                    not isinstance(sender, Mapping)
                    or controls.signing_did != sender.get("did")
                )
            ):
                return False
        return (
            row.get("content_mode") == ContentMode.ENCRYPTED
            and _stored_object(row.get("encrypted_envelope")) == claim.artifact.envelope
        )
    return (
        row.get("content_mode") == ContentMode.PLAINTEXT
        and bool(claim.artifact.signature)
        and bool(claim.artifact.signed_payload)
        and row.get("signature") == claim.artifact.signature
        and row.get("signed_payload") == claim.artifact.signed_payload
    )


async def read_stored_message(db, *, claim: StoredMessageClaim) -> StoredMessageLookup:
    """Read the kind's canonical table and apply the one stored-artifact rule."""
    _require_named_claim(claim)
    table = "messages" if claim.kind is MessageKind.MAIL else "chat_messages"
    row = await db.get_manager("aweb").fetch_one(
        "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", claim.message_id
    )
    if row is None:
        return StoredMessageLookup(state=StoredMessageState.MISSING)
    if not stored_message_matches(row, claim=claim):
        return StoredMessageLookup(state=StoredMessageState.CONFLICT)
    if claim.chat_participant_dids is not None:
        participants = await db.get_manager("aweb").fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            row["session_id"],
        )
        remaining = set(claim.chat_participant_dids)
        current_keys = claim.chat_participant_current_keys or {}
        for party in participants:
            did = party["did"]
            matches = {
                expected
                for expected in remaining
                if did == expected
                or (did.startswith("did:key:") and current_keys.get(expected) == did)
            }
            if len(matches) != 1:
                return StoredMessageLookup(
                    state=StoredMessageState.PARTICIPANTS_CHANGED
                )
            remaining.remove(matches.pop())
        if remaining:
            return StoredMessageLookup(state=StoredMessageState.PARTICIPANTS_CHANGED)
    return StoredMessageLookup(state=StoredMessageState.EXACT, message=dict(row))


@dataclass(frozen=True, kw_only=True)
class StoredFederationReceipt:
    metadata: dict
    result: dict


def established_federation_receipt(
    row: Mapping | None,
    *,
    envelope_hash: str,
    kind: MessageKind,
) -> StoredFederationReceipt | None:
    """Recognize the exact established outer envelope, never a partial write.

    This proof includes audience/route fields that a native message row does
    not contain. Phase B still checks its canonical metadata under the current
    authority token before returning the established result.
    """
    if not isinstance(kind, MessageKind):
        raise TypeError("Select a named MessageKind before reading an ingress receipt.")
    if row is None:
        return None
    if (
        row.get("legacy_unreplayable")
        or row.get("envelope_hash") != envelope_hash
        or row.get("storage_kind") != kind.value
        or row.get("established_result") is None
    ):
        raise FederationAuthorityError("federation_message_replay_conflict")
    metadata = _stored_object(row.get("canonical_metadata"))
    result = _stored_object(row.get("established_result"))
    if metadata is None or result is None:
        raise FederationAuthorityError("federation_message_replay_conflict")
    return StoredFederationReceipt(metadata=dict(metadata), result=dict(result))
