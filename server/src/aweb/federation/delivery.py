"""Atomic Phase-B delivery for verified federation envelopes."""

from __future__ import annotations


from aweb.human_kind import IdentityKind, is_verified_human
from aweb.member_team_key import (
    MemberProjection,
    member_projection_columns_sql,
    messaging_identity_projection,
)
from collections.abc import Mapping

from aweb.messaging.kinds import ContentMode, MessagePriority
from aweb.messaging.chat_storage import store_chat
from aweb.messaging.message_replay import established_federation_receipt
from aweb.messaging.mail_storage import (
    store_mail,
    MailStorageInput,
    MailIdAvailability,
    MailSender,
    MailRecipient,
    MailAttestation,
    PlaintextMailContent,
    EncryptedMailContent,
)

from aweb.db import TransactionInfra
from aweb.federation.errors import FederationPolicyRefused
from aweb.messaging.delivery_policy import (
    DeliveryAttempt,
    DeliveryPolicyRefused,
    DeliverySender,
    authorize_delivery,
)

from aweb.agent_wake import record_did_wakes
from aweb.messaging.chat_policy import HumanChatRefused, recipient_label

import hashlib
import json
import logging

import asyncpg
from fastapi import HTTPException
from aweb.application_state import RegistryClientUnavailable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable
from uuid import UUID

from awid.e2ee_keys import validate_encryption_key_assertion
from awid.federation_errors import FederationAuthorityError
from pgdbm.errors import AsyncDBError
from awid.signing import canonical_json_bytes

from aweb.inbound_modes import effective_inbound_mode
from aweb.service_errors import ForbiddenError
from aweb.e2ee_messages import encrypted_message_storage_metadata
from aweb.federation.authority_state import AuthoritySecurityToken
from aweb.federation.envelope import FederationEnvelope
from aweb.message_events import FederatedMessageSentContext
from aweb.hooks import MutationDeliveryOutcome
from aweb.messaging.kinds import MessageKind

BeforeCommit = Callable[[], Awaitable[None]]

logger = logging.getLogger(__name__)


def federation_envelope_hash(envelope: FederationEnvelope, signature: str) -> str:
    """Hash the signed envelope and signature, excluding adjacent membership and lookup proofs."""
    payload = envelope.model_dump(
        mode="json",
        exclude_none=True,
        exclude={
            "sender_active_team_id",
            "sender_team_certificate",
            "target_address_lookup_authorization",
            "target_address_lookup_timestamp",
        },
    )
    payload["preserved_signature"] = signature
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _metadata(envelope: FederationEnvelope) -> dict[str, object]:
    return {
        "kind": envelope.type,
        "sender_did_aw": envelope.sender_did_aw,
        "sender_current_did_key": envelope.sender_current_did_key,
        "sender_address": envelope.sender_address,
        "sender_delivery_origin": envelope.sender_delivery_origin,
        "target_did_aw": envelope.target_did_aw,
        "target_current_did_key": envelope.target_current_did_key,
        "target_address": envelope.target_address,
        "target_delivery_origin": envelope.target_delivery_origin,
        "conversation_id": envelope.conversation_id,
        "content_mode": envelope.content_mode or ContentMode.PLAINTEXT,
    }


def _decode_json(value):
    if isinstance(value, str):
        return json.loads(value)
    return value


async def _require_phase_a(
    tx,
    envelope: FederationEnvelope,
    token: AuthoritySecurityToken | None,
) -> str | None:
    if envelope.sender_did_aw.startswith("did:key:"):
        if envelope.sender_current_did_key != envelope.sender_did_aw:
            raise FederationAuthorityError("local_sender_route_mismatch")
        return None
    if token is None:
        raise FederationAuthorityError("federation_authority_cas_conflict")
    row = await tx.fetch_one(
        """
        SELECT c.controller_did
        FROM {{tables.federation_address_authority_cohorts}} c
        JOIN {{tables.federation_did_checkpoints}} d
          ON d.did_aw = c.bound_did_aw
         AND d.revision = c.checkpoint_revision
         AND d.seq = c.checkpoint_seq
         AND d.entry_hash = c.checkpoint_entry_hash
         AND d.current_did_key = c.bound_current_did_key
        WHERE c.canonical_address = $1
          AND c.bound_did_aw = $2
          AND c.bound_current_did_key = $3
          AND c.authoritative_delivery_origin = $4
          AND c.checkpoint_revision = $5
          AND c.generation = $6
          AND c.expires_at > clock_timestamp()
        FOR UPDATE OF c, d
        """,
        envelope.sender_address,
        envelope.sender_did_aw,
        envelope.sender_current_did_key,
        envelope.sender_delivery_origin,
        token.checkpoint_revision,
        token.cohort_generation,
    )
    if row is None:
        raise FederationAuthorityError("federation_authority_cas_conflict")
    return str(row["controller_did"])


def _route_value(value: object) -> str:
    return str(value or "").strip()


async def _require_current_stored_route(
    tx,
    *,
    envelope: FederationEnvelope,
    expected: dict,
) -> UUID | None:
    conversation_id = UUID(str(envelope.conversation_id))
    conversation = await tx.fetch_one(
        """
        SELECT conversation_type, status
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        FOR UPDATE
        """,
        conversation_id,
    )
    if (
        conversation is None
        or conversation["conversation_type"] != envelope.type
        or conversation["status"] != "active"
    ):
        raise FederationAuthorityError("federation_conversation_invalid")
    rows = await tx.fetch_all(
        """
        SELECT did, address, delivery_origin, current_did_key, transport_hint, agent_id
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = ANY($2::text[])
        ORDER BY did
        FOR UPDATE
        """,
        conversation_id,
        [envelope.sender_did_aw, envelope.target_did_aw],
    )
    participants = {row["did"]: dict(row) for row in rows}
    expected_conversation = expected.get("conversation") or {}
    if set(participants) != {envelope.sender_did_aw, envelope.target_did_aw} or set(
        expected_conversation
    ) != set(participants):
        raise FederationAuthorityError("federation_conversation_invalid")

    def require_participants(
        current: dict[str, dict],
        expected_participants: dict[str, dict],
        *,
        include_transport_hint: bool,
    ) -> None:
        route_fields = ["address", "delivery_origin", "current_did_key"]
        if include_transport_hint:
            route_fields.append("transport_hint")
        for did in (envelope.sender_did_aw, envelope.target_did_aw):
            if any(
                _route_value(current[did].get(field))
                != _route_value(expected_participants[did].get(field))
                for field in route_fields
            ):
                raise FederationAuthorityError("federation_conversation_invalid")
        sender = expected_participants[envelope.sender_did_aw]
        target = expected_participants[envelope.target_did_aw]
        if (
            _route_value(sender.get("address")) != _route_value(envelope.sender_address)
            or _route_value(sender.get("delivery_origin"))
            != _route_value(envelope.sender_delivery_origin)
            or _route_value(target.get("address")) != envelope.target_address
        ):
            raise FederationAuthorityError("federation_conversation_invalid")
        sender_key = _route_value(sender.get("current_did_key"))
        target_key = _route_value(target.get("current_did_key"))
        if (envelope.sender_did_aw.startswith("did:aw:") and not sender_key) or (
            sender_key and sender_key != envelope.sender_current_did_key
        ):
            raise FederationAuthorityError("federation_conversation_invalid")
        if (envelope.target_did_aw.startswith("did:aw:") and not target_key) or (
            target_key and target_key != envelope.target_current_did_key
        ):
            raise FederationAuthorityError("federation_conversation_invalid")
        if _route_value(target.get("delivery_origin")):
            raise FederationAuthorityError("federation_conversation_invalid")
        if include_transport_hint and (
            _route_value(sender.get("transport_hint"))
            != "federation:" + _route_value(envelope.sender_delivery_origin)
            or _route_value(target.get("transport_hint")) != "local"
        ):
            raise FederationAuthorityError("federation_conversation_invalid")

    require_participants(
        participants,
        expected_conversation,
        include_transport_hint=True,
    )
    stored_agent_id = participants[envelope.target_did_aw].get("agent_id")
    storage_reference = UUID(str(stored_agent_id)) if stored_agent_id is not None else None
    if envelope.type != "chat":
        return storage_reference
    session = await tx.fetch_one(
        "SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id = $1 FOR UPDATE",
        conversation_id,
    )
    if session is None:
        raise FederationAuthorityError("federation_conversation_invalid")
    chat_rows = await tx.fetch_all(
        """
        SELECT did, address, delivery_origin, current_did_key
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = ANY($2::text[])
        ORDER BY did
        FOR UPDATE
        """,
        conversation_id,
        [envelope.sender_did_aw, envelope.target_did_aw],
    )
    chat_participants = {row["did"]: dict(row) for row in chat_rows}
    expected_chat = expected.get("chat") or {}
    if set(chat_participants) != {
        envelope.sender_did_aw,
        envelope.target_did_aw,
    } or set(expected_chat) != set(chat_participants):
        raise FederationAuthorityError("federation_conversation_invalid")
    require_participants(
        chat_participants,
        expected_chat,
        include_transport_hint=False,
    )

    return storage_reference


@dataclass(frozen=True, kw_only=True)
class _LockedRecipientResidence:
    """Transaction-local storage references, separate from participant authority."""

    recipient: dict
    storage_agent_ids: tuple[UUID, ...]
    residences: tuple[MemberProjection, ...]


async def _lock_current_recipient(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: Mapping,
) -> _LockedRecipientResidence:
    """Lock exact-DID residence without selecting a membership as its authority.

    Continuations (docs/identity-messaging-contract.md:313-318) makes independently verified
    address residence independent of current membership and binding markers.
    Row IDs locate storage and notification attribution only. They grant no
    same-team admission; that remains the current-member policy owner's rule.
    """
    target_did = envelope.target_did_aw
    target_key = envelope.target_current_did_key
    global_did = target_did if target_did.startswith("did:aw:") else None
    if global_did:
        if recipient.get("did_aw") != global_did:
            raise FederationAuthorityError("recipient_identity_not_found")
        if recipient.get("did_key") != target_key:
            raise FederationAuthorityError("recipient_current_key_mismatch")
    elif target_did != target_key:
        raise FederationAuthorityError("recipient_current_key_mismatch")
    else:
        # A key-addressed stored participant may still carry global policy.
        # Discover that policy before taking row locks, then recheck the claim
        # under the lock; raw claims supply no principal identity here.
        claims = await tx.fetch_all(
            "SELECT DISTINCT did_aw FROM {{tables.agents}} "
            "WHERE did_key=$1 AND deleted_at IS NULL AND NULLIF(did_aw, '') IS NOT NULL",
            target_key,
        )
        if len(claims) > 1:
            raise FederationAuthorityError("recipient_policy_rejected")
        global_did = claims[0]["did_aw"] if claims else None

    identity_mode = None
    if global_did:
        try:
            # Lock every policy-bearing row in the existing stable order.
            # SHARE avoids upgrades between deliveries to the same identity.
            identity_mode = await effective_inbound_mode(tx, global_did, for_share=True)
        except ForbiddenError as exc:
            raise FederationAuthorityError("recipient_policy_rejected") from exc

    selector = "a.did_aw" if target_did.startswith("did:aw:") else "a.did_key"
    rows = await tx.fetch_all(
        "SELECT " + member_projection_columns_sql("a") + " FROM {{tables.agents}} a "
        f"WHERE {selector}=$1 AND a.deleted_at IS NULL ORDER BY a.agent_id FOR SHARE OF a",
        target_did,
    )
    residences = tuple(MemberProjection.from_row(row) for row in rows)
    if not residences:
        raise FederationAuthorityError("recipient_identity_not_found")
    if not target_did.startswith("did:aw:"):
        if {row["did_aw"] for row in residences if row["did_aw"]} != (
            {global_did} if global_did else set()
        ):
            raise FederationAuthorityError("recipient_identity_not_found")

    current = _resident_participant(
        residences=residences,
        envelope=envelope,
        recipient=recipient,
        policy_did=global_did,
    )
    if identity_mode is not None:
        current["inbound_mode"] = identity_mode
    return _LockedRecipientResidence(
        recipient=current,
        storage_agent_ids=tuple(row["agent_id"] for row in residences),
        residences=residences,
    )


def _resident_participant(
    *,
    residences: tuple[MemberProjection, ...],
    envelope: FederationEnvelope,
    recipient: Mapping,
    policy_did: str | None,
) -> dict:
    """Keep verified target identity and explicit references separate from rows.

    Continuations (docs/identity-messaging-contract.md:301-316) assigns key
    authority to the resolved address. A unique known residence retains its
    storage/event attribution, never a membership or newest-row authority.
    """
    current = dict(recipient)
    current.update(agent_id=None, team_id=None, did_key=envelope.target_current_did_key)
    if envelope.target_did_aw.startswith("did:aw:"):
        current.update(
            did_aw=envelope.target_did_aw,
            policy_did_aw=envelope.target_did_aw,
            has_global_claim=True,
        )
    else:
        projections = [messaging_identity_projection(row) for row in residences]
        identities = {row.get("did_aw") for row in projections}
        current["did_aw"] = identities.pop() if len(identities) == 1 else None
        current["policy_did_aw"] = policy_did
        current["has_global_claim"] = policy_did is not None
        modes = {row["inbound_mode"] for row in residences}
        if len(modes) != 1 and not current["has_global_claim"]:
            raise FederationAuthorityError("recipient_policy_rejected")
        current["inbound_mode"] = modes.pop() if len(modes) == 1 else None
        scopes = {row["identity_scope"] for row in residences}
        current["identity_scope"] = scopes.pop() if len(scopes) == 1 else None

    # A marker for an old signing key cannot classify the current identity.
    humans = [
        row
        for row in residences
        if row["did_key"] == envelope.target_current_did_key and is_verified_human(row)
    ]
    current["agent_type"] = IdentityKind.HUMAN.value if humans else IdentityKind.UNKNOWN.value
    current["human_verified_key"] = envelope.target_current_did_key if humans else None
    reference = recipient.get("agent_id")
    attributed = next((row for row in residences if str(row["agent_id"]) == str(reference)), None)
    if attributed is None and reference is None and len(residences) == 1:
        attributed = residences[0]
    if attributed is not None:
        current.update(
            agent_id=attributed["agent_id"],
            team_id=attributed["team_id"],
            alias=attributed["alias"],
        )
    return current


async def _require_recipient_encryption_assertion(
    tx,
    *,
    envelope: FederationEnvelope,
    storage_agent_ids: tuple[UUID, ...],
) -> None:
    """Validate identity-signed keys in locked residence storage.

    A storage row ID confers no participant authority.
    """
    if envelope.content_mode != ContentMode.ENCRYPTED:
        return
    encrypted = envelope.encrypted_envelope or {}
    expected_did = envelope.target_current_did_key
    recipient_ref = next(
        (
            item
            for item in encrypted.get("recipients") or []
            if isinstance(item, dict) and item.get("did") == expected_did
        ),
        None,
    )
    key_id = str((recipient_ref or {}).get("encryption_key_id") or "").strip()
    if not key_id:
        raise FederationAuthorityError("recipient_encryption_assertion_missing")
    rows = await tx.fetch_all(
        """
        SELECT assertion_canonical, assertion_signature
        FROM {{tables.agent_encryption_keys}}
        WHERE agent_id = ANY($1::uuid[]) AND encryption_key_id = $2
          AND revoked_at IS NULL
        ORDER BY agent_id
        FOR UPDATE
        """,
        list(storage_agent_ids),
        key_id,
    )
    if not rows:
        raise FederationAuthorityError("recipient_encryption_assertion_missing")
    invalid_assertion = None
    for row in rows:
        try:
            assertion = json.loads(row["assertion_canonical"])
            if not isinstance(assertion, dict):
                raise ValueError("assertion must be an object")
            if assertion.get("encryption_key_id") != key_id:
                raise ValueError("assertion must bind the addressed encryption key")
            assertion["signature"] = row["assertion_signature"]
            validate_encryption_key_assertion(
                assertion,
                current_did_key=expected_did,
                stable_id=(
                    envelope.target_did_aw if envelope.target_did_aw.startswith("did:aw:") else None
                ),
                now=datetime.now(timezone.utc),
            )
        except (TypeError, ValueError) as exc:
            logger.warning("Resident encryption assertion is invalid or stale", exc_info=True)
            invalid_assertion = exc
        else:
            return
    raise FederationAuthorityError(
        "recipient_encryption_assertion_invalid_or_stale"
    ) from invalid_assertion


async def _authorize_policy(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: Mapping,
    stored_route_continuation: bool,
    registry_client,
) -> None:
    try:
        await authorize_delivery(
            TransactionInfra(None, tx),
            recipient=recipient,
            registry_client=registry_client,
            sender=DeliverySender(
                did=envelope.sender_did_aw,
                address=envelope.sender_address,
                verified_dids=(envelope.sender_did_aw, envelope.sender_current_did_key),
            ),
            attempt=DeliveryAttempt.STORED_ROUTE
            if stored_route_continuation
            else DeliveryAttempt.FIRST_CONTACT,
        )
    except DeliveryPolicyRefused as exc:
        raise FederationPolicyRefused(exc) from exc
    except (HTTPException, RegistryClientUnavailable) as exc:
        raise FederationAuthorityError("federation_authority_coordination_unavailable") from exc


async def _ensure_sender_contact(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: Mapping,
    controller_did: str | None,
) -> None:
    owner_did = str(recipient.get("did_aw") or "").strip()
    if (
        not owner_did.startswith("did:aw:")
        or not envelope.sender_did_aw.startswith("did:aw:")
        or not controller_did
    ):
        return
    await tx.execute(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at,
            label, reference_type, status
        ) VALUES (
            $1, $2, $3, $4, clock_timestamp(), $5, 'identity', 'active'
        )
        ON CONFLICT (owner_did, contact_address) DO NOTHING
        """,
        owner_did,
        envelope.sender_address,
        envelope.sender_did_aw,
        controller_did,
        envelope.sender_address.split("/", 1)[-1],
    )


async def _ensure_mail_conversation(
    tx,
    envelope: FederationEnvelope,
    recipient: Mapping,
    *,
    preserve_existing_route: bool,
) -> None:
    conversation_id = UUID(str(envelope.conversation_id))
    existing = await tx.fetch_one(
        """
        SELECT conversation_type, status
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        FOR UPDATE
        """,
        conversation_id,
    )
    if existing is None:
        if envelope.target_did_aw.startswith("did:key:"):
            raise FederationAuthorityError("local_recipient_route_missing")
        await tx.execute(
            """
            INSERT INTO {{tables.conversations}} (
                conversation_id, conversation_type, team_id, created_by_did,
                created_at, updated_at, expires_at
            ) VALUES ($1, 'mail', $2, $3, clock_timestamp(), clock_timestamp(),
                      clock_timestamp() + INTERVAL '30 days')
            """,
            conversation_id,
            recipient.get("team_id"),
            envelope.sender_did_aw,
        )
    elif existing["conversation_type"] != "mail" or existing["status"] != "active":
        raise FederationAuthorityError("federation_conversation_invalid")
    await _upsert_conversation_participants(
        tx,
        envelope,
        recipient,
        conversation_id,
        preserve_existing_route=preserve_existing_route,
    )


async def _ensure_chat_session(
    tx,
    envelope: FederationEnvelope,
    recipient: Mapping,
    *,
    preserve_existing_route: bool,
) -> None:
    session_id = UUID(str(envelope.conversation_id))
    existing = await tx.fetch_one(
        """
        SELECT c.conversation_type, c.status,
               EXISTS (SELECT 1 FROM {{tables.chat_sessions}} s WHERE s.session_id = c.conversation_id) AS has_session
        FROM {{tables.conversations}} c
        WHERE c.conversation_id = $1
        FOR UPDATE
        """,
        session_id,
    )
    if existing is None:
        if envelope.target_did_aw.startswith("did:key:"):
            raise FederationAuthorityError("local_recipient_route_missing")
        await tx.execute(
            """
            INSERT INTO {{tables.conversations}} (
                conversation_id, conversation_type, team_id, created_by_did,
                created_at, updated_at, expires_at
            ) VALUES ($1, 'chat', $2, $3, clock_timestamp(), clock_timestamp(),
                      clock_timestamp() + INTERVAL '30 days')
            """,
            session_id,
            recipient.get("team_id"),
            envelope.sender_did_aw,
        )
        await tx.execute(
            "INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by) VALUES ($1, $2, $3)",
            session_id,
            recipient.get("team_id"),
            envelope.sender_did_aw,
        )
    elif (
        existing["conversation_type"] != "chat"
        or existing["status"] != "active"
        or not existing["has_session"]
    ):
        raise FederationAuthorityError("federation_conversation_invalid")
    await _upsert_conversation_participants(
        tx,
        envelope,
        recipient,
        session_id,
        preserve_existing_route=preserve_existing_route,
    )
    for did, agent_id, alias, address, origin, current_key in _participants(envelope, recipient):
        await tx.execute(
            """
            INSERT INTO {{tables.chat_participants}} (
                session_id, did, agent_id, alias, address, delivery_origin, current_did_key
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (session_id, did) DO UPDATE SET
                agent_id = CASE WHEN $8 THEN COALESCE({{tables.chat_participants}}.agent_id, EXCLUDED.agent_id) ELSE EXCLUDED.agent_id END,
                alias = EXCLUDED.alias,
                address = CASE WHEN $8 THEN {{tables.chat_participants}}.address ELSE EXCLUDED.address END,
                delivery_origin = CASE WHEN $8 THEN {{tables.chat_participants}}.delivery_origin ELSE EXCLUDED.delivery_origin END,
                current_did_key = CASE WHEN $8 THEN COALESCE({{tables.chat_participants}}.current_did_key, EXCLUDED.current_did_key) ELSE EXCLUDED.current_did_key END
            """,
            session_id,
            did,
            agent_id,
            alias,
            address,
            origin,
            current_key,
            preserve_existing_route,
        )


def _participants(envelope: FederationEnvelope, recipient: Mapping):
    sender_alias = (envelope.sender_address or envelope.sender_did_aw).split("/", 1)[-1]
    target_alias = str(recipient.get("alias") or envelope.target_address.split("/", 1)[-1])
    return (
        (
            envelope.sender_did_aw,
            None,
            sender_alias,
            envelope.sender_address,
            envelope.sender_delivery_origin,
            envelope.sender_current_did_key,
        ),
        (
            envelope.target_did_aw,
            recipient.get("agent_id"),
            target_alias,
            envelope.target_address,
            None,
            envelope.target_current_did_key,
        ),
    )


async def _upsert_conversation_participants(
    tx,
    envelope: FederationEnvelope,
    recipient: Mapping,
    conversation_id: UUID,
    *,
    preserve_existing_route: bool,
) -> None:
    for index, (did, agent_id, alias, address, origin, current_key) in enumerate(
        _participants(envelope, recipient)
    ):
        await tx.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (
                conversation_id, did, agent_id, alias, address, delivery_origin,
                current_did_key, transport_hint, role
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (conversation_id, did) DO UPDATE SET
                agent_id = CASE WHEN $10 THEN COALESCE({{tables.conversation_participants}}.agent_id, EXCLUDED.agent_id) ELSE EXCLUDED.agent_id END,
                alias = EXCLUDED.alias,
                address = CASE WHEN $10 THEN {{tables.conversation_participants}}.address ELSE EXCLUDED.address END,
                delivery_origin = CASE WHEN $10 THEN {{tables.conversation_participants}}.delivery_origin ELSE EXCLUDED.delivery_origin END,
                current_did_key = CASE WHEN $10 THEN COALESCE({{tables.conversation_participants}}.current_did_key, EXCLUDED.current_did_key) ELSE EXCLUDED.current_did_key END,
                transport_hint = CASE WHEN $10 THEN {{tables.conversation_participants}}.transport_hint ELSE EXCLUDED.transport_hint END
            """,
            conversation_id,
            did,
            agent_id,
            alias,
            address,
            origin,
            current_key,
            "federation:" + origin if origin else "local",
            "initiator" if index == 0 else "participant",
            preserve_existing_route,
        )
    count = await tx.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1 AND did = ANY($2::text[])
        """,
        conversation_id,
        [envelope.sender_did_aw, envelope.target_did_aw],
    )
    if count != 2:
        raise FederationAuthorityError("federation_conversation_invalid")


async def _store_mail(
    db,
    *,
    envelope: FederationEnvelope,
    signature: str,
    recipient: Mapping,
    id_chain: dict | None,
    recipient_storage_agent_id: UUID | str | None,
):
    """Project an admitted inbound envelope through the canonical mail writer."""
    encrypted = envelope.content_mode == ContentMode.ENCRYPTED
    content = (
        EncryptedMailContent(
            envelope=envelope.encrypted_envelope or {},
            metadata=encrypted_message_storage_metadata(envelope.encrypted_envelope or {}),
        )
        if encrypted
        else PlaintextMailContent(subject=envelope.subject or "", body=envelope.body)
    )
    stored = await store_mail(
        db,
        message=MailStorageInput(
            local_team_id=recipient.get("team_id"),
            sender=MailSender(
                did=envelope.sender_did_aw,
                alias=(envelope.sender_address or envelope.sender_did_aw).split("/", 1)[-1],
                address=envelope.sender_address,
            ),
            recipient=MailRecipient(
                did=envelope.target_did_aw,
                alias=recipient.get("alias") or envelope.target_address.split("/", 1)[-1],
                agent_id=str(recipient_storage_agent_id)
                if recipient_storage_agent_id is not None
                else None,
            ),
            content=content,
            attestation=MailAttestation(
                signature=None if encrypted else signature,
                signed_payload=None if encrypted else envelope.signed_payload,
                id_chain=id_chain,
            ),
            priority=envelope.priority or MessagePriority.NORMAL,
            message_id=UUID(envelope.message_id),
            conversation_id=envelope.conversation_id,
            # Phase B has locked/claimed the UUID receipt. Migration015's
            # insert trigger couples every prior native row to a receipt, so
            # any existing message was already refused/answered at that check.
            id_availability=MailIdAvailability.CONFIRMED_UNUSED,
        ),
    )
    await db.get_manager("aweb").execute(
        "UPDATE {{tables.conversations}} SET updated_at = clock_timestamp() WHERE conversation_id = $1",
        UUID(str(envelope.conversation_id)),
    )
    return {"message_id": stored.message_id, "created_at": stored.created_at}


async def _store_chat(
    db,
    *,
    envelope: FederationEnvelope,
    signature: str,
    id_chain: dict | None,
):
    """Use the same chat insert/receipt owner as native sends after ingress admission."""
    encrypted = envelope.content_mode == ContentMode.ENCRYPTED
    metadata = (
        encrypted_message_storage_metadata(envelope.encrypted_envelope or {}) if encrypted else None
    )
    stored = await store_chat(
        db,
        session_id=UUID(str(envelope.conversation_id)),
        sender_did=envelope.sender_did_aw,
        sender_address=envelope.sender_address,
        body="" if encrypted else envelope.body,
        leaving=envelope.sender_leaving,
        hang_on=envelope.hang_on,
        reply_to=UUID(envelope.reply_to) if envelope.reply_to else None,
        signature=None if encrypted else signature,
        signed_payload=None if encrypted else envelope.signed_payload,
        content_mode=ContentMode.ENCRYPTED if encrypted else ContentMode.PLAINTEXT,
        message_version=2 if encrypted else 1,
        encrypted_envelope=envelope.encrypted_envelope if encrypted else None,
        encrypted_metadata=metadata,
        message_id=UUID(envelope.message_id),
        id_chain=id_chain,
        # Phase B wakes only its resolved/locked recipient below the writer.
        wake_dids=(),
    )
    if stored is None:
        raise FederationAuthorityError("federation_conversation_invalid")
    return stored


async def replay_federation_mutation_outbox(app, manager, *, limit: int = 100) -> int:
    """Retry pending committed mutation callbacks through the application's configured owner."""
    callback = getattr(app.state, "on_mutation", None)
    if callback is None:
        return 0
    return await deliver_federation_mutation_outbox(manager, callback, limit=limit)


async def deliver_federation_mutation_outbox(manager, callback, *, limit: int = 100) -> int:
    """Replay the least-attempted pending rows before retrying older failures.

    docs/aw-hooks-sot.md:83-88 requires durable at-least-once recovery. A
    permanently failing batch cannot prevent an untried neighbour from running.
    Row locks still coordinate concurrent workers; callback order is not a
    conversation-delivery ordering guarantee.
    """
    delivered = 0
    async with manager.transaction() as tx:
        rows = await tx.fetch_all(
            """
            SELECT outbox_id, event_type, payload_json
            FROM {{tables.federation_mutation_outbox}}
            WHERE delivered_at IS NULL
            ORDER BY attempt_count, created_at, outbox_id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
            """,
            limit,
        )
        for row in rows:
            payload = _decode_json(row["payload_json"])
            try:
                outcome = await callback(row["event_type"], payload)
                if isinstance(outcome, MutationDeliveryOutcome):
                    outcome.require_delivery()
            except Exception as exc:
                logger.warning(
                    "Federation mutation outbox delivery failed failure_type=%s",
                    type(exc).__name__,
                    extra={"outbox_id": str(row["outbox_id"])},
                )
                await tx.execute(
                    """
                    UPDATE {{tables.federation_mutation_outbox}}
                    SET attempt_count = attempt_count + 1,
                        last_error = $2
                    WHERE outbox_id = $1 AND delivered_at IS NULL
                    """,
                    row["outbox_id"],
                    type(exc).__name__,
                )
                continue
            await tx.execute(
                """
                UPDATE {{tables.federation_mutation_outbox}}
                SET delivered_at = clock_timestamp(),
                    attempt_count = attempt_count + 1,
                    last_error = NULL
                WHERE outbox_id = $1 AND delivered_at IS NULL
                """,
                row["outbox_id"],
            )
            delivered += 1
    return delivered


async def _deliver_federated_phase_b(
    db,
    *,
    envelope: FederationEnvelope,
    signature: str,
    recipient: Mapping,
    id_chain: dict | None = None,
    authority_token: AuthoritySecurityToken | None,
    registry_client,
    stored_route_continuation: bool = False,
    stored_route_snapshot: dict | None = None,
    before_commit: BeforeCommit | None = None,
    envelope_hash_override: str | None = None,
) -> dict[str, object]:
    if not envelope.conversation_id:
        raise FederationAuthorityError("federation_conversation_invalid")
    manager = db.get_manager("aweb")
    message_id = UUID(envelope.message_id)
    envelope_hash = envelope_hash_override or federation_envelope_hash(envelope, signature)
    metadata = _metadata(envelope)

    async with manager.transaction() as tx:
        controller_did = await _require_phase_a(tx, envelope, authority_token)
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            "federation-message:" + envelope.message_id,
            timeout=1.0,
        )
        receipt = await tx.fetch_one(
            """
            SELECT envelope_hash, canonical_metadata, storage_kind,
                   legacy_unreplayable, established_result
            FROM {{tables.message_ingress_receipts}}
            WHERE message_id = $1
            FOR UPDATE
            """,
            message_id,
        )
        established = established_federation_receipt(
            receipt, envelope_hash=envelope_hash, kind=MessageKind(envelope.type)
        )
        if established is not None:
            # Canonical metadata is bound only after ingress has restored its
            # accepted address/route projection and Phase A has admitted it.
            if established.metadata != metadata:
                raise FederationAuthorityError("federation_message_replay_conflict")
            return established.result

        locked_residence = await _lock_current_recipient(
            tx,
            envelope=envelope,
            recipient=recipient,
        )
        recipient = locked_residence.recipient
        if envelope.type == "chat" and is_verified_human(recipient):
            raise HumanChatRefused(recipient_label(recipient))
        recipient_storage_agent_id = recipient.get("agent_id")
        if stored_route_continuation:
            if stored_route_snapshot is None:
                raise FederationAuthorityError("federation_conversation_invalid")
            stored_reference = await _require_current_stored_route(
                tx,
                envelope=envelope,
                expected=stored_route_snapshot,
            )
            # Retain the saved reference after its participant and exact DID
            # residence are locked. Reuse those facts for storage/event
            # attribution; admission is still checked by the policy owner.
            if stored_reference in locked_residence.storage_agent_ids:
                recipient_storage_agent_id = stored_reference
                attributed = next(
                    row
                    for row in locked_residence.residences
                    if row["agent_id"] == stored_reference
                )
                recipient.update(
                    agent_id=attributed["agent_id"],
                    team_id=attributed["team_id"],
                    alias=attributed["alias"],
                )
        await _require_recipient_encryption_assertion(
            tx,
            envelope=envelope,
            storage_agent_ids=locked_residence.storage_agent_ids,
        )
        await _authorize_policy(
            tx,
            envelope=envelope,
            recipient=recipient,
            registry_client=registry_client,
            stored_route_continuation=stored_route_continuation,
        )
        await _ensure_sender_contact(
            tx,
            envelope=envelope,
            recipient=recipient,
            controller_did=controller_did,
        )
        existing_conversation = await tx.fetch_one(
            "SELECT 1 FROM {{tables.conversations}} WHERE conversation_id = $1",
            UUID(str(envelope.conversation_id)),
        )
        if existing_conversation is not None and not stored_route_continuation:
            raise FederationAuthorityError("federation_conversation_invalid")

        await tx.execute(
            """
            INSERT INTO {{tables.message_ingress_receipts}} (
                message_id, envelope_hash, canonical_metadata, storage_kind,
                legacy_unreplayable
            ) VALUES ($1, $2, $3::jsonb, $4, FALSE)
            """,
            message_id,
            envelope_hash,
            json.dumps(metadata, sort_keys=True, separators=(",", ":")),
            envelope.type,
        )
        if envelope.type == "mail":
            await _ensure_mail_conversation(
                tx,
                envelope,
                recipient,
                preserve_existing_route=stored_route_continuation,
            )
            message = await _store_mail(
                TransactionInfra(db, tx),
                envelope=envelope,
                signature=signature,
                recipient=recipient,
                id_chain=id_chain,
                recipient_storage_agent_id=recipient_storage_agent_id,
            )
        else:
            await _ensure_chat_session(
                tx,
                envelope,
                recipient,
                preserve_existing_route=stored_route_continuation,
            )
            message = await _store_chat(
                TransactionInfra(db, tx),
                envelope=envelope,
                signature=signature,
                id_chain=id_chain,
            )
        # Wake the admitted identity whose residence is locked through commit.
        # Storage row references never become wake or participant authority.
        record_did_wakes((recipient.get("did_aw"), recipient.get("did_key")), envelope.type)

        created_at: datetime = message["created_at"]
        result: dict[str, object] = {
            "message_id": envelope.message_id,
            "conversation_id": envelope.conversation_id,
            "status": "delivered",
            "delivered_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if envelope.type == "chat":
            result["session_id"] = envelope.conversation_id
        await tx.execute(
            """
            UPDATE {{tables.message_ingress_receipts}}
            SET established_result = $2::jsonb, updated_at = clock_timestamp()
            WHERE message_id = $1
            """,
            message_id,
            json.dumps(result, sort_keys=True, separators=(",", ":")),
        )
        event_context = FederatedMessageSentContext(
            kind=MessageKind(envelope.type),
            team_id=recipient.get("team_id"),
            from_did=envelope.sender_current_did_key,
            from_did_aw=envelope.sender_did_aw,
            to_agent_id=str(recipient.get("agent_id") or "") or None,
            from_alias=(envelope.sender_address or envelope.sender_did_aw).split("/", 1)[-1],
            message_id=envelope.message_id,
            conversation_id=envelope.conversation_id,
            to_alias=recipient.get("alias"),
            subject=envelope.subject or "",
            priority=envelope.priority,
            content_mode=envelope.content_mode,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.federation_mutation_outbox}} (
                message_id, event_type, payload_json
            ) VALUES ($1, $2, $3::jsonb)
            """,
            message_id,
            event_context.event_type.value,
            json.dumps(event_context.to_context(), sort_keys=True, separators=(",", ":")),
        )
        if before_commit is not None:
            await before_commit()
        return result


async def deliver_federated_phase_b(
    db,
    *,
    envelope: FederationEnvelope,
    signature: str,
    recipient: Mapping,
    id_chain: dict | None = None,
    authority_token: AuthoritySecurityToken | None,
    registry_client,
    stored_route_continuation: bool = False,
    stored_route_snapshot: dict | None = None,
    before_commit: BeforeCommit | None = None,
    envelope_hash_override: str | None = None,
) -> dict[str, object]:
    """Commit validated federation delivery or its exact receipt under the authority token."""
    try:
        return await _deliver_federated_phase_b(
            db,
            envelope=envelope,
            signature=signature,
            recipient=recipient,
            id_chain=id_chain,
            authority_token=authority_token,
            registry_client=registry_client,
            stored_route_continuation=stored_route_continuation,
            stored_route_snapshot=stored_route_snapshot,
            before_commit=before_commit,
            envelope_hash_override=envelope_hash_override,
        )
    except FederationAuthorityError:
        raise
    except (AsyncDBError, asyncpg.PostgresError) as exc:
        raise FederationAuthorityError("federation_authority_coordination_unavailable") from exc
