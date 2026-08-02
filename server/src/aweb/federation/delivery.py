"""Atomic Phase-B delivery for verified federation envelopes."""

from __future__ import annotations

import hashlib
import json
import logging

import asyncpg
from datetime import datetime, timezone
from typing import Awaitable, Callable
from uuid import UUID

from awid.e2ee_keys import validate_encryption_key_assertion
from awid.federation_errors import FederationAuthorityError
from pgdbm.errors import AsyncDBError
from awid.signing import canonical_json_bytes

from aweb.e2ee_messages import encrypted_message_storage_metadata
from aweb.federation.authority_state import AuthoritySecurityToken
from aweb.federation.envelope import FederationEnvelope

BeforeCommit = Callable[[], Awaitable[None]]

logger = logging.getLogger(__name__)


def federation_envelope_hash(envelope: FederationEnvelope, signature: str) -> str:
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
        "content_mode": envelope.content_mode or "legacy_plaintext_v1",
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
) -> None:
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
        SELECT did, address, delivery_origin, current_did_key, transport_hint
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
    if (
        set(participants) != {envelope.sender_did_aw, envelope.target_did_aw}
        or set(expected_conversation) != set(participants)
    ):
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
        if (
            envelope.sender_did_aw.startswith("did:aw:")
            and not sender_key
        ) or (sender_key and sender_key != envelope.sender_current_did_key):
            raise FederationAuthorityError("federation_conversation_invalid")
        if (
            envelope.target_did_aw.startswith("did:aw:")
            and not target_key
        ) or (target_key and target_key != envelope.target_current_did_key):
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
    if envelope.type != "chat":
        return
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
    if (
        set(chat_participants) != {envelope.sender_did_aw, envelope.target_did_aw}
        or set(expected_chat) != set(chat_participants)
    ):
        raise FederationAuthorityError("federation_conversation_invalid")
    require_participants(
        chat_participants,
        expected_chat,
        include_transport_hint=False,
    )


async def _lock_current_recipient(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: dict,
) -> dict:
    agent_id = recipient.get("agent_id")
    if agent_id is None:
        raise FederationAuthorityError("recipient_identity_not_found")
    row = await tx.fetch_one(
        """
        SELECT agent_id, team_id, did_key, did_aw, address, alias,
               inbound_mode, identity_scope
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        FOR UPDATE
        """,
        agent_id,
    )
    if row is None:
        raise FederationAuthorityError("recipient_identity_not_found")
    current = dict(row)
    target_did = str(envelope.target_did_aw or "").strip()
    if target_did.startswith("did:aw:"):
        if str(current.get("did_aw") or "").strip() != target_did:
            raise FederationAuthorityError("recipient_identity_not_found")
    elif str(current.get("did_key") or "").strip() != target_did:
        raise FederationAuthorityError("recipient_identity_not_found")
    if str(current.get("did_key") or "").strip() != envelope.target_current_did_key:
        raise FederationAuthorityError("recipient_current_key_mismatch")
    return current


async def _require_recipient_encryption_assertion(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: dict,
) -> None:
    if envelope.content_mode != "encrypted_v2":
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
    row = await tx.fetch_one(
        """
        SELECT assertion_canonical, assertion_signature
        FROM {{tables.agent_encryption_keys}}
        WHERE agent_id = $1 AND encryption_key_id = $2
          AND revoked_at IS NULL
        FOR UPDATE
        """,
        recipient["agent_id"],
        key_id,
    )
    if row is None:
        raise FederationAuthorityError("recipient_encryption_assertion_missing")
    try:
        assertion = json.loads(row["assertion_canonical"])
        if not isinstance(assertion, dict):
            raise ValueError("assertion must be an object")
        assertion["signature"] = row["assertion_signature"]
        validate_encryption_key_assertion(
            assertion,
            current_did_key=expected_did,
            stable_id=(
                envelope.target_did_aw
                if envelope.target_did_aw.startswith("did:aw:")
                else None
            ),
            now=datetime.now(timezone.utc),
        )
    except Exception as exc:
        raise FederationAuthorityError(
            "recipient_encryption_assertion_invalid_or_stale"
        ) from exc


async def _authorize_policy(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: dict,
    stored_route_continuation: bool,
) -> None:
    mode = str(recipient.get("inbound_mode") or "").strip().lower()
    recipient_global = str(recipient.get("did_aw") or "").startswith("did:aw:")
    if recipient_global and mode == "open":
        return
    if recipient_global and mode not in {"team_and_contacts", "contacts_only"}:
        raise FederationAuthorityError("recipient_policy_rejected")
    if not recipient_global and stored_route_continuation:
        return

    recipient_team = str(recipient.get("team_id") or "").strip()
    if recipient_team:
        same_team = await tx.fetch_one(
            """
            SELECT agent_id FROM {{tables.agents}}
            WHERE team_id = $1 AND deleted_at IS NULL
              AND (did_aw = $2 OR did_key = $2)
            LIMIT 1
            FOR UPDATE
            """,
            recipient_team,
            envelope.sender_did_aw,
        )
        if same_team is not None:
            return

    owner_dids = [
        value
        for value in {
            str(recipient.get("did_aw") or "").strip(),
            str(recipient.get("did_key") or "").strip(),
        }
        if value
    ]
    bindings = await tx.fetch_all(
        """
        SELECT contact_did_aw
        FROM {{tables.contacts}}
        WHERE owner_did = ANY($1::text[])
          AND reference_type = 'identity'
          AND status = 'active'
          AND contact_address = $2
        ORDER BY contact_id
        FOR UPDATE
        """,
        owner_dids,
        envelope.sender_address,
    )
    if any(row["contact_did_aw"] == envelope.sender_did_aw for row in bindings):
        return
    if any(row["contact_did_aw"] is None for row in bindings):
        raise FederationAuthorityError("contact_identity_binding_required")
    raise FederationAuthorityError("recipient_policy_rejected")


async def _ensure_sender_contact(
    tx,
    *,
    envelope: FederationEnvelope,
    recipient: dict,
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
    recipient: dict,
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
    recipient: dict,
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
                agent_id = EXCLUDED.agent_id,
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


def _participants(envelope: FederationEnvelope, recipient: dict):
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
    recipient: dict,
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
                agent_id = EXCLUDED.agent_id,
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


async def _store_mail(tx, envelope: FederationEnvelope, signature: str, recipient: dict):
    metadata = (
        encrypted_message_storage_metadata(envelope.encrypted_envelope or {})
        if envelope.content_mode == "encrypted_v2"
        else {}
    )
    row = await tx.fetch_one(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, from_address, to_alias,
            subject, body, priority, team_id, from_agent_id, to_agent_id,
            signature, signed_payload, created_at, conversation_id,
            message_version, content_mode, encrypted_envelope,
            encrypted_ciphertext, encrypted_key_wraps, encrypted_ciphertext_hash,
            encrypted_ciphertext_size, encrypted_key_wraps_hash,
            encrypted_inner_header_hash, encrypted_suite,
            encrypted_signing_key_id, signed_envelope_hash
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11,
            $12, $13, clock_timestamp(), $14, $15, $16, $17::jsonb,
            $18, $19::jsonb, $20, $21, $22, $23, $24, $25, $26
        ) RETURNING message_id, created_at
        """,
        UUID(envelope.message_id),
        envelope.sender_did_aw,
        envelope.target_did_aw,
        (envelope.sender_address or envelope.sender_did_aw).split("/", 1)[-1],
        envelope.sender_address,
        recipient.get("alias") or envelope.target_address.split("/", 1)[-1],
        "" if metadata else (envelope.subject or ""),
        "" if metadata else envelope.body,
        envelope.priority or "normal",
        recipient.get("team_id"),
        recipient.get("agent_id"),
        None if metadata else signature,
        None if metadata else envelope.signed_payload,
        UUID(str(envelope.conversation_id)),
        2 if metadata else 1,
        "encrypted_v2" if metadata else "legacy_plaintext_v1",
        json.dumps(envelope.encrypted_envelope, sort_keys=True, separators=(",", ":")) if metadata else None,
        metadata.get("encrypted_ciphertext"),
        json.dumps(metadata.get("encrypted_key_wraps"), sort_keys=True, separators=(",", ":")) if metadata.get("encrypted_key_wraps") is not None else None,
        metadata.get("encrypted_ciphertext_hash"),
        metadata.get("encrypted_ciphertext_size"),
        metadata.get("encrypted_key_wraps_hash"),
        metadata.get("encrypted_inner_header_hash"),
        metadata.get("encrypted_suite"),
        metadata.get("encrypted_signing_key_id"),
        metadata.get("signed_envelope_hash"),
    )
    await tx.execute(
        "UPDATE {{tables.conversations}} SET updated_at = clock_timestamp() WHERE conversation_id = $1",
        UUID(str(envelope.conversation_id)),
    )
    return row


async def _store_chat(tx, envelope: FederationEnvelope, signature: str):
    metadata = (
        encrypted_message_storage_metadata(envelope.encrypted_envelope or {})
        if envelope.content_mode == "encrypted_v2"
        else {}
    )
    participant = await tx.fetch_one(
        """
        SELECT alias, agent_id FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        UUID(str(envelope.conversation_id)),
        envelope.sender_did_aw,
    )
    row = await tx.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}} (
            message_id, session_id, from_agent_id, from_did, from_alias,
            from_address, body, sender_leaving, hang_on, reply_to,
            signature, signed_payload, content_mode, message_version,
            encrypted_envelope, encrypted_ciphertext, encrypted_key_wraps,
            encrypted_ciphertext_hash, encrypted_ciphertext_size,
            encrypted_key_wraps_hash, encrypted_inner_header_hash,
            encrypted_suite, encrypted_signing_key_id, signed_envelope_hash,
            created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15::jsonb, $16, $17::jsonb,
            $18, $19, $20, $21, $22, $23, $24, clock_timestamp()
        ) RETURNING message_id, created_at
        """,
        UUID(envelope.message_id),
        UUID(str(envelope.conversation_id)),
        participant.get("agent_id"),
        envelope.sender_did_aw,
        participant["alias"],
        envelope.sender_address,
        "" if metadata else envelope.body,
        envelope.sender_leaving,
        envelope.hang_on,
        UUID(envelope.reply_to) if envelope.reply_to else None,
        None if metadata else signature,
        None if metadata else envelope.signed_payload,
        "encrypted_v2" if metadata else "legacy_plaintext_v1",
        2 if metadata else 1,
        json.dumps(envelope.encrypted_envelope, sort_keys=True, separators=(",", ":")) if metadata else None,
        metadata.get("encrypted_ciphertext"),
        json.dumps(metadata.get("encrypted_key_wraps"), sort_keys=True, separators=(",", ":")) if metadata.get("encrypted_key_wraps") is not None else None,
        metadata.get("encrypted_ciphertext_hash"),
        metadata.get("encrypted_ciphertext_size"),
        metadata.get("encrypted_key_wraps_hash"),
        metadata.get("encrypted_inner_header_hash"),
        metadata.get("encrypted_suite"),
        metadata.get("encrypted_signing_key_id"),
        metadata.get("signed_envelope_hash"),
    )
    await tx.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}} (
            session_id, did, agent_id, last_read_message_id, last_read_at
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (session_id, did) DO UPDATE SET
            agent_id = EXCLUDED.agent_id,
            last_read_message_id = EXCLUDED.last_read_message_id,
            last_read_at = EXCLUDED.last_read_at
        """,
        UUID(str(envelope.conversation_id)),
        envelope.sender_did_aw,
        participant.get("agent_id"),
        row["message_id"],
        row["created_at"],
    )
    return row


async def replay_federation_mutation_outbox(app, manager, *, limit: int = 100) -> int:
    callback = getattr(app.state, "on_mutation", None)
    if callback is None:
        return 0
    delivered = 0
    async with manager.transaction() as tx:
        rows = await tx.fetch_all(
            """
            SELECT outbox_id, event_type, payload_json
            FROM {{tables.federation_mutation_outbox}}
            WHERE delivered_at IS NULL
            ORDER BY created_at, outbox_id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
            """,
            limit,
        )
        for row in rows:
            payload = _decode_json(row["payload_json"])
            try:
                await callback(row["event_type"], payload)
            except Exception as exc:
                logger.warning(
                    "Federation mutation outbox delivery failed",
                    extra={"outbox_id": str(row["outbox_id"])},
                    exc_info=True,
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
    recipient: dict,
    authority_token: AuthoritySecurityToken | None,
    stored_route_continuation: bool = False,
    stored_route_snapshot: dict | None = None,
    before_commit: BeforeCommit | None = None,
    envelope_hash_override: str | None = None,
) -> dict[str, object]:
    if not envelope.conversation_id:
        raise FederationAuthorityError("federation_conversation_invalid")
    manager = db.get_manager("aweb")
    message_id = UUID(envelope.message_id)
    envelope_hash = envelope_hash_override or federation_envelope_hash(
        envelope, signature
    )
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
        if receipt is not None:
            if (
                receipt["legacy_unreplayable"]
                or receipt["envelope_hash"] != envelope_hash
                or _decode_json(receipt["canonical_metadata"]) != metadata
                or receipt["storage_kind"] != envelope.type
                or receipt["established_result"] is None
            ):
                raise FederationAuthorityError("federation_message_replay_conflict")
            return dict(_decode_json(receipt["established_result"]))

        recipient = await _lock_current_recipient(
            tx,
            envelope=envelope,
            recipient=recipient,
        )
        if stored_route_continuation:
            if stored_route_snapshot is None:
                raise FederationAuthorityError("federation_conversation_invalid")
            await _require_current_stored_route(
                tx,
                envelope=envelope,
                expected=stored_route_snapshot,
            )
        await _require_recipient_encryption_assertion(
            tx,
            envelope=envelope,
            recipient=recipient,
        )
        await _authorize_policy(
            tx,
            envelope=envelope,
            recipient=recipient,
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
            message = await _store_mail(tx, envelope, signature, recipient)
        else:
            await _ensure_chat_session(
                tx,
                envelope,
                recipient,
                preserve_existing_route=stored_route_continuation,
            )
            message = await _store_chat(tx, envelope, signature)

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
        event_payload = {
            "team_id": recipient.get("team_id"),
            "from_agent_id": None,
            "from_did": envelope.sender_current_did_key,
            "from_did_aw": envelope.sender_did_aw,
            "to_agent_id": str(recipient.get("agent_id") or "") or None,
            "from_alias": (envelope.sender_address or envelope.sender_did_aw).split("/", 1)[-1],
            "message_id": envelope.message_id,
            "conversation_id": envelope.conversation_id,
            "session_id": envelope.conversation_id if envelope.type == "chat" else None,
            "to_alias": recipient.get("alias"),
            "subject": envelope.subject or "",
            "priority": envelope.priority or "normal",
            "content_mode": envelope.content_mode or "legacy_plaintext_v1",
            "federated": True,
        }
        await tx.execute(
            """
            INSERT INTO {{tables.federation_mutation_outbox}} (
                message_id, event_type, payload_json
            ) VALUES ($1, $2, $3::jsonb)
            """,
            message_id,
            "message.sent" if envelope.type == "mail" else "chat.message_sent",
            json.dumps(event_payload, sort_keys=True, separators=(",", ":")),
        )
        if before_commit is not None:
            await before_commit()
        return result


async def deliver_federated_phase_b(
    db,
    *,
    envelope: FederationEnvelope,
    signature: str,
    recipient: dict,
    authority_token: AuthoritySecurityToken | None,
    stored_route_continuation: bool = False,
    stored_route_snapshot: dict | None = None,
    before_commit: BeforeCommit | None = None,
    envelope_hash_override: str | None = None,
) -> dict[str, object]:
    try:
        return await _deliver_federated_phase_b(
            db,
            envelope=envelope,
            signature=signature,
            recipient=recipient,
            authority_token=authority_token,
            stored_route_continuation=stored_route_continuation,
            stored_route_snapshot=stored_route_snapshot,
            before_commit=before_commit,
            envelope_hash_override=envelope_hash_override,
        )
    except FederationAuthorityError:
        raise
    except (AsyncDBError, asyncpg.PostgresError) as exc:
        raise FederationAuthorityError(
            "federation_authority_coordination_unavailable"
        ) from exc
