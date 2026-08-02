from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from pgdbm.errors import ConnectionError as DatabaseConnectionError

from awid.federation_errors import FederationAuthorityError
from aweb.federation.authority_state import AuthoritySecurityToken
from aweb.federation.delivery import (
    deliver_federated_phase_b,
    replay_federation_mutation_outbox,
)
from aweb.federation.envelope import FederationEnvelope


class _DB:
    def __init__(self, manager) -> None:
        self.manager = manager

    def get_manager(self, _name="aweb"):
        return self.manager


def _envelope(*, message_id: UUID | None = None, kind: str = "mail") -> FederationEnvelope:
    return FederationEnvelope(
        type=kind,
        sender_did_aw="did:aw:alice",
        sender_current_did_key="did:key:z6Mkalice",
        sender_address="alpha.example/alice",
        sender_delivery_origin="https://aweb.alpha.example",
        target_address="beta.example/bob",
        target_did_aw="did:aw:bob",
        target_current_did_key="did:key:z6Mkbob",
        target_delivery_origin="https://aweb.beta.example",
        body="hello",
        subject="subject" if kind == "mail" else None,
        priority="normal" if kind == "mail" else None,
        message_id=str(message_id or uuid4()),
        conversation_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        signed_payload='{"signed":true}',
    )


async def _seed_recipient_and_authority(db, envelope: FederationEnvelope) -> tuple[dict, AuthoritySecurityToken]:
    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:beta.example', 'beta.example', 'Beta', 'did:key:z6Mkteam')
        """
    )
    recipient = await db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, inbound_mode, identity_scope
        ) VALUES (
            'backend:beta.example', $1, $2, $3, 'bob', 'open', 'global'
        )
        RETURNING agent_id, team_id, did_key, did_aw, address, alias, inbound_mode
        """,
        envelope.target_current_did_key,
        envelope.target_did_aw,
        envelope.target_address,
    )
    await db.execute(
        """
        INSERT INTO {{tables.federation_did_checkpoints}} (
            did_aw, seq, entry_hash, state_hash, current_did_key, revision
        ) VALUES ($1, 1, $2, $3, $4, 1)
        """,
        envelope.sender_did_aw,
        "a" * 64,
        "b" * 64,
        envelope.sender_current_did_key,
    )
    await db.execute(
        """
        INSERT INTO {{tables.federation_address_authority_cohorts}} (
            canonical_address, authority_selection, authority_name, controller_did,
            authority_statement_version, authority_statement_digest, inherited,
            registry_explicit, registry_origin, bound_did_aw, bound_current_did_key,
            checkpoint_seq, checkpoint_entry_hash, checkpoint_revision,
            authoritative_delivery_origin, authoritative_read_completed_at,
            expires_at, generation, revision, publishing_fence
        ) VALUES (
            $1, 'dns', '_awid.alpha.example', 'did:key:z6Mkcontroller',
            'aweb.federation-authority.dns.v1', $2, FALSE, TRUE,
            'https://registry.alpha.example', $3, $4, 1, $5, 1, $6,
            clock_timestamp(), clock_timestamp() + INTERVAL '59 seconds', 1, 1, 1
        )
        """,
        envelope.sender_address,
        "sha256:" + "c" * 64,
        envelope.sender_did_aw,
        envelope.sender_current_did_key,
        "a" * 64,
        envelope.sender_delivery_origin,
    )
    return dict(recipient), AuthoritySecurityToken(
        envelope.sender_address or "",
        envelope.sender_did_aw,
        1,
        1,
    )


async def _seed_stored_route(db, envelope: FederationEnvelope, recipient: dict) -> dict:
    conversation_id = UUID(str(envelope.conversation_id))
    await db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did
        ) VALUES ($1, $2, $3, $4)
        """,
        conversation_id,
        envelope.type,
        recipient["team_id"],
        envelope.sender_did_aw,
    )
    await db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, delivery_origin,
            current_did_key, transport_hint, role
        ) VALUES
            ($1, $2, NULL, 'alice', $3, $4, $5, $6, 'initiator'),
            ($1, $7, $8, 'bob', $9, NULL, $10, 'local', 'participant')
        """,
        conversation_id,
        envelope.sender_did_aw,
        envelope.sender_address,
        envelope.sender_delivery_origin,
        envelope.sender_current_did_key,
        "federation:" + str(envelope.sender_delivery_origin),
        envelope.target_did_aw,
        recipient["agent_id"],
        envelope.target_address,
        envelope.target_current_did_key,
    )
    if envelope.type == "chat":
        await db.execute(
            """
            INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
            VALUES ($1, $2, $3)
            """,
            conversation_id,
            recipient["team_id"],
            envelope.sender_did_aw,
        )
        await db.execute(
            """
            INSERT INTO {{tables.chat_participants}} (
                session_id, did, agent_id, alias, address, delivery_origin,
                current_did_key
            ) VALUES
                ($1, $2, NULL, 'alice', $3, $4, $5),
                ($1, $6, $7, 'bob', $8, NULL, $9)
            """,
            conversation_id,
            envelope.sender_did_aw,
            envelope.sender_address,
            envelope.sender_delivery_origin,
            envelope.sender_current_did_key,
            envelope.target_did_aw,
            recipient["agent_id"],
            envelope.target_address,
            envelope.target_current_did_key,
        )
    conversation = {
        envelope.sender_did_aw: {
            "did": envelope.sender_did_aw,
            "address": envelope.sender_address,
            "delivery_origin": envelope.sender_delivery_origin,
            "current_did_key": envelope.sender_current_did_key,
            "transport_hint": "federation:" + str(envelope.sender_delivery_origin),
        },
        envelope.target_did_aw: {
            "did": envelope.target_did_aw,
            "address": envelope.target_address,
            "delivery_origin": None,
            "current_did_key": envelope.target_current_did_key,
            "transport_hint": "local",
        },
    }
    chat = (
        {
            did: {key: value for key, value in participant.items() if key != "transport_hint"}
            for did, participant in conversation.items()
        }
        if envelope.type == "chat"
        else None
    )
    return {"conversation": conversation, "chat": chat}


@pytest.mark.asyncio
async def test_phase_b_commits_receipt_message_participants_and_outbox_together(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)

    result = await deliver_federated_phase_b(
        _DB(manager),
        envelope=envelope,
        signature="signed-message",
        recipient=recipient,
        authority_token=token,
    )

    assert result["message_id"] == envelope.message_id
    assert result["conversation_id"] == envelope.conversation_id
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(envelope.message_id),
    ) == 1
    receipt = await manager.fetch_one(
        """
        SELECT envelope_hash, legacy_unreplayable, established_result
        FROM {{tables.message_ingress_receipts}} WHERE message_id = $1
        """,
        UUID(envelope.message_id),
    )
    assert receipt["envelope_hash"].startswith("sha256:")
    assert receipt["legacy_unreplayable"] is False
    established = receipt["established_result"]
    if isinstance(established, str):
        established = json.loads(established)
    assert established["message_id"] == envelope.message_id
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.federation_mutation_outbox}} WHERE message_id = $1",
        UUID(envelope.message_id),
    ) == 1
    route_hints = await manager.fetch_all(
        """
        SELECT did, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        ORDER BY did
        """,
        UUID(str(envelope.conversation_id)),
    )
    assert {row["did"]: row["transport_hint"] for row in route_hints} == {
        envelope.sender_did_aw: "federation:" + str(envelope.sender_delivery_origin),
        envelope.target_did_aw: "local",
    }
    contact = await manager.fetch_one(
        """
        SELECT owner_did, contact_address, contact_did_aw,
               binding_controller_did, status
        FROM {{tables.contacts}}
        WHERE owner_did = $1 AND contact_address = $2
        """,
        envelope.target_did_aw,
        envelope.sender_address,
    )
    assert dict(contact) == {
        "owner_did": envelope.target_did_aw,
        "contact_address": envelope.sender_address,
        "contact_did_aw": envelope.sender_did_aw,
        "binding_controller_did": "did:key:z6Mkcontroller",
        "status": "active",
    }


@pytest.mark.asyncio
async def test_phase_b_database_outage_has_stable_retryable_failure() -> None:
    class FailedManager:
        @asynccontextmanager
        async def transaction(self):
            raise DatabaseConnectionError("database unavailable")
            yield

    envelope = _envelope()
    with pytest.raises(FederationAuthorityError) as error:
        await deliver_federated_phase_b(
            _DB(FailedManager()),
            envelope=envelope,
            signature="signed-message",
            recipient={},
            authority_token=None,
        )

    assert error.value.reason == "federation_authority_coordination_unavailable"
    assert error.value.http_status == 503
    assert error.value.retryable is True


@pytest.mark.asyncio
async def test_phase_b_rejects_missing_authority_token_without_effects(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, _token = await _seed_recipient_and_authority(manager, envelope)

    with pytest.raises(FederationAuthorityError) as error:
        await deliver_federated_phase_b(
            _DB(manager), envelope=envelope, signature="signed-message",
            recipient=recipient, authority_token=None,
        )

    assert error.value.reason == "federation_authority_cas_conflict"
    for table in ("message_ingress_receipts", "messages", "contacts"):
        assert await manager.fetch_value(
            f'SELECT COUNT(*) FROM "aweb".{table}'
        ) == 0


@pytest.mark.asyncio
async def test_phase_b_chat_commits_session_message_and_participants(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope(kind="chat")
    recipient, token = await _seed_recipient_and_authority(manager, envelope)

    result = await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-chat",
        recipient=recipient, authority_token=token,
    )

    assert result["session_id"] == envelope.conversation_id
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(envelope.message_id),
    ) == 1
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_participants}} WHERE session_id = $1",
        UUID(envelope.conversation_id),
    ) == 2


@pytest.mark.asyncio
async def test_phase_b_exact_replay_returns_established_result_without_effects(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    first = await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )
    await manager.execute(
        "DELETE FROM {{tables.contacts}} WHERE owner_did = $1 AND contact_address = $2",
        envelope.target_did_aw,
        envelope.sender_address,
    )
    await manager.execute(
        "UPDATE {{tables.agents}} SET inbound_mode = 'team_and_contacts' WHERE agent_id = $1",
        recipient["agent_id"],
    )
    effect_tables = (
        "contacts",
        "conversations",
        "conversation_participants",
        "messages",
        "message_ingress_receipts",
        "federation_mutation_outbox",
    )
    before = {
        table: await manager.fetch_value(f'SELECT COUNT(*) FROM "aweb".{table}')
        for table in effect_tables
    }

    replay = await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )

    after = {
        table: await manager.fetch_value(f'SELECT COUNT(*) FROM "aweb".{table}')
        for table in effect_tables
    }
    assert replay == first
    assert after == before
    assert after["contacts"] == 0
    assert after["federation_mutation_outbox"] == 1


@pytest.mark.asyncio
async def test_phase_b_waits_for_and_enforces_concurrent_recipient_policy_change(
    aweb_cloud_db,
) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)

    async with manager.transaction() as policy_tx:
        await policy_tx.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'team_and_contacts' WHERE agent_id = $1",
            recipient["agent_id"],
        )
        delivery = asyncio.create_task(
            deliver_federated_phase_b(
                _DB(manager),
                envelope=envelope,
                signature="signed-message",
                recipient=recipient,
                authority_token=token,
            )
        )
        await asyncio.sleep(0.1)
        assert not delivery.done(), "Phase B must wait for the recipient policy row lock"

    with pytest.raises(FederationAuthorityError) as error:
        await delivery
    assert error.value.reason == "recipient_policy_rejected"
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id = $1",
        UUID(envelope.message_id),
    ) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("mutation", ["delete", "change_route"])
async def test_phase_b_rechecks_stored_route_after_concurrent_mutation(
    aweb_cloud_db,
    kind: str,
    mutation: str,
) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope(kind=kind)
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    stored_route_snapshot = await _seed_stored_route(manager, envelope, recipient)
    conversation_id = UUID(str(envelope.conversation_id))

    async with manager.transaction() as route_change:
        if mutation == "delete":
            if kind == "chat":
                await route_change.execute(
                    "DELETE FROM {{tables.chat_participants}} WHERE session_id = $1",
                    conversation_id,
                )
                await route_change.execute(
                    "DELETE FROM {{tables.chat_sessions}} WHERE session_id = $1",
                    conversation_id,
                )
            await route_change.execute(
                "DELETE FROM {{tables.conversations}} WHERE conversation_id = $1",
                conversation_id,
            )
        else:
            await route_change.execute(
                """
                UPDATE {{tables.conversation_participants}}
                SET address = CASE WHEN did = $2 THEN 'changed.example/alice' ELSE address END,
                    delivery_origin = CASE
                        WHEN did = $2 THEN 'https://changed.example'
                        ELSE 'https://changed-target.example'
                    END,
                    transport_hint = CASE
                        WHEN did = $2 THEN 'changed-sender-hint'
                        ELSE 'changed-target-hint'
                    END
                WHERE conversation_id = $1 AND did = ANY($3::text[])
                """,
                conversation_id,
                envelope.sender_did_aw,
                [envelope.sender_did_aw, envelope.target_did_aw],
            )
            if kind == "chat":
                await route_change.execute(
                    """
                    UPDATE {{tables.chat_participants}}
                    SET address = CASE WHEN did = $2 THEN 'changed.example/alice' ELSE address END,
                        delivery_origin = CASE
                            WHEN did = $2 THEN 'https://changed.example'
                            ELSE 'https://changed-target.example'
                        END
                    WHERE session_id = $1 AND did = ANY($3::text[])
                    """,
                    conversation_id,
                    envelope.sender_did_aw,
                    [envelope.sender_did_aw, envelope.target_did_aw],
                )
        delivery = asyncio.create_task(
            deliver_federated_phase_b(
                _DB(manager),
                envelope=envelope,
                signature="signed-message",
                recipient=recipient,
                authority_token=token,
                stored_route_continuation=True,
                stored_route_snapshot=stored_route_snapshot,
            )
        )
        await asyncio.sleep(0.1)
        assert not delivery.done(), "Phase B must wait for stored-route mutation"

    with pytest.raises(FederationAuthorityError) as error:
        await delivery
    assert error.value.reason == "federation_conversation_invalid"
    if mutation == "delete":
        assert await manager.fetch_value(
            "SELECT COUNT(*) FROM {{tables.conversations}} WHERE conversation_id = $1",
            conversation_id,
        ) == 0
    else:
        assert await manager.fetch_value(
            """
            SELECT address FROM {{tables.conversation_participants}}
            WHERE conversation_id = $1 AND did = $2
            """,
            conversation_id,
            envelope.sender_did_aw,
        ) == "changed.example/alice"
        changed_target = await manager.fetch_one(
            """
            SELECT delivery_origin, transport_hint
            FROM {{tables.conversation_participants}}
            WHERE conversation_id = $1 AND did = $2
            """,
            conversation_id,
            envelope.target_did_aw,
        )
        assert dict(changed_target) == {
            "delivery_origin": "https://changed-target.example",
            "transport_hint": "changed-target-hint",
        }
    storage_table = "messages" if kind == "mail" else "chat_messages"
    assert await manager.fetch_value(
        f'SELECT COUNT(*) FROM "aweb".{storage_table} WHERE message_id = $1',
        UUID(envelope.message_id),
    ) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "store", "participant"),
    [
        ("mail", "conversation", "sender"),
        ("mail", "conversation", "target"),
        ("chat", "conversation", "sender"),
        ("chat", "conversation", "target"),
        ("chat", "chat", "sender"),
        ("chat", "chat", "target"),
    ],
)
async def test_phase_b_rejects_missing_global_stored_route_key(
    aweb_cloud_db,
    kind: str,
    store: str,
    participant: str,
) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope(kind=kind)
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    snapshot = await _seed_stored_route(manager, envelope, recipient)
    did = (
        envelope.sender_did_aw if participant == "sender" else envelope.target_did_aw
    )
    if store == "conversation":
        await manager.execute(
            """
            UPDATE {{tables.conversation_participants}}
            SET current_did_key = NULL
            WHERE conversation_id = $1 AND did = $2
            """,
            UUID(str(envelope.conversation_id)),
            did,
        )
    else:
        await manager.execute(
            """
            UPDATE {{tables.chat_participants}}
            SET current_did_key = NULL
            WHERE session_id = $1 AND did = $2
            """,
            UUID(str(envelope.conversation_id)),
            did,
        )
    snapshot[store][did]["current_did_key"] = None

    with pytest.raises(FederationAuthorityError) as error:
        await deliver_federated_phase_b(
            _DB(manager),
            envelope=envelope,
            signature="signed-message",
            recipient=recipient,
            authority_token=token,
            stored_route_continuation=True,
            stored_route_snapshot=snapshot,
        )

    assert error.value.reason == "federation_conversation_invalid"
    storage_table = "messages" if kind == "mail" else "chat_messages"
    assert await manager.fetch_value(
        f'SELECT COUNT(*) FROM "aweb".{storage_table} WHERE message_id = $1',
        UUID(envelope.message_id),
    ) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize(
    "malformed_route",
    ["target_origin", "sender_transport_hint", "target_transport_hint"],
)
async def test_phase_b_rejects_preexisting_noncanonical_stored_route(
    aweb_cloud_db,
    kind: str,
    malformed_route: str,
) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope(kind=kind)
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    snapshot = await _seed_stored_route(manager, envelope, recipient)
    conversation_id = UUID(str(envelope.conversation_id))
    sender_did = envelope.sender_did_aw
    target_did = envelope.target_did_aw
    if malformed_route == "target_origin":
        await manager.execute(
            """
            UPDATE {{tables.conversation_participants}}
            SET delivery_origin = 'https://poisoned-target.example'
            WHERE conversation_id = $1 AND did = $2
            """,
            conversation_id,
            target_did,
        )
        snapshot["conversation"][target_did]["delivery_origin"] = (
            "https://poisoned-target.example"
        )
    else:
        did = sender_did if malformed_route.startswith("sender") else target_did
        await manager.execute(
            """
            UPDATE {{tables.conversation_participants}}
            SET transport_hint = 'poisoned-route'
            WHERE conversation_id = $1 AND did = $2
            """,
            conversation_id,
            did,
        )
        snapshot["conversation"][did]["transport_hint"] = "poisoned-route"

    with pytest.raises(FederationAuthorityError) as error:
        await deliver_federated_phase_b(
            _DB(manager),
            envelope=envelope,
            signature="signed-message",
            recipient=recipient,
            authority_token=token,
            stored_route_continuation=True,
            stored_route_snapshot=snapshot,
        )

    assert error.value.reason == "federation_conversation_invalid"


@pytest.mark.asyncio
async def test_phase_b_rejects_preexisting_external_chat_target_origin(
    aweb_cloud_db,
) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope(kind="chat")
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    snapshot = await _seed_stored_route(manager, envelope, recipient)
    conversation_id = UUID(str(envelope.conversation_id))
    await manager.execute(
        """
        UPDATE {{tables.chat_participants}}
        SET delivery_origin = 'https://poisoned-target.example'
        WHERE session_id = $1 AND did = $2
        """,
        conversation_id,
        envelope.target_did_aw,
    )
    snapshot["chat"][envelope.target_did_aw]["delivery_origin"] = (
        "https://poisoned-target.example"
    )

    with pytest.raises(FederationAuthorityError) as error:
        await deliver_federated_phase_b(
            _DB(manager),
            envelope=envelope,
            signature="signed-message",
            recipient=recipient,
            authority_token=token,
            stored_route_continuation=True,
            stored_route_snapshot=snapshot,
        )

    assert error.value.reason == "federation_conversation_invalid"
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}} WHERE message_id = $1",
        UUID(envelope.message_id),
    ) == 0


@pytest.mark.asyncio
async def test_phase_b_changed_same_id_conflicts_across_mail_and_chat(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )
    changed = _envelope(message_id=UUID(envelope.message_id), kind="chat")
    changed = changed.model_copy(update={"conversation_id": envelope.conversation_id})

    with pytest.raises(FederationAuthorityError) as error:
        await deliver_federated_phase_b(
            _DB(manager), envelope=changed, signature="signed-message",
            recipient=recipient, authority_token=token,
        )

    assert error.value.reason == "federation_message_replay_conflict"


@pytest.mark.asyncio
async def test_contact_does_not_transfer_when_an_address_is_reassigned(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    first = _envelope()
    recipient, first_token = await _seed_recipient_and_authority(manager, first)
    await deliver_federated_phase_b(
        _DB(manager), envelope=first, signature="signed-first",
        recipient=recipient, authority_token=first_token,
    )

    replacement = _envelope().model_copy(
        update={
            "sender_address": first.sender_address,
            "sender_did_aw": "did:aw:replacement",
            "sender_current_did_key": "did:key:z6Mkreplacement",
            "sender_delivery_origin": first.sender_delivery_origin,
        }
    )
    await manager.execute(
        """
        INSERT INTO {{tables.federation_did_checkpoints}} (
            did_aw, seq, entry_hash, state_hash, current_did_key, revision
        ) VALUES ($1, 1, $2, $3, $4, 1)
        """,
        replacement.sender_did_aw,
        "d" * 64,
        "e" * 64,
        replacement.sender_current_did_key,
    )
    await manager.execute(
        """
        UPDATE {{tables.federation_address_authority_cohorts}}
        SET controller_did = 'did:key:z6Mkreplacementcontroller',
            bound_did_aw = $2,
            bound_current_did_key = $3,
            checkpoint_entry_hash = $4,
            authoritative_delivery_origin = $5,
            generation = generation + 1,
            authoritative_read_completed_at = clock_timestamp(),
            expires_at = clock_timestamp() + INTERVAL '59 seconds'
        WHERE canonical_address = $1
        """,
        replacement.sender_address,
        replacement.sender_did_aw,
        replacement.sender_current_did_key,
        "d" * 64,
        replacement.sender_delivery_origin,
    )
    replacement_token = AuthoritySecurityToken(
        replacement.sender_address or "", replacement.sender_did_aw, 1, 2
    )

    await deliver_federated_phase_b(
        _DB(manager), envelope=replacement, signature="signed-replacement",
        recipient=recipient, authority_token=replacement_token,
    )

    contact = await manager.fetch_one(
        """
        SELECT contact_did_aw, binding_controller_did
        FROM {{tables.contacts}}
        WHERE owner_did = $1 AND contact_address = $2
        """,
        replacement.target_did_aw,
        replacement.sender_address,
    )
    assert dict(contact) == {
        "contact_did_aw": first.sender_did_aw,
        "binding_controller_did": "did:key:z6Mkcontroller",
    }


@pytest.mark.asyncio
async def test_phase_b_forced_failure_rolls_back_every_effect(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)

    async def fail_before_commit() -> None:
        raise RuntimeError("forced rollback")

    with pytest.raises(RuntimeError, match="forced rollback"):
        await deliver_federated_phase_b(
            _DB(manager), envelope=envelope, signature="signed-message",
            recipient=recipient, authority_token=token,
            before_commit=fail_before_commit,
        )

    for table in ("message_ingress_receipts", "messages", "federation_mutation_outbox"):
        assert await manager.fetch_value(
            f'SELECT COUNT(*) FROM "aweb".{table} WHERE message_id = $1',
            UUID(envelope.message_id),
        ) == 0
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.conversations}} WHERE conversation_id = $1",
        UUID(envelope.conversation_id),
    ) == 0


@pytest.mark.asyncio
async def test_committed_outbox_retries_after_hook_failure(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )

    async def fail(_event_type, _payload):
        raise RuntimeError("offline")

    app = SimpleNamespace(state=SimpleNamespace(on_mutation=fail))
    assert await replay_federation_mutation_outbox(app, manager) == 0
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.federation_mutation_outbox}} WHERE delivered_at IS NULL"
    ) == 1

    delivered = []

    async def succeed(event_type, payload):
        delivered.append((event_type, payload["message_id"]))

    app.state.on_mutation = succeed
    assert await replay_federation_mutation_outbox(app, manager) == 1
    assert delivered == [("message.sent", envelope.message_id)]
    assert await manager.fetch_value(
        "SELECT COUNT(*) FROM {{tables.federation_mutation_outbox}} WHERE delivered_at IS NULL"
    ) == 0


@pytest.mark.asyncio
async def test_concurrent_outbox_workers_deliver_a_committed_event_once(aweb_cloud_db) -> None:
    manager = aweb_cloud_db.aweb_db
    envelope = _envelope()
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    await deliver_federated_phase_b(
        _DB(manager), envelope=envelope, signature="signed-message",
        recipient=recipient, authority_token=token,
    )

    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def hold_delivery(_event_type, _payload):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()

    app = SimpleNamespace(state=SimpleNamespace(on_mutation=hold_delivery))
    first = asyncio.create_task(replay_federation_mutation_outbox(app, manager))
    await entered.wait()
    second = asyncio.create_task(replay_federation_mutation_outbox(app, manager))
    await asyncio.sleep(0.05)

    assert calls == 1
    release.set()
    assert sum(await asyncio.gather(first, second)) == 1
