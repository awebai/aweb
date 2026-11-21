"""DB component: native writers and ingress share the migration015 UUID receipt.

Authority/conversation inputs use the existing explicit Phase-B fixture; this
is trigger/transaction coverage, not a public ingress authentication claim.
"""

from uuid import UUID

import pytest

from awid.federation_errors import FederationAuthorityError
from aweb.federation.delivery import deliver_federated_phase_b
from aweb.messaging.chat_storage import store_chat
from aweb.messaging.mail_storage import (
    MailAttestation,
    MailRecipient,
    MailSender,
    MailStorageInput,
    PlaintextMailContent,
    store_mail,
)
from test_federation_activation_delivery import (
    _DB,
    _envelope,
    _seed_recipient_and_authority,
    _seed_stored_route,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_native_message_receipt_blocks_federation_before_storage_or_outbox(
    aweb_cloud_db, kind
):
    manager = aweb_cloud_db.aweb_db
    db = _DB(manager)
    envelope = _envelope(kind=kind)
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    await _seed_stored_route(manager, envelope, recipient)
    message_id, conversation_id = (
        UUID(envelope.message_id),
        UUID(envelope.conversation_id),
    )
    if kind == "mail":
        await store_mail(
            db,
            message=MailStorageInput(
                sender=MailSender(did=envelope.sender_did_aw),
                recipient=MailRecipient(did=envelope.target_did_aw),
                content=PlaintextMailContent(subject="subject", body="hello"),
                priority="normal",
                message_id=message_id,
                conversation_id=conversation_id,
                attestation=MailAttestation(
                    signature="signed-message", signed_payload=envelope.signed_payload
                ),
            ),
        )
    else:
        result = await store_chat(
            db,
            session_id=conversation_id,
            sender_did=envelope.sender_did_aw,
            body="hello",
            message_id=message_id,
            signature="signed-message",
            signed_payload=envelope.signed_payload,
            wake_dids=(),
        )
        assert result is not None
    receipt = await manager.fetch_one(
        "SELECT * FROM {{tables.message_ingress_receipts}} WHERE message_id=$1",
        message_id,
    )
    assert receipt["legacy_unreplayable"] is True
    assert receipt["established_result"] is None
    with pytest.raises(FederationAuthorityError) as refused:
        await deliver_federated_phase_b(
            db,
            envelope=envelope,
            signature="signed-message",
            recipient=recipient,
            authority_token=token,
            stored_route_continuation=True,
            registry_client=None,
        )
    assert refused.value.reason == "federation_message_replay_conflict"
    assert refused.value.http_status == 409
    assert (
        await manager.fetch_one(
            "SELECT * FROM {{tables.message_ingress_receipts}} WHERE message_id=$1",
            message_id,
        )
        == receipt
    )
    assert (
        await manager.fetch_value(
            "SELECT count(*) FROM {{tables.federation_mutation_outbox}} WHERE message_id=$1",
            message_id,
        )
        == 0
    )
    table = "messages" if kind == "mail" else "chat_messages"
    assert (
        await manager.fetch_value(
            f"SELECT count(*) FROM {{{{tables.{table}}}}} WHERE message_id=$1",
            message_id,
        )
        == 1
    )
